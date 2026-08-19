"""End-to-end gate for path traversal: findings -> repo -> harness -> oracle,
on secfix's own fixtures, via the in-process local sandbox. Mirrors
tests/test_pipeline_cmdi.py's structure exactly, swapped to the
pathtraversal harness and oracle.
"""
from pathlib import Path

from secfix.findings import Finding
from secfix.harness.python_pathtraversal import generate_harness
from secfix.oracle import pathtraversal
from secfix.repo import analyze_finding
from secfix.sandbox.local import LocalSandbox
from secfix.trace import trace_from_json

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_pipeline(fixture_rel_path: str, start_line: int, end_line: int, tmp_path: Path):
    finding = Finding(
        rule_id="python.lang.security.audit.path-traversal-open",
        message="tainted string used to build a file path",
        file_path=Path(fixture_rel_path),
        start_line=start_line,
        end_line=end_line,
        code_span="",
    )

    target = analyze_finding(finding, REPO_ROOT)
    assert target.kind == "supported", getattr(target, "reason", None)

    harness_result = generate_harness(target, tmp_path)
    assert harness_result.kind == "generated", harness_result.reason

    (tmp_path / harness_result.filename).write_text(harness_result.source)

    sandbox = LocalSandbox(REPO_ROOT, i_understand_local_is_unsafe=True)
    sandbox_result = sandbox.run(tmp_path, harness_filename=harness_result.filename)
    assert sandbox_result.exit_code == 0, sandbox_result.stdout + sandbox_result.stderr
    assert sandbox_result.trace_path is not None

    trace = trace_from_json(sandbox_result.trace_path.read_text())
    return pathtraversal.evaluate(trace, harness_result.sentinel)


def test_vulnerable_fixture_confirmed(tmp_path):
    result = _run_pipeline("tests/fixtures/vulnerable_pathtraversal_example.py", 9, 9, tmp_path)
    assert result.verdict == pathtraversal.VERDICT_CONFIRMED
    assert "SECFIX_TAINT_" in result.offending_sql
    assert ".." in result.offending_sql


def test_vulnerable_join_fixture_confirmed_via_absolute_probe(tmp_path):
    """Regression test for the false-safe gap: this fixture blocklists ".."
    outright, so the relative-traversal probe never reaches the sink at all
    — only the absolute-path probe does, discarding BASE_DIR via
    os.path.join's absolute-override behavior. Before the oracle gained
    signal (b), this fixture came back not_reproduced despite being
    genuinely exploitable.
    """
    result = _run_pipeline(
        "tests/fixtures/vulnerable_pathtraversal_join_example.py", 16, 16, tmp_path
    )
    assert result.verdict == pathtraversal.VERDICT_CONFIRMED
    assert "SECFIX_TAINT_" in result.offending_sql
    # The base directory contributed nothing at all to what reached the
    # sink — the clearest possible demonstration of the bypass.
    assert ".." not in result.offending_sql
    assert result.offending_sql.startswith("/")
    assert "srv" not in result.offending_sql


def test_safe_fixture_not_reproduced(tmp_path):
    """Covers BOTH probes: evaluate() only returns not_reproduced if no
    entry in the trace (from either the relative-traversal or the
    absolute-path probe) shows an escape, so this also proves the safe
    fixture's resolve+is_relative_to confinement isn't bypassable via the
    absolute-override trick either.
    """
    result = _run_pipeline("tests/fixtures/safe_pathtraversal_example.py", 13, 13, tmp_path)
    assert result.verdict == pathtraversal.VERDICT_NOT_REPRODUCED
