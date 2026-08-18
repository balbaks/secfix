"""End-to-end gate: findings -> repo -> harness -> oracle, on secfix's own
fixtures, via the in-process local sandbox. This is the "must run green"
checkpoint called out in the build order before Docker/model/report work.
"""
from pathlib import Path

from secfix.findings import Finding
from secfix.harness.python_sqli import generate_harness
from secfix.oracle import sqli
from secfix.repo import analyze_finding
from secfix.sandbox.local import LocalSandbox
from secfix.trace import trace_from_json

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_pipeline(fixture_rel_path: str, start_line: int, end_line: int, tmp_path: Path):
    finding = Finding(
        rule_id="python.lang.security.audit.sql-injection",
        message="tainted string used to build a SQL query",
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
    return sqli.evaluate(trace, harness_result.sentinel)


def test_vulnerable_fixture_confirmed(tmp_path):
    result = _run_pipeline("tests/fixtures/vulnerable_example.py", 13, 15, tmp_path)
    assert result.verdict == sqli.VERDICT_CONFIRMED
    assert "SECFIX_TAINT_" in result.offending_sql


def test_safe_fixture_not_reproduced(tmp_path):
    result = _run_pipeline("tests/fixtures/safe_example.py", 12, 12, tmp_path)
    assert result.verdict == sqli.VERDICT_NOT_REPRODUCED


def test_half_fixed_fixture_still_confirmed(tmp_path):
    """A function where one of two queries was fixed but the other wasn't must
    still come back CONFIRMED — the oracle must not stop at the first safe
    query and declare victory."""
    result = _run_pipeline("tests/fixtures/half_fixed_example.py", 14, 17, tmp_path)
    assert result.verdict == sqli.VERDICT_CONFIRMED
    assert "SECFIX_TAINT_" in result.offending_sql
    # The offending SQL is the second (still-vulnerable) query, not the first.
    assert "audit_log" in result.offending_sql
