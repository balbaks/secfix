"""End-to-end gate for OS command injection: findings -> repo -> harness ->
oracle, on secfix's own fixtures, via the in-process local sandbox. Mirrors
tests/test_pipeline.py's structure exactly, swapped to the cmdi harness and
oracle.
"""
from pathlib import Path

from secfix.findings import Finding
from secfix.harness.python_cmdi import generate_harness
from secfix.oracle import cmdi
from secfix.repo import analyze_finding
from secfix.sandbox.local import LocalSandbox
from secfix.trace import trace_from_json

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_pipeline(fixture_rel_path: str, start_line: int, end_line: int, tmp_path: Path):
    finding = Finding(
        rule_id="python.lang.security.audit.dangerous-system-call",
        message="tainted string used to build a shell command",
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
    return cmdi.evaluate(trace, harness_result.sentinel)


def test_vulnerable_fixture_confirmed(tmp_path):
    result = _run_pipeline("tests/fixtures/vulnerable_cmdi_example.py", 9, 9, tmp_path)
    assert result.verdict == cmdi.VERDICT_CONFIRMED
    assert "SECFIX_TAINT_" in result.offending_sql


def test_safe_fixture_not_reproduced(tmp_path):
    result = _run_pipeline("tests/fixtures/safe_cmdi_example.py", 9, 9, tmp_path)
    assert result.verdict == cmdi.VERDICT_NOT_REPRODUCED
