"""Exercises apply_and_verify_patch's post-patch verdict logic end-to-end on
an isolated scratch git repo (never the real project repo, since the function
under test creates branches and commits).
"""
import subprocess
from pathlib import Path

import secfix.harness.python_cmdi as cmdi_harness
import secfix.harness.python_pathtraversal as pathtraversal_harness
import secfix.vulnclass as vulnclass
from secfix.findings import Finding
from secfix.models import PatchResult
from secfix.oracle import cmdi as oracle_cmdi
from secfix.oracle import pathtraversal as oracle_pathtraversal
from secfix.patch import KIND_FAILED, KIND_VALIDATED, apply_and_verify_patch
from secfix.repo import analyze_finding
from secfix.sandbox.local import LocalSandbox

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _init_scratch_repo(tmp_path: Path, fixture_name: str, target_rel: str) -> Path:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo_root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_root, check=True)

    (repo_root / target_rel).write_text((FIXTURES / fixture_name).read_text())
    subprocess.run(["git", "add", target_rel], cwd=repo_root, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=repo_root, check=True)
    return repo_root


def test_miscounted_hunk_header_recovered_via_recount(tmp_path):
    """LLM-generated diffs routinely get the @@ hunk line *counts* arithmetically
    wrong while the context/location is otherwise correct — plain `git apply
    --check` rejects these as "corrupt patch". apply_and_verify_patch must fall
    back to `--recount` and still validate the patch rather than failing on a
    cosmetic header miscount.
    """
    target_rel = "vuln_target.py"
    repo_root = _init_scratch_repo(tmp_path, "vulnerable_example.py", target_rel)

    # Correct location (line 13) and correct context, but the header claims
    # 3/3 lines when the hunk body actually has 4/4 (1 leading ctx + 2 changed
    # + 1 trailing ctx) — the exact "normal LLM diff imprecision" shape.
    diff_text = (
        f"--- a/{target_rel}\n"
        f"+++ b/{target_rel}\n"
        "@@ -13,3 +13,3 @@\n"
        "     cursor = conn.cursor()\n"
        "-    query = \"SELECT * FROM users WHERE name = '%s'\" % name\n"
        "-    cursor.execute(query)\n"
        "+    query = \"SELECT * FROM users WHERE name = %s\"\n"
        "+    cursor.execute(query, (name,))\n"
        "     return cursor.fetchall()\n"
    )

    finding = Finding(
        rule_id="python.lang.security.audit.sql-injection",
        message="tainted string used to build a SQL query",
        file_path=Path(target_rel),
        start_line=13,
        end_line=15,
        code_span="",
    )
    target = analyze_finding(finding, repo_root)
    assert target.kind == "supported", getattr(target, "reason", None)

    patch_result = PatchResult(
        diff=diff_text,
        explanation="parameterized the query",
        notes="",
    )
    sandbox = LocalSandbox(repo_root, i_understand_local_is_unsafe=True)
    workdir = tmp_path / "work"
    workdir.mkdir()

    result = apply_and_verify_patch(
        repo_root, Path(target_rel), target, patch_result, sandbox, workdir
    )

    assert result.kind == KIND_VALIDATED, result.detail


def test_partial_patch_not_validated(tmp_path):
    """Two queries share the tainted param; a diff that parameterizes only
    the first must NOT come back validated, because the second query still
    lets the sentinel reach raw SQL.
    """
    target_rel = "vuln_target.py"
    repo_root = _init_scratch_repo(tmp_path, "two_query_vulnerable_example.py", target_rel)
    original = (repo_root / target_rel).read_text()

    # Build a real git diff that fixes only the first query, by editing the
    # working tree and letting git compute it (guarantees the diff is in a
    # form `git apply` will accept), then restoring the original so
    # apply_and_verify_patch starts from a clean, unpatched HEAD.
    partially_fixed = original.replace(
        '''cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)''',
        '''cursor.execute("SELECT * FROM users WHERE name = ?", (name,))''',
    )
    assert partially_fixed != original  # sanity: the replace actually matched
    (repo_root / target_rel).write_text(partially_fixed)
    diff_text = subprocess.run(
        ["git", "diff"], cwd=repo_root, check=True, capture_output=True, text=True
    ).stdout
    subprocess.run(["git", "checkout", "-q", "--", target_rel], cwd=repo_root, check=True)

    finding = Finding(
        rule_id="python.lang.security.audit.sql-injection",
        message="tainted string used to build a SQL query",
        file_path=Path(target_rel),
        start_line=15,
        end_line=16,
        code_span="",
    )
    target = analyze_finding(finding, repo_root)
    assert target.kind == "supported", getattr(target, "reason", None)

    patch_result = PatchResult(
        diff=diff_text,
        explanation="parameterized the first query only",
        notes="second query left interpolated on purpose, to exercise the failure path",
    )
    sandbox = LocalSandbox(repo_root, i_understand_local_is_unsafe=True)
    workdir = tmp_path / "work"
    workdir.mkdir()

    result = apply_and_verify_patch(
        repo_root, Path(target_rel), target, patch_result, sandbox, workdir
    )

    assert result.kind != KIND_VALIDATED
    assert result.kind == KIND_FAILED
    assert "STILL reproducible" in result.detail
    assert "audit_log" in result.detail


def test_cmdi_argv_rewrite_validated(tmp_path):
    """Closes the loop for cmdi: a diff that rewrites os.system(f"...") to
    subprocess.run([...], shell=False) must apply via plain `git apply
    --check` (well-formed by construction, same as sqli) and must come back
    VALIDATED once re-verified with the cmdi harness/oracle — the sentinel
    reaches the sink only as an argv element, never a shell-parsed string.
    """
    target_rel = "vuln_target.py"
    repo_root = _init_scratch_repo(tmp_path, "vulnerable_cmdi_example.py", target_rel)
    original = (repo_root / target_rel).read_text()

    # Build a real git diff by editing the working tree and letting git
    # compute it (guarantees the diff is in a form `git apply` will
    # accept), then restoring the original so apply_and_verify_patch starts
    # from a clean, unpatched HEAD — same technique as the sqli tests above.
    fixed = original.replace("import os", "import subprocess").replace(
        'return os.system(f"ping -c 1 {host}")',
        'return subprocess.run(["ping", "-c", "1", host], shell=False)',
    )
    assert fixed != original  # sanity: both replacements actually matched
    (repo_root / target_rel).write_text(fixed)
    diff_text = subprocess.run(
        ["git", "diff"], cwd=repo_root, check=True, capture_output=True, text=True
    ).stdout
    subprocess.run(["git", "checkout", "-q", "--", target_rel], cwd=repo_root, check=True)

    finding = Finding(
        rule_id="python.lang.security.audit.dangerous-system-call",
        message="tainted string used to build a shell command",
        file_path=Path(target_rel),
        start_line=9,
        end_line=9,
        code_span="",
    )
    target = analyze_finding(finding, repo_root)
    assert target.kind == "supported", getattr(target, "reason", None)

    patch_result = PatchResult(
        diff=diff_text,
        explanation="rewrote os.system to subprocess.run with an argv list and shell=False",
        notes="",
    )
    sandbox = LocalSandbox(repo_root, i_understand_local_is_unsafe=True)
    workdir = tmp_path / "work"
    workdir.mkdir()

    result = apply_and_verify_patch(
        repo_root,
        Path(target_rel),
        target,
        patch_result,
        sandbox,
        workdir,
        generate_harness_fn=cmdi_harness.generate_harness,
        oracle_module=oracle_cmdi,
        vuln_name=vulnclass.CMDI.name,
    )

    assert result.kind == KIND_VALIDATED, result.detail
    assert "argv element" in result.detail  # oracle_cmdi's own not_reproduced wording, reused verbatim


def test_pathtraversal_confine_rewrite_validated(tmp_path):
    """Closes the loop for path traversal: a diff that adds resolve+confine
    logic before the open() call must apply via plain `git apply --check`
    (well-formed by construction, same as sqli/cmdi) and must come back
    VALIDATED once re-verified with the pathtraversal harness/oracle — the
    traversal segment no longer survives, unresolved, to the sink.
    """
    target_rel = "vuln_target.py"
    repo_root = _init_scratch_repo(tmp_path, "vulnerable_pathtraversal_example.py", target_rel)
    original = (repo_root / target_rel).read_text()

    # The replacement function uses a *local* import (rather than a top-level
    # one) because the diff must touch only the function itself — same
    # constraint vulnclass.PATHTRAVERSAL's remediation_guidance states
    # explicitly, mirroring cmdi's "self-contained function" requirement.
    fixed = original.replace(
        'def read_file(filename):\n'
        '    return open(f"{BASE_DIR}/{filename}").read()',
        'def read_file(filename):\n'
        '    import pathlib\n'
        '    base = pathlib.Path(BASE_DIR).resolve()\n'
        '    candidate = pathlib.Path(BASE_DIR, filename).resolve()\n'
        '    if not candidate.is_relative_to(base):\n'
        '        candidate = base / pathlib.Path(filename).name\n'
        '    return open(candidate).read()',
    )
    assert fixed != original  # sanity: the replace actually matched
    (repo_root / target_rel).write_text(fixed)
    diff_text = subprocess.run(
        ["git", "diff"], cwd=repo_root, check=True, capture_output=True, text=True
    ).stdout
    subprocess.run(["git", "checkout", "-q", "--", target_rel], cwd=repo_root, check=True)

    finding = Finding(
        rule_id="python.lang.security.audit.path-traversal-open",
        message="tainted string used to build a file path",
        file_path=Path(target_rel),
        start_line=9,
        end_line=9,
        code_span="",
    )
    target = analyze_finding(finding, repo_root)
    assert target.kind == "supported", getattr(target, "reason", None)

    patch_result = PatchResult(
        diff=diff_text,
        explanation="resolved the path and confined it to BASE_DIR before opening",
        notes="",
    )
    sandbox = LocalSandbox(repo_root, i_understand_local_is_unsafe=True)
    workdir = tmp_path / "work"
    workdir.mkdir()

    result = apply_and_verify_patch(
        repo_root,
        Path(target_rel),
        target,
        patch_result,
        sandbox,
        workdir,
        generate_harness_fn=pathtraversal_harness.generate_harness,
        oracle_module=oracle_pathtraversal,
        vuln_name=vulnclass.PATHTRAVERSAL.name,
    )

    assert result.kind == KIND_VALIDATED, result.detail
