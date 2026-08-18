"""Exercises apply_and_verify_patch's post-patch verdict logic end-to-end on
an isolated scratch git repo (never the real project repo, since the function
under test creates branches and commits).
"""
import subprocess
from pathlib import Path

from secfix.findings import Finding
from secfix.models import PatchResult
from secfix.patch import KIND_VALIDATED, apply_and_verify_patch
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
