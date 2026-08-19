"""Apply a model-generated patch to a scratch branch and re-verify it using
the same sentinel/trace mechanism that confirmed the original finding —
never by re-reading the source. A patch is only "validated" if a fresh
harness run shows the sentinel is no longer reproducible per the oracle
for the finding's vuln class (rule-agnostic: callers supply which
harness/oracle to re-verify with, defaulting to sqli's for backward
compatibility with existing callers).
"""
from __future__ import annotations

import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import secfix.harness.python_sqli as _sqli_harness
from secfix.models import PatchResult
from secfix.oracle import sqli as _sqli_oracle
from secfix.repo import HarnessTarget
from secfix.sandbox.base import Sandbox
from secfix.trace import trace_from_json

KIND_VALIDATED = "validated"
KIND_FAILED = "failed"
KIND_NEEDS_MANUAL_REVIEW = "needs_manual_review"


@dataclass
class PatchApplyResult:
    kind: str  # validated | failed | needs_manual_review
    detail: str
    branch_name: str = ""
    diff: str = ""
    explanation: str = ""
    notes: str = ""


def _diff_touched_paths(diff: str) -> set[str]:
    paths: set[str] = set()
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                for raw in (parts[2], parts[3]):
                    paths.add(raw[2:] if raw[:2] in ("a/", "b/") else raw)
        elif line.startswith("--- ") or line.startswith("+++ "):
            raw = line[4:].strip().split("\t")[0]
            if raw == "/dev/null":
                continue
            paths.add(raw[2:] if raw[:2] in ("a/", "b/") else raw)
    return paths


def _diff_touches_only(diff: str, target_file: Path) -> bool:
    touched = _diff_touched_paths(diff)
    return bool(touched) and touched == {str(target_file)}


def _run_git(repo_root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo_root), *args], capture_output=True, text=True)


def apply_and_verify_patch(
    repo_root: Path,
    target_file: Path,
    target: HarnessTarget,
    patch_result: PatchResult,
    sandbox: Sandbox,
    workdir: Path,
    generate_harness_fn: Callable[[HarnessTarget, Path], Any] = _sqli_harness.generate_harness,
    oracle_module: Any = _sqli_oracle,
    vuln_name: str = "SQL injection",
) -> PatchApplyResult:
    if not _diff_touches_only(patch_result.diff, target_file):
        return PatchApplyResult(
            kind=KIND_FAILED,
            detail="model-generated diff touches file(s) other than the target file; refusing to apply",
            diff=patch_result.diff,
            explanation=patch_result.explanation,
            notes=patch_result.notes,
        )

    # int(time.time()) alone only has 1-second resolution: two findings
    # processed within the same wall-clock second collide on branch name,
    # and the resulting "branch already exists" error looks unrelated to its
    # real cause. A short random suffix makes collisions practically
    # impossible regardless of how fast findings are processed.
    branch_name = f"secfix/{target_file.stem}-{int(time.time())}-{uuid.uuid4().hex[:6]}"
    checkout = _run_git(repo_root, "checkout", "-b", branch_name)
    if checkout.returncode != 0:
        return PatchApplyResult(
            kind=KIND_FAILED,
            detail=f"could not create scratch branch {branch_name!r}: {checkout.stderr.strip()}",
            branch_name=branch_name,
        )

    patch_file = workdir / "secfix_patch.diff"
    diff_text = patch_result.diff if patch_result.diff.endswith("\n") else patch_result.diff + "\n"
    patch_file.write_text(diff_text)

    # Strict check first. Model-generated diffs routinely have correct context
    # but arithmetic-wrong @@ hunk line counts (an LLM miscounting lines is
    # normal); --recount recomputes those counts from the hunk body and
    # rescues an otherwise-correct patch that --check alone would reject as
    # "corrupt patch". It does NOT rescue a hunk whose declared location is
    # actually wrong, so this is a legitimate fallback, not a laxer check.
    check = _run_git(repo_root, "apply", "--check", str(patch_file))
    if check.returncode != 0:
        recount_check = _run_git(repo_root, "apply", "--check", "--recount", str(patch_file))
        if recount_check.returncode != 0:
            return PatchApplyResult(
                kind=KIND_FAILED,
                detail=f"patch does not apply cleanly: {check.stderr.strip()}",
                branch_name=branch_name,
                diff=patch_result.diff,
                explanation=patch_result.explanation,
                notes=patch_result.notes,
            )
        apply_args = ["--recount"]
    else:
        apply_args = []

    apply_ = _run_git(repo_root, "apply", *apply_args, str(patch_file))
    if apply_.returncode != 0:
        return PatchApplyResult(
            kind=KIND_FAILED,
            detail=f"git apply failed: {apply_.stderr.strip()}",
            branch_name=branch_name,
            diff=patch_result.diff,
            explanation=patch_result.explanation,
            notes=patch_result.notes,
        )

    _run_git(repo_root, "add", str(target_file))
    commit = _run_git(
        repo_root, "commit", "-m", f"secfix: patch {vuln_name} in {target_file}"
    )
    if commit.returncode != 0:
        return PatchApplyResult(
            kind=KIND_FAILED,
            detail=f"could not commit patch on scratch branch: {commit.stderr.strip()}",
            branch_name=branch_name,
            diff=patch_result.diff,
            explanation=patch_result.explanation,
            notes=patch_result.notes,
        )

    harness_result = generate_harness_fn(target, workdir)
    if harness_result.kind != "generated":
        return PatchApplyResult(
            kind=KIND_NEEDS_MANUAL_REVIEW,
            detail=f"patch applied, but a re-verification harness could not be generated: {harness_result.reason}",
            branch_name=branch_name,
            diff=patch_result.diff,
            explanation=patch_result.explanation,
            notes=patch_result.notes,
        )

    (workdir / harness_result.filename).write_text(harness_result.source)
    sandbox_result = sandbox.run(
        workdir,
        harness_filename=harness_result.filename,
        invalidate_modules=[target.module_import_path],
    )

    if sandbox_result.trace_path is None:
        return PatchApplyResult(
            kind=KIND_NEEDS_MANUAL_REVIEW,
            detail="patch applied, but the post-patch harness run produced no trace "
            f"(exit_code={sandbox_result.exit_code}); inspect the branch manually",
            branch_name=branch_name,
            diff=patch_result.diff,
            explanation=patch_result.explanation,
            notes=patch_result.notes,
        )

    trace = trace_from_json(sandbox_result.trace_path.read_text())
    verdict = oracle_module.evaluate(trace, harness_result.sentinel)

    if verdict.verdict == oracle_module.VERDICT_NOT_REPRODUCED:
        return PatchApplyResult(
            kind=KIND_VALIDATED,
            detail=f"post-patch trace confirms the fix: {verdict.detail}",
            branch_name=branch_name,
            diff=patch_result.diff,
            explanation=patch_result.explanation,
            notes=patch_result.notes,
        )

    if verdict.verdict == oracle_module.VERDICT_CONFIRMED:
        return PatchApplyResult(
            kind=KIND_FAILED,
            detail=f"patch applied but the vulnerability is STILL reproducible: "
            f"{verdict.detail} — offending: {verdict.offending_sql}",
            branch_name=branch_name,
            diff=patch_result.diff,
            explanation=patch_result.explanation,
            notes=patch_result.notes,
        )

    return PatchApplyResult(
        kind=KIND_NEEDS_MANUAL_REVIEW,
        detail=f"post-patch verdict was uncertain: {verdict.detail}",
        branch_name=branch_name,
        diff=patch_result.diff,
        explanation=patch_result.explanation,
        notes=patch_result.notes,
    )
