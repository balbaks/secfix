"""secfix CLI.

  secfix run \\
      --finding finding.json \\
      --repo ./target \\
      --rule sqli \\
      --sandbox docker|local \\
      --model <provider> \\
      [--open-pr]

Dry-run by default: writes a scratch branch + report to disk and prints the
exact git/gh commands to publish. --open-pr pushes the branch and opens a PR
directly, and only ever fires for a patch that re-verified as `validated`.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

from secfix.findings import load_sqli_findings
from secfix.harness.python_sqli import generate_harness
from secfix.models import ModelError, PatchContext, generate_patch
from secfix.oracle import sqli as oracle_sqli
from secfix.patch import KIND_VALIDATED, apply_and_verify_patch
from secfix.report import build_pr_body, build_report, write_report_to_disk
from secfix.repo import analyze_finding
from secfix.sandbox.base import Sandbox
from secfix.sandbox.docker import DockerSandbox
from secfix.sandbox.local import LocalSandbox
from secfix.trace import trace_from_json


def _current_branch(repo_root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _build_sandbox(args: argparse.Namespace, repo_root: Path) -> Sandbox:
    if args.sandbox == "docker":
        return DockerSandbox(repo_root)
    return LocalSandbox(repo_root, i_understand_local_is_unsafe=args.i_understand_local_is_unsafe)


def _open_pr(repo_root: Path, branch_name: str, pr_body_path: Path) -> None:
    push = subprocess.run(
        ["git", "-C", str(repo_root), "push", "-u", "origin", branch_name],
        capture_output=True,
        text=True,
    )
    if push.returncode != 0:
        print(f"git push failed: {push.stderr.strip()}")
        return

    gh = subprocess.run(
        [
            "gh", "pr", "create",
            "--title", f"secfix: SQL injection fix ({branch_name})",
            "--body-file", str(pr_body_path),
        ],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
    )
    if gh.returncode != 0:
        print(f"gh pr create failed: {gh.stderr.strip()}")
    else:
        print(gh.stdout.strip())


def run_command(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo).resolve()
    finding_path = Path(args.finding)

    findings = load_sqli_findings(finding_path, repo_root)
    if not findings:
        print("No SQLi findings in input.")
        return 0

    original_branch = _current_branch(repo_root)
    output_root = Path(args.output) if args.output else repo_root / ".secfix_out"

    exit_status = 0

    for i, finding in enumerate(findings):
        print(f"\n=== Finding {i + 1}/{len(findings)}: {finding.file_path}:{finding.start_line} ({finding.rule_id}) ===")

        target = analyze_finding(finding, repo_root)
        if target.kind != "supported":
            print(f"UNCERTAIN (needs manual harness): {target.reason}")
            continue

        workdir = Path(tempfile.mkdtemp(prefix="secfix_"))
        harness_result = generate_harness(target, workdir)
        if harness_result.kind != "generated":
            print(f"UNCERTAIN (harness skipped): {harness_result.reason}")
            continue

        (workdir / harness_result.filename).write_text(harness_result.source)

        try:
            sandbox = _build_sandbox(args, repo_root)
        except RuntimeError as e:
            print(str(e))
            return 1

        sandbox_result = sandbox.run(workdir, harness_filename=harness_result.filename)
        if sandbox_result.trace_path is None:
            print(f"UNCERTAIN: harness produced no trace (exit_code={sandbox_result.exit_code})")
            print(sandbox_result.stdout[-2000:])
            print(sandbox_result.stderr[-1000:])
            continue

        trace = trace_from_json(sandbox_result.trace_path.read_text())
        verdict = oracle_sqli.evaluate(trace, harness_result.sentinel)
        print(f"Oracle verdict: {verdict.verdict} — {verdict.detail}")

        finding_output_dir = output_root / f"finding_{i + 1}"
        patch_apply_result = None

        if verdict.verdict == oracle_sqli.VERDICT_CONFIRMED:
            print(f"Offending SQL: {verdict.offending_sql}")

            context = PatchContext(
                finding_summary=finding.message or finding.rule_id,
                vulnerable_snippet=finding.code_span,
                file_path=str(finding.file_path),
                harness_source=harness_result.source,
                offending_sql=verdict.offending_sql,
                oracle_detail=verdict.detail,
            )

            try:
                patch_result = generate_patch(context, provider=args.model)
            except ModelError as e:
                print(f"Patch generation failed: {e}")
                report_text = build_report(finding, target, verdict, harness_result.sentinel, None)
                disk = write_report_to_disk(finding_output_dir, report_text, branch_name="")
                print(f"Report written to {disk.report_path}")
                exit_status = 1
                continue

            patch_apply_result = apply_and_verify_patch(
                repo_root, finding.file_path, target, patch_result, sandbox, workdir
            )
            print(f"Patch status: {patch_apply_result.kind} — {patch_apply_result.detail}")

            if patch_apply_result.branch_name:
                subprocess.run(
                    ["git", "-C", str(repo_root), "checkout", original_branch],
                    capture_output=True,
                    text=True,
                )

            if patch_apply_result.kind != KIND_VALIDATED:
                exit_status = 1

        report_text = build_report(finding, target, verdict, harness_result.sentinel, patch_apply_result)

        pr_body = None
        should_open_pr = False
        if patch_apply_result is not None and patch_apply_result.kind == KIND_VALIDATED:
            pr_body = build_pr_body(finding, target, patch_apply_result)
            should_open_pr = args.open_pr

        disk = write_report_to_disk(
            finding_output_dir,
            report_text,
            branch_name=patch_apply_result.branch_name if patch_apply_result else "",
            pr_body=pr_body,
            open_pr=should_open_pr,
        )
        print(f"Report written to {disk.report_path}")

        if should_open_pr:
            _open_pr(repo_root, patch_apply_result.branch_name, disk.pr_body_path)
        else:
            print(disk.next_steps)

    return exit_status


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secfix")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="Validate and patch SQL-injection findings")
    run_parser.add_argument("--finding", required=True, help="Path to a Semgrep JSON results file")
    run_parser.add_argument("--repo", required=True, help="Path to the local, authorized target repo")
    run_parser.add_argument(
        "--rule", default="sqli", choices=["sqli"],
        help="Finding class to process (fixed to sqli in v0.1.0)",
    )
    run_parser.add_argument(
        "--sandbox", choices=["docker", "local"], default="docker",
        help="Execution sandbox (docker is mandatory for non-fixture code)",
    )
    run_parser.add_argument(
        "--model", default="anthropic", choices=["anthropic", "groq", "ollama"],
        help="Patch-generation model provider",
    )
    run_parser.add_argument(
        "--output", default=None,
        help="Directory to write reports/branch info (default: <repo>/.secfix_out)",
    )
    run_parser.add_argument(
        "--open-pr", action="store_true",
        help="Push the scratch branch and open a PR for validated patches (default: dry-run)",
    )
    run_parser.add_argument(
        "--i-understand-local-is-unsafe", action="store_true",
        help="Required to use --sandbox local; only ever point it at trusted fixtures",
    )
    run_parser.set_defaults(func=run_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
