"""In-process sandbox: runs the harness via pytest.main() in the current
interpreter for fast iteration. This provides NO isolation whatsoever — the
target's module-level code (including anything imported at module scope)
executes with the operator's full privileges. Refuses to run unless the
caller explicitly acknowledges that. Intended ONLY for secfix's own trusted
test fixtures; authorized-pentest targets must use --sandbox docker.
"""
from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path

from secfix.harness.python_sqli import TRACE_FILENAME
from secfix.sandbox.base import Sandbox, SandboxResult


class LocalSandbox(Sandbox):
    def __init__(self, repo_root: Path, i_understand_local_is_unsafe: bool = False):
        if not i_understand_local_is_unsafe:
            raise RuntimeError(
                "LocalSandbox executes target code in-process with NO isolation "
                "(no network block, no filesystem restriction, no resource "
                "limits). Pass --i-understand-local-is-unsafe to acknowledge "
                "this, and only point it at code you fully trust, such as "
                "secfix's own test fixtures. For authorized-pentest targets, "
                "use --sandbox docker."
            )
        self.repo_root = Path(repo_root)

    def run(
        self,
        workdir: Path,
        harness_filename: str = "test_secfix_repro.py",
        invalidate_modules: list[str] | None = None,
    ) -> SandboxResult:
        import pytest

        workdir = Path(workdir)
        harness_path = workdir / harness_filename
        trace_path = workdir / TRACE_FILENAME

        # Without this, re-verifying a patch against a module edited on disk
        # since the last run would silently re-execute the OLD cached module
        # object instead of picking up the fix (or the still-vulnerable
        # pre-patch code) — Python only runs a module's top level once per
        # sys.modules entry.
        for prefix in invalidate_modules or []:
            for name in [n for n in sys.modules if n == prefix or n.startswith(prefix + ".")]:
                del sys.modules[name]

        sys.path.insert(0, str(self.repo_root))
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                exit_code = pytest.main(["-q", "-s", "--import-mode=importlib", str(harness_path)])
        finally:
            try:
                sys.path.remove(str(self.repo_root))
            except ValueError:
                pass

        return SandboxResult(
            exit_code=int(exit_code),
            stdout=stdout_buf.getvalue(),
            stderr=stderr_buf.getvalue(),
            trace_path=trace_path if trace_path.exists() else None,
        )
