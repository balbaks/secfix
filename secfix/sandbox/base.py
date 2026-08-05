"""Sandbox interface. A sandbox's job is to run a generated pytest harness
against a target repo and hand back a trace file plus process output —
nothing more. It does not know about findings, oracles, or patches.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    trace_path: Optional[Path]


class Sandbox:
    def run(
        self,
        workdir: Path,
        harness_filename: str = "test_secfix_repro.py",
        invalidate_modules: Optional[list[str]] = None,
    ) -> SandboxResult:
        """invalidate_modules: import-path prefixes (e.g. the target module)
        to purge from sys.modules before running. Only meaningful for
        in-process sandboxes (LocalSandbox) re-verifying a patch against code
        that was already imported once this process — out-of-process
        sandboxes (Docker) get a fresh interpreter every run and ignore it.
        """
        raise NotImplementedError
