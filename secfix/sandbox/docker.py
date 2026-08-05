"""Docker sandbox: MANDATORY for any target code we did not author ourselves.

Two phases:
  SETUP    docker build — network allowed, target deps get installed here.
  EXECUTE  docker run   — network none, non-root, read-only rootfs + tmpfs
           /tmp, all caps dropped, pids/memory/cpu limits, --rm, and no host
           mounts at all (the target repo is baked into the image during
           SETUP as a read-only-in-spirit copy; nothing from the host is
           bind-mounted at EXECUTE time).

Because EXECUTE gives the container no way to hand a file back to the host,
the harness (secfix/harness/python_sqli.py) prints its ExecutionTrace to
stdout wrapped in TRACE_START_MARKER/TRACE_END_MARKER; this sandbox scrapes
that from captured `docker run` output and writes it to a local trace file
for the oracle to read, exactly as LocalSandbox does from disk.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from secfix.harness.python_sqli import TRACE_END_MARKER, TRACE_FILENAME, TRACE_START_MARKER
from secfix.sandbox.base import Sandbox, SandboxResult


def _as_text(output: str | bytes | None) -> str:
    """subprocess.TimeoutExpired.stdout/.stderr can be bytes even when the
    parent subprocess.run() call was made with text=True — the partial
    buffer captured at the moment of timeout isn't always passed through the
    universal-newlines/text decoding layer. Normalize before use.
    """
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode(errors="replace")
    return output


_DOCKERFILE_TEMPLATE = """\
FROM {base_image}
WORKDIR /workspace
COPY requirements.txt /workspace/requirements.txt
RUN pip install --no-cache-dir pytest -r requirements.txt
COPY repo/ /workspace/
RUN useradd --create-home --uid 10001 secfix
USER secfix
"""


class DockerSandbox(Sandbox):
    def __init__(
        self,
        repo_root: Path,
        base_image: str = "python:3.11-slim",
        memory: str = "256m",
        cpus: str = "1",
        pids_limit: int = 128,
        setup_timeout: int = 300,
        execute_timeout: int = 60,
    ):
        self.repo_root = Path(repo_root)
        self.base_image = base_image
        self.memory = memory
        self.cpus = cpus
        self.pids_limit = pids_limit
        self.setup_timeout = setup_timeout
        self.execute_timeout = execute_timeout

    def run(
        self,
        workdir: Path,
        harness_filename: str = "test_secfix_repro.py",
        invalidate_modules: list[str] | None = None,
    ) -> SandboxResult:
        # Every run gets a fresh container, so there is no cross-run module
        # cache to invalidate; accepted only for interface parity with
        # LocalSandbox.
        workdir = Path(workdir)
        harness_path = workdir / harness_filename
        image_tag = f"secfix-run-{uuid.uuid4().hex[:12]}"

        with tempfile.TemporaryDirectory(prefix="secfix_build_") as build_ctx_str:
            build_ctx = Path(build_ctx_str)
            build_result = self._setup(build_ctx, harness_path, harness_filename, image_tag)
            if build_result is not None:
                return build_result

            try:
                run = self._execute(image_tag, harness_filename)
            finally:
                subprocess.run(
                    ["docker", "rmi", "-f", image_tag], capture_output=True, text=True
                )

        trace_path = self._extract_trace_from_stdout(run.stdout, workdir)
        return SandboxResult(
            exit_code=run.returncode,
            stdout=run.stdout,
            stderr=run.stderr,
            trace_path=trace_path,
        )

    def _setup(
        self, build_ctx: Path, harness_path: Path, harness_filename: str, image_tag: str
    ) -> SandboxResult | None:
        # requirements.txt is copied and installed in its own layer, BEFORE
        # the repo (which includes the harness file that's unique on every
        # single run). Ordering it this way lets Docker's build cache reuse
        # the pip-install layer across repeated runs against the same
        # target — putting the ever-changing harness ahead of it would
        # invalidate that layer's cache every time and force a fresh
        # network install on every run.
        requirements = self.repo_root / "requirements.txt"
        if requirements.exists():
            shutil.copy2(requirements, build_ctx / "requirements.txt")
        else:
            (build_ctx / "requirements.txt").write_text("")

        repo_copy = build_ctx / "repo"
        shutil.copytree(
            self.repo_root,
            repo_copy,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".venv", "venv"),
        )
        shutil.copy2(harness_path, repo_copy / harness_filename)

        dockerfile = _DOCKERFILE_TEMPLATE.format(base_image=self.base_image)
        (build_ctx / "Dockerfile").write_text(dockerfile)

        try:
            build = subprocess.run(
                ["docker", "build", "-t", image_tag, str(build_ctx)],
                capture_output=True,
                text=True,
                timeout=self.setup_timeout,
            )
        except subprocess.TimeoutExpired as e:
            return SandboxResult(
                exit_code=124,
                stdout=_as_text(e.stdout),
                stderr=_as_text(e.stderr) + "\nsecfix: docker build timed out (SETUP phase)",
                trace_path=None,
            )

        if build.returncode != 0:
            return SandboxResult(
                exit_code=build.returncode, stdout=build.stdout, stderr=build.stderr, trace_path=None
            )
        return None

    def _execute(self, image_tag: str, harness_filename: str) -> subprocess.CompletedProcess:
        cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--read-only",
            "--tmpfs", "/tmp:rw,size=64m",
            "--cap-drop", "ALL",
            "--pids-limit", str(self.pids_limit),
            "--memory", self.memory,
            "--cpus", self.cpus,
            "--user", "10001:10001",
            image_tag,
            "python", "-m", "pytest", "-q", "-s", "-p", "no:cacheprovider",
            "--import-mode=importlib", f"/workspace/{harness_filename}",
        ]
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=self.execute_timeout)
        except subprocess.TimeoutExpired as e:
            return subprocess.CompletedProcess(
                cmd,
                returncode=124,
                stdout=_as_text(e.stdout),
                stderr=_as_text(e.stderr) + "\nsecfix: docker run timed out (EXECUTE phase)",
            )

    def _extract_trace_from_stdout(self, stdout: str, workdir: Path) -> Path | None:
        if TRACE_START_MARKER not in stdout or TRACE_END_MARKER not in stdout:
            return None
        start = stdout.index(TRACE_START_MARKER) + len(TRACE_START_MARKER)
        end = stdout.index(TRACE_END_MARKER, start)
        trace_json = stdout[start:end].strip()

        trace_path = workdir / TRACE_FILENAME
        trace_path.write_text(trace_json)
        return trace_path
