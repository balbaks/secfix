"""Generates a self-contained pytest module that reproduces an OS
command-injection finding by calling the flagged function with a tainted
sentinel and recording mocks for os.system/subprocess.*, then writes the
resulting ExecutionTrace to disk for the oracle to inspect.

Mirrors secfix.harness.python_sqli's structure. Unlike SQLi, there's no
"how does the function obtain its sink" ambiguity to resolve — os.system
and subprocess.* are (almost) always accessed as plain module attributes,
so the harness always monkeypatches them directly on the real os/subprocess
modules rather than needing SQLi's db_access_kind detection at all.

The generated module embeds its own copy of the recording-mock classes
(rather than importing secfix.trace) so it has zero dependency on secfix
being installed inside whatever environment/sandbox runs it — only pytest.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path

from secfix.harness.django_bootstrap import django_bootstrap_lines
from secfix.repo import HarnessTarget

TRACE_FILENAME = "secfix_trace.json"

# Printed around the trace JSON on stdout so a sandbox with no shared
# filesystem view of the workdir (e.g. Docker, --rm, no host mounts) can
# still recover the trace by scraping captured process output.
TRACE_START_MARKER = "===SECFIX_TRACE_START==="
TRACE_END_MARKER = "===SECFIX_TRACE_END==="

_MOCK_PREAMBLE = '''\
import json


class _ExecutedCommand:
    def __init__(self, sql, params=None):
        self.sql = sql
        self.params = params

    def to_dict(self):
        return {"sql": self.sql, "params": self.params}


class _CompletedProcessStub:
    returncode = 0
    stdout = b""
    stderr = b""


class _PopenStub:
    returncode = 0

    def communicate(self, *a, **k):
        return (b"", b"")

    def wait(self, *a, **k):
        return 0

    def poll(self):
        return 0

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class _CommandRecorder:
    def __init__(self, trace):
        self._trace = trace

    def _record(self, cmd, shell):
        # A command is only shell-interpreted as a single string when it IS
        # a string AND a shell is actually invoked (os.system always does;
        # subprocess.* only when shell=True). Everything else (argv lists,
        # or a string passed with shell=False) never gets shell-parsed as a
        # whole, so it's recorded as argv-shaped data instead.
        if isinstance(cmd, str) and shell:
            self._trace.append(_ExecutedCommand(sql=cmd, params={"shell": True}))
        else:
            self._trace.append(
                _ExecutedCommand(sql="", params={"argv": cmd, "shell": bool(shell)})
            )

    def system(self, cmd):
        self._record(cmd, shell=True)
        return 0

    def run(self, cmd, *args, **kwargs):
        self._record(cmd, shell=kwargs.get("shell", False))
        return _CompletedProcessStub()

    def call(self, cmd, *args, **kwargs):
        self._record(cmd, shell=kwargs.get("shell", False))
        return 0

    def check_call(self, cmd, *args, **kwargs):
        self._record(cmd, shell=kwargs.get("shell", False))
        return 0

    def check_output(self, cmd, *args, **kwargs):
        self._record(cmd, shell=kwargs.get("shell", False))
        return b""

    def Popen(self, cmd, *args, **kwargs):
        self._record(cmd, shell=kwargs.get("shell", False))
        return _PopenStub()
'''


@dataclass
class HarnessResult:
    kind: str  # "generated" | "skipped"
    source: str = ""
    reason: str = ""
    sentinel: str = ""
    trace_output_path: Path = None
    # Unique per run (derived from the sentinel) so that repeated in-process
    # sandbox runs never collide on a cached sys.modules entry — see
    # LocalSandbox, which import-mode=importlib's each harness by this name.
    filename: str = ""


def _new_sentinel() -> str:
    return f"SECFIX_TAINT_{secrets.token_hex(4)}"


def generate_harness(target: HarnessTarget, workdir: Path) -> HarnessResult:
    """Build the pytest harness source for a supported HarnessTarget.

    Returns kind="skipped" (with reason) rather than raising when a
    required argument's shape can't be determined safely — per spec, the
    harness must never guess its way into a broken call.
    """
    unknown_params = [name for name, lit in (target.benign_defaults or {}).items() if lit is None]
    if unknown_params:
        return HarnessResult(
            kind="skipped",
            reason=(
                "cannot synthesize a benign default for required parameter(s): "
                + ", ".join(unknown_params)
            ),
        )

    sentinel = _new_sentinel()
    trace_output_path = workdir / TRACE_FILENAME
    source = _render_source(target, sentinel, trace_output_path)
    filename = f"test_secfix_repro_{sentinel.rsplit('_', 1)[-1]}.py"
    return HarnessResult(
        kind="generated",
        source=source,
        sentinel=sentinel,
        trace_output_path=trace_output_path,
        filename=filename,
    )


def _render_source(target: HarnessTarget, sentinel: str, trace_output_path: Path) -> str:
    kwargs_items = [f"    {name!r}: {literal}," for name, literal in (target.benign_defaults or {}).items()]
    kwargs_items.append(f"    {target.tainted_param!r}: SENTINEL,")
    kwargs_block = "\n".join(kwargs_items)

    lines = [
        _MOCK_PREAMBLE,
        "",
        f"SENTINEL = {sentinel!r}",
        f"TRACE_OUTPUT_PATH = {str(trace_output_path)!r}",
        "",
        "",
        f"def test_cmdi_repro(monkeypatch):",
        *django_bootstrap_lines(target),
        f"    import {target.module_import_path} as _target_module",
        "    import os",
        "    import subprocess",
        "",
        "    trace = []",
        "    recorder = _CommandRecorder(trace)",
        "    monkeypatch.setattr(os, 'system', recorder.system)",
        "    monkeypatch.setattr(subprocess, 'run', recorder.run)",
        "    monkeypatch.setattr(subprocess, 'call', recorder.call)",
        "    monkeypatch.setattr(subprocess, 'check_call', recorder.check_call)",
        "    monkeypatch.setattr(subprocess, 'check_output', recorder.check_output)",
        "    monkeypatch.setattr(subprocess, 'Popen', recorder.Popen)",
        "",
        "    kwargs = {",
        kwargs_block,
        "    }",
        "",
        "    try:",
        f"        _target_module.{target.function_name}(**kwargs)",
        "    except Exception:",
        "        pass",
        "",
        "    trace_json = json.dumps([c.to_dict() for c in trace])",
        "    try:",
        "        with open(TRACE_OUTPUT_PATH, 'w') as f:",
        "            f.write(trace_json)",
        "    except OSError:",
        "        pass  # e.g. no shared filesystem view of the workdir under Docker",
        "",
        f"    print({TRACE_START_MARKER!r})",
        "    print(trace_json)",
        f"    print({TRACE_END_MARKER!r})",
        "",
    ]
    return "\n".join(lines)
