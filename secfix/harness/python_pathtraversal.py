"""Generates a self-contained pytest module that reproduces a path-traversal
finding by calling the flagged function with a tainted sentinel and
recording mocks for the file/path sinks, then writes the resulting
ExecutionTrace to disk for the oracle to inspect.

Mirrors secfix.harness.python_cmdi's structure. Like cmdi (and unlike
sqli), there's no "how does the function obtain its sink" ambiguity: open,
os.open, os.remove/unlink, and the shutil path functions are (almost)
always accessed as plain module/builtin attributes, so the harness always
monkeypatches them directly rather than needing sqli's db_access_kind
detection.

The tainted kwarg value is NOT the bare sentinel — a bare marker carries no
traversal semantics, so it can't distinguish vulnerable from safe behavior
at the sink. Instead the harness calls the target function TWICE with two
different sentinel-derived payloads, both feeding the same trace list:

  1. "../../../" + sentinel  — a relative ".."-laden probe.
  2. "/" + sentinel           — an absolute-path probe.

Both probes are needed, not just the first: `os.path.join(base, tainted)`
(and pathlib's `Path(base, tainted)`) silently discard `base` entirely when
`tainted` is itself an absolute path — a ".."-only probe would never
exercise that bypass and a fix that merely strips/blocks ".." would come
back (wrongly) `not_reproduced`. Both probes' recorded sink calls land in
the same trace list; the bare sentinel is passed to the oracle separately
for detection/redaction of either probe's result (see
oracle/pathtraversal.py's docstring for the full verdict reasoning).

v0.1.0 scope guard: only patches plain callables (builtins.open, os.open,
os.remove, os.unlink, shutil.copy/copyfile/move/rmtree/copytree) — not
pathlib.Path.open. A bound method stored as a *class* attribute does not
get re-bound via the descriptor protocol the way a plain function does, so
naively monkeypatching Path.open the same way as a module-level callable
would silently drop the `self` argument; correctly supporting it needs a
different patching shape and is left for a follow-up, the same kind of
documented scope limit cmdi's oracle applies to shell-invoking argv lists.

The generated module embeds its own copy of the recording-mock classes
(rather than importing secfix.trace) so it has zero dependency on secfix
being installed inside whatever environment/sandbox runs it — only pytest.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path

from secfix.repo import HarnessTarget

TRACE_FILENAME = "secfix_trace.json"

# Printed around the trace JSON on stdout so a sandbox with no shared
# filesystem view of the workdir (e.g. Docker, --rm, no host mounts) can
# still recover the trace by scraping captured process output.
TRACE_START_MARKER = "===SECFIX_TRACE_START==="
TRACE_END_MARKER = "===SECFIX_TRACE_END==="

_MOCK_PREAMBLE = '''\
import json


class _ExecutedPathOp:
    def __init__(self, sql, params=None):
        self.sql = sql
        self.params = params

    def to_dict(self):
        return {"sql": self.sql, "params": self.params}


class _FileStub:
    def read(self, *a, **k):
        return ""

    def write(self, *a, **k):
        return 0

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def __iter__(self):
        return iter(())


class _PathRecorder:
    def __init__(self, trace):
        self._trace = trace

    def _record(self, op, path):
        self._trace.append(_ExecutedPathOp(sql=str(path), params={"op": op}))

    def open(self, file, *args, **kwargs):
        self._record("open", file)
        return _FileStub()

    def os_open(self, path, *args, **kwargs):
        self._record("os.open", path)
        return 0

    def os_remove(self, path, *args, **kwargs):
        self._record("os.remove", path)

    def os_unlink(self, path, *args, **kwargs):
        self._record("os.unlink", path)

    def shutil_copy(self, src, dst, *args, **kwargs):
        self._record("shutil.copy(src)", src)
        self._record("shutil.copy(dst)", dst)
        return str(dst)

    def shutil_copyfile(self, src, dst, *args, **kwargs):
        self._record("shutil.copyfile(src)", src)
        self._record("shutil.copyfile(dst)", dst)
        return str(dst)

    def shutil_move(self, src, dst, *args, **kwargs):
        self._record("shutil.move(src)", src)
        self._record("shutil.move(dst)", dst)
        return str(dst)

    def shutil_rmtree(self, path, *args, **kwargs):
        self._record("shutil.rmtree", path)

    def shutil_copytree(self, src, dst, *args, **kwargs):
        self._record("shutil.copytree(src)", src)
        self._record("shutil.copytree(dst)", dst)
        return str(dst)
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
    benign_items = [f"    {name!r}: {literal}," for name, literal in (target.benign_defaults or {}).items()]
    traversal_kwargs_block = "\n".join(
        benign_items + [f"    {target.tainted_param!r}: TAINTED_VALUE_TRAVERSAL,"]
    )
    absolute_kwargs_block = "\n".join(
        benign_items + [f"    {target.tainted_param!r}: TAINTED_VALUE_ABSOLUTE,"]
    )

    lines = [
        _MOCK_PREAMBLE,
        "",
        f"SENTINEL = {sentinel!r}",
        "TAINTED_VALUE_TRAVERSAL = '../../../' + SENTINEL",
        "TAINTED_VALUE_ABSOLUTE = '/' + SENTINEL",
        f"TRACE_OUTPUT_PATH = {str(trace_output_path)!r}",
        "",
        "",
        f"def test_pathtraversal_repro(monkeypatch):",
        f"    import {target.module_import_path} as _target_module",
        "    import builtins",
        "    import os",
        "    import shutil",
        "",
        "    trace = []",
        "    recorder = _PathRecorder(trace)",
        "    # Captured before patching: builtins.open is about to become the",
        "    # recording mock, so the trace-file write below must use the real one.",
        "    _real_open = builtins.open",
        "    monkeypatch.setattr(builtins, 'open', recorder.open)",
        "    monkeypatch.setattr(os, 'open', recorder.os_open)",
        "    monkeypatch.setattr(os, 'remove', recorder.os_remove)",
        "    monkeypatch.setattr(os, 'unlink', recorder.os_unlink)",
        "    monkeypatch.setattr(shutil, 'copy', recorder.shutil_copy)",
        "    monkeypatch.setattr(shutil, 'copyfile', recorder.shutil_copyfile)",
        "    monkeypatch.setattr(shutil, 'move', recorder.shutil_move)",
        "    monkeypatch.setattr(shutil, 'rmtree', recorder.shutil_rmtree)",
        "    monkeypatch.setattr(shutil, 'copytree', recorder.shutil_copytree)",
        "",
        "    traversal_kwargs = {",
        traversal_kwargs_block,
        "    }",
        "    absolute_kwargs = {",
        absolute_kwargs_block,
        "    }",
        "",
        "    # Both probes feed the same trace list — the oracle inspects every",
        "    # recorded sink call regardless of which probe produced it.",
        "    try:",
        f"        _target_module.{target.function_name}(**traversal_kwargs)",
        "    except Exception:",
        "        pass",
        "",
        "    try:",
        f"        _target_module.{target.function_name}(**absolute_kwargs)",
        "    except Exception:",
        "        pass",
        "",
        "    trace_json = json.dumps([op.to_dict() for op in trace])",
        "    try:",
        "        with _real_open(TRACE_OUTPUT_PATH, 'w') as f:",
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
