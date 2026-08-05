"""Generates a self-contained pytest module that reproduces a SQLi finding
by calling the flagged function with a tainted sentinel and a recording mock
DB connection, then writes the resulting ExecutionTrace to disk for the
oracle to inspect.

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


class _ExecutedQuery:
    def __init__(self, sql, params=None):
        self.sql = sql
        self.params = params

    def to_dict(self):
        return {"sql": self.sql, "params": self.params}


class _RecordingCursor:
    def __init__(self, trace):
        self._trace = trace

    def execute(self, sql, params=None):
        self._trace.append(_ExecutedQuery(sql, params))
        return self

    def executemany(self, sql, seq_of_params=None):
        for params in seq_of_params or [None]:
            self._trace.append(_ExecutedQuery(sql, params))
        return self

    def fetchone(self):
        return None

    def fetchall(self):
        return []

    def fetchmany(self, size=1):
        return []

    def close(self):
        pass

    def __iter__(self):
        return iter(())

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class _RecordingConnection:
    def __init__(self):
        self.trace = []

    def cursor(self, *args, **kwargs):
        return _RecordingCursor(self.trace)

    def execute(self, sql, params=None):
        return _RecordingCursor(self.trace).execute(sql, params)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False
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

    Returns kind="skipped" (with reason) rather than raising when the DB
    access path or a required argument's shape can't be determined safely —
    per spec, the harness must never guess its way into a broken call.
    """
    if target.db_access_kind == "unknown":
        return HarnessResult(
            kind="skipped",
            reason=(
                "could not determine how the function obtains its DB connection "
                "(no conn/cursor-like parameter and no recognized getter call)"
            ),
        )

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
    # Sentinel suffix (SECFIX_TAINT_<8hex>) is already unique per run and a
    # valid identifier fragment, so reuse it for the module filename.
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

    monkeypatch_line = ""
    if target.db_access_kind == "param":
        kwargs_items.append(f"    {target.db_access_name!r}: conn,")
    elif target.db_access_kind == "module_getter":
        monkeypatch_line = (
            f"    monkeypatch.setattr(_target_module, {target.db_access_name!r}, "
            f"lambda *a, **k: conn)\n"
        )

    kwargs_block = "\n".join(kwargs_items)

    lines = [
        _MOCK_PREAMBLE,
        "",
        f"SENTINEL = {sentinel!r}",
        f"TRACE_OUTPUT_PATH = {str(trace_output_path)!r}",
        "",
        "",
        f"def test_sqli_repro(monkeypatch):",
        f"    import {target.module_import_path} as _target_module",
        "",
        "    conn = _RecordingConnection()",
        monkeypatch_line.rstrip("\n") if monkeypatch_line else "",
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
        "    trace_json = json.dumps([q.to_dict() for q in conn.trace])",
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
    return "\n".join(line for line in lines if line is not None)
