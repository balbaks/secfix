"""Sentinel-based OS command-injection oracle. Consumes only an
ExecutionTrace (never source) and renders a verdict per the
sentinel-location rule:

  sentinel substring inside a shell-interpreted command string (os.system,
  or subprocess.*(..., shell=True) with a string command) -> confirmed
  sentinel found only as a separate argv element passed to subprocess with
  shell=False (the default)                                -> not_reproduced
  no command sink recorded / sentinel absent everywhere     -> uncertain

Mirrors secfix.oracle.sqli's structure and reuses the same ExecutionTrace
contract: `sql` holds the shell-interpreted command string when one exists,
`params` holds argv-shaped (non-shell-interpreted) data otherwise.

v0.1.0 scope guard: does not special-case an argv list that itself invokes
a shell, e.g. `subprocess.run(["/bin/sh", "-c", tainted], shell=False)` —
that pattern IS exploitable but isn't detected as `confirmed` by this
heuristic and is left for manual review, the same kind of documented scope
limit repo.py applies to nested functions/methods.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from secfix.trace import ExecutionTrace

VERDICT_CONFIRMED = "confirmed"
VERDICT_NOT_REPRODUCED = "not_reproduced"
VERDICT_UNCERTAIN = "uncertain"


@dataclass
class OracleResult:
    verdict: str
    detail: str
    offending_sql: Optional[str] = None


def _params_contain(params: Any, sentinel: str) -> bool:
    if params is None:
        return False
    if isinstance(params, str):
        return sentinel in params
    if isinstance(params, (list, tuple, set)):
        return any(_params_contain(p, sentinel) for p in params)
    if isinstance(params, dict):
        return any(_params_contain(v, sentinel) for v in params.values())
    return sentinel in str(params)


def evaluate(trace: ExecutionTrace, sentinel: str) -> OracleResult:
    if not trace:
        return OracleResult(
            verdict=VERDICT_UNCERTAIN,
            detail="no os.system()/subprocess.*() calls were recorded — the command "
            "sink may not have been reached, or the harness call failed before "
            "issuing a command",
        )

    for cmd in trace:
        if sentinel in cmd.sql:
            return OracleResult(
                verdict=VERDICT_CONFIRMED,
                detail="tainted sentinel was found inside a command string that "
                "gets shell-interpreted (os.system, or subprocess with shell=True)",
                offending_sql=cmd.sql,
            )

    for cmd in trace:
        if _params_contain(cmd.params, sentinel):
            return OracleResult(
                verdict=VERDICT_NOT_REPRODUCED,
                detail="tainted sentinel reached the command sink only as a "
                "separate argv element (shell=False), never inside a "
                "shell-interpreted string — not exploitable via this path",
            )

    return OracleResult(
        verdict=VERDICT_UNCERTAIN,
        detail="a command sink was called but the sentinel was not observed in "
        "any command string or argv list — cannot confirm or rule out",
    )
