"""Sentinel-based SQLi oracle. Consumes only an ExecutionTrace (never source)
and renders a verdict per the sentinel-location rule:

  sentinel substring inside an executed `sql` string  -> confirmed
  sentinel found only in `params` of an execute call   -> not_reproduced
  no execute recorded / sentinel absent everywhere     -> uncertain
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
            detail="no execute()/executemany() calls were recorded — the DB access "
            "path may not have been reached, or the harness call failed before "
            "issuing a query",
        )

    for query in trace:
        if sentinel in query.sql:
            return OracleResult(
                verdict=VERDICT_CONFIRMED,
                detail="tainted sentinel was found interpolated directly into an "
                "executed SQL string",
                offending_sql=query.sql,
            )

    for query in trace:
        if _params_contain(query.params, sentinel):
            return OracleResult(
                verdict=VERDICT_NOT_REPRODUCED,
                detail="tainted sentinel reached the DB layer only via bound "
                "params, never interpolated into the SQL string — parameterized "
                "and not exploitable via this path",
            )

    return OracleResult(
        verdict=VERDICT_UNCERTAIN,
        detail="execute() was called but the sentinel was not observed in any "
        "SQL string or params — cannot confirm or rule out",
    )
