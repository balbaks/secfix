"""Shared execution-trace contract: produced by harnesses, consumed by oracles
and the patch verifier. Kept dependency-free so it can be dropped into a
sandboxed harness process on its own.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ExecutedQuery:
    sql: str
    params: Any = None


ExecutionTrace = list[ExecutedQuery]


def trace_to_json(trace: ExecutionTrace) -> str:
    return json.dumps([asdict(q) for q in trace], default=repr)


def trace_from_json(data: str) -> ExecutionTrace:
    raw = json.loads(data)
    return [ExecutedQuery(sql=item["sql"], params=item.get("params")) for item in raw]


class RecordingCursor:
    """A DB-API cursor stand-in that records every execute(d) call instead of
    touching a real database. Returns benign empty results so the caller's
    control flow (row iteration, fetch calls) does not blow up.
    """

    def __init__(self, trace: ExecutionTrace):
        self._trace = trace
        self.rowcount = 0
        self.lastrowid = None
        self.description = None

    def execute(self, sql: str, params: Any = None) -> "RecordingCursor":
        self._trace.append(ExecutedQuery(sql=sql, params=params))
        return self

    def executemany(self, sql: str, seq_of_params: Any = None) -> "RecordingCursor":
        for params in seq_of_params or [None]:
            self._trace.append(ExecutedQuery(sql=sql, params=params))
        return self

    def fetchone(self) -> None:
        return None

    def fetchall(self) -> list:
        return []

    def fetchmany(self, size: int = 1) -> list:
        return []

    def close(self) -> None:
        pass

    def __iter__(self):
        return iter(())

    def __enter__(self) -> "RecordingCursor":
        return self

    def __exit__(self, *exc_info) -> bool:
        return False


class RecordingConnection:
    """A DB-API connection stand-in. Hands out RecordingCursor instances that
    all share the same trace list so every query issued during a harness run
    ends up in one place.
    """

    def __init__(self, trace: ExecutionTrace | None = None):
        self.trace: ExecutionTrace = trace if trace is not None else []

    def cursor(self, *args: Any, **kwargs: Any) -> RecordingCursor:
        return RecordingCursor(self.trace)

    def execute(self, sql: str, params: Any = None) -> RecordingCursor:
        # Some code paths call connection.execute(...) directly (e.g. sqlite3).
        return RecordingCursor(self.trace).execute(sql, params)

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def close(self) -> None:
        pass

    def __enter__(self) -> "RecordingConnection":
        return self

    def __exit__(self, *exc_info) -> bool:
        return False
