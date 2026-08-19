"""Sentinel-based Python path-traversal oracle. Consumes only an
ExecutionTrace (never source) and renders a verdict per the
sentinel-resolution rule:

  recorded sink path contains the sentinel AND either
    (a) still carries a literal ".." path segment, OR
    (b) is itself exactly the absolute-path probe payload ("/" + sentinel),
        meaning nothing from the target's base directory survived into it
                                                              -> confirmed
  recorded sink path contains the sentinel but neither (a) nor (b) holds
                                                              -> not_reproduced
  no file/path sink recorded, or the sentinel isn't found in any recorded
  path                                                       -> uncertain

Mirrors secfix.oracle.sqli/cmdi's structure and shares the same
ExecutionTrace contract: `sql` holds the raw path string handed to the sink
(open/os.open/os.remove/shutil.*/etc — see harness/python_pathtraversal.py),
`params` holds {"op": <sink name>} metadata, unused by the verdict rule
itself.

Reasoning for TWO signals, not one:
The harness runs two probes into the same trace (see
harness/python_pathtraversal.py._render_source): a relative ".."-laden
payload and a bare absolute-path payload ("/" + sentinel). Checking only for
surviving ".." (the v0.1.0 version of this oracle) missed a very common
Python bug: `os.path.join(base, tainted)` — and pathlib's `Path(base,
tainted)` — silently discard `base` entirely when `tainted` is itself an
absolute path, per os.path.join's documented behavior ("If a component is
an absolute path, all previous components are thrown away"). That bypass
produces a final sink path with NO ".." in it at all, so a ".."-only oracle
reports it `not_reproduced` — a false-safe on a real, exploitable
vulnerability. A ".."-only *blocklist* "fix" is exactly as blind to this:
it stops probe (a) and does nothing about probe (b).

  (a) ".." survival: a naive sink never calls any path-resolution
      primitive, so whatever ".." was in the tainted value is still
      sitting in the string verbatim when it reaches the sink. Any correct
      confinement fix (realpath, Path.resolve(), normpath, or basename
      stripping) collapses or discards it first.
  (b) absolute-payload survival: if the sink call's final path is *exactly*
      the raw "/" + sentinel probe value, the target's own base-directory
      text contributed nothing whatsoever to what reached the sink — proof
      the tainted input fully overrode it (the os.path.join/Path-join
      discard behavior above). A correctly confined fix never lets the
      sink see this raw value unchanged: it either rejects it outright, or
      resolves+re-anchors it under the base first (which changes the
      string — see the safe fixture, whose fallback path is
      `base / Path(filename).name`, never equal to the raw payload).

Neither check requires knowing the target's actual base-directory value —
(a) is a property of the string alone, and (b) is an exact-equality check
against a value the harness itself generated, so both stay generic across
arbitrary target code, mirroring how sqli's bound-params-vs-string-
interpolation rule and cmdi's shell-string-vs-argv rule are also purely
structural, trace-only checks.

What this oracle's verdict actually means (read this before trusting a
NOT_REPRODUCED): this is a controlled-probe oracle, the same kind sqli and
cmdi already are — it confirms whether the target neutralizes the harness's
own two traversal probes (relative ".." and absolute-override), not whether
it's immune to traversal in general. Neutralizing both probes means the
target is confined against these two dominant real-world techniques;
failing either means it is not. It deliberately does NOT attempt arbitrary
attacker-syntax coverage (that would mean guessing at real-world exploit
strings rather than checking the harness's own controlled sentinel, which is
exactly the discipline sqli's and cmdi's oracles already hold to). (b) is
also intentionally an *exact* match against the raw probe value, not a
looser "is this path absolute" test — a legitimately confined fix can still
produce an absolute path (e.g. `base_dir / safe_name` when base itself is
absolute), and flagging that would be a false positive.

Vectors outside the two-probe set are out of scope and a NOT_REPRODUCED
verdict says nothing about them either way — e.g. symlink-based races (the
confinement check and the actual open racing against a symlink swapped in
between), OS/filesystem-level encoded or doubled separators, Windows
drive-root absolute paths ("C:\\..."), or a bypass that reaches the sink
with something appended/prepended to the discarded-base absolute path (e.g.
`os.path.join(base, tainted) + ".txt"`). These are left for manual review,
the same kind of documented scope limit cmdi's oracle and repo.py apply
elsewhere.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from secfix.trace import ExecutionTrace

VERDICT_CONFIRMED = "confirmed"
VERDICT_NOT_REPRODUCED = "not_reproduced"
VERDICT_UNCERTAIN = "uncertain"

# Matches ".." as a standalone path segment (either separator, either end of
# string) rather than as a substring of a longer component — so "..hidden"
# or "foo..bar" don't false-positive.
_TRAVERSAL_RE = re.compile(r"(^|[\\/])\.\.([\\/]|$)")


@dataclass
class OracleResult:
    verdict: str
    detail: str
    offending_sql: Optional[str] = None


def _contains_traversal(path: str) -> bool:
    return bool(_TRAVERSAL_RE.search(path))


def _is_absolute_override(path: str, sentinel: str) -> bool:
    """True iff `path` is exactly the absolute-path probe payload the
    harness injected ("/" + sentinel) — i.e. nothing from the target's own
    base-directory logic survived into the final sink argument.
    """
    return path == "/" + sentinel


def evaluate(trace: ExecutionTrace, sentinel: str) -> OracleResult:
    if not trace:
        return OracleResult(
            verdict=VERDICT_UNCERTAIN,
            detail="no file/path sink (open, os.open, os.remove, shutil.*, ...) was "
            "recorded — the sink may not have been reached, or the harness call "
            "failed before performing a path operation",
        )

    for op in trace:
        if sentinel not in op.sql:
            continue
        if _contains_traversal(op.sql):
            return OracleResult(
                verdict=VERDICT_CONFIRMED,
                detail="tainted sentinel reached a file/path sink with its '../' "
                "traversal segment(s) still literally present and unresolved — "
                "the path was never confined to a base directory",
                offending_sql=op.sql,
            )
        if _is_absolute_override(op.sql, sentinel):
            return OracleResult(
                verdict=VERDICT_CONFIRMED,
                detail="tainted sentinel reached a file/path sink as a bare "
                "absolute path with none of the target's base-directory text "
                "surviving — the base was discarded entirely (the classic "
                "os.path.join(base, absolute_input) bypass), not confined",
                offending_sql=op.sql,
            )

    for op in trace:
        if sentinel in op.sql:
            return OracleResult(
                verdict=VERDICT_NOT_REPRODUCED,
                detail="tainted sentinel reached the sink only after its traversal "
                "segment was resolved/stripped away and no absolute-path override "
                "reached the sink unchanged — the path was confined before use "
                "and not exploitable via either probe",
            )

    return OracleResult(
        verdict=VERDICT_UNCERTAIN,
        detail="a file/path sink was called but the sentinel was not observed in "
        "any recorded path — cannot confirm or rule out",
    )
