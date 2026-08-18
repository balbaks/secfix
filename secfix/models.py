"""Swappable model boundary for patch generation. One entry point,
`generate_patch`, dispatches to a cloud provider (Anthropic, default) or a
local one (Ollama). No SDK dependency: both providers are plain HTTP calls
via urllib so secfix stays dependency-light.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

_FENCE_ALL_RE = re.compile(r"```[a-zA-Z]*\n(.*?)```", re.DOTALL)
_DIFF_HEADER_RE = re.compile(r"^(---|\+\+\+|diff --git) ", re.MULTILINE)

DIFF_MARKER = "=== DIFF ==="
EXPLANATION_MARKER = "=== EXPLANATION ==="
NOTES_MARKER = "=== NOTES ==="

DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5"
DEFAULT_OLLAMA_MODEL = "codellama"


@dataclass
class PatchContext:
    finding_summary: str
    vulnerable_snippet: str
    file_path: str
    harness_source: str
    offending_sql: str
    oracle_detail: str


@dataclass
class PatchResult:
    diff: str
    explanation: str
    notes: str = ""


class ModelError(RuntimeError):
    pass


def generate_patch(context: PatchContext, provider: str = "anthropic", **kwargs: Any) -> PatchResult:
    if provider == "anthropic":
        return _anthropic_generate_patch(context, **kwargs)
    if provider == "ollama":
        return _ollama_generate_patch(context, **kwargs)
    raise ValueError(f"unknown model provider: {provider!r} (expected 'anthropic' or 'ollama')")


def _build_prompt(context: PatchContext) -> str:
    return f"""You are fixing a confirmed SQL-injection vulnerability in an authorized \
security engagement. The vulnerability was CONFIRMED by runtime reproduction, not \
static analysis: a unique sentinel value was passed into the function below and \
observed landing directly inside the executed SQL string.

File: {context.file_path}

Vulnerable code:
```python
{context.vulnerable_snippet}
```

Finding: {context.finding_summary}

Observed injectable query (sentinel redacted as SENTINEL):
{context.offending_sql}

Oracle detail: {context.oracle_detail}

Fix the vulnerability by converting the query to use parameterized/bound \
placeholders (e.g. `?` or `%s` passed via the DB API's `params` argument) \
instead of string interpolation. Do not change unrelated behavior. Only \
modify {context.file_path}.

Respond in EXACTLY this format, nothing else:

{DIFF_MARKER}
<a unified diff (git diff format) touching only {context.file_path}>
{EXPLANATION_MARKER}
<1-3 sentences on what changed and why it fixes the vulnerability>
{NOTES_MARKER}
<any residual risk or behavior change the reviewer should know about, or "none">
"""


def _extract_diff(diff_raw: str) -> str:
    """diff_raw may embed the diff directly, or wrap it (and possibly other,
    non-diff context) in one or more fenced code blocks. If any fenced
    blocks are present, exactly one of them must look like a unified diff
    (a ---/+++ header pair or a `diff --git` line) — zero or multiple such
    blocks is ambiguous and must raise rather than silently falling through
    to raw, unparsed text that would corrupt `git apply`.
    """
    blocks = _FENCE_ALL_RE.findall(diff_raw)
    if not blocks:
        return diff_raw.strip()

    qualifying = [b.strip() for b in blocks if _DIFF_HEADER_RE.search(b)]
    if len(qualifying) != 1:
        raise ModelError(
            "expected exactly one fenced code block containing a unified diff "
            f"(---/+++ or diff --git headers) in the model response, found "
            f"{len(qualifying)} (out of {len(blocks)} fenced block(s) total)"
        )
    return qualifying[0]


def _parse_response(text: str) -> PatchResult:
    if DIFF_MARKER not in text or EXPLANATION_MARKER not in text:
        raise ModelError(
            "model response did not follow the required DIFF/EXPLANATION/NOTES format"
        )

    diff_start = text.index(DIFF_MARKER) + len(DIFF_MARKER)
    explanation_start = text.index(EXPLANATION_MARKER)
    diff_raw = text[diff_start:explanation_start].strip()
    diff = _extract_diff(diff_raw)

    if NOTES_MARKER in text:
        notes_start = text.index(NOTES_MARKER)
        explanation = text[explanation_start + len(EXPLANATION_MARKER) : notes_start].strip()
        notes = text[notes_start + len(NOTES_MARKER) :].strip()
    else:
        explanation = text[explanation_start + len(EXPLANATION_MARKER) :].strip()
        notes = ""

    return PatchResult(diff=diff, explanation=explanation, notes=notes)


def _anthropic_generate_patch(
    context: PatchContext, model: str = DEFAULT_ANTHROPIC_MODEL, api_key: str | None = None
) -> PatchResult:
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise ModelError("ANTHROPIC_API_KEY is not set")

    body = json.dumps(
        {
            "model": model,
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": _build_prompt(context)}],
        }
    ).encode()

    request = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as resp:
            payload = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise ModelError(f"Anthropic API error {e.code}: {e.read().decode(errors='replace')}") from e
    except urllib.error.URLError as e:
        raise ModelError(f"failed to reach Anthropic API: {e}") from e

    text = "".join(block.get("text", "") for block in payload.get("content", []))
    return _parse_response(text)


def _ollama_generate_patch(
    context: PatchContext, model: str = DEFAULT_OLLAMA_MODEL, host: str = "http://localhost:11434"
) -> PatchResult:
    body = json.dumps(
        {"model": model, "prompt": _build_prompt(context), "stream": False}
    ).encode()

    request = urllib.request.Request(
        f"{host}/api/generate",
        data=body,
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as resp:
            payload = json.loads(resp.read())
    except urllib.error.URLError as e:
        raise ModelError(f"failed to reach Ollama at {host}: {e}") from e

    return _parse_response(payload.get("response", ""))
