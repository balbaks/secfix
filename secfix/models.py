"""Swappable model boundary for patch generation. One entry point,
`generate_patch`, dispatches to a cloud provider (Anthropic, default;
or Groq, OpenAI-compatible) or a local one (Ollama). No SDK dependency:
all providers are plain HTTP calls via urllib so secfix stays
dependency-light.

Models are asked for a full corrected function body, never a raw diff.
Some models (esp. smaller/open ones) reliably produce diffs with malformed
or missing `@@` hunk headers that can't be safely salvaged — recomputing
the diff ourselves from (original function, model's replacement) via
difflib guarantees a well-formed diff by construction, regardless of how
the model writes.
"""
from __future__ import annotations

import difflib
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

_FENCE_ALL_RE = re.compile(r"```[a-zA-Z]*\n(.*?)```", re.DOTALL)

FIXED_FUNCTION_MARKER = "=== FIXED_FUNCTION ==="
EXPLANATION_MARKER = "=== EXPLANATION ==="
NOTES_MARKER = "=== NOTES ==="

DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5"
DEFAULT_GROQ_MODEL = "openai/gpt-oss-120b"
DEFAULT_OLLAMA_MODEL = "codellama"


@dataclass
class PatchContext:
    finding_summary: str
    file_path: str
    harness_source: str
    offending_sql: str
    oracle_detail: str
    # Full original source of the file, plus the 1-indexed, inclusive line
    # range of the enclosing function within it. Together these let us
    # splice the model's replacement back into the real file and diff
    # ourselves — the model never has to produce a diff at all.
    full_source: str
    function_start_line: int
    function_end_line: int


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
    if provider == "groq":
        return _groq_generate_patch(context, **kwargs)
    if provider == "ollama":
        return _ollama_generate_patch(context, **kwargs)
    raise ValueError(
        f"unknown model provider: {provider!r} (expected 'anthropic', 'groq', or 'ollama')"
    )


def _function_lines(context: PatchContext) -> tuple[list[str], int, int]:
    """Return (all lines of the original file, start_idx, end_idx) where
    original_lines[start_idx:end_idx] is exactly the enclosing function,
    using Python slice semantics (end_idx exclusive) from the 1-indexed,
    inclusive function_start_line/function_end_line.
    """
    lines = context.full_source.splitlines(keepends=True)
    start_idx = context.function_start_line - 1
    end_idx = context.function_end_line
    return lines, start_idx, end_idx


def _build_prompt(context: PatchContext) -> str:
    lines, start_idx, end_idx = _function_lines(context)
    function_source = "".join(lines[start_idx:end_idx])

    return f"""You are fixing a confirmed SQL-injection vulnerability in an authorized \
security engagement. The vulnerability was CONFIRMED by runtime reproduction, not \
static analysis: a unique sentinel value was passed into the function below and \
observed landing directly inside the executed SQL string.

File: {context.file_path}

The full, original function (lines {context.function_start_line}-{context.function_end_line}):
```python
{function_source}```

Finding: {context.finding_summary}

Observed injectable query (sentinel redacted as SENTINEL):
{context.offending_sql}

Oracle detail: {context.oracle_detail}

Fix the vulnerability by converting the query to use parameterized/bound \
placeholders (e.g. `?` or `%s` passed via the DB API's `params` argument) \
instead of string interpolation. Preserve the function's signature, name, \
and all unrelated behavior exactly — change only what's needed to fix the \
injection.

Respond in EXACTLY this format, nothing else:

{FIXED_FUNCTION_MARKER}
<the COMPLETE corrected function, from its `def` line to its last line, \
ready to replace the original verbatim — same indentation, no diff syntax, \
no line numbers, no markdown fences, no surrounding prose>
{EXPLANATION_MARKER}
<1-3 sentences on what changed and why it fixes the vulnerability>
{NOTES_MARKER}
<any residual risk or behavior change the reviewer should know about, or "none">
"""


def _extract_replacement(raw: str) -> str:
    """raw may be the replacement function directly, or wrap it (and
    possibly other, non-replacement context) in one or more fenced code
    blocks. Unlike a diff, a full function body has no structural marker to
    single it out among several fenced blocks, so the only safe rule is:
    zero fences -> use the raw text; exactly one fence -> use its content;
    two or more -> ambiguous, raise rather than guess which one is real.
    """
    blocks = _FENCE_ALL_RE.findall(raw)
    if not blocks:
        return raw.strip()
    if len(blocks) != 1:
        raise ModelError(
            "expected exactly one fenced code block containing the replacement "
            f"function in the model response, found {len(blocks)}"
        )
    return blocks[0].strip()


def _compute_diff(context: PatchContext, replacement: str) -> str:
    """Build a unified diff ourselves from (original file, model's function
    replacement spliced into it) via difflib, instead of trusting the model
    to hand-write diff syntax. This makes a malformed/missing @@ header
    structurally impossible: difflib always emits correct headers because
    it computes them from the real before/after line arrays, not from
    anything the model wrote.
    """
    lines, start_idx, end_idx = _function_lines(context)
    if not (0 <= start_idx < end_idx <= len(lines)):
        raise ModelError(
            "internal error: function line range "
            f"{context.function_start_line}-{context.function_end_line} is out of "
            f"bounds for {context.file_path} ({len(lines)} lines)"
        )

    replacement_lines = (replacement.strip("\n") + "\n").splitlines(keepends=True)
    new_lines = lines[:start_idx] + replacement_lines + lines[end_idx:]

    diff_lines = list(
        difflib.unified_diff(
            lines, new_lines, fromfile=f"a/{context.file_path}", tofile=f"b/{context.file_path}"
        )
    )
    if not diff_lines:
        raise ModelError(
            "model's replacement function is identical to the original — no fix was made"
        )
    return "".join(diff_lines)


def _parse_response(text: str, context: PatchContext) -> PatchResult:
    if FIXED_FUNCTION_MARKER not in text or EXPLANATION_MARKER not in text:
        raise ModelError(
            "model response did not follow the required "
            "FIXED_FUNCTION/EXPLANATION/NOTES format"
        )

    fn_start = text.index(FIXED_FUNCTION_MARKER) + len(FIXED_FUNCTION_MARKER)
    explanation_start = text.index(EXPLANATION_MARKER)
    replacement_raw = text[fn_start:explanation_start].strip()
    replacement = _extract_replacement(replacement_raw)

    if NOTES_MARKER in text:
        notes_start = text.index(NOTES_MARKER)
        explanation = text[explanation_start + len(EXPLANATION_MARKER) : notes_start].strip()
        notes = text[notes_start + len(NOTES_MARKER) :].strip()
    else:
        explanation = text[explanation_start + len(EXPLANATION_MARKER) :].strip()
        notes = ""

    diff = _compute_diff(context, replacement)
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
    return _parse_response(text, context)


def _groq_generate_patch(
    context: PatchContext, model: str = DEFAULT_GROQ_MODEL, api_key: str | None = None
) -> PatchResult:
    api_key = api_key or os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise ModelError("GROQ_API_KEY is not set")

    body = json.dumps(
        {
            "model": model,
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": _build_prompt(context)}],
        }
    ).encode()

    request = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=body,
        headers={
            "content-type": "application/json",
            "Authorization": f"Bearer {api_key}",
            # Groq's endpoint sits behind Cloudflare, which WAF-blocks the
            # default "Python-urllib/x.y" User-Agent as bot traffic (403,
            # Cloudflare error code 1010) before the request ever reaches
            # Groq's auth layer. Any non-default value clears it.
            "User-Agent": "secfix/0.1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as resp:
            payload = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise ModelError(f"Groq API error {e.code}: {e.read().decode(errors='replace')}") from e
    except urllib.error.URLError as e:
        raise ModelError(f"failed to reach Groq API: {e}") from e

    # OpenAI-compatible chat-completions response shape: the message text we
    # feed to _parse_response is identical in kind to what the Anthropic
    # path produces, so the same messy-wrapper handling (fenced blocks,
    # prose preambles, ambiguous-block fail-loud) applies unchanged.
    text = payload["choices"][0]["message"]["content"]
    return _parse_response(text, context)


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

    return _parse_response(payload.get("response", ""), context)
