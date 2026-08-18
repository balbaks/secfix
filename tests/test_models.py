"""Unit tests for models._parse_response and the full-replacement diff
pipeline — no API key required.

Models are asked for a complete corrected function body, never a raw diff
(see the module docstring in secfix/models.py for why: models like Groq's
gpt-oss-120b reliably produce diffs with malformed/missing @@ headers that
can't be safely salvaged). _parse_response extracts that replacement, then
_compute_diff builds the actual unified diff itself via difflib against the
real file content, so the diff is well-formed by construction regardless of
what the model wrote. Each test here exercises a real response shape a
model might emit: clean, prefaced with prose, function wrapped in a fenced
code block, extra blank lines, missing NOTES section, etc.
"""
import json
import re
import subprocess
import urllib.error
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from secfix.models import (
    EXPLANATION_MARKER,
    FIXED_FUNCTION_MARKER,
    NOTES_MARKER,
    ModelError,
    PatchContext,
    _groq_generate_patch,
    _parse_response,
)

# A small, realistic file: a helper + the vulnerable function, so the
# function-to-replace is neither the first nor the last line of the file —
# proves _compute_diff's splice respects real surrounding content.
_ORIGINAL_FILE = (
    '"""module docstring."""\n'
    "import sqlite3\n"
    "\n"
    "\n"
    "def get_connection():\n"
    '    return sqlite3.connect(":memory:")\n'
    "\n"
    "\n"
    "def find_user_by_name(name):\n"
    "    conn = get_connection()\n"
    "    cursor = conn.cursor()\n"
    "    query = \"SELECT * FROM users WHERE name = '%s'\" % name\n"
    "    cursor.execute(query)\n"
    "    return cursor.fetchall()\n"
)
_FUNCTION_START_LINE = 9
_FUNCTION_END_LINE = 14

# Exactly the original function's text, lines 9-14 above — used to prove a
# no-op "fix" is rejected rather than silently accepted.
_ORIGINAL_FUNCTION = (
    "def find_user_by_name(name):\n"
    "    conn = get_connection()\n"
    "    cursor = conn.cursor()\n"
    "    query = \"SELECT * FROM users WHERE name = '%s'\" % name\n"
    "    cursor.execute(query)\n"
    "    return cursor.fetchall()\n"
)

_FIXED_FUNCTION = (
    "def find_user_by_name(name):\n"
    "    conn = get_connection()\n"
    "    cursor = conn.cursor()\n"
    '    query = "SELECT * FROM users WHERE name = %s"\n'
    "    cursor.execute(query, (name,))\n"
    "    return cursor.fetchall()\n"
)

_EXPLANATION = "Replaced string interpolation with a bound parameter placeholder."
_NOTES = "none"

_CONTEXT = PatchContext(
    finding_summary="tainted string used to build a SQL query",
    file_path="app.py",
    harness_source="",
    offending_sql="SELECT * FROM users WHERE name = 'SECFIX_TAINT_deadbeef'",
    oracle_detail="tainted sentinel was found interpolated directly into an executed SQL string",
    full_source=_ORIGINAL_FILE,
    function_start_line=_FUNCTION_START_LINE,
    function_end_line=_FUNCTION_END_LINE,
)


def _build(function=_FIXED_FUNCTION, explanation=_EXPLANATION, notes=_NOTES, *, prefix=""):
    parts = [f"{prefix}{FIXED_FUNCTION_MARKER}\n{function}\n{EXPLANATION_MARKER}\n{explanation}"]
    if notes is not None:
        parts.append(f"{NOTES_MARKER}\n{notes}")
    return "\n".join(parts)


def _expected_fixed_file() -> str:
    lines = _ORIGINAL_FILE.splitlines(keepends=True)
    return "".join(lines[: _FUNCTION_START_LINE - 1]) + _FIXED_FUNCTION + "".join(
        lines[_FUNCTION_END_LINE:]
    )


# ---------------------------------------------------------------------------
# Happy-path / clean format
# ---------------------------------------------------------------------------

def test_clean_format():
    result = _parse_response(_build(), _CONTEXT)
    assert result.explanation == _EXPLANATION
    assert result.notes == _NOTES
    assert "-    query = \"SELECT * FROM users WHERE name = '%s'\" % name" in result.diff
    assert "+    cursor.execute(query, (name,))" in result.diff
    assert result.diff.startswith("--- a/app.py\n+++ b/app.py\n")


def test_missing_notes_section():
    text = f"{FIXED_FUNCTION_MARKER}\n{_FIXED_FUNCTION}\n{EXPLANATION_MARKER}\n{_EXPLANATION}"
    result = _parse_response(text, _CONTEXT)
    assert result.notes == ""
    assert result.explanation == _EXPLANATION


# ---------------------------------------------------------------------------
# The diff is computed by us, not the model — prove it's well-formed by
# construction: it must apply cleanly via plain `git apply` (no --recount
# fallback needed) and produce exactly the expected file content.
# ---------------------------------------------------------------------------

def test_computed_diff_applies_cleanly_and_produces_expected_file(tmp_path):
    result = _parse_response(_build(), _CONTEXT)

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    (repo / "app.py").write_text(_ORIGINAL_FILE)
    subprocess.run(["git", "add", "app.py"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo, check=True)

    patch_file = tmp_path / "computed.diff"
    patch_file.write_text(result.diff)

    check = subprocess.run(
        ["git", "apply", "--check", str(patch_file)], cwd=repo, capture_output=True, text=True
    )
    assert check.returncode == 0, check.stderr

    subprocess.run(["git", "apply", str(patch_file)], cwd=repo, check=True)
    assert (repo / "app.py").read_text() == _expected_fixed_file()


def test_noop_replacement_raises():
    # The model returned the function unchanged — no fix was actually made.
    result_text = _build(function=_ORIGINAL_FUNCTION)
    with pytest.raises(ModelError, match="identical to the original"):
        _parse_response(result_text, _CONTEXT)


# ---------------------------------------------------------------------------
# Messy preambles / prose before the first marker
# ---------------------------------------------------------------------------

def test_preamble_prose_ignored():
    text = "Sure! Here is the fix you requested.\n\n" + _build()
    result = _parse_response(text, _CONTEXT)
    assert result.explanation == _EXPLANATION
    assert "+    cursor.execute(query, (name,))" in result.diff


def test_preamble_with_code_context():
    text = (
        "I'll convert the query to use parameterized placeholders.\n"
        "The change touches only app.py.\n\n"
    ) + _build()
    result = _parse_response(text, _CONTEXT)
    assert "+    cursor.execute(query, (name,))" in result.diff


# ---------------------------------------------------------------------------
# Fenced code blocks inside the FIXED_FUNCTION section
# ---------------------------------------------------------------------------

def test_fenced_function_with_language_tag():
    fenced = f"```python\n{_FIXED_FUNCTION}```"
    text = f"{FIXED_FUNCTION_MARKER}\n{fenced}\n{EXPLANATION_MARKER}\n{_EXPLANATION}\n{NOTES_MARKER}\n{_NOTES}"
    result = _parse_response(text, _CONTEXT)
    assert "+    cursor.execute(query, (name,))" in result.diff  # fences stripped


def test_fenced_function_no_language_tag():
    fenced = f"```\n{_FIXED_FUNCTION}```"
    text = f"{FIXED_FUNCTION_MARKER}\n{fenced}\n{EXPLANATION_MARKER}\n{_EXPLANATION}\n{NOTES_MARKER}\n{_NOTES}"
    result = _parse_response(text, _CONTEXT)
    assert "+    cursor.execute(query, (name,))" in result.diff


# ---------------------------------------------------------------------------
# Extra whitespace between sections
# ---------------------------------------------------------------------------

def test_extra_blank_lines_between_sections():
    text = (
        f"{FIXED_FUNCTION_MARKER}\n\n\n{_FIXED_FUNCTION}\n\n\n"
        f"{EXPLANATION_MARKER}\n\n{_EXPLANATION}\n\n"
        f"{NOTES_MARKER}\n\n{_NOTES}\n\n"
    )
    result = _parse_response(text, _CONTEXT)
    assert result.explanation == _EXPLANATION
    assert result.notes == _NOTES
    assert "+    cursor.execute(query, (name,))" in result.diff


# ---------------------------------------------------------------------------
# Wrapped-replacement variety: realistic messy model outputs, same fix
# ---------------------------------------------------------------------------

def test_wrapped_in_fenced_block_with_preamble():
    text = (
        "Looking at this, the vulnerability is classic string-formatted SQL.\n\n"
        f"{FIXED_FUNCTION_MARKER}\n```python\n{_FIXED_FUNCTION}```\n{EXPLANATION_MARKER}\n{_EXPLANATION}\n"
        f"{NOTES_MARKER}\n{_NOTES}\n"
    )
    result = _parse_response(text, _CONTEXT)
    assert "+    cursor.execute(query, (name,))" in result.diff


def test_wrapped_diff_then_long_explanation_paragraph():
    long_explanation = (
        "This change removes the % string-formatting that let a value containing SQL "
        "metacharacters alter the query. Instead, the value is passed as a bound "
        "parameter through the DB-API's params argument, so the driver treats it as "
        "pure data no matter what characters it contains."
    )
    result = _parse_response(_build(explanation=long_explanation), _CONTEXT)
    assert result.explanation == long_explanation
    assert "+    cursor.execute(query, (name,))" in result.diff


def test_wrapped_two_code_blocks_context_has_dash_line():
    """The extra fenced block being non-Python content (not code at all)
    doesn't matter here — unlike diffs, a full function has no structural
    marker to single one block out, so ANY second fenced block is ambiguous
    and must raise, regardless of what it looks like.
    """
    text = (
        f"{FIXED_FUNCTION_MARKER}\n"
        "For context, here's what changed conceptually:\n"
        "```text\n"
        "- uses % string formatting (vulnerable)\n"
        "- switches to a bound parameter\n"
        "```\n\n"
        "And here's the actual fixed function:\n"
        f"```python\n{_FIXED_FUNCTION}```\n"
        f"{EXPLANATION_MARKER}\n{_EXPLANATION}\n{NOTES_MARKER}\n{_NOTES}\n"
    )
    with pytest.raises(ModelError, match="fenced code block"):
        _parse_response(text, _CONTEXT)


# ---------------------------------------------------------------------------
# Hardened fenced-block selection: ambiguous cases must raise, never guess
# ---------------------------------------------------------------------------

def test_multiple_fenced_blocks_raises():
    text = (
        f"{FIXED_FUNCTION_MARKER}\n"
        f"```python\n{_FIXED_FUNCTION}```\n"
        "Here's an alternative fix we considered:\n"
        f"```python\n{_FIXED_FUNCTION}```\n"
        f"{EXPLANATION_MARKER}\n{_EXPLANATION}\n{NOTES_MARKER}\n{_NOTES}\n"
    )
    with pytest.raises(ModelError, match="fenced code block"):
        _parse_response(text, _CONTEXT)


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------

def test_missing_fixed_function_marker_raises():
    with pytest.raises(ModelError, match="FIXED_FUNCTION"):
        _parse_response(f"{EXPLANATION_MARKER}\nsome explanation\n{NOTES_MARKER}\nnone", _CONTEXT)


def test_missing_explanation_marker_raises():
    with pytest.raises(ModelError):
        _parse_response(f"{FIXED_FUNCTION_MARKER}\nsome function", _CONTEXT)


def test_completely_empty_raises():
    with pytest.raises(ModelError):
        _parse_response("", _CONTEXT)


def test_only_prose_raises():
    with pytest.raises(ModelError):
        _parse_response("The fix is to use parameterized queries.", _CONTEXT)


# ---------------------------------------------------------------------------
# Groq provider: HTTP request/response shape and error handling, fully
# mocked (no network, no GROQ_API_KEY). Confirms the OpenAI-compatible
# response text is routed through the exact same _parse_response/
# _compute_diff path as every other provider — including a diff the model
# never wrote a single character of.
# ---------------------------------------------------------------------------

@contextmanager
def _fake_response(payload: dict):
    class _Resp:
        def read(self):
            return json.dumps(payload).encode()

    yield _Resp()


def test_groq_generate_patch_computes_diff_from_wrapped_function():
    # Groq/OpenAI-compatible models wrap replacements in fences + prose
    # exactly like Anthropic models do; this proves that messy shape
    # survives unchanged, AND that the diff we get back was computed by us
    # (well-formed unified diff), never hand-written by the model.
    content = (
        "Sure, here's the fix:\n\n"
        f"{FIXED_FUNCTION_MARKER}\n```python\n{_FIXED_FUNCTION}```\n{EXPLANATION_MARKER}\n{_EXPLANATION}\n"
        f"{NOTES_MARKER}\n{_NOTES}\n"
    )
    fake_payload = {"choices": [{"message": {"content": content}}]}

    with patch("secfix.models.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value = _fake_response(fake_payload)
        result = _groq_generate_patch(_CONTEXT, api_key="test-groq-key")

    assert result.explanation == _EXPLANATION
    assert result.diff.startswith("--- a/app.py\n+++ b/app.py\n")
    assert "+    cursor.execute(query, (name,))" in result.diff

    # Assert the request shape: OpenAI-compatible endpoint, Bearer auth,
    # messages array — not the Anthropic shape.
    request = mock_urlopen.call_args[0][0]
    assert request.full_url == "https://api.groq.com/openai/v1/chat/completions"
    assert request.get_header("Authorization") == "Bearer test-groq-key"
    sent_body = json.loads(request.data)
    assert sent_body["messages"] == [{"role": "user", "content": sent_body["messages"][0]["content"]}]
    assert "x-api-key" not in {h.lower() for h in request.headers}


def test_groq_generate_patch_401_raises_model_error():
    error = urllib.error.HTTPError(
        url="https://api.groq.com/openai/v1/chat/completions",
        code=401,
        msg="Unauthorized",
        hdrs=None,
        fp=None,
    )
    error.read = lambda: b'{"error": {"message": "Invalid API Key"}}'

    with patch("secfix.models.urllib.request.urlopen", side_effect=error):
        with pytest.raises(ModelError, match="Groq API error 401"):
            _groq_generate_patch(_CONTEXT, api_key="bad-key")


def test_bogus_diff_looking_response_treated_as_literal_function_text():
    """The failure mode that motivated this redesign: a live gpt-oss-120b
    response once came back with a bare '@@' hunk header (no line numbers at
    all), which neither plain `git apply` nor `--recount` could salvage.
    With the full-replacement prompt the model is never asked for diff
    syntax at all — but if it ignores that and emits diff-looking text in
    the FIXED_FUNCTION slot anyway, there's no special-case "is this a
    diff?" detection: it's spliced in as literal function text, exactly
    like any other replacement. The unified diff we hand back is still
    difflib's own well-formed construction regardless of how garbled the
    model's "function" is; that's a model-compliance problem for the
    harness re-verification step to catch, not something the parser
    salvages or rejects.
    """
    bogus_looking_like_a_diff = "--- a/app.py\n+++ b/app.py\n@@\n-old line\n+new line\n"
    result = _parse_response(_build(function=bogus_looking_like_a_diff), _CONTEXT)

    # A real, well-formed hunk header with actual numbers — difflib's own,
    # never anything the model wrote.
    assert re.search(r"^@@ -\d+,\d+ \+\d+,\d+ @@", result.diff, re.MULTILINE)
    # The model's bogus diff-looking text appears only as literal spliced-in
    # content (a "+" content line), never interpreted as diff structure.
    assert "+--- a/app.py" in result.diff
