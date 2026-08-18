"""Unit tests for models._parse_response — no API key required.

Each test exercises a real response shape a model might emit: clean, prefaced
with prose, diff wrapped in a fenced code block, extra blank lines, missing
NOTES section, etc.
"""
import json
import urllib.error
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from secfix.models import (
    DIFF_MARKER,
    EXPLANATION_MARKER,
    NOTES_MARKER,
    ModelError,
    PatchContext,
    _groq_generate_patch,
    _parse_response,
)

_DIFF = "--- a/app.py\n+++ b/app.py\n@@ -5,1 +5,1 @@\n-    query = 'SELECT * FROM users WHERE id = %s' % uid\n+    cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))"
_EXPLANATION = "Replaced string interpolation with a bound parameter placeholder."
_NOTES = "none"


def _build(diff=_DIFF, explanation=_EXPLANATION, notes=_NOTES, *, prefix=""):
    parts = [f"{prefix}{DIFF_MARKER}\n{diff}\n{EXPLANATION_MARKER}\n{explanation}"]
    if notes is not None:
        parts.append(f"{NOTES_MARKER}\n{notes}")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Happy-path / clean format
# ---------------------------------------------------------------------------

def test_clean_format():
    result = _parse_response(_build())
    assert result.diff == _DIFF
    assert result.explanation == _EXPLANATION
    assert result.notes == _NOTES


def test_missing_notes_section():
    text = f"{DIFF_MARKER}\n{_DIFF}\n{EXPLANATION_MARKER}\n{_EXPLANATION}"
    result = _parse_response(text)
    assert result.notes == ""
    assert result.explanation == _EXPLANATION


# ---------------------------------------------------------------------------
# Messy preambles / prose before the first marker
# ---------------------------------------------------------------------------

def test_preamble_prose_ignored():
    text = "Sure! Here is the fix you requested.\n\n" + _build()
    result = _parse_response(text)
    assert result.diff == _DIFF
    assert result.explanation == _EXPLANATION


def test_preamble_with_code_context():
    text = (
        "I'll convert the query to use parameterized placeholders.\n"
        "The change touches only app.py.\n\n"
    ) + _build()
    result = _parse_response(text)
    assert result.diff == _DIFF


# ---------------------------------------------------------------------------
# Fenced code blocks inside the DIFF section
# ---------------------------------------------------------------------------

def test_fenced_diff_with_language_tag():
    fenced = f"```diff\n{_DIFF}\n```"
    text = f"{DIFF_MARKER}\n{fenced}\n{EXPLANATION_MARKER}\n{_EXPLANATION}\n{NOTES_MARKER}\n{_NOTES}"
    result = _parse_response(text)
    assert result.diff == _DIFF  # fences stripped


def test_fenced_diff_no_language_tag():
    fenced = f"```\n{_DIFF}\n```"
    text = f"{DIFF_MARKER}\n{fenced}\n{EXPLANATION_MARKER}\n{_EXPLANATION}\n{NOTES_MARKER}\n{_NOTES}"
    result = _parse_response(text)
    assert result.diff == _DIFF


def test_fenced_diff_other_language_tag():
    fenced = f"```patch\n{_DIFF}\n```"
    text = f"{DIFF_MARKER}\n{fenced}\n{EXPLANATION_MARKER}\n{_EXPLANATION}\n{NOTES_MARKER}\n{_NOTES}"
    result = _parse_response(text)
    assert result.diff == _DIFF


# ---------------------------------------------------------------------------
# Extra whitespace between sections
# ---------------------------------------------------------------------------

def test_extra_blank_lines_between_sections():
    text = (
        f"{DIFF_MARKER}\n\n\n{_DIFF}\n\n\n"
        f"{EXPLANATION_MARKER}\n\n{_EXPLANATION}\n\n"
        f"{NOTES_MARKER}\n\n{_NOTES}\n\n"
    )
    result = _parse_response(text)
    assert result.diff == _DIFF
    assert result.explanation == _EXPLANATION
    assert result.notes == _NOTES


# ---------------------------------------------------------------------------
# Wrapped-diff variety: realistic messy model outputs, same diff each time
# ---------------------------------------------------------------------------

def test_wrapped_in_fenced_diff_block_with_preamble():
    text = (
        "Looking at this, the vulnerability is classic string-formatted SQL.\n\n"
        f"{DIFF_MARKER}\n```diff\n{_DIFF}\n```\n{EXPLANATION_MARKER}\n{_EXPLANATION}\n"
        f"{NOTES_MARKER}\n{_NOTES}\n"
    )
    result = _parse_response(text)
    assert result.diff == _DIFF


def test_wrapped_prose_then_unfenced_diff():
    text = "Here's the fix:\n\n" + _build()
    result = _parse_response(text)
    assert result.diff == _DIFF


def test_wrapped_diff_then_long_explanation_paragraph():
    long_explanation = (
        "This change removes the % string-formatting that let a value containing SQL "
        "metacharacters alter the query. Instead, the value is passed as a bound "
        "parameter through the DB-API's params argument, so the driver treats it as "
        "pure data no matter what characters it contains."
    )
    result = _parse_response(_build(explanation=long_explanation))
    assert result.diff == _DIFF
    assert result.explanation == long_explanation


def test_wrapped_two_code_blocks_only_one_is_the_patch():
    text = (
        f"{DIFF_MARKER}\n"
        "For context, here's the original vulnerable line:\n"
        "```python\n"
        "query = 'SELECT * FROM users WHERE id = %s' % uid\n"
        "```\n\n"
        "And here's the patch:\n"
        f"```diff\n{_DIFF}\n```\n"
        f"{EXPLANATION_MARKER}\n{_EXPLANATION}\n{NOTES_MARKER}\n{_NOTES}\n"
    )
    result = _parse_response(text)
    assert result.diff == _DIFF


def test_wrapped_two_code_blocks_context_has_dash_line():
    """The non-diff context block contains a line starting with '-' (a bullet
    point) — must not be mistaken for the diff just because it starts with a
    dash; only a block with real ---/+++/diff --git headers qualifies.
    """
    text = (
        f"{DIFF_MARKER}\n"
        "For context, here's what changed conceptually:\n"
        "```text\n"
        "- uses % string formatting (vulnerable)\n"
        "- switches to a bound parameter\n"
        "```\n\n"
        "And here's the actual patch:\n"
        f"```diff\n{_DIFF}\n```\n"
        f"{EXPLANATION_MARKER}\n{_EXPLANATION}\n{NOTES_MARKER}\n{_NOTES}\n"
    )
    result = _parse_response(text)
    assert result.diff == _DIFF


# ---------------------------------------------------------------------------
# Hardened fenced-block selection: ambiguous cases must raise, never guess
# ---------------------------------------------------------------------------

def test_multiple_diff_looking_fenced_blocks_raises():
    text = (
        f"{DIFF_MARKER}\n"
        f"```diff\n{_DIFF}\n```\n"
        "Here's an alternative patch we considered:\n"
        f"```diff\n{_DIFF}\n```\n"
        f"{EXPLANATION_MARKER}\n{_EXPLANATION}\n{NOTES_MARKER}\n{_NOTES}\n"
    )
    with pytest.raises(ModelError, match="fenced code block"):
        _parse_response(text)


def test_fenced_block_present_but_none_look_like_a_diff_raises():
    text = (
        f"{DIFF_MARKER}\n"
        "```python\n"
        "query = 'SELECT * FROM users WHERE id = %s' % uid\n"
        "```\n"
        f"{EXPLANATION_MARKER}\n{_EXPLANATION}\n{NOTES_MARKER}\n{_NOTES}\n"
    )
    with pytest.raises(ModelError, match="fenced code block"):
        _parse_response(text)


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------

def test_missing_diff_marker_raises():
    with pytest.raises(ModelError, match="DIFF"):
        _parse_response(f"{EXPLANATION_MARKER}\nsome explanation\n{NOTES_MARKER}\nnone")


def test_missing_explanation_marker_raises():
    with pytest.raises(ModelError):
        _parse_response(f"{DIFF_MARKER}\nsome diff")


def test_completely_empty_raises():
    with pytest.raises(ModelError):
        _parse_response("")


def test_only_prose_raises():
    with pytest.raises(ModelError):
        _parse_response("The fix is to use parameterized queries.")


# ---------------------------------------------------------------------------
# Groq provider: HTTP request/response shape and error handling, fully
# mocked (no network, no GROQ_API_KEY). Confirms the OpenAI-compatible
# response text is routed through the exact same _parse_response/
# _extract_diff path as every other provider.
# ---------------------------------------------------------------------------

_CONTEXT = PatchContext(
    finding_summary="tainted string used to build a SQL query",
    vulnerable_snippet="query = 'SELECT * FROM users WHERE id = %s' % uid",
    file_path="app.py",
    harness_source="",
    offending_sql="SELECT * FROM users WHERE id = 'SECFIX_TAINT_deadbeef'",
    oracle_detail="tainted sentinel was found interpolated directly into an executed SQL string",
)


@contextmanager
def _fake_response(payload: dict):
    class _Resp:
        def read(self):
            return json.dumps(payload).encode()

    yield _Resp()


def test_groq_generate_patch_parses_wrapped_diff():
    # Groq/OpenAI-compatible models wrap diffs in fences + prose exactly like
    # Anthropic models do; this proves that messy shape survives unchanged.
    content = (
        "Sure, here's the fix:\n\n"
        f"{DIFF_MARKER}\n```diff\n{_DIFF}\n```\n{EXPLANATION_MARKER}\n{_EXPLANATION}\n"
        f"{NOTES_MARKER}\n{_NOTES}\n"
    )
    fake_payload = {"choices": [{"message": {"content": content}}]}

    with patch("secfix.models.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value = _fake_response(fake_payload)
        result = _groq_generate_patch(_CONTEXT, api_key="test-groq-key")

    assert result.diff == _DIFF
    assert result.explanation == _EXPLANATION

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
