"""Unit tests for Finding.is_sqli / is_cmdi / is_pathtraversal rule-marker
matching. Real Semgrep registry rule ids don't all spell things the obvious
way (no "injection" in a raw-SQL audit rule, no "command" in a
dangerous-subprocess-use rule), so these markers need to be broad
substring/pattern matches rather than a hardcoded list tied to one repo's
scan output.
"""
from pathlib import Path

from secfix.findings import Finding


def _finding(rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        message="",
        file_path=Path("app.py"),
        start_line=1,
        end_line=1,
        code_span="",
    )


# ---------------------------------------------------------------------------
# Real rule ids pulled from a Semgrep scan of pygoat (a deliberately
# vulnerable Django app) - these are the actual registry spellings that
# motivated broadening the markers, not synthetic examples.
# ---------------------------------------------------------------------------

def test_pygoat_sqli_rule_classifies_as_sqli():
    finding = _finding("python.django.security.audit.raw-query.avoid-raw-sql")
    assert finding.is_sqli
    assert not finding.is_cmdi
    assert not finding.is_pathtraversal


def test_pygoat_subprocess_injection_rule_classifies_as_cmdi():
    finding = _finding("subprocess-injection.subprocess-injection")
    assert finding.is_cmdi
    assert not finding.is_sqli
    assert not finding.is_pathtraversal


def test_pygoat_dangerous_subprocess_use_rule_classifies_as_cmdi():
    finding = _finding(
        "python.lang.security.audit.dangerous-subprocess-use.dangerous-subprocess-use"
    )
    assert finding.is_cmdi
    assert not finding.is_sqli
    assert not finding.is_pathtraversal


# ---------------------------------------------------------------------------
# Pre-existing spellings must keep matching - broadening the markers must
# not narrow them.
# ---------------------------------------------------------------------------

def test_classic_sql_injection_spelling_still_matches():
    assert _finding("python.lang.security.audit.sql-injection").is_sqli


def test_classic_command_injection_spelling_still_matches():
    assert _finding("javascript.lang.security.audit.command-injection").is_cmdi


def test_classic_path_traversal_spelling_still_matches():
    assert _finding("python.lang.security.audit.path-traversal-open").is_pathtraversal


def test_traversal_marker_catches_non_prefixed_registry_spelling():
    # e.g. javascript.express.security.audit.express-path-join-resolve-traversal
    finding = _finding("express-path-join-resolve-traversal")
    assert finding.is_pathtraversal
    assert not finding.is_sqli
    assert not finding.is_cmdi


def test_unrelated_rule_matches_nothing():
    finding = _finding("python.lang.security.audit.eval-detected")
    assert not finding.is_sqli
    assert not finding.is_cmdi
    assert not finding.is_pathtraversal
