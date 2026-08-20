"""Parse Semgrep JSON output into normalized Finding objects."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

# Substrings matched against a Semgrep rule id to decide "this is SQLi".
# Kept intentionally simple/explicit for v0.1.0 rather than a fuzzy matcher.
# Registry rules don't all spell it "sql-injection" — e.g. Django's raw-query
# audit rule (python.django.security.audit.raw-query.avoid-raw-sql) flags
# raw SQL without ever using the word "injection", so "raw-sql"/"raw-query"
# are included alongside the more literal markers.
SQLI_RULE_MARKERS = (
    "sql-injection",
    "sqli",
    "sql_injection",
    "tainted-sql",
    "raw-sql",
    "raw-query",
)

# Same approach for OS command injection. Registry rules here include
# subprocess-injection.subprocess-injection and the python.lang.security.audit
# dangerous-subprocess-use family, neither of which say "command-injection".
CMDI_RULE_MARKERS = (
    "command-injection",
    "cmdi",
    "command_injection",
    "os-command-injection",
    "shell-injection",
    "dangerous-system-call",
    "subprocess-shell-true",
    "subprocess-injection",
    "dangerous-subprocess-use",
)

# Same approach for path traversal. "traversal" alone (no "path-" prefix)
# catches registry rules like the Express resolve/join traversal audit
# (...express-path-join-resolve-traversal) that the more specific markers
# below would miss.
PATHTRAVERSAL_RULE_MARKERS = (
    "path-traversal",
    "pathtraversal",
    "path_traversal",
    "directory-traversal",
    "path-injection",
    "tainted-path",
    "traversal",
)


@dataclass
class Finding:
    rule_id: str
    message: str
    file_path: Path
    start_line: int
    end_line: int
    code_span: str

    @property
    def is_sqli(self) -> bool:
        rule = self.rule_id.lower()
        return any(marker in rule for marker in SQLI_RULE_MARKERS)

    @property
    def is_cmdi(self) -> bool:
        rule = self.rule_id.lower()
        return any(marker in rule for marker in CMDI_RULE_MARKERS)

    @property
    def is_pathtraversal(self) -> bool:
        rule = self.rule_id.lower()
        return any(marker in rule for marker in PATHTRAVERSAL_RULE_MARKERS)


def _extract_span(repo_root: Path, file_path: str, start_line: int, end_line: int) -> str:
    full_path = repo_root / file_path
    lines = full_path.read_text().splitlines()
    # Semgrep line numbers are 1-indexed and inclusive.
    return "\n".join(lines[start_line - 1 : end_line])


def load_findings(finding_json_path: Path, repo_root: Path) -> list[Finding]:
    """Parse a Semgrep JSON results file into a list of Finding.

    v0.1.0 processes one finding at a time downstream, but parsing returns
    the full normalized list so the caller can select/filter.
    """
    data = json.loads(Path(finding_json_path).read_text())
    results = data.get("results", [])

    findings: list[Finding] = []
    for result in results:
        file_path = result["path"]
        start_line = result["start"]["line"]
        end_line = result["end"]["line"]
        rule_id = result.get("check_id", "")
        message = result.get("extra", {}).get("message", "")

        code_span = _extract_span(repo_root, file_path, start_line, end_line)

        findings.append(
            Finding(
                rule_id=rule_id,
                message=message,
                file_path=Path(file_path),
                start_line=start_line,
                end_line=end_line,
                code_span=code_span,
            )
        )

    return findings


def load_sqli_findings(finding_json_path: Path, repo_root: Path) -> list[Finding]:
    return [f for f in load_findings(finding_json_path, repo_root) if f.is_sqli]


def load_cmdi_findings(finding_json_path: Path, repo_root: Path) -> list[Finding]:
    return [f for f in load_findings(finding_json_path, repo_root) if f.is_cmdi]


def load_pathtraversal_findings(finding_json_path: Path, repo_root: Path) -> list[Finding]:
    return [f for f in load_findings(finding_json_path, repo_root) if f.is_pathtraversal]
