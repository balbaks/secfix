"""Per-vulnerability-class text: remediation guidance for the patch prompt
and wording for reports. Kept in its own module (rather than folded into
cli.py's _RULE_CONFIG) because report.py and models.py must not depend on
cli.py — both need this text, cli.py just does the per-rule lookup and
passes the resolved strings/VulnClass down.

Each field is a complete, class-appropriate unit of text (a full sentence
or a grammatically-safe noun phrase with its article already decided),
never a generic template fragment — the point of this module is to let
each vuln class say the right, specific thing, not to paper over the
differences with shared boilerplate.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnClass:
    title: str  # Title Case, for report headers — "SQL Injection"
    finding_kind_phrase: str  # article + noun phrase — "a SQL-injection finding"
    name: str  # prose name for "a confirmed {name} vulnerability" — "SQL-injection"
    sink_description: str  # article + noun phrase — "an executed SQL string"
    sink_noun: str  # bare noun — "query" — for "Observed injectable {sink_noun}:"
    remediation_guidance: str  # full sentence(s) embedded in the patch prompt
    impact_text: str  # full paragraph for the report's ## Impact section
    mock_step_text: str  # full sentence, report reproduction step 2
    mock_observation_text: str  # full sentence (ending in ":"), report step 3
    code_fence_lang: str  # fenced-code-block language tag — "sql"


SQLI = VulnClass(
    title="SQL Injection",
    finding_kind_phrase="a SQL-injection finding",
    name="SQL-injection",
    sink_description="an executed SQL string",
    sink_noun="query",
    remediation_guidance=(
        "Fix the vulnerability by converting the query to use parameterized/bound "
        "placeholders (e.g. `?` or `%s` passed via the DB API's `params` argument) "
        "instead of string interpolation."
    ),
    impact_text=(
        "An attacker who controls the tainted parameter can inject arbitrary SQL, "
        "potentially reading, modifying, or deleting data beyond the query's intended "
        "scope, or bypassing application logic enforced only at the query level."
    ),
    mock_step_text=(
        "The function's DB access path was replaced with a recording mock — no real "
        "database, network, or seed data was used."
    ),
    mock_observation_text=(
        "The mock observed the following query executed with the sentinel interpolated "
        "directly into the SQL text (not passed as a bound parameter):"
    ),
    code_fence_lang="sql",
)

CMDI = VulnClass(
    title="OS Command Injection",
    finding_kind_phrase="an OS-command-injection finding",
    name="OS-command-injection",
    sink_description="a shell-interpreted command string",
    sink_noun="command",
    remediation_guidance=(
        "Fix the vulnerability by avoiding the shell entirely: build the command as an "
        'argv list (e.g. `["ping", "-c", "1", host]`) and pass it to subprocess with '
        "shell=False (the default) — never use os.system, never subprocess with "
        "shell=True, and never string-interpolate untrusted input into a shell command "
        "string. Escaping or quoting the input is not a fix and must not be used instead "
        "of shell=False. The function you return must be complete and runnable exactly as "
        "written, with no missing names: it is spliced back in as a drop-in replacement "
        "for only this function, so nothing outside it (including its module's top-level "
        "imports) can be changed. If your fix needs a name — a module, a class, anything — "
        "that isn't already available inside the original function, import or define it as "
        "part of the function body itself; never reference a name without also making it "
        "resolvable from within the function. Conversely, don't add an import or "
        "assignment the rewritten function body no longer uses."
    ),
    impact_text=(
        "An attacker who controls the tainted parameter can inject arbitrary shell "
        "commands, potentially executing arbitrary code, reading or exfiltrating files, "
        "or pivoting further into the host, with the same privileges as the vulnerable "
        "process."
    ),
    mock_step_text=(
        "The function's os.system/subprocess sinks were replaced with a recording mock "
        "— no real process was spawned and no real command was executed."
    ),
    mock_observation_text=(
        "The mock observed the following command executed with the sentinel "
        "interpolated directly into a shell-parsed string (not passed as a separate "
        "argv element):"
    ),
    code_fence_lang="sh",
)
