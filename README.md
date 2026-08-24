# secfix

**Most tools flag a vulnerability and suggest a fix. secfix proves it.**

secfix validates a security finding by *running the flagged code* and watching
the exploit happen — then it patches the code, re-runs, and confirms the exploit
is gone. It refuses to claim a finding is "fixed" unless a fresh execution trace,
captured after the patch, proves it. No trusting the model's word. No trusting a
static re-read of the source. Proof by execution, or it says so.

Then I pointed it at real Django apps and hit a wall — and instead of hiding that,
I mapped exactly where autonomous vulnerability reproduction breaks down. That
investigation is documented in
[`docs/V1_NOTES.md`](../../tree/v1-django-bootstrap-spike/docs/V1_NOTES.md) on the
[`v1-django-bootstrap-spike`](../../tree/v1-django-bootstrap-spike) branch, and
it's the most interesting part of this repo.

> **AUTHORIZED USE ONLY.** secfix executes flagged code from the target codebase
> in order to reproduce findings. Only run it against code you own or are
> explicitly authorized to test — a signed pentest engagement, or your own
> repository. Do not point it at third-party code without permission.

---

## What it does

Given a Semgrep finding, secfix reproduces the vulnerability in a sandbox, and —
if reproduction succeeds — generates a patch and re-runs the *same* reproduction
to prove the patch closes it. The result is proof by execution, not a suggestion
to review by eye.

It currently handles **SQL injection, OS command injection, and path traversal**
in **Python**, for importable module-level functions.

## How it works

A straight line from a Semgrep finding to a verified fix:

1. **Locate.** Parse the Semgrep finding and locate the flagged function in the
   target repo.
2. **Generate a harness.** Build a pytest harness that calls the function with a
   unique tainted sentinel (`SECFIX_TAINT_<8hex>`) and a recording fake for
   whatever sink the vulnerability class cares about (a mock DB cursor for SQLi, a
   subprocess/shell spy for command injection, a filesystem-open spy for path
   traversal).
3. **Run it in a sandbox.** The harness executes in a locked-down Docker
   container — no network, non-root, read-only rootfs, capabilities dropped,
   resource limits — and emits a structured execution trace.
4. **Judge with an oracle.** The oracle inspects the trace, not the source. If the
   sentinel shows up unsafely inside the sink (interpolated into executed SQL,
   passed to a shell, used to build a path that escapes the intended directory),
   the finding is `confirmed`. If the sentinel only ever reaches the sink through
   a safe path (bound params, no shell, a validated path), it's `not_reproduced`.
   Anything else is `uncertain`.
5. **Patch.** For confirmed findings, a swappable model backend (Anthropic or a
   local Ollama model) writes a fix as a full replacement of the flagged function.
   The diff is computed by secfix itself via `difflib` against the real file —
   never accepted as raw text from the model — and validated to touch only the
   target file.
6. **Re-verify.** The patched code runs through the identical harness and oracle
   again, on a fresh trace. Only if that fresh trace comes back `not_reproduced`
   is the fix considered `validated`.
7. **Report.** A writeup and PR body are written to disk. No PR is opened unless
   you pass `--open-pr`.

**The core principle:** secfix refuses to claim a finding is fixed unless a fresh
execution trace, produced after the patch was applied, proves it. There is no step
where the model's own account of what it changed is trusted. If re-verification
doesn't produce a clean trace, the patch is reported as unvalidated — never
silently upgraded.

## Supported

- **Language:** Python only.
- **Vulnerability classes:** SQL injection, OS command injection, path traversal.
- **Granularity:** unit-level, importable module-level functions only. No web
  server, no HTTP, no real database. Methods, nested functions, and non-function
  targets are reported as `unsupported` and left for manual review rather than
  force-fitting a harness onto them.

## Limitations, and what running it against a real target found

secfix's fixture tests all pass — but that's a narrow claim: it proves the pipeline
is internally correct against code shaped like its own test fixtures (plain,
dependency-free, importable functions). Running it against a real vulnerable
application surfaced the actual ceiling of that approach, and I think the honest
map of that ceiling is more valuable than the passing tests.

**The framework wall.** secfix was pointed at pygoat, a real, deliberately
vulnerable Django application, using a real Semgrep scan of it. Reproduce it
yourself:

```bash
semgrep --config p/python --config p/security-audit --json -o pygoat.json /path/to/pygoat
```

(Semgrep ruleset counts drift as `p/python` and `p/security-audit` update
upstream — 84 is what that command produced at time of testing against pygoat, not
a number this tool guarantees.)

That scan produced 84 findings. Only 2 matched secfix's supported
vulnerability-class rule markers (see `secfix/findings.py`) — everything else is a
class secfix doesn't attempt (XSS, hardcoded secrets, insecure deserialization,
and so on). Of those 2, one was driven through the full pipeline: `secfix run`
generated a harness, ran it in the sandbox, and the target module's import failed
with `django.core.exceptions.ImproperlyConfigured` (settings accessed before
Django's app registry is populated). The oracle recorded this as `UNCERTAIN` — not
`confirmed`, not `not_reproduced` — because execution never reached the sink at
all, in either direction, to have an opinion about. The second supported-class
finding was not driven through end-to-end.

The root cause is structural: secfix's harness imports the target module and calls
the flagged function directly, and it never calls `django.setup()`. Django (like
Flask, and most web frameworks) couples ordinary application code to framework
state at import time — settings, app registry, ORM configuration, request context.
The function can't be called in isolation because, in a framework app, there mostly
isn't such a thing as calling it in isolation. Net result on this target: 0 of 84
raw findings, and 0 of the 2 in secfix's supported scope, reached a conclusive
verdict.

This is the real gap between "proven against fixtures" and "useful against
production code," and it's the main thing worth knowing before pointing this at
anything real: **it works on scripts and libraries, not on web application code —
yet.** The `v1-django-bootstrap-spike` branch is where I went after that wall; see
the next section.

**Scope.** Authorized targets only. Reproduction is unit-level: secfix confirms
that a function taints a sink when called directly with malicious input, not that
the vulnerability is reachable from an HTTP endpoint or any particular deployment.
A `confirmed` verdict is about the function, not about exploitability of the
running service.

**Path-traversal rule markers are uncalibrated.** The SQLi and command-injection
rule-id markers were broadened against real rule ids observed in the pygoat scan
(`raw-query`, `subprocess-injection`, `dangerous-subprocess-use`, and similar). The
pygoat scan produced zero path-traversal findings, so there was no real rule id to
calibrate the path-traversal markers against. They remain a conservative set of
known Python spellings, and should be treated as unverified against real-world
scans until one turns up a path-traversal finding to check them against.

## The V1 investigation: going after the framework wall

The most interesting work in this repo lives on the
[`v1-django-bootstrap-spike`](../../tree/v1-django-bootstrap-spike) branch,
documented in full in
[`docs/V1_NOTES.md`](../../tree/v1-django-bootstrap-spike/docs/V1_NOTES.md).

Short version: I tried to make secfix work on real Django code, and worked through
the walls one at a time — detecting the framework, matching the target's own Python
version in the sandbox, calling `django.setup()`, provisioning a migrated database,
and building a real request with `django.test.RequestFactory`. It got a **real
Django view SQL-injection finding all the way to a `confirmed` verdict** — the
sentinel landing unparameterized in executed SQL, proven by execution.

But the honest conclusion is the point: reaching that verdict required
hand-supplying knowledge that secfix cannot yet derive from the code — the specific
database row the view's ORM call needs, and a framework-internal file-size threshold
the view's form validation depends on. Some walls generalize cheaply (Python-version
matching, DB provisioning); the rest (inferring a view's full data dependencies)
are the boundary where solo scope ends and team-scale integration work begins.
`V1_NOTES.md` maps exactly which is which. That map — where autonomous vulnerability
reproduction stops being automatic — is the real result.

## Safety

- **Sandbox isolation.** The default sandbox for code you didn't write is Docker:
  no network at execute time, non-root user, read-only rootfs with a tmpfs `/tmp`,
  all capabilities dropped, pid/memory/cpu limits. A `local` in-process sandbox
  exists but is explicitly zero-isolation, gated behind
  `--i-understand-local-is-unsafe`, and intended only for secfix's own fixtures.
- **Refuse, don't lie.** The oracle and re-verification step fail closed: a finding
  is `confirmed` only on direct trace evidence, and a patch is `validated` only if a
  fresh post-patch trace proves it. Anything short of that is reported as
  `uncertain` or unvalidated, never rounded up.
- **Dry run by default.** secfix never pushes a branch or opens a PR unless you pass
  `--open-pr`. By default it writes a report and a scratch branch to disk and prints
  the exact `git push` / `gh pr create` commands, leaving the decision to publish
  with you.

## Status

v0.1.0, proof of concept. Not production software: it has a real, demonstrated gap
on framework-coupled web application code (see Limitations and the V1
investigation), one uncalibrated rule-marker set, and has been exercised against its
own fixtures plus two real Django targets.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

Docker is required for `--sandbox docker` (the sandbox for any code you didn't
author yourself) — install it separately and make sure the daemon is running before
invoking `secfix run`.

## Usage

```bash
secfix run \
  --finding finding.json \
  --repo ./target \
  --rule sqli \
  --sandbox docker \
  --model anthropic \
  [--open-pr]
```

- `--finding` — Semgrep JSON results file.
- `--repo` — path to the local, authorized target repo.
- `--rule` — `sqli`, `cmdi`, or `pathtraversal`.
- `--sandbox` — `docker` (mandatory for any code you didn't author yourself) or
  `local` (in-process, zero isolation — only for secfix's own fixtures; requires
  `--i-understand-local-is-unsafe`).
- `--model` — `anthropic` (default, needs `ANTHROPIC_API_KEY`) or `ollama` (local,
  needs a running Ollama server).
- `--open-pr` — push the scratch branch and open a PR for any patch that re-verified
  as `validated`. Omit for a dry run: branch + report on disk, PR left to you.

### Self-contained demo (no external target needed)

`examples/demo_sqli_finding.json` is a Semgrep-shaped finding against secfix's own
`tests/fixtures/vulnerable_example.py`:

```bash
.venv/bin/pip install -e .
export ANTHROPIC_API_KEY=...   # supply your own key
secfix run \
  --finding examples/demo_sqli_finding.json \
  --repo . \
  --rule sqli \
  --sandbox docker \
  --model anthropic
```

## Development

```bash
.venv/bin/pip install -e .
.venv/bin/python -m pytest tests/
```

`tests/fixtures/vulnerable_example.py` / `safe_example.py` (and their `_cmdi` /
`_pathtraversal` counterparts) are secfix's own dependency-free fixtures for the
local sandbox's fast inner loop — the only code that sandbox is meant to touch.
