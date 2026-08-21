# secfix

**AUTHORIZED USE ONLY.** secfix executes flagged code from the target
codebase in order to reproduce findings. Only run it against code you own or
are explicitly authorized to test — a signed pentest engagement, or your own
repository. Do not point it at third-party code without permission.

## What it is

secfix is a security triage tool that validates static-analysis findings by
actually running the flagged code and watching what happens, rather than
re-reading the source and guessing. Given a Semgrep finding, it reproduces
the vulnerability in a sandbox, and — if reproduction succeeds — generates a
patch and re-runs the same reproduction to prove the patch closes it. The
result is proof by execution, not a suggestion to review by eye.

It is meant for authorized security work only: your own codebase, or a
target you have explicit permission to test.

## How it works

The pipeline is a straight line from a Semgrep finding to a verified fix:

1. **Locate.** Parse the Semgrep finding and locate the flagged function in
   the target repo.
2. **Generate a harness.** Build a pytest harness that calls the function
   with a unique tainted sentinel (`SECFIX_TAINT_<8hex>`) and a recording
   fake for whatever sink the vulnerability class cares about (a mock DB
   cursor for SQLi, a subprocess/shell spy for command injection, a
   filesystem-open spy for path traversal).
3. **Run it in a sandbox.** The harness executes in a locked-down Docker
   container — no network, non-root, read-only rootfs, capabilities
   dropped, resource limits — and emits a structured execution trace.
4. **Judge with an oracle.** The oracle inspects the trace, not the source.
   If the sentinel shows up unsafely inside the sink (interpolated into
   executed SQL, passed to a shell, used to build a file path that escapes
   the intended directory), the finding is `confirmed`. If the sentinel only
   ever reaches the sink through a safe path (bound params, no shell, a
   validated path), it's `not_reproduced`. Anything else is `uncertain`.
5. **Patch.** For confirmed findings, a swappable model backend (Anthropic
   or a local Ollama model) writes a fix as a full replacement of the
   flagged function. The diff is computed by secfix itself via `difflib`
   against the real file — never accepted as raw text from the model — and
   validated to touch only the target file.
6. **Re-verify.** The patched code is run through the identical harness and
   oracle again, on a fresh trace. Only if that fresh trace comes back
   `not_reproduced` is the fix considered `validated`.
7. **Report.** A writeup and PR body are written to disk. No PR is opened
   unless you pass `--open-pr`.

The core principle governing all of this: secfix refuses to claim a finding
is fixed unless a fresh execution trace, produced after the patch was
applied, proves it. There is no step where the model's own account of what
it changed is trusted. If re-verification doesn't produce a clean trace, the
patch is reported as unvalidated, not silently upgraded.

## Supported

- Language: Python only.
- Vulnerability classes: SQL injection, OS command injection, path
  traversal.
- Reproduction granularity: unit-level, importable module-level functions
  only. No web server, no HTTP, no real database. Methods, nested
  functions, and non-function targets are reported as `unsupported` and
  left for manual review rather than force-fitting a harness onto them.

## Limitations, and what running it against a real target found

secfix's fixture tests all pass, and that's a real but narrow claim: it
proves the pipeline is internally correct against code shaped like its own
test fixtures — plain, dependency-free, importable functions. Running it
against a real vulnerable application surfaced the actual ceiling of that
approach.

**The framework wall.** secfix was pointed at pygoat, a real, deliberately
vulnerable Django application, using a real Semgrep scan of it. Reproduce
this yourself:

```bash
semgrep --config p/python --config p/security-audit --json -o pygoat.json /path/to/pygoat
```

(Semgrep ruleset counts drift as `p/python` and `p/security-audit` are
updated upstream — 84 is what that command produced at time of testing
against pygoat, not a number this tool guarantees you'll reproduce
exactly.)

That scan produced 84 findings. Of those 84, only 2 matched secfix's
supported vulnerability-class rule markers (see `secfix/findings.py`) —
everything else is a class secfix doesn't attempt (XSS, hardcoded secrets,
insecure deserialization, and so on). Of those 2, one was driven through
the full pipeline: `secfix run` against that finding generated a harness,
ran it in the sandbox, and the target module's import failed with
`django.core.exceptions.ImproperlyConfigured` (settings accessed before
Django's app registry is populated). The oracle recorded this as
`UNCERTAIN` — not `confirmed`, not `not_reproduced` — because execution
never reached the sink at all, in either direction, to have an opinion
about. The second of the two supported-class findings was not driven
through the pipeline end-to-end.

The root cause is structural, not a bug in that one harness: secfix's
harness works by importing the target module and calling the flagged
function directly, and it never calls `django.setup()`. Django (like
Flask, and most web frameworks) couples ordinary application code to
framework state at import time — settings, app registry, ORM
configuration, request context — none of which the harness bootstraps. The
function can't be called in isolation because, in a framework app, there
mostly isn't such a thing as calling it in isolation. Net result: 0 of 84
raw findings, and 0 of the 2 in secfix's own supported scope, reached a
conclusive verdict on this target.

This is the real gap between "proven against fixtures" and "useful against
production code," and it's the main thing worth knowing about this tool
before pointing it at anything real: it currently works on scripts and
libraries, not on web application code. Closing it means building
framework-aware harness generation — a Django/Flask app-context bootstrap
per framework — which does not exist yet.

**Scope.** Authorized targets only, by design and by license of use — see
the notice at the top of this file. Reproduction is unit-level: secfix
confirms that a function taints a sink when called directly with malicious
input, not that the vulnerability is reachable from an HTTP endpoint or any
particular deployment. A `confirmed` verdict is about the function, not
about exploitability of the running service.

**Path-traversal rule markers are uncalibrated.** The SQLi and command
injection rule-id markers (the substrings used to recognize a Semgrep rule
as belonging to a given vulnerability class) were broadened against real
rule ids observed in the pygoat scan — `raw-query`, `subprocess-injection`,
`dangerous-subprocess-use`, and similar. The pygoat scan produced zero
path-traversal findings, so there was no real rule id to calibrate the
path-traversal markers against. They remain the original, conservative set
of known Python spellings, and should be treated as unverified against a
real-world scan until one turns up a path-traversal finding to check them
against.

## Safety

- **Sandbox isolation.** The default and only sandbox meant for code you
  didn't write yourself is Docker: no network at execute time, non-root
  user, read-only rootfs with a tmpfs `/tmp`, all capabilities dropped,
  pid/memory/cpu limits. A `local` in-process sandbox exists but is
  explicitly zero-isolation, gated behind
  `--i-understand-local-is-unsafe`, and intended only for secfix's own
  test fixtures.
- **Refuse, don't lie.** The oracle and the re-verification step are built
  to fail closed: a finding is `confirmed` only on direct trace evidence,
  and a patch is `validated` only if a fresh post-patch trace proves it.
  Anything short of that is reported as `uncertain` or unvalidated, never
  rounded up.
- **Dry run by default.** secfix never pushes a branch or opens a PR unless
  you explicitly pass `--open-pr`. The default behavior is to write a
  report and a scratch branch to disk and print the exact `git push` /
  `gh pr create` commands, leaving the decision to publish with you.

## Status

v0.1.0, proof of concept. Not production software: it has a real,
demonstrated gap on framework-coupled web application code (see
Limitations above), one uncalibrated rule-marker set, and has only been
exercised against its own fixtures and one real target.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

Docker is required to use `--sandbox docker` (the sandbox for any code you
didn't author yourself) — install it separately and make sure the daemon is
running before invoking `secfix run`.

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
- `--sandbox` — `docker` (mandatory for any code you didn't author yourself)
  or `local` (in-process, zero isolation — only for secfix's own test
  fixtures; requires `--i-understand-local-is-unsafe`).
- `--model` — `anthropic` (default, needs `ANTHROPIC_API_KEY`) or `ollama`
  (local, needs a running Ollama server).
- `--open-pr` — push the scratch branch and open a PR for any patch that
  re-verified as `validated`. Omit this and secfix does a dry run: branch +
  report on disk, PR left to you.

Docker sandbox requirements: a locked-down container per run — setup phase
(`docker build`) has network access to install target deps; execute phase
(`docker run`) has `--network none`, a non-root user, read-only rootfs with a
tmpfs `/tmp`, all capabilities dropped, and pid/memory/cpu limits.

`examples/demo_sqli_finding.json` is a Semgrep-shaped finding against
secfix's own `tests/fixtures/vulnerable_example.py`, for a self-contained
run with no external target repo needed:

```bash
.venv/bin/pip install -e .
# supply your own Anthropic API key
export ANTHROPIC_API_KEY=...
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

`tests/fixtures/vulnerable_example.py` and `tests/fixtures/safe_example.py`
(and their `_cmdi`/`_pathtraversal` counterparts) are secfix's own
dependency-free fixtures for the local sandbox's fast inner loop — the only
code that sandbox is meant to ever touch.
