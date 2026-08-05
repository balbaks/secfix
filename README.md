# secfix

**AUTHORIZED USE ONLY.** secfix executes flagged code from the target
codebase in order to reproduce findings. Only run it against code you own or
are explicitly authorized to test (e.g. under a signed pentest engagement or
your own repository). Do not point it at third-party code without
permission.

## What it does

secfix takes a Semgrep SQL-injection finding and tells you whether it's
real — not by re-reading the source (that's what Semgrep already did), but
by actually running the flagged function and watching what reaches the
database.

1. **Reproduce.** It locates the function the finding points at, generates a
   pytest harness that calls it with a unique tainted sentinel
   (`SECFIX_TAINT_<8hex>`) and a recording mock DB connection/cursor (no real
   database, no network, no seed data), and runs that harness in a sandbox.
2. **Judge.** An oracle inspects the resulting trace: if the sentinel shows
   up interpolated inside an executed SQL string, the finding is
   `confirmed`. If it only ever appears in bound `params`, it's
   `not_reproduced` (parameterized, not exploitable via this path).
   Otherwise it's `uncertain`.
3. **Patch.** For confirmed findings, a swappable model backend generates a
   fix. The diff is validated to touch only the target file, applied on a
   scratch branch, and re-verified with the same trace mechanism — the
   sentinel must have moved out of the SQL string and into params.
4. **Report.** A CVE-style writeup and PR body are written to disk. No PR is
   opened unless you pass `--open-pr`; by default secfix prints the exact
   `git push` / `gh pr create` commands instead.

## Scope (v0.1.0)

- Python only, SQL injection only.
- Unit-level reproduction only — no web server, no HTTP, no real DB.
- Only importable, module-level functions are supported. Methods, nested
  functions, and module-level code are reported as `unsupported` and left
  for manual review rather than force-fitting a harness onto them.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

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
- `--sandbox` — `docker` (mandatory for any code you didn't author yourself)
  or `local` (in-process, **zero isolation** — only for secfix's own test
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

## Development

```bash
.venv/bin/pip install -e .
.venv/bin/python -m pytest tests/
```

`tests/fixtures/vulnerable_example.py` and `tests/fixtures/safe_example.py`
are secfix's own dependency-free fixtures for the local sandbox's fast inner
loop — the only code that sandbox is meant to ever touch.
