# V1 Django-bootstrap spike notes

Proof-of-concept only (branch `v1-django-bootstrap-spike`), not shipped
framework support. Goal: get one Django finding from pygoat past the
app-context wall documented in the README to a real oracle verdict.

## What worked

Detecting a top-level `manage.py`, extracting its `DJANGO_SETTINGS_MODULE`
string, and having the generated harness set that env var and call
`django.setup()` before importing the flagged module (`secfix/repo.py`,
`secfix/harness/python_cmdi.py`) was enough to get past the
`ImproperlyConfigured` wall entirely. Against pygoat's
`introduction/mitre.py:command_out`, this reached a `confirmed` oracle
verdict — the first Django finding to do so.

## Known unsolved sub-problem: import-time filesystem side effects

Getting there also required a target-specific workaround that was **not**
kept in the general sandbox template: pygoat's `settings.py` runs
`django_heroku.settings(locals())` at import time, which calls
`os.makedirs(STATIC_ROOT, exist_ok=True)` as a side effect of just
importing settings — before any test code runs. That conflicts with the
Docker sandbox's read-only EXECUTE rootfs (`secfix/sandbox/docker.py`):
`os.makedirs` on a missing directory fails with `OSError: [Errno 30]
Read-only file system`, not `ImproperlyConfigured`.

The spike worked around this by hardcoding `RUN mkdir -p
/workspace/staticfiles` into the Dockerfile template, pre-creating the
directory during the writable SETUP phase so `exist_ok=True` no-ops at
EXECUTE time. That's pygoat's `STATIC_ROOT` value specifically, not a
general fix, so it was deliberately left out of the committed code.

This is a real, separate problem from framework-bootstrap detection, and
still needs solving for real Django support: any settings module (or any
import chain reachable from the flagged function) can perform filesystem
writes as a side effect of import, and the read-only EXECUTE rootfs will
break on all of them. Candidate directions, not yet evaluated:

- Detect known Django write-path settings (`STATIC_ROOT`, `MEDIA_ROOT`,
  logging file handlers, etc.) from the settings module after
  `django.setup()` and pre-create them during SETUP, generically rather
  than hardcoded per target.
- Give EXECUTE a writable tmpfs mount beyond just `/tmp` (loosens the
  read-only guarantee — needs a security tradeoff discussion, not just an
  engineering one, since it's the isolation boundary for code we didn't
  author).

## Also required, unrelated to Django bootstrap

pygoat's `requirements.txt` pins `psycopg2==2.9.3`, which compiles a C
extension and needs `build-essential`/`libpq-dev` — absent from the
`python:3.11-slim` sandbox base image, and slow enough to also need the
SETUP timeout raised from 300s to 600s. Both changes were kept (see
`secfix/sandbox/docker.py`) since they're general — any target with a
compiled dependency hits the same wall — but the apt-get install is
unconditional on every build, which is worth fixing (see TODO comment at
the call site) before this leaves spike status.
