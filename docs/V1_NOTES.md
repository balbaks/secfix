# V1 Django-bootstrap spike notes

Proof-of-concept only (branch `v1-django-bootstrap-spike`), not shipped
framework support. Goal: get one Django finding from pygoat past the
app-context wall documented in the README to a real oracle verdict, then
test whether that generalizes to a second, unrelated Django app.

## App 1: pygoat (Django 4.2) — reached a verdict, after three walls

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

## App 2: django.nV (Django 1.8) — two walls fell cheaply, one didn't

Second, unrelated deliberately-vulnerable Django app, picked to test
whether pygoat's fixes generalized or were a one-off. Its only
supported-class finding (of 30 total) is a `connection.cursor()` SQLi in a
view function, `taskManager/views.py:upload(request, project_id)`.

**Wall B — Python/Django version mismatch. Fixed generically, no drama.**
django.nV pins `Django==1.8.3`, which can't import on Python 3.10+
(`collections.abc` alias removal) or 3.12 (`six` meta-path loader shim
removal) — no harness fix touches this, it's the framework itself failing
to import. Added `secfix/sandbox/pyversion.py`: parses a `Django==X.Y` pin
from `requirements.txt`, maps it to a base image via an empirical band
table, and `DockerSandbox` now picks its base image per target instead of
a single hardcoded `python:3.11-slim`. Verified: pygoat still resolves to
`python:3.11-slim` (no regression), django.nV resolves to `python:3.6-slim`
and **builds successfully on the first try** — this wall terminated, it
didn't spiral into further fixes.

**Wall A — DB-access detection too narrow. Fixed generically.**
`_guess_db_access` only recognized bare-name getter calls
(`get_connection()`); Django's idiomatic `from django.db import
connection; connection.cursor()` is an attribute call on an imported
object, not a getter, and didn't match — harness generation skipped before
Docker or Django ever entered the picture. Added a `module_attr`
`db_access_kind` for this pattern (`secfix/repo.py`,
`secfix/harness/python_sqli.py`). Also discovered while fixing this: the
pygoat spike had only wired the Django bootstrap into
`python_cmdi.py`, because that's the rule pygoat's finding happened to use.
django.nV's finding is `sqli` — without also fixing this, it would have
skipped bootstrap silently. Factored the bootstrap into
`secfix/harness/django_bootstrap.py`, shared by both harnesses.

**Wall C — request-shaped taint. Hit it, did not fix it. This is the
boundary.**
With B and A both fixed, the full pipeline ran, `django.setup()` succeeded,
and `taskManager.views` imported cleanly (confirmed via Django's own
deprecation warnings firing during app-registry population — proof
`django.setup()` actually executed, not just that it didn't error). The
harness then called `upload(request=SENTINEL, project_id='test_value')` and
crashed one line into real application code:

```
File "/workspace/taskManager/views.py", line 172, in upload
    if request.method == 'POST':
AttributeError: 'str' object has no attribute 'method'
```

The real SQLi is at line 178, reached only through `request.POST.get('name')`
— but secfix's tainted-parameter guesser has no model of "this argument is
an HTTP request object with a `.POST`/`.GET`/`.FILES` inside it"; it falls
back to guessing the first unannotated scalar parameter and hands it a raw
string sentinel. `request.method` on a string blows up before the function
body reaches anywhere near the injection.

This is not "one more pattern" the way Wall A was. It needs the harness
generator to construct a realistic mock `HttpRequest` (`.method`, `.POST`,
`.GET`, `.FILES`, at minimum) and thread the taint sentinel through
`request.POST`/`request.GET` rather than through the function argument
directly. That's framework-aware harness *generation*, not a detection
heuristic — a materially bigger piece of work than anything built in this
spike, and it's exactly the shape of work the spike's scope
(`Don't ship full Django support`) was drawn to exclude. It also isn't a
corner case: request-shaped view functions are the majority of what a real
Django app's Semgrep findings look like, not module-level functions with
scalar params (pygoat's `command_out(command)` was the easy, non-view
case).

## Conclusion

Contained walls generalize cheaply: per-target Python-version images (Wall
B) and one more AST pattern for DB access (Wall A) each fell on the first
attempt, against an app neither was written for. The request-modeling wall
(Wall C) does not — and it's the one guarding the majority of real Django
findings, not an edge case. V1 is deliberately parked here: the boundary
of solo, incremental scope is "detect the framework and get past its
app-context wall," and it does not yet extend to "understand the
framework's request/response model well enough to reproduce a view-level
vulnerability." That's the next spike, not a fix.
