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

## App 2: django.nV (Django 1.8) — A and B fell cheaply; C and D took the rest of the spike

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

**Wall C — request-shaped taint. Hit it, then fixed it narrowly
(uncommitted).**
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

**Update: fixed, and narrower than the paragraph above predicted.**
`secfix/repo.py` adds `_detect_request_taint`: it matches a parameter
literally named `request` (the Django convention) and a direct
`request.POST/GET/FILES.get('key')` call or `['key']` subscript within the
finding's own span, and records `{request_param, dict_name, key}` on
`HarnessTarget.request_taint`. `secfix/harness/python_sqli.py` uses that to
build a real request via `django.test.RequestFactory` — `.post()` or
`.get()` depending on which dict — with `SENTINEL` planted at exactly that
key, instead of handing the view a bare string. This is a real
`HttpRequest`, not a hand-rolled mock built to look like one: `.method`,
`.POST`, `.GET`, `.FILES` all behave correctly, because `RequestFactory` is
Django's own test tool for this. Verified against django.nV's `upload`: the
harness gets past `request.method` and reaches the next wall (Wall D,
below) instead of `AttributeError: 'str' object has no attribute 'method'`.

Both caveats implicit in "narrow" held in practice: it only recognizes a
param literally named `request` and only a direct `.get()`/subscript
access within the span — a variable populated from `request.POST`
elsewhere in the function, or a custom request-like wrapper, is not
detected and falls back to the old scalar-sentinel guess. And it only
plants the *one* key the finding's tainted read uses — it has no model of
a view's *other* request data needs (a second form field, a session,
`request.user`). Those show up as Wall D's requirements, not this one's.

## App 2, continued: Wall D — the app-context/DB wall. Reached `confirmed`.

With Wall C fixed, the same `upload` finding
(`taskManager/views.py:178-185`) still wasn't at a verdict — everything
past `request.method` touches the ORM, `django.setup()` never runs
migrations, and Docker EXECUTE's rootfs is read-only outside `/tmp`
(`secfix/sandbox/docker.py`). Before any DB provisioning, a bare
`django.setup()` gets exactly this:

```
File ".../django/db/backends/sqlite3/base.py", line 204, in get_new_connection
    conn = Database.connect(**conn_params)
django.db.utils.OperationalError: unable to open database file
```

django.nV's `settings.py` hardcodes `NAME = os.path.join(BASE_DIR,
'db.sqlite3')` — not `:memory:`, and not read from `DATABASE_URL`, so the
bootstrap's env-var fallback (`secfix/harness/django_bootstrap.py`) never
applies here. There is no database file at all until something creates one.

**Generic fix, kept: bake `manage.py migrate --noinput` into SETUP.**
`secfix/sandbox/docker.py` now detects a Django target (reusing
`secfix/repo.py`'s `_detect_django_settings_module` — the same manage.py
check the bootstrap already used) and, when detected, adds `RUN python
manage.py migrate --noinput` to the Dockerfile, gated so a non-Django
target never pays for a step that would just fail with "no such file:
manage.py". Because SETUP (`docker build`) is still writable, this bakes a
real, migrated `db.sqlite3` into the image; EXECUTE, though read-only, can
still read it, and a plain read is all the ORM calls above need. This
generalizes to any Django target with a real (non-`:memory:`) sqlite path,
not just django.nV — the same shape of fix as Wall A and Wall B.

Past that, pushing `upload` to a verdict surfaced a sequence of
view-specific requirements, each hit and resolved (or not) in turn:

1. **A real row at the finding's exact pk.** `Project.objects.get(pk=project_id)`
   is the first ORM call in the view. secfix's existing benign-default guess
   for an untainted param is a string (`project_id='test_value'`), which
   matches no integer pk — `Project.DoesNotExist`. Required overriding
   `project_id` to a real int, and seeding a `Project` row at that pk.

2. **Seeding itself can't happen at EXECUTE time.** Creating the row inside
   the test body (after `django.setup()`, before calling the view) hits the
   same read-only rootfs as everything else in EXECUTE:

   ```
   django.db.utils.OperationalError: attempt to write a readonly database
   ```

   The row has to be baked into the image during SETUP, same as the schema.
   Added `django_seed_command: str | None` to `DockerSandbox.__init__` — a
   single shell command run right after migrate, before the image is
   frozen — but deliberately **not** wired into the CLI and given no
   Django-generic logic. It's an escape hatch a finding-specific driver can
   use, not a mechanism secfix has any model for on its own: nothing
   detects "this view needs a `Project` row with `text` and `start_date`
   set" from the AST. That has to be supplied by hand per target, same as
   pygoat's `STATIC_ROOT` hardcode in the Wall C sub-problem above.

3. **`request.FILES` needs an actual file, not just `request.POST`.**
   `ProjectFileForm` (`taskManager/forms.py`) requires both `name` and
   `file`. Wall C's fix only plants the sentinel at the *one*
   `request.POST`/`GET`/`FILES` key the finding's tainted read uses — with
   only `POST['name']` populated, `form.is_valid()` is `False` and
   `upload()` silently takes the "invalid form" branch straight to
   `render_to_response`. No exception, no crash: this is a different
   failure shape than A/B/C. There's nothing to catch — the harness just
   quietly never reaches the sink and would report `not
   confirmed`/`inconclusive` as if the code were safe, unless something is
   specifically checking reachability. This is a real gap in Wall C's fix,
   not a new wall of its own: a view's form can require fields the
   finding's own tainted read never touches.

4. **The file has to be big enough to become a *real* temp file.**
   `store_uploaded_file()` (`taskManager/misc.py`) calls
   `uploaded_file.temporary_file_path()`, which only exists on Django's
   `TemporaryUploadedFile`. Anything under `FILE_UPLOAD_MAX_MEMORY_SIZE`
   (2.5MB default) becomes an `InMemoryUploadedFile` via
   `MemoryFileUploadHandler` instead, which has no such method and would
   raise `AttributeError`. Required a >2.5MB dummy payload in
   `request.FILES['file']` — a framework-internal threshold with no trace
   in the view's own source; nothing short of actually running the request
   through Django's upload-handler chain surfaces this requirement.

5. **No auth/session wall — for this view.** Unlike `manage_tasks` and
   `manage_projects`, a few functions away in the same file (`if
   user.is_authenticated(): ... if user.has_perm(...)`), `upload()` never
   touches `request.user`. This wall exists in the same file secfix would
   have to handle for other findings — it just didn't apply to this one.

One more failure fired and was silently absorbed, not a blocker:
`store_uploaded_file`'s `os.system("mv ...")` fails on the read-only
rootfs (`mv: ... unable to remove target: Read-only file system`), but
`os.system` doesn't raise on a nonzero exit, so execution reaches the sink
anyway. A second, unrelated bug in django.nV itself
(`redirect('/taskManager/' + project_id + ...)`, concatenating a str
literal with an int `project_id`) throws `TypeError` right after the
sink — irrelevant, since the harness's `except Exception: pass` discards
anything past the point the trace was already recorded.

**Verdict: `confirmed`.**

```
insert into taskManager_file ('name','path','project_id') values
('SECFIX_TAINT_eb1a5228','/static/taskManager/uploads/SECFIX_TAINT_eb1a5228',1)
```

The sentinel lands unparameterized (`params: null`) directly in the
executed SQL string — this is the first real (non-pygoat), non-scalar-param
Django *view* finding secfix has taken end-to-end to an oracle verdict.

**On generalization — the actual answer to "does D generalize."** Of the
five requirements above, exactly one (#1, DB provisioning via `migrate`)
generalizes cleanly to any Django target, the same way Wall A and Wall B
did. Requirement #2 generalizes as a *mechanism* (`django_seed_command`
exists on any `DockerSandbox` now) but not as *content* — something still
has to know it's a `Project`, with a `pk`, `text`, and `start_date`, and
nothing in secfix derives that from the AST. Requirements #3 and #4 are new
information, not just "Wall C, but more": modeling one tainted key in
`request.POST` (Wall C's fix) is not the same problem as modeling
everything else a view's form validation needs, and #4 shows that even
"put a file in FILES" has a framework-internal size threshold with no
signature in the source. #5 is a reminder that whether auth is a wall is
per-view, not per-app — `upload()` dodged it; its neighbors in the same
file would not. None of #2–#5 are one more AST pattern the way Wall A
was: each is either hand-supplied per finding or genuinely undetectable
from the code alone.

## Conclusion

Contained walls generalize cheaply: per-target Python-version images (Wall
B), one more AST pattern for DB access (Wall A), and baking `manage.py
migrate` into the image (the DB-provisioning half of Wall D) each fell on
the first attempt, against an app neither was written for. Wall C's fix —
modeling one tainted key inside `request.POST`/`GET`/`FILES` via a real
`django.test.RequestFactory` request — also generalizes, but narrowly: only
a param literally named `request`, only a direct `.get()`/subscript within
the finding's own span.

Past that, Wall D showed the boundary runs deeper than Wall C alone: this
spike did take one real Django view finding (django.nV's `upload`, an
A1/A4-adjacent SQLi) all the way to a `confirmed` oracle verdict — but only
by hand-supplying two things nothing in secfix derives from the AST: the
specific model row (`Project`, with its required fields) the view's ORM
call needs, and an oversized dummy file to satisfy a framework-internal
upload-handler threshold the view's own form validation depends on. Both
are per-view, per-model knowledge; neither is "one more pattern" the way
Wall A was, and a third requirement (the view's form needing a field the
finding's tainted read never touches) fails silently rather than crashing,
which is a new problem shape, not just a new wall.

V1 is deliberately parked here, one layer further down than before: the
boundary of solo, incremental scope now covers "detect the framework, get
past its app-context wall, provision a real schema, and construct a
syntactically real request for the one key a finding taints" — and it does
not yet extend to "understand a view's *full* data dependencies (its other
form fields, the rows its ORM calls expect, framework-internal thresholds)
well enough to reproduce a view-level vulnerability without a human
supplying that knowledge by hand, per finding." That's still the next
spike, not a fix.
