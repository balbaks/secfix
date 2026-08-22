"""Shared by python_sqli.py and python_cmdi.py.

v0.1.0 spike: module-import-time framework coupling (settings, app
registry) is the wall documented in the README as secfix's real gap on
web-framework code. For a detected Django target, get past just enough of
that wall to attempt import: point DJANGO_SETTINGS_MODULE at the app's own
settings and call django.setup(). DATABASE_URL is pre-set to an in-memory
sqlite DSN (only if the settings module doesn't already override it) as a
best-effort fallback for settings that read DB config from the environment
(dj_database_url / django-heroku convention) — setup() itself never opens a
DB connection, so this only matters if the settings module's own
import-time code does. Settings that hardcode a non-sqlite DATABASES dict,
or that have their own import-time filesystem/network side effects, are out
of scope for this spike.
"""
from __future__ import annotations

from secfix.repo import HarnessTarget


def django_bootstrap_lines(target: HarnessTarget) -> list[str]:
    if not target.django_settings_module:
        return []
    return [
        "    import os as _secfix_os",
        f"    _secfix_os.environ.setdefault('DJANGO_SETTINGS_MODULE', {target.django_settings_module!r})",
        "    _secfix_os.environ.setdefault('DATABASE_URL', 'sqlite://:memory:')",
        "    import django as _secfix_django",
        "    _secfix_django.setup()",
        "",
    ]
