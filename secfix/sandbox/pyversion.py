"""v0.1.0 spike: pick a sandbox base image matched to the target's pinned
Django version, instead of a single hardcoded python:3.11-slim for every
target.

Rationale (empirical, from the django.nV diagnostic): Django's own
documented Python-support windows are conservative, but the two concrete
breakages found running Django 1.8.3 on modern Python were both later and
more specific than "Django 1.8 doesn't claim Python 3.10+ support" would
suggest — collections.abc alias removal (Python 3.10) and the six
meta-path-importer load_module fallback removal (Python 3.12). The bands
below target "newest Python that still predates both of those," not a
strict transcription of Django's release-note support matrix, and are a
first-pass guess, not calibrated against a real corpus of Django-version
compatibility failures.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

DEFAULT_BASE_IMAGE = "python:3.11-slim"

_DJANGO_PIN_RE = re.compile(
    r"""^\s*[Dd]jango\s*(?:==|~=|>=)\s*([\d]+)\.([\d]+)""", re.MULTILINE
)

# Ordered oldest-first. A target's pinned Django (major, minor) is matched
# against the first band whose upper bound it's strictly below.
_DJANGO_PYTHON_BANDS: list[tuple[tuple[int, int], str]] = [
    ((1, 11), "python:3.6-slim"),   # Django <1.11: stay clear of collections.abc alias removal (3.10) and six shim removal (3.12)
    ((2, 2), "python:3.7-slim"),
    ((3, 0), "python:3.8-slim"),
    ((3, 2), "python:3.9-slim"),
    ((4, 0), "python:3.10-slim"),
    ((4, 2), "python:3.11-slim"),
]


def detect_django_version(repo_root: Path) -> Optional[tuple[int, int]]:
    """Best-effort (major, minor) Django pin from the target's
    requirements.txt. Returns None if there's no requirements.txt, or no
    line pins Django with ==, ~=, or >=.
    """
    requirements = repo_root / "requirements.txt"
    if not requirements.exists():
        return None
    match = _DJANGO_PIN_RE.search(requirements.read_text())
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)))


def detect_base_image(repo_root: Path) -> str:
    """Pick a sandbox base image for the target repo. Falls back to
    DEFAULT_BASE_IMAGE when no Django pin is found, or the pin doesn't fall
    below any known band's upper bound (i.e. it's newer than anything we
    have a specific band for, so the default modern image is already the
    right match).
    """
    version = detect_django_version(repo_root)
    if version is None:
        return DEFAULT_BASE_IMAGE
    for upper_bound, image in _DJANGO_PYTHON_BANDS:
        if version < upper_bound:
            return image
    return DEFAULT_BASE_IMAGE
