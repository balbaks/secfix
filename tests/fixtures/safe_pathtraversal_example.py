"""Fixture: safe from path traversal. Resolves the requested path and
confines it to the base directory — anything that would resolve outside
BASE_DIR is remapped to the equivalent basename inside it before being
opened, so a ".."-laden filename can never escape.
"""
from pathlib import Path

BASE_DIR = "/srv/uploads"


def read_file(filename):
    base = Path(BASE_DIR).resolve()
    candidate = Path(BASE_DIR, filename).resolve()
    if not candidate.is_relative_to(base):
        candidate = base / Path(filename).name
    return open(candidate).read()
