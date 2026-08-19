"""Fixture: intentionally vulnerable to path traversal via the
absolute-path override of os.path.join — a ".." blocklist stops the
relative-traversal probe but does nothing to stop
os.path.join(base, "/abs/path") from discarding base entirely. Used only
by secfix's own test suite to exercise the harness/oracle pipeline under
--sandbox local.
"""
import os

BASE_DIR = "/srv/uploads"


def read_file(filename):
    if ".." in filename:
        raise ValueError("no traversal allowed")
    return open(os.path.join(BASE_DIR, filename)).read()
