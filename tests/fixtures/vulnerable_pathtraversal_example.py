"""Fixture: intentionally vulnerable to path traversal. Used only by
secfix's own test suite to exercise the harness/oracle pipeline under
--sandbox local.
"""
BASE_DIR = "/srv/uploads"


def read_file(filename):
    return open(f"{BASE_DIR}/{filename}").read()
