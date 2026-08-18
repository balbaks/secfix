"""Fixture: intentionally vulnerable to OS command injection. Used only by
secfix's own test suite to exercise the harness/oracle pipeline under
--sandbox local.
"""
import os


def ping_host(host):
    return os.system(f"ping -c 1 {host}")
