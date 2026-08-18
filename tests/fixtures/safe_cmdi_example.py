"""Fixture: safe from OS command injection. The tainted value is a single
argv element passed to subprocess with shell=False (the default) — never
shell-interpreted, so shell metacharacters in it have no special meaning.
"""
import subprocess


def ping_host(host):
    return subprocess.run(["ping", "-c", "1", host], shell=False)
