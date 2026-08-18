"""Fixture: two queries, BOTH interpolated (vulnerable), same tainted param.
Used to prove that a patch which parameterizes only one of the two queries
must not come back "validated" — the oracle must catch the sentinel still
reaching the second, unpatched query.
"""
import sqlite3


def get_connection():
    return sqlite3.connect(":memory:")


def find_user_and_log(name):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
    cursor.execute("SELECT * FROM audit_log WHERE actor = '%s'" % name)
    return cursor.fetchall()
