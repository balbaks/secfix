"""Fixture: intentionally vulnerable to SQL injection. Used only by secfix's
own test suite to exercise the harness/oracle pipeline under --sandbox local.
"""
import sqlite3


def get_connection():
    return sqlite3.connect(":memory:")


def find_user_by_name(name):
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '%s'" % name
    cursor.execute(query)
    return cursor.fetchall()
