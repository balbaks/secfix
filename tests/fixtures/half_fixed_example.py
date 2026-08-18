"""Fixture: two queries, first parameterized (fixed), second still interpolated
(vulnerable). Proves the oracle catches a half-fix — CONFIRMED must be returned
even though one of the two queries is already safe.
"""
import sqlite3


def get_connection():
    return sqlite3.connect(":memory:")


def find_user_and_log(name):
    conn = get_connection()
    cursor = conn.cursor()
    # Fixed: parameterized
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    # Still vulnerable: sentinel lands in SQL string here
    cursor.execute("SELECT * FROM audit_log WHERE actor = '%s'" % name)
    return cursor.fetchall()
