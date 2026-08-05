"""Fixture: parameterized query, NOT vulnerable. Exercises the oracle's
not_reproduced path.
"""
import sqlite3


def get_connection():
    return sqlite3.connect(":memory:")


def find_user_by_name(name):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cursor.fetchall()
