import os
import re
import sqlite3

DB_PASSWORD = os.environ.get("DB_PASSWORD")  # secret read from the environment
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,32}$")  # allow-list (CWE-20)


def get_user(conn: sqlite3.Connection, username: str):
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Invalid username")
    query = "SELECT * FROM users WHERE username = ?"  # parameterized (CWE-89)
    return conn.execute(query, (username,)).fetchall()
