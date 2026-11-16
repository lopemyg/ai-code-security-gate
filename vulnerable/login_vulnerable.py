import sqlite3

DB_PASSWORD = "SuperSecret123!"  # CWE-259 / CWE-798: hard-coded secret


def get_user(conn: sqlite3.Connection, username: str):
    query = "SELECT * FROM users WHERE username = '" + username + "'"  # CWE-89
    return conn.execute(query).fetchall()
