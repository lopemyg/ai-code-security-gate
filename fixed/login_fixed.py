import os
import re
import sqlite3

DB_PASSWORD = os.environ.get("DB_PASSWORD")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,32}$")


def get_user(conn: sqlite3.Connection, username: str, actor: str = ""):
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Invalid username")
    if actor and not USERNAME_PATTERN.fullmatch(actor):
        raise ValueError("Invalid username")
    if actor and actor != username:
        raise PermissionError("Not allowed to read this user")
    query = "SELECT * FROM users WHERE username = ?"
    return conn.execute(query, (username,)).fetchall()


def check_password(password: str) -> bool:
    return bool(DB_PASSWORD) and password == DB_PASSWORD
