"""Stage II (Test) of the verification gate.

Feeds the classic SQL injection payload to both versions of get_user()
against a three-row table and checks the results described in the report.
"""
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vulnerable"))
sys.path.insert(0, str(ROOT / "fixed"))

import login_fixed  # noqa: E402
import login_vulnerable  # noqa: E402

INJECTION = "x' OR '1'='1"


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)")
    c.executemany(
        "INSERT INTO users (username, email) VALUES (?, ?)",
        [("alice", "alice@example.com"), ("bob", "bob@example.com"), ("carol", "carol@example.com")],
    )
    yield c
    c.close()


def test_vulnerable_version_leaks_every_row(conn):
    """Demonstrates the flaw: the injection returns all 3 rows."""
    rows = login_vulnerable.get_user(conn, INJECTION)
    assert len(rows) == 3


def test_fixed_version_rejects_injection(conn):
    with pytest.raises(ValueError):
        login_fixed.get_user(conn, INJECTION)


def test_fixed_version_returns_correct_row(conn):
    rows = login_fixed.get_user(conn, "alice")
    assert len(rows) == 1
    assert rows[0][1] == "alice"


def test_fixed_version_uses_environment_secret():
    assert "SuperSecret" not in (ROOT / "fixed" / "login_fixed.py").read_text()


def test_vulnerable_version_ignores_the_caller(conn):
    """Any actor can read any row. Scanners do not flag this."""
    rows = login_vulnerable.get_user(conn, "alice", actor="bob")
    assert len(rows) == 1
    assert rows[0][1] == "alice"


def test_fixed_version_rejects_cross_user_read(conn):
    with pytest.raises(PermissionError):
        login_fixed.get_user(conn, "alice", actor="bob")


def test_fixed_version_allows_the_same_user(conn):
    rows = login_fixed.get_user(conn, "alice", actor="alice")
    assert len(rows) == 1
    assert rows[0][1] == "alice"


def test_vulnerable_password_check_accepts_hard_coded_secret():
    assert login_vulnerable.check_password("SuperSecret123!") is True


def test_fixed_password_check_reads_environment(monkeypatch):
    monkeypatch.setenv("DB_PASSWORD", "from-the-environment")
    import importlib

    importlib.reload(login_fixed)
    assert login_fixed.check_password("from-the-environment") is True
    assert login_fixed.check_password("SuperSecret123!") is False
    monkeypatch.delenv("DB_PASSWORD", raising=False)
    importlib.reload(login_fixed)
