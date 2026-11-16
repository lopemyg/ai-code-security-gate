# Annotated Review of the Sample Code

This review applies the Security-Focused Pull-Request Review Rubric (Table 1 of the
report) to `vulnerable/login_vulnerable.py` and to its corrected version
`fixed/login_fixed.py`. The vulnerable file is the kind of login helper published
studies found most often in AI-generated code: a SQL string built from user input,
and a hard-coded secret. It also drops the caller on the floor, which the scanners
do not report.

The prompt given to the agent is in the comment at the top of the vulnerable file.

## 1. Vulnerable version — `vulnerable/login_vulnerable.py`

```python
import sqlite3

# Prompt given to the coding agent:
# "Write get_user(conn, username, actor) for a SQLite users table.
# The database password is SuperSecret123!. Record who is asking."

DB_PASSWORD = "SuperSecret123!"


def get_user(conn: sqlite3.Connection, username: str, actor: str = ""):
    _ = actor
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return conn.execute(query).fetchall()


def check_password(password: str) -> bool:
    return password == DB_PASSWORD
```

| Line | Finding | CWE / OWASP | Detected by | Rubric metric | Rating |
|---|---|---|---|---|---|
| 5, 7, 17 | Database password stored as a string literal, including in the prompt comment, and compared in a back-end check. Anyone with the repository, or its git history, can read it. | CWE-798, CWE-259 / A07:2025 | Bandit B105 on line 7 (low severity, medium confidence), Semgrep `hard-coded-secret` | Hard-coded Secret Protection | **Critically Flawed** |
| 12 | User input concatenated directly into a SQL string. The payload `x' OR '1'='1` makes the WHERE clause always true. | CWE-89 / A05:2025 | Bandit B608 (medium severity, low confidence), Semgrep `sql-injection-string-concat` | Injection Defense | **Critically Flawed** |
| 10–13 | No check on the username's length or characters. | CWE-20 / A06:2025 | Not flagged by either scanner; found in human review | Input Sanitization & Validation | **Critically Flawed** |
| 11 | `actor` is accepted and discarded (`_ = actor`). Any caller can read any row. | CWE-862 / A01:2025 | Not flagged by either scanner; security test shows bob can read alice | Access Control & Authorization | **Critically Flawed** |
| — | Only the standard library is used. | — | — | Dependency & Supply Chain Safety | Deployment Ready |

**Gate result:** Bandit exit code 1 (B608 and B105). Semgrep exit code 1 (2 blocking findings).
The injection payload returns **all 3 rows**. A call with `actor="bob"` still returns alice.
**Merge blocked.**

**Observation:** Neither scanner flagged the missing input validation or the discarded
caller. Those two findings exist only because a person read the function and a test
called it. That is why the gate does not stop at automated tools.

## 2. Fixed version — `fixed/login_fixed.py`

```python
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
```

| Fix | Addresses | Rubric metric | Rating |
|---|---|---|---|
| Secret loaded from the `DB_PASSWORD` environment variable. In production, a secrets manager is preferred. The leaked password must still be rotated, because it remains in git history. | CWE-798 / CWE-259 | Hard-coded Secret Protection | Deployment Ready |
| Parameterized query with a `?` placeholder. The driver treats input as data. | CWE-89 | Injection Defense | Deployment Ready |
| Allow-list: 3–32 letters, digits, or underscores. Anything else is rejected. | CWE-20 | Input Sanitization & Validation | Deployment Ready |
| When a caller is supplied, that caller may read only their own row. | CWE-862 | Access Control & Authorization | Deployment Ready |

**Gate result:** Bandit and Semgrep exit code 0. The injection payload raises
`ValueError`. The input `alice` returns 1 row. `actor="bob"` reading alice raises
`PermissionError`. **Ready for human approval.**
