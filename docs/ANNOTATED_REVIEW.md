# Annotated Review of the Sample Code

This review applies the Security-Focused Pull-Request Review Rubric (Table 1 of the
report) to `vulnerable/login_vulnerable.py` and to its corrected version
`fixed/login_fixed.py`. The vulnerable file reproduces two weaknesses that published
studies found most often in AI-generated code: SQL injection and hard-coded secrets.

## 1. Vulnerable version — `vulnerable/login_vulnerable.py`

```python
import sqlite3

DB_PASSWORD = "SuperSecret123!"  # CWE-259 / CWE-798: hard-coded secret


def get_user(conn: sqlite3.Connection, username: str):
    query = "SELECT * FROM users WHERE username = '" + username + "'"  # CWE-89
    return conn.execute(query).fetchall()
```

| Line | Finding | CWE / OWASP | Detected by | Rubric metric | Rating |
|---|---|---|---|---|---|
| 3 | Database password stored as a string literal in source code. Anyone with access to the repository, or its git history, can read it. | CWE-798, CWE-259 / A07:2025 | Bandit B105 (low severity), Semgrep `hard-coded-secret` | Hard-coded Secret Protection | **Critically Flawed** |
| 7 | User input concatenated directly into a SQL string. The payload `x' OR '1'='1` turns the WHERE clause into a condition that is always true. | CWE-89 / A05:2025 | Bandit B608 (medium severity), Semgrep `sql-injection-string-concat` | Injection Defense | **Critically Flawed** |
| 6–8 | No check on the username's type, length, or characters. | CWE-20 / A06:2025 | Not flagged by either scanner; found in human review | Input Sanitization & Validation | **Critically Flawed** |
| — | Only the standard library is used. | — | — | Dependency & Supply Chain Safety | Deployment Ready |
| — | The function returns any user's record to any caller. Authorization would need to be enforced by the code that calls it. | CWE-862 / A01:2025 | Human review | Access Control & Authorization | Revision Needed (out of scope for this sample) |

**Gate result:** Bandit exit code 1 (2 findings), Semgrep exit code 1 (2 blocking findings).
The security test returns **all 3 rows** for the injection payload. **Merge blocked.**

**Observation:** Neither scanner flagged the missing input validation. Only the human
review stage caught it, which is why the gate does not rely on automated tools alone.

## 2. Fixed version — `fixed/login_fixed.py`

```python
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
```

| Fix | Addresses | Rubric metric | Rating |
|---|---|---|---|
| Secret loaded from the `DB_PASSWORD` environment variable. In production, a secrets manager is preferred, and the leaked password must be rotated because it remains in git history. | CWE-798 / CWE-259 | Hard-coded Secret Protection | Deployment Ready |
| Parameterized query with a `?` placeholder. The database driver treats input as data, never as SQL. | CWE-89 | Injection Defense | Deployment Ready |
| Allow-list regular expression: 3–32 letters, digits, or underscores. Anything else is rejected. | CWE-20 | Input Sanitization & Validation | Deployment Ready |

**Gate result:** Bandit and Semgrep exit code 0 (no findings). The injection payload is
rejected, and the normal input `alice` returns exactly 1 row. **Ready for human approval.**
