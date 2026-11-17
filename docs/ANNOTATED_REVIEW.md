# Annotated Review of the Sample Code

This note records two decisions for Section 3.4 of the report: why this login helper was
the example, and how each line was placed in a column of Table 1, the Security-Focused
Pull-Request Review Rubric. The code under review is `vulnerable/login_vulnerable.py`
and the corrected copy `fixed/login_fixed.py`. The tests that produced the observations
below are in `tests/test_injection.py`. Scans were Bandit 1.9.4 and the local Semgrep
rules in `.semgrep/rules.yml`.

## 1. How the example was selected

The sample had to be small enough to read in a report and large enough to exercise the
verification gate. Four constraints decided it.

The literature the report already cites points at a login query. Pearce et al. prompted
Copilot and, in the Python cases reproduced as Figures 3 and 4, the suggested code built
a SQL statement by placing the username and the password into the query string. That
pattern is CWE-89. The same body of work, and the weaknesses named in Section 2.2, also
treat hard-coded credentials as a defect that appears often in generated code and that
still runs correctly, which is why a scan is required to see it. A login lookup can carry
both defects in one function.

The prompt was written so a second, quieter defect would be visible to a person. The
agent was asked to record who is asking. The returned function accepts `actor` and then
discards it. That is CWE-862. It was included because Section 3.4 needs a finding the
scanners do not report. If every defect in the sample were a Bandit or Semgrep hit, the
human-review stage would have nothing of its own to do.

The prompt and the returned code were kept together. The comment at the top of
`vulnerable/login_vulnerable.py` is the prompt. The password in that prompt is the fake
value `SuperSecret123!`. Keeping the prompt in the file means a reader can see what was
requested, what came back, and what the review later marked. The file is the exhibit.
It is not a cleaned-up illustration with the CWE numbers already written on the buggy
lines. Those labels belong in this review.

One pair of files was used so the four stages of the gate run on the same change. Stage I
scans a directory. Stage II runs one test file against both versions. Stage III is this
annotation. Stage IV is the same scan and the same tests after the corrections in
`fixed/`. A larger application would have buried the demonstration.

The sample was also bounded on purpose. It imports only the standard library. It has no
file path, no upload, no shell command, and no page that renders HTML. Those omissions
are recorded in Section 3 so the rubric rows for path traversal, file upload, command
injection, cross-site scripting, and supply chain are not treated as if this login
function had tested them.

## 2. How the code was annotated

The rating is the column whose wording matches the evidence. A neighboring column was
not used to be generous. Where the evidence meets only part of a column, the unmet
clause is written in the notes and the rating stays with the column the code actually
reaches.

The reviewer went through the following steps for each file.

1. Read the prompt, then the function, before running a tool. Note any argument the
   prompt requested that the function does not use. In this sample that argument is
   `actor`.
2. Run Bandit on the directory and record the test id, the CWE, the severity, the
   confidence, and the line. Run Semgrep with `.semgrep/rules.yml` and record the rule
   id and the line. A clean exit is itself a result and is recorded.
3. Run `tests/test_injection.py`. The fixture builds a three-row table, `alice`, `bob`,
   and `carol`. Record what the payload `x' OR '1'='1` returns, what a normal username
   returns, and what happens when `actor` is a different user.
4. For each of the five metrics, quote the rubric cell that fits and name the line,
   the scanner finding, or the test that justifies it. If no line in this sample can
   meet a cell, say so. Absence of a dependency is evidence about the dependency
   metric. Absence of a file path is not evidence that path traversal was defended.
5. Compare the two files on the same metric. A fix is accepted when the vulnerable
   behavior is gone and the replacement matches the remediation already stated in
   Section 3.5, or, for access control, when the rubric's own wording is met.
6. Separate the automated gate from the rubric. Bandit and Semgrep can block a merge
   and still leave a metric at Critically Flawed or Revision Needed, because those
   tools do not score Table 1. The tests can pass and still leave a metric short of
   Deployment Ready. That gap is the reason Stage III is a person.

Ratings use the three labels in Table 1 and no others: **Critically Flawed**,
**Revision Needed**, and **Deployment Ready**.

## 3. What this sample can show

| Rubric concern | In this sample | How it was judged |
|---|---|---|
| CWE-798, CWE-259, hard-coded password | Yes. Assigned on line 7 and compared on line 17. | Bandit B105, Semgrep `hard-coded-secret`, and `test_vulnerable_password_check_accepts_hard_coded_secret`. |
| CWE-321, hard-coded cryptographic key | No key material. | Not scored from this file. The metric is scored on the password that is present. |
| CWE-89, SQL injection | Yes. Line 12 concatenates `username` into the query. | Bandit B608, Semgrep `sql-injection-string-concat`, and the three-row test. |
| CWE-77, CWE-78, command injection | No `os.system` and no `shell=True`. | Semgrep has rules for both. They did not fire, because the patterns are not in the file. That is not a test of command injection. |
| CWE-79, cross-site scripting | No HTML output. | Not instantiated. |
| CWE-94, code injection | No `eval` or `exec`. | Semgrep has a rule. It did not fire. That is not a test of code injection. |
| CWE-20, input validation | Yes, by what the vulnerable function omits, and by the allow-list in the fixed function. | Human reading, plus the injection string failing the allow-list. |
| CWE-22, path traversal, and CWE-434, unrestricted upload | No path and no upload. | Outside this sample. A Deployment Ready rating on input validation here means the username only. |
| CWE-284, CWE-862, missing authorization | Yes. `actor` is discarded. | Human reading and `test_vulnerable_version_ignores_the_caller`. Scanners reported nothing on this line. |
| CWE-1104, CWE-1357, CWE-1395, supply chain | No third-party package. | Deployment Ready because there is nothing to vet. The 30-day, download-count, and known-CVE checks had no package to inspect. |

## 4. Vulnerable version

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

| Line | What the reviewer saw | Evidence | Metric | Rating |
|---|---|---|---|---|
| 5, 7, 17 | The prompt states the password, line 7 assigns it, and line 17 accepts that exact string. A person with the repository, or its history, can read it. The check still runs, which is why the defect is easy to miss without a scan. | Bandit B105 on line 7, low severity, medium confidence, CWE-259. Semgrep `hard-coded-secret`, CWE-798. The password test returns true for `SuperSecret123!`. | Hard-coded Secret Protection | **Critically Flawed** |
| 12 | `username` is concatenated into the SQL text. The payload `x' OR '1'='1` makes the WHERE clause true for every row. | Bandit B608, medium severity, low confidence, CWE-89. Semgrep `sql-injection-string-concat`. The test returns 3 rows. | Injection Defense | **Critically Flawed** |
| 10–13 | Nothing inspects the username's length or characters before it is used. | Neither scanner reported this. The injection payload is accepted as a username. | Input Sanitization & Validation | **Critically Flawed** |
| 11 | The prompt asked the function to record who is asking. The body assigns `actor` to `_` and returns the row anyway. Bob can read Alice. | Neither scanner reported this. `test_vulnerable_version_ignores_the_caller` returns Alice's row when `actor` is `bob`. | Access Control & Authorization | **Critically Flawed** |
| — | Imports are `sqlite3` only. | No third-party name, version, or advisory to review. | Dependency & Supply Chain Safety | **Deployment Ready** |

Bandit exits 1. Semgrep exits 1 with two blocking findings, the password assignment and
the concatenated query. The merge is blocked. The scanners' silence on lines 10–13 and
on line 11 is the observation this sample was built to produce: Stage I does not see
every metric in Table 1.

## 5. Fixed version

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

| What changed | Why this column | Metric | Rating |
|---|---|---|---|
| Line 5 reads `DB_PASSWORD` from the environment. The fixed file contains no `SuperSecret` literal. `check_password` returns true only for the value supplied at runtime. Section 3.5.2 still prefers a secrets manager, and this value is not encrypted. The Critically Flawed condition, a secret written in the file, is gone. The Revision Needed condition, a placeholder left in the file, is not what this code does. | The secret is outside the source. The encryption clause of the Deployment Ready cell is recorded as unmet. | Hard-coded Secret Protection | **Deployment Ready**, with that limit |
| Line 16 uses a `?` placeholder and passes `username` as a bound parameter. The driver treats the value as data. The security test raises `ValueError` from the allow-list on line 10, so that test shows the malicious string is rejected before the query runs. The parameterization itself was confirmed by reading line 16. Command injection, XSS, and `eval` were not added to this function, so those CWEs stay unscored. | The SQL path matches the Deployment Ready wording for the query this function runs. | Injection Defense | **Deployment Ready** for CWE-89 |
| Lines 6 and 10–13 accept only a username of 3 to 32 letters, digits, or underscores. Anything else, including the injection payload, raises `ValueError`. `alice` is accepted and returns one row. The function has no path and no buffer, so CWE-22 and CWE-434 are not demonstrated. | The username is held to a written specification. | Input Sanitization & Validation | **Deployment Ready** for this argument |
| Lines 14–15 reject a caller whose name is not the requested username. Bob reading Alice raises `PermissionError`. The same user reading herself returns one row. If `actor` is omitted, the condition `if actor` is false and the row is returned with no caller at all. `test_fixed_version_returns_correct_row` calls `get_user(conn, "alice")` and expects that row. The rule is real when a caller is supplied, and it is skipped when the caller is missing. Least privilege is not applied on that path. | The rubric's Revision Needed cell is the one that fits: some authorization is present, and the rule is not in force for every call. | Access Control & Authorization | **Revision Needed** |
| Imports are `os`, `re`, and `sqlite3`. | Same reasoning as the vulnerable file. | Dependency & Supply Chain Safety | **Deployment Ready** |

Bandit exits 0. Semgrep exits 0. The automated stages pass. Stage III does not. Access
control is still Revision Needed, and the report's own rule is that every metric must
be Deployment Ready before a merge. The fixed file is the right remediation for the
SQL string and the hard-coded password. It is not yet a merge.

## 6. Scores side by side

| Metric | Vulnerable | Fixed | What decided the fixed rating |
|---|---|---|---|
| Hard-coded Secret Protection | Critically Flawed | Deployment Ready, secret not encrypted | The literal is gone and the check reads the environment. Bandit B105 and Semgrep `hard-coded-secret` are silent. |
| Dependency & Supply Chain Safety | Deployment Ready | Deployment Ready | Standard library only. No package was available to fail the supply-chain checks. |
| Injection Defense | Critically Flawed | Deployment Ready for CWE-89 | The query uses `?`. The payload test raises `ValueError` at the allow-list. Other injection CWEs were not in the file. |
| Input Sanitization & Validation | Critically Flawed | Deployment Ready for the username | Allow-list on length and characters. Path and upload rules were not in scope. |
| Access Control & Authorization | Critically Flawed | Revision Needed | A supplied caller may read only their own row. A missing caller still may. |

The vulnerable file is blocked by Stage I and by the injection test. The fixed file
clears Stage I and Stage II and stops at Stage III on access control. That split is
the result the demonstration is meant to document.
