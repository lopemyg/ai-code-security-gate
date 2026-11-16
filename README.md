# AI Code Security Gate

Companion repository for **"Security Review of AI-Generated Code: A Comprehensive Review
Framework for Building Safely With AI Agents"** (CSCI 400, Group 5, John Jay College of
Criminal Justice).

It contains the sample code, verification gate, and pull-request policy described in the
report, so that the demonstration in Section 3.4 can be reproduced.

> ⚠️ `vulnerable/` is **intentionally insecure** teaching code. Do not deploy or reuse it.
> The password in it is fake.

## Contents

| Path | Purpose | Report section |
|---|---|---|
| `vulnerable/login_vulnerable.py` | Sample with SQL injection (CWE-89) and a hard-coded password (CWE-259/798) | 3.4 |
| `fixed/login_fixed.py` | Corrected version: parameterized query, secret from the environment, allow-list validation | 3.4, 3.5 |
| `tests/test_injection.py` | Stage II security tests using the payload `x' OR '1'='1` on a three-row table | 3.1, 3.4 |
| `.semgrep/rules.yml` | Local Semgrep rules mapped to rubric metrics (CWE-89, 798, 78, 94) | 3.1, 3.2 |
| `.github/workflows/security-gate.yml` | CI pipeline running the gate on every pull request | 3.1 |
| `.github/pull_request_template.md` | AI-use disclosure, rubric scoring, and reviewer sign-off | 4.1–4.6 |
| `docs/ANNOTATED_REVIEW.md` | Line-by-line review of the sample code against the rubric | 1.1, 2.2 |
| `scripts/run_gate.sh` | Runs the scan and test stages locally | 3.4 |

## The verification gate

| Stage | What happens | Tool |
|---|---|---|
| I. Scan | Static analysis for known weakness patterns | Semgrep, Bandit |
| II. Test | Security tests with malicious input | pytest |
| III. Review | A person scores the PR with the rubric and confirms every fix | Human reviewer |
| IV. Retest | Scans and tests rerun automatically on the fixed code | GitHub Actions |

## Run it locally

```bash
pip install -r requirements-dev.txt

./scripts/run_gate.sh vulnerable   # GATE RESULT: BLOCKED
./scripts/run_gate.sh fixed        # GATE RESULT: PASSED

semgrep scan --config .semgrep/rules.yml --error vulnerable   # 2 blocking findings, exit 1
semgrep scan --config .semgrep/rules.yml --error fixed        # 0 findings, exit 0
```

### Expected results

| Stage | Vulnerable version | Fixed version |
|---|---|---|
| Bandit | B608 SQL injection (CWE-89, medium/low confidence), B105 hard-coded password (CWE-259, low/medium confidence). Exit 1 → **blocked** | No issues. Exit 0 |
| Semgrep | 2 blocking findings. Exit 1 → **blocked** | 0 findings. Exit 0 |
| Injection test | Returns all 3 rows (injection succeeds) | Input rejected; `alice` returns 1 row |

## Enforcing the gate on GitHub (Stage III)

In **Settings → Branches → Branch protection rules** for `main`:

1. Enable **Require a pull request before merging** with at least **1 approval**.
2. Enable **Require status checks to pass** and select **Gate (scan + test on application code)**.

With these settings, a pull request cannot merge until the scans and tests pass *and* a
human reviewer approves it.

## Security rubric (summary)

Each pull request is scored on five metrics as **Critically Flawed**, **Revision Needed**,
or **Deployment Ready**. Only code that is Deployment Ready on every metric may be merged.

| Metric | Main CWEs | OWASP Top 10:2025 |
|---|---|---|
| Hard-coded Secret Protection | CWE-798, 259, 321 | A02, A04, A07 |
| Dependency & Supply Chain Safety | CWE-1104, 1357, 1395 | A03 |
| Injection Defense | CWE-77, 78, 79, 89, 94 | A05 |
| Input Sanitization & Validation | CWE-20, 22, 434 | A06, A10 |
| Access Control & Authorization | CWE-284, 862 | A01 |

See the full rubric in Table 1 of the report.

## Authors

Agustin Lopez, Jack Sklover, Noushad Ahmed, and Peter Apolinares.
