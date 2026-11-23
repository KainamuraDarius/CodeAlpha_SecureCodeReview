# CodeAlpha Secure Code Review: MediTrack

A secure code review of **MediTrack**, a small Python/Flask pharmacy portal. The
repository holds the insecure original, the fixed version, and a test suite that
proves each vulnerability exists in one and is gone from the other.

> ⚠️ `vulnerable/` is **deliberately insecure**: it contains SQL injection, remote
> code execution and more. Run it only on your own machine, and never expose it
> to a network.

📄 **Full findings:** [REPORT.md](REPORT.md)

## Results at a glance

16 vulnerabilities found (5 Critical, 5 High, 5 Medium, 1 Low), all fixed:

| ID | Vulnerability | Severity | Fix |
|----|---------------|----------|-----|
| V-01 | SQL injection (login bypass, data dump) | Critical | Parameterised queries |
| V-02 | Server-side template injection → RCE | Critical | Fixed template files, input passed as data |
| V-03 | OS command injection in ping tool | Critical | Allow-list validation, no shell |
| V-04 | Insecure deserialisation (pickle) | Critical | JSON + schema validation |
| V-05 | Hard-coded secret key, forgeable admin role, debug mode | Critical | Key from env, role from DB, debug off |
| V-06 | Reflected and stored XSS | High | Auto-escaping, Content-Security-Policy |
| V-07 | IDOR: reading other patients' prescriptions | High | Ownership check in the query |
| V-08 | Path traversal in report download | High | `send_from_directory` + filename allow-list |
| V-09 | Unsalted MD5 password hashes | High | scrypt with per-user salt |
| V-10 | Default `admin` / `admin123` account | High | No seeded accounts; CLI to create admins |
| V-11 | Cross-site request forgery | Medium | CSRF tokens, SameSite cookies |
| V-12 | Open redirect after login | Medium | Same-site paths only |
| V-13 | Passwords written to logs | Medium | Log events, never secrets |
| V-14 | No brute-force protection; no security headers | Medium | Lockout after 5 failures; CSP, HSTS, etc. |
| V-15 | 18 known CVEs in pinned dependencies | Medium | Upgraded; pip-audit clean |
| V-16 | Username enumeration | Low | One generic error, constant-time check |

| Tool | Vulnerable app | Secure app |
|------|---------------|-----------|
| Exploit tests | 21 of 21 attacks succeed | 0 of 21 succeed |
| Bandit | 11 issues | 2 Low (reviewed, accepted) |
| Semgrep | 20 findings | 2 (false positive, explained in the report) |
| pip-audit | 18 advisories | 0 |

## Method

1. **Static analysis** with [Bandit](https://bandit.readthedocs.io/) and
   [Semgrep](https://semgrep.dev/). Output is in [`scans/`](scans/).
2. **Dependency audit** with [pip-audit](https://pypi.org/project/pip-audit/).
3. **Manual review**: each piece of user input traced from `request.*` to where
   it is used. This found 7 issues that neither scanner reported (IDOR, path
   traversal, CSRF, open redirect, default credentials, username enumeration,
   template injection).
4. **Proof**: every finding has an exploit in
   [`tests/test_findings.py`](tests/test_findings.py) that runs against both apps.

## Project layout

```
vulnerable/        the application under review (insecure on purpose)
  app.py           every flaw tagged with its ID, e.g. # [V-01]
  requirements.txt outdated pins (finding V-15)
secure/            the remediated application
  app.py           each fix tagged with the ID it resolves
  templates/       Jinja templates (auto-escaped, no |safe)
tests/
  conftest.py      starts either app with the same demo data
  test_findings.py one proof-of-concept per finding, run against both apps
scans/             raw Bandit, Semgrep and pip-audit output
REPORT.md          the full review: findings, impact, fixes, recommendations
```

## Running it

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt

.venv/bin/pytest -v          # 52 tests: every attack, against both apps
```

Run the secure app locally:

```bash
export MEDITRACK_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
export MEDITRACK_INSECURE_COOKIES=1      # only for plain-HTTP localhost testing
.venv/bin/flask --app secure.app create-user admin --role admin   # prompts for a password
.venv/bin/flask --app secure.app run
```

Run the vulnerable app (local only) to try the attacks by hand:

```bash
.venv/bin/flask --app vulnerable.app run          # login: admin / admin123
# http://127.0.0.1:5000/search?q={{7*7}}           -> shows 49 (template injection)
# http://127.0.0.1:5000/search?q=' UNION SELECT username,password,role FROM users --
```

Re-run the scanners:

```bash
.venv/bin/bandit -r vulnerable secure
.venv/bin/semgrep scan --metrics=off --config p/python --config p/flask vulnerable secure
.venv/bin/pip-audit -r vulnerable/requirements.txt --no-deps --disable-pip
```

## Author

Kainamura Darius, CodeAlpha Cyber Security Internship, Task 3.
