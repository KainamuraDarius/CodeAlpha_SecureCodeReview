# Secure Code Review Report: MediTrack Pharmacy Portal

CodeAlpha Cyber Security Internship, Task 3
Author: Kainamura Darius · 

---

## 1. Summary

MediTrack is a small Python/Flask web application for a pharmacy. Patients log
in to view their prescriptions and message the pharmacist, and staff manage
stock. The review found **16 vulnerabilities** in `vulnerable/app.py`:

| Severity | Count | Findings |
|----------|-------|----------|
| Critical | 5 | SQL injection, template injection (RCE), command injection, insecure deserialisation, hard-coded secret key + debug mode |
| High     | 5 | Cross-site scripting, IDOR, path traversal, MD5 password hashing, default admin password |
| Medium   | 5 | CSRF, open redirect, passwords in logs, no brute-force protection / hardening, vulnerable dependencies |
| Low      | 1 | Username enumeration |

Four of the Critical findings each let an attacker **run commands on the
server**. The fifth (the hard-coded key) lets anyone holding the source code log
in as the administrator without a password. Together they put every
patient's prescription data at risk.

All 16 are fixed in `secure/app.py`. Each finding has an automated
proof-of-concept in `tests/test_findings.py`. The suite runs every attack against
both versions and checks that it **succeeds on the vulnerable app and fails on
the fixed one** (52 tests, all passing).

## 2. Scope and method

| Item | Detail |
|------|--------|
| Language / framework | Python 3.13, Flask 3, SQLite, Jinja2 |
| Code reviewed | `vulnerable/app.py` (≈235 lines), `vulnerable/requirements.txt` |
| Static analysis (SAST) | **Bandit** 1.9.4, **Semgrep** 1.186.0 (rulesets `p/python`, `p/flask`, `p/secrets`) |
| Dependency analysis (SCA) | **pip-audit** 2.10.1 against the PyPI advisory database |
| Manual review | Line-by-line reading of every route, following user input (`request.*`) to where it is used (SQL, templates, files, shell, redirects, logs) |
| Verification | Every finding confirmed by a working exploit, written as a pytest test |
| Classification | CWE IDs; OWASP Top 10 (2021) categories; severity from impact × ease of exploitation |

Raw scanner output is in [`scans/`](scans/).

### What the tools found and what they missed

| ID | Finding | Bandit | Semgrep | pip-audit | Manual |
|----|---------|:------:|:-------:|:---------:|:------:|
| V-01 | SQL injection | ✔ | ✔ | | ✔ |
| V-02 | Template injection (SSTI) | | ~ ¹ | | ✔ |
| V-03 | Command injection | ✔ | ✔ | | ✔ |
| V-04 | Insecure deserialisation | ✔ | ✔ | | ✔ |
| V-05 | Hard-coded secret / debug | ✔ | ~ ² | | ✔ |
| V-06 | Cross-site scripting | | ✔ | | ✔ |
| V-07 | IDOR | | | | ✔ |
| V-08 | Path traversal | | | | ✔ |
| V-09 | MD5 password hashing | ✔ | ✔ | | ✔ |
| V-10 | Default admin password | | | | ✔ |
| V-11 | CSRF | | | | ✔ |
| V-12 | Open redirect | | | | ✔ |
| V-13 | Passwords in logs | | ✔ | | ✔ |
| V-14 | No brute-force protection / hardening | ~ ³ | | | ✔ |
| V-15 | Vulnerable dependencies | | | ✔ | |
| V-16 | Username enumeration | | | | ✔ |

¹ Semgrep reported the line as "raw HTML formatting" (XSS), not as template injection, so it missed the RCE.
² Semgrep flagged debug mode but not the hard-coded `SECRET_KEY`.
³ Bandit flagged only `host="0.0.0.0"`.

**Takeaway:** the scanners found 9 of the 16 issues between them, almost all
of them *injection* bugs that match a code pattern. They found none of the
*logic* bugs: missing ownership checks, CSRF, open redirects, default
accounts. Those depend on what the code is *meant* to do, and only a human
reviewer knows that. Static analysis is a good first pass, not a replacement for
manual review.

---

## 3. Findings

Line numbers refer to `vulnerable/app.py`. Each block in the code is tagged with
its ID (e.g. `# [V-01]`).

### V-01 SQL injection (Critical)

**CWE-89 · OWASP A03 Injection · Lines 66–70 (login), 99–101 (search)**

User input is joined directly into SQL strings:

```python
query = ("SELECT * FROM users WHERE username = '" + username + "' "
         "AND password = '" + pw_hash + "'")
db().execute(f"SELECT name, stock, price FROM medicines WHERE name LIKE '%{q}%'")
```

**Exploit:**
- Log in as admin with **no password**: username `admin' --` turns the rest of the query into a comment.
- Dump every password hash from the search box: `zzz' UNION SELECT username, password, role FROM users --`

**Impact:** full read access to the database, authentication bypass.

**Fix:** parameterised queries. The database driver sends the value separately
from the SQL, so it can never change the query's structure:

```python
db().execute("SELECT id, password FROM users WHERE username = ?", (username,))
db().execute("SELECT ... WHERE name LIKE ? ESCAPE '\\'", ("%" + _escape_like(q) + "%",))
```

### V-02 Server-side template injection → remote code execution (Critical)

**CWE-1336 / CWE-94 · OWASP A03 Injection · Lines 106–112**

The search term is inserted into the **template source** with an f-string, and the
result is passed to `render_template_string()`. Jinja then *executes* whatever
the user typed:

```python
page = LAYOUT + "..." + f"<p>Results for: {q}</p>..."
return render_template_string(page)
```

**Exploit:**
- `/search?q={{7*191}}` displays `1337`.
- `/search?q={{ cycler.__init__.__globals__.os.popen("id").read() }}` runs `id` on the server.

No login is needed.

**Impact:** an anonymous attacker takes over the server.

**Fix:** templates are fixed files (`secure/templates/*.html`). User input is
passed only as a *variable* (`render_template("search.html", q=q)`), which Jinja
treats as data and HTML-escapes. Never build template source from user input.

### V-03 OS command injection (Critical)

**CWE-78 · OWASP A03 Injection · Lines 172–176**

```python
subprocess.run("ping -c 1 -W 1 " + host, shell=True, ...)
```

**Exploit:** `/admin/ping?host=127.0.0.1; cat /etc/shadow` runs a second command.
Admin access is needed, but V-05 and V-10 make admin access trivial to get.

**Fix:**
- Validate `host` against an allow-list: a real IP address via `ipaddress.ip_address`, or a hostname regex. Reject anything starting with `-`.
- Pass an argument list without a shell: `subprocess.run([PING, "-c", "1", "-W", "1", "--", host])`.
- Use an absolute path to `ping`, and `--` to end option parsing.

### V-04 Insecure deserialisation (Critical)

**CWE-502 · OWASP A08 Software and Data Integrity Failures · Lines 183–184**

```python
records = pickle.loads(request.files["backup"].read())
```

`pickle` can rebuild *any* Python object, including one whose `__reduce__`
method calls `os.system`. Unpickling the upload runs it.

**Exploit:** upload a pickle whose `__reduce__` returns `(eval, ("…code…",))`. The
test writes a marker file this way.

**Fix:**
- Accept **JSON** only, which can contain nothing but data.
- Validate every record: `name` is a string of 1–100 characters, and `stock` and `price` are non-negative integers.
- Limit the upload size with `MAX_CONTENT_LENGTH` (1 MB).
- Never unpickle data you did not create yourself.

### V-05 Hard-coded secret key, trusted session role, debug mode (Critical)

**CWE-798, CWE-565, CWE-489 · OWASP A07 / A05 · Lines 32, 147, 234**

Flask signs its session cookie with `SECRET_KEY`, which here is
`"meditrack-dev-key"` in the source code. Anyone who reads the repository can
sign their own cookie. The admin pages check `session["role"]`, so the
attacker can grant themselves the admin role. In addition, `debug=True` exposes
the Werkzeug interactive debugger, which is a Python console in the browser.

**Exploit:** sign `{"user_id": 1, "role": "admin"}` with the leaked key, using
`itsdangerous` (see `test_v05_forged_session_cookie_grants_admin`). The cookie
opens `/admin/messages`.

**Fix:**
- The key comes from the `MEDITRACK_SECRET_KEY` environment variable, and the app **refuses to start** without it.
- The session stores only `user_id`. The role is read from the database on every request (`load_user`), so editing the cookie cannot change it.
- `session.clear()` runs on login, which prevents session fixation.
- `debug=False`, and the app binds to `127.0.0.1` by default.

### V-06 Cross-site scripting: reflected and stored (High)

**CWE-79 · OWASP A03 Injection · Lines 106 (reflected), 153–157 (stored)**

- **Reflected:** the search term is written into the HTML unescaped (the same line as V-02).
- **Stored:** patient messages are shown in the admin inbox with `{{ m.body|safe }}`.

**Exploit:** a patient sends the message
`<img src=x onerror=alert(document.cookie)>`. The script runs in the
**administrator's** browser when they open the inbox.

**Impact:** session theft, and actions performed as the admin.

**Fix:**
- Jinja auto-escaping on every template, with no `|safe` on user content.
- A `Content-Security-Policy` that blocks inline scripts (`script-src 'self'`), as a second layer of defence.

### V-07 Insecure direct object reference (High)

**CWE-639 · OWASP A01 Broken Access Control · Lines 119–120**

`/prescriptions/<id>` checks that the user is logged in, but not that the
prescription is **theirs**.

**Exploit:** log in as Alice and open `/prescriptions/2`, which shows Bob's
diabetes diagnosis.

**Impact:** leaks medical data, which is sensitive personal data under Uganda's
Data Protection and Privacy Act 2019 and the GDPR.

**Fix:** the query includes ownership (`WHERE id = ? AND user_id = ?`), and admins
are the only exception. The app returns the same `404` for "not yours" and "does
not exist", so an attacker can't tell which IDs are real.

### V-08 Path traversal (High)

**CWE-22 · OWASP A01 Broken Access Control · Lines 165–166**

```python
return send_file(os.path.join(REPORTS_DIR, name))
```

**Exploit:**
- `?file=../app.py` downloads the source code, which exposes the secret key (V-05).
- `?file=/etc/passwd` reads any file the server can read. `os.path.join` discards the base directory when given an absolute path.

**Fix:**
- `send_from_directory()`, which uses Werkzeug's `safe_join` and refuses paths that leave the folder.
- Before that, a strict filename allow-list: `[A-Za-z0-9_-]+\.(txt|csv|pdf)`.

### V-09 Weak password hashing (High)

**CWE-916 / CWE-327 · OWASP A02 Cryptographic Failures · Lines 64–65, 214**

Passwords are stored as unsalted MD5. MD5 is designed to be fast: a GPU can
test billions of guesses per second, and common passwords have precomputed
lookup tables. Combined with V-01, an attacker can dump the hashes and crack
most of them in minutes.

**Fix:**
- `werkzeug.security.generate_password_hash`, which uses **scrypt** with a random salt per password and deliberately slow work factors.
- `check_password_hash` for verification.
- `create_user` enforces a minimum password length of 12 characters.

### V-10 Default administrator account (High)

**CWE-1392 · OWASP A07 Identification and Authentication Failures · Line 214**

Every install creates `admin` / `admin123`, which is one of the first
combinations attackers try.

**Fix:** no accounts are seeded. Administrators are created explicitly with
`flask --app secure.app create-user <name> --role admin`, which prompts for the
password twice.

### V-11 Cross-site request forgery (Medium)

**CWE-352 · OWASP A01 Broken Access Control · Line 133**

The message form accepts any POST that arrives with the session cookie. A
hostile web page can submit a form on the victim's behalf.

**Fix:**
- A random per-session CSRF token, checked with `secrets.compare_digest` before every POST, PUT, PATCH or DELETE.
- `SameSite=Lax` cookies.
- Logout now requires a POST, so a third-party page cannot log users out.
- *In a larger app, use Flask-WTF's `CSRFProtect` rather than hand-written code.*

### V-12 Open redirect (Medium)

**CWE-601 · OWASP A01 Broken Access Control · Line 76**

After login the user is sent to `?next=` without any check.

**Exploit:** `https://meditrack.example/login?next=https://evil.example/login` gives
the user a link to the **real** site. After they log in, it sends them to a
look-alike page that asks them to "log in again", which is a phishing setup.

**Fix:** `_safe_next()` accepts only same-site paths. A valid target starts with
one `/`, with no scheme, no host, no `//` and no `\`. Anything else falls back to `/`.

### V-13 Passwords written to logs (Medium)

**CWE-532 · OWASP A09 Security Logging and Monitoring Failures · Line 62**

`log.info("Login attempt user=%s password=%s", …)` copies every password,
including mistyped ones that are often close to the real one, into log files.
Log files are usually kept longer and protected less carefully than the database.

**Fix:** the app logs the event, the username and the IP address, and never the
secret. Failed logins are logged at `WARNING`, so monitoring can alert on them.

### V-14 No brute-force protection and missing hardening (Medium)

**CWE-307, CWE-1004, CWE-693 · OWASP A07 / A05 · Line 58**

- Unlimited login attempts are allowed. Combined with V-16, an attacker can guess passwords for known usernames indefinitely.
- The session cookie lacks the `SameSite`, `Secure` and lifetime settings, and the app sends no security headers.

**Fix:**
- After 5 failures for a username **or** an IP address, further attempts get `429` for 15 minutes. This in-memory version works for one process; with several workers, use Flask-Limiter backed by Redis.
- Cookie settings: `HttpOnly`, `SameSite=Lax`, `Secure` (on unless explicitly disabled for local HTTP), and a 30-minute lifetime.
- Response headers: `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, and `Strict-Transport-Security` over HTTPS.

### V-15 Dependencies with known vulnerabilities (Medium)

**CWE-1104 · OWASP A06 Vulnerable and Outdated Components · `vulnerable/requirements.txt`**

pip-audit found **18 published advisories** in the pinned versions:

| Package | Pinned | Advisories | Examples |
|---------|--------|-----------:|----------|
| Flask | 2.2.2 | 2 | CVE-2023-30861 (session cookie cached by proxies) |
| Werkzeug | 2.2.2 | 11 | CVE-2023-25577 (multipart DoS), CVE-2024-34069 (debugger RCE), CVE-2023-46136 |
| Jinja2 | 3.1.2 | 5 | CVE-2024-56326 and CVE-2025-27516 (sandbox escape), CVE-2024-22195 (XSS in `xmlattr`) |

**Fix:** `secure/requirements.txt` pins current releases (Flask 3.1.3,
Werkzeug 3.1.9, Jinja2 3.1.6), and pip-audit reports **no known
vulnerabilities**. Run `pip-audit` in CI and enable Dependabot so new
advisories are caught automatically.

### V-16 Username enumeration (Low)

**CWE-204 · OWASP A07 · Line 78**

The login form says "No such user" or "Wrong password", which tells an attacker
which usernames exist.

**Fix:** one message for both cases: "Invalid username or password". When the
user does not exist, the app still checks the password against a dummy hash, so
the response time does not reveal the difference either.

---

## 4. Results after remediation

| Check | Vulnerable | Secure |
|-------|-----------|--------|
| Exploit tests (`pytest`) | 21 of 21 attacks succeed | **0 of 21 attacks succeed**; the 5 normal-use and validation tests pass |
| Bandit | 11 issues (4 High, 4 Medium, 3 Low) | 2 Low, reviewed and accepted (below) |
| Semgrep | 20 findings (6 Error, 14 Warning) | 2, false positive (below) |
| pip-audit | 18 advisories in 3 packages | **0** |

**Remaining tool output, triaged:**

- **Bandit B404 and B603** (subprocess imported and called): `ping` runs with
  an argument list, no shell, an absolute path and an allow-listed host. Bandit
  reports every subprocess call, so a warning here is expected.
- **Semgrep `subprocess-injection`** (lines 265–266): Semgrep sees request data
  reaching `subprocess`, but it does not recognise `_valid_host()` as a
  sanitiser. The tests show that `;`, `|`, `` ` ``, `$()`, spaces and leading
  `-` are all rejected with `400`. This is a false positive.

## 5. Secure coding recommendations

General practices for any Python web project, drawn from this review:

1. **Never build code from strings of user input.** This covers SQL, templates,
   shell commands and HTML. Use parameterised queries, template variables,
   argument lists, and auto-escaping.
2. **Validate input with allow-lists, not block-lists.** Describe what *is*
   valid (a regex, a type, a range), and reject everything else.
3. **Authorise every request on the server.** Check *who owns* the object, not
   only *whether* someone is logged in. Keep roles on the server, not in cookies.
4. **Keep secrets out of source code.** Load keys from the environment or a
   secrets manager, and fail closed if they are missing. Scan commits with
   `gitleaks` or Semgrep `p/secrets`.
5. **Hash passwords with a slow, salted algorithm**: scrypt, Argon2 or bcrypt.
   Never MD5 or SHA-1 alone.
6. **Use data-only formats for untrusted input**: JSON, not pickle or
   `yaml.load`. Validate the structure after parsing.
7. **Secure defaults:** debug off, no default accounts, secure cookies, security
   headers, least privilege.
8. **Log events, not secrets.** Log failed logins and access-denied events so
   they can be monitored. Never log passwords, tokens or full card numbers.
9. **Keep dependencies patched**, and run `pip-audit` in CI.
10. **Automate the review:** run Bandit and Semgrep on every pull request. Then
    pay most manual review time to access control and business logic, which
    tools cannot judge.
11. **Write a test for every vulnerability you fix**, so the bug can't quietly
    come back.

## 6. Reproducing this review

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest -v                                    # exploit tests, both apps
.venv/bin/bandit -r vulnerable secure                  # SAST
.venv/bin/semgrep scan --metrics=off --config p/python --config p/flask --config p/secrets vulnerable secure
.venv/bin/pip-audit -r vulnerable/requirements.txt --no-deps --disable-pip
.venv/bin/pip-audit -r secure/requirements.txt --no-deps --disable-pip
```
