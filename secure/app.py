"""MediTrack, remediated.

Same features and routes as ``vulnerable/app.py``. Comments tagged ``[V-xx]``
point to the finding in REPORT.md that each change fixes.
"""

import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import time
from functools import wraps
from urllib.parse import urlsplit

import click
from flask import (
    Flask,
    abort,
    g,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

log = logging.getLogger("meditrack")

# [V-14] Login throttling: after MAX_FAILURES failures for one username or one
# client IP, further attempts are refused for LOCKOUT_SECONDS. This in-memory
# version suits a single process; behind several workers use Flask-Limiter + Redis.
MAX_FAILURES = 5
LOCKOUT_SECONDS = 15 * 60

# [V-03] Strict allow-list for the ping target: a hostname or an IP address only.
PING = shutil.which("ping") or "/usr/bin/ping"  # absolute path, not looked up via $PATH
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?)+$")

# [V-16] Hash checked against when the username does not exist, so the response
# time does not reveal which usernames are registered.
_DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(16))


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        DATABASE=os.path.join(BASE_DIR, "meditrack.db"),
        # [V-05] The key comes from the environment, never from source code.
        SECRET_KEY=os.environ.get("MEDITRACK_SECRET_KEY"),
        # [V-14] Session cookie hardening.
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("MEDITRACK_INSECURE_COOKIES") != "1",
        PERMANENT_SESSION_LIFETIME=30 * 60,
        MAX_CONTENT_LENGTH=1 * 1024 * 1024,
    )
    if config:
        app.config.update(config)
    if not app.config["SECRET_KEY"]:
        raise RuntimeError(
            "Set MEDITRACK_SECRET_KEY, e.g. "
            "export MEDITRACK_SECRET_KEY="
            "$(python -c 'import secrets; print(secrets.token_hex(32))')"
        )
    app.extensions["login_failures"] = {}

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    with app.app_context():
        init_db(db())

    # ---- authentication helpers -------------------------------------------------

    @app.before_request
    def load_user():
        # [V-05] Only the user id lives in the session. The role is read from the
        # database on every request, so it cannot be changed from the client.
        g.user = None
        uid = session.get("user_id")
        if uid is not None:
            g.user = db().execute(
                "SELECT id, username, role FROM users WHERE id = ?", (uid,)
            ).fetchone()
            if g.user is None:
                session.clear()

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)

        return wrapped

    def admin_required(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user["role"] != "admin":
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    # ---- CSRF protection [V-11] ----------------------------------------------------

    def csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def check_csrf():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            expected = session.get("csrf_token")
            if not expected or not secrets.compare_digest(sent, expected):
                abort(400, "Missing or invalid CSRF token")

    # ---- security headers [V-14] ------------------------------------------------

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    # ---- routes -----------------------------------------------------------------

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            ip = request.remote_addr or "?"
            if _locked_out(app, ("user", username)) or _locked_out(app, ("ip", ip)):
                return render_template("login.html", error="Too many attempts. Try later."), 429

            # [V-01] Parameterised query. [V-09] Salted scrypt hash check.
            user = db().execute(
                "SELECT id, password FROM users WHERE username = ?", (username,)
            ).fetchone()
            ok = check_password_hash(user["password"] if user else _DUMMY_HASH, password)
            if user and ok:
                _clear_failures(app, ("user", username))
                session.clear()  # new session on login (prevents session fixation)
                session["user_id"] = user["id"]
                # [V-13] Log the event, never the secret.
                log.info("login ok user=%s ip=%s", username, ip)
                return redirect(_safe_next(request.args.get("next")))

            _record_failure(app, ("user", username))
            _record_failure(app, ("ip", ip))
            log.warning("login failed user=%s ip=%s", username, ip)
            # [V-16] One message whether or not the user exists.
            error = "Invalid username or password"
        return render_template("login.html", error=error)

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.route("/search")
    def search():
        q = request.args.get("q", "")
        # [V-01] Parameterised query; the % wildcards are part of the bound value.
        rows = db().execute(
            "SELECT name, stock, price FROM medicines WHERE name LIKE ? ESCAPE '\\'",
            ("%" + _escape_like(q) + "%",),
        ).fetchall()
        # [V-02][V-06] The template is a fixed file; q is passed as data and auto-escaped.
        return render_template("search.html", q=q, rows=rows)

    @app.route("/prescriptions/<int:pid>")
    @login_required
    def prescription(pid):
        # [V-07] Ownership is part of the query. Admins may view any prescription.
        if g.user["role"] == "admin":
            row = db().execute("SELECT * FROM prescriptions WHERE id = ?", (pid,)).fetchone()
        else:
            row = db().execute(
                "SELECT * FROM prescriptions WHERE id = ? AND user_id = ?", (pid, g.user["id"])
            ).fetchone()
        if row is None:
            abort(404)  # same answer for "not yours" and "does not exist"
        return render_template("prescription.html", p=row)

    @app.route("/messages", methods=["GET", "POST"])
    @login_required
    def messages():
        sent = False
        if request.method == "POST":
            body = request.form.get("body", "").strip()[:2000]
            if body:
                db().execute(
                    "INSERT INTO messages (user_id, body) VALUES (?, ?)", (g.user["id"], body)
                )
                db().commit()
                sent = True
        return render_template("messages.html", sent=sent)

    @app.route("/admin/messages")
    @admin_required
    def admin_messages():
        rows = db().execute(
            "SELECT m.body, u.username FROM messages m JOIN users u ON u.id = m.user_id"
        ).fetchall()
        # [V-06] Rendered with auto-escaping (no |safe) in admin_messages.html.
        return render_template("admin_messages.html", rows=rows)

    @app.route("/reports/download")
    @login_required
    def download_report():
        # [V-08] send_from_directory rejects "..", absolute paths and anything
        # outside REPORTS_DIR; we also only serve .txt / .csv / .pdf reports.
        name = request.args.get("file", "")
        if not re.fullmatch(r"[A-Za-z0-9_-]+\.(txt|csv|pdf)", name):
            abort(404)
        return send_from_directory(REPORTS_DIR, name, as_attachment=True)

    @app.route("/admin/ping")
    @admin_required
    def admin_ping():
        host = request.args.get("host", "127.0.0.1")
        if not _valid_host(host):
            abort(400, "Invalid host")
        # [V-03] Argument list, no shell, "--" ends option parsing.
        try:
            out = subprocess.run(
                [PING, "-c", "1", "-W", "1", "--", host],
                capture_output=True, text=True, timeout=10, check=False,
            )
            result = out.stdout + out.stderr
        except (OSError, subprocess.TimeoutExpired) as exc:
            result = f"ping failed: {exc.__class__.__name__}"
        return render_template("ping.html", host=host, result=result)

    @app.route("/admin/import", methods=["POST"])
    @admin_required
    def admin_import():
        # [V-04] JSON is data-only: parsing it cannot run code. Every record is validated.
        try:
            records = json.loads(request.files["backup"].read().decode("utf-8"))
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError):
            abort(400, "Upload a JSON file in the 'backup' field")
        if not isinstance(records, list) or not all(_valid_medicine(r) for r in records):
            abort(400, "Each record needs name (text), stock and price (non-negative integers)")
        db().executemany(
            "INSERT INTO medicines (name, stock, price) VALUES (?, ?, ?)",
            [(r["name"], r["stock"], r["price"]) for r in records],
        )
        db().commit()
        return render_template("imported.html", count=len(records))

    # ---- CLI: accounts are created explicitly, never seeded [V-10] ---------------

    @app.cli.command("create-user")
    @click.argument("username")
    @click.option("--role", type=click.Choice(["patient", "admin"]), default="patient")
    @click.password_option()
    def create_user_cmd(username, role, password):
        """Create a user with a password you type in."""
        create_user(db(), username, password, role)
        click.echo(f"Created {role} {username}")

    return app


# ---- helpers ----------------------------------------------------------------------


def create_user(conn, username, password, role="patient"):
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    conn.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), role),  # [V-09] scrypt + salt
    )
    conn.commit()


def _safe_next(target):
    # [V-12] Only same-site relative paths ("/x"), never "//evil" or "https://evil".
    if not target:
        return "/"
    parts = urlsplit(target)
    if parts.scheme or parts.netloc or not target.startswith("/") or target.startswith("//") \
            or "\\" in target:
        return "/"
    return target


def _escape_like(text):
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _valid_host(host):
    if host.startswith("-"):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.fullmatch(host))


def _valid_medicine(r):
    return (
        isinstance(r, dict)
        and isinstance(r.get("name"), str) and 0 < len(r["name"]) <= 100
        and all(type(r.get(k)) is int and r[k] >= 0 for k in ("stock", "price"))
    )


def _locked_out(app, key):
    count, since = app.extensions["login_failures"].get(key, (0, 0.0))
    if count >= MAX_FAILURES and time.monotonic() - since < LOCKOUT_SECONDS:
        return True
    if count >= MAX_FAILURES:  # lockout expired
        _clear_failures(app, key)
    return False


def _record_failure(app, key):
    count, since = app.extensions["login_failures"].get(key, (0, time.monotonic()))
    app.extensions["login_failures"][key] = (count + 1, time.monotonic() if count == 0 else since)


def _clear_failures(app, key):
    app.extensions["login_failures"].pop(key, None)


def init_db(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('patient', 'admin')));
        CREATE TABLE IF NOT EXISTS medicines (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, stock INTEGER NOT NULL,
            price INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS prescriptions (
            id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
            drug TEXT, dosage TEXT, notes TEXT);
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), body TEXT);
        """
    )
    if conn.execute("SELECT COUNT(*) FROM medicines").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO medicines (name, stock, price) VALUES (?, ?, ?)",
            [("Paracetamol 500mg", 120, 2000), ("Amoxicillin 250mg", 40, 6500),
             ("Coartem", 25, 12000), ("Metformin 500mg", 60, 4500)],
        )
        conn.commit()


if __name__ == "__main__":
    # [V-05] Debug stays off; host and port come from the environment.
    create_app().run(
        host=os.environ.get("MEDITRACK_HOST", "127.0.0.1"),
        port=int(os.environ.get("MEDITRACK_PORT", "5000")),
        debug=False,
    )
