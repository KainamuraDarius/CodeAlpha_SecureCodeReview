"""MediTrack: a small pharmacy portal, written INSECURELY on purpose.

This is the application under review. Every flaw is tagged with the finding ID
used in REPORT.md (e.g. ``# [V-01]``). Do not deploy this code anywhere.
"""

import hashlib
import logging
import os
import pickle
import sqlite3
import subprocess

from flask import Flask, g, redirect, render_template_string, request, send_file, session

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("meditrack")

LAYOUT = """<!doctype html><title>MediTrack</title>
<nav><a href="/">Home</a> | <a href="/search">Medicines</a> |
{% if session.user %}<a href="/messages">Contact pharmacist</a> |
<a href="/logout">Logout ({{ session.user }})</a>
{% else %}<a href="/login">Login</a>{% endif %}</nav>
<hr>"""


def create_app(db_path=None):
    app = Flask(__name__)
    # [V-05] Hard-coded secret key: anyone with the source can forge session cookies.
    app.config["SECRET_KEY"] = "meditrack-dev-key"
    app.config["DATABASE"] = db_path or os.path.join(BASE_DIR, "meditrack.db")

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

    @app.route("/")
    def index():
        return render_template_string(LAYOUT + "<h1>Welcome to MediTrack</h1>")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = ""
        # [V-14] No rate limiting/lockout, no cookie flags, no security headers.
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            # [V-13] Credentials written to the application log in plain text.
            log.info("Login attempt user=%s password=%s", username, password)
            # [V-09] Unsalted MD5 password hash.
            pw_hash = hashlib.md5(password.encode()).hexdigest()
            # [V-01] SQL injection: user input concatenated into the query.
            query = (
                "SELECT * FROM users WHERE username = '" + username + "' "
                "AND password = '" + pw_hash + "'"
            )
            user = db().execute(query).fetchone()
            if user:
                session["user"] = user["username"]
                session["user_id"] = user["id"]
                session["role"] = user["role"]
                # [V-12] Open redirect: ``next`` is followed without validation.
                return redirect(request.args.get("next", "/"))
            # [V-16] Username enumeration through different error messages.
            exists = db().execute(
                "SELECT 1 FROM users WHERE username = ?", (username,)
            ).fetchone()
            error = "Wrong password" if exists else "No such user"
        return render_template_string(
            LAYOUT
            + """<h2>Login</h2><p style="color:red">{{ error }}</p>
            <form method="post"><input name="username"> <input name="password" type="password">
            <button>Login</button></form>""",
            error=error,
        )

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect("/")

    @app.route("/search")
    def search():
        q = request.args.get("q", "")
        # [V-01] SQL injection (UNION-based) in the search box.
        rows = db().execute(
            f"SELECT name, stock, price FROM medicines WHERE name LIKE '%{q}%'"
        ).fetchall()
        items = "".join(
            f"<li>{r['name']} | stock {r['stock']} | UGX {r['price']}</li>" for r in rows
        )
        # [V-02] Server-side template injection + [V-06] reflected XSS:
        # the search term is pasted into the template source itself.
        page = (
            LAYOUT
            + "<h2>Medicines</h2><form><input name=q><button>Search</button></form>"
            + f"<p>Results for: {q}</p><ul>{items}</ul>"
        )
        return render_template_string(page)

    @app.route("/prescriptions/<int:pid>")
    def prescription(pid):
        if "user_id" not in session:
            return redirect("/login")
        # [V-07] IDOR: any logged-in user can read any prescription by changing the ID.
        row = db().execute("SELECT * FROM prescriptions WHERE id = ?", (pid,)).fetchone()
        if row is None:
            return "Not found", 404
        return render_template_string(
            LAYOUT + "<h2>Prescription #{{ p.id }}</h2><p>{{ p.drug }}: {{ p.dosage }}</p>"
            "<p>Patient notes: {{ p.notes }}</p>",
            p=row,
        )

    @app.route("/messages", methods=["GET", "POST"])
    def messages():
        if "user_id" not in session:
            return redirect("/login")
        # [V-11] No CSRF token on this state-changing form.
        if request.method == "POST":
            db().execute(
                "INSERT INTO messages (user_id, body) VALUES (?, ?)",
                (session["user_id"], request.form.get("body", "")),
            )
            db().commit()
        return render_template_string(
            LAYOUT + """<h2>Message the pharmacist</h2>
            <form method="post"><textarea name="body"></textarea><button>Send</button></form>"""
        )

    @app.route("/admin/messages")
    def admin_messages():
        # [V-05] Authorisation trusts a role stored in a cookie signed with the leaked key.
        if session.get("role") != "admin":
            return "Forbidden", 403
        rows = db().execute(
            "SELECT m.body, u.username FROM messages m JOIN users u ON u.id = m.user_id"
        ).fetchall()
        # [V-06] Stored XSS: patient messages rendered with |safe in the admin's browser.
        return render_template_string(
            LAYOUT + "<h2>Inbox</h2>{% for m in rows %}<div><b>{{ m.username }}</b>: "
            "{{ m.body|safe }}</div>{% endfor %}",
            rows=rows,
        )

    @app.route("/reports/download")
    def download_report():
        if "user_id" not in session:
            return redirect("/login")
        name = request.args.get("file", "")
        # [V-08] Path traversal: ``file=../app.py`` or an absolute path escapes REPORTS_DIR.
        return send_file(os.path.join(REPORTS_DIR, name))

    @app.route("/admin/ping")
    def admin_ping():
        if session.get("role") != "admin":
            return "Forbidden", 403
        host = request.args.get("host", "127.0.0.1")
        # [V-03] OS command injection: ``host=127.0.0.1;id`` runs ``id``.
        out = subprocess.run(
            "ping -c 1 -W 1 " + host, shell=True, capture_output=True, text=True, timeout=10
        )
        return "<pre>" + out.stdout + out.stderr + "</pre>"

    @app.route("/admin/import", methods=["POST"])
    def admin_import():
        if session.get("role") != "admin":
            return "Forbidden", 403
        # [V-04] Insecure deserialisation: pickle executes code embedded in the upload.
        records = pickle.loads(request.files["backup"].read())
        for r in records:
            db().execute(
                "INSERT INTO medicines (name, stock, price) VALUES (?, ?, ?)",
                (r["name"], r["stock"], r["price"]),
            )
        db().commit()
        return f"Imported {len(records)} medicines"

    return app


def init_db(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT);
        CREATE TABLE IF NOT EXISTS medicines (
            id INTEGER PRIMARY KEY, name TEXT, stock INTEGER, price INTEGER);
        CREATE TABLE IF NOT EXISTS prescriptions (
            id INTEGER PRIMARY KEY, user_id INTEGER, drug TEXT, dosage TEXT, notes TEXT);
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY, user_id INTEGER, body TEXT);
        """
    )
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        md5 = lambda s: hashlib.md5(s.encode()).hexdigest()  # noqa: E731
        conn.executemany(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            [
                # [V-10] Default administrator account with a guessable password.
                ("admin", md5("admin123"), "admin"),
                ("alice", md5("alice-pass-1"), "patient"),
                ("bob", md5("bob-pass-2"), "patient"),
            ],
        )
        conn.executemany(
            "INSERT INTO medicines (name, stock, price) VALUES (?, ?, ?)",
            [("Paracetamol 500mg", 120, 2000), ("Amoxicillin 250mg", 40, 6500),
             ("Coartem", 25, 12000), ("Metformin 500mg", 60, 4500)],
        )
        conn.executemany(
            "INSERT INTO prescriptions (user_id, drug, dosage, notes) VALUES (?, ?, ?, ?)",
            [(2, "Amoxicillin 250mg", "3x daily, 7 days", "Penicillin test negative"),
             (3, "Metformin 500mg", "2x daily", "Type 2 diabetes, HbA1c 8.1%")],
        )
        conn.commit()


if __name__ == "__main__":
    # [V-05] Debug mode exposes the Werkzeug console (remote code execution) and stack traces.
    create_app().run(host="0.0.0.0", port=5000, debug=True)
