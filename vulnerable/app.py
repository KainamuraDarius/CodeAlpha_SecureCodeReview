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

LAYOUT = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MediTrack</title>
<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/static/style.css"></head>
<body class="build-vulnerable">
<div class="build">⚠ VULNERABLE BUILD · deliberately insecure, for security training only</div>
<header class="topbar"><div class="wrap">
<a class="brand" href="/"><svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32"
rx="8" fill="#0f766e"/><path d="M13 7h6v6h6v6h-6v6h-6v-6H7v-6h6z" fill="#fff"/></svg>MediTrack</a>
<nav class="nav"><a href="/">Home</a><a href="/search">Medicines</a>
{% if session.user %}<a href="/messages">Contact pharmacist</a>
{% if session.role == 'admin' %}<a href="/admin/messages">Inbox</a>{% endif %}{% endif %}</nav>
<div class="user">{% if session.user %}<span class="chip">● {{ session.user }}
{% if session.role == 'admin' %} · staff{% endif %}</span>
<a class="linkbtn" href="/logout">Log out</a>
{% else %}<a class="btn" href="/login">Log in</a>{% endif %}</div>
</div></header>
<main><div class="wrap">
"""

FOOTER = """
</div></main>
<footer><div class="wrap"><span>MediTrack pharmacy portal · CodeAlpha secure code review</span>
<span>Vulnerable build</span></div></footer>
</body></html>"""


def page(content):
    return LAYOUT + content + FOOTER


def fmt_price(v):
    # UNION-injected rows put text in this column, so only format real numbers.
    return f"{v:,}" if isinstance(v, int) else v


def stock_badge(v):
    low = " low" if isinstance(v, int) and v < 30 else ""
    return f'<span class="badge{low}">{v} in stock</span>'


HOME = """
<section class="hero">
  <h1>Your pharmacy, one click away.</h1>
  <p>Check medicine availability, view your prescriptions and message the pharmacist,
  all in one place.</p>
  <form class="searchbar" action="/search">
    <input name="q" placeholder="Search medicines, e.g. Paracetamol" aria-label="Search medicines">
    <button class="btn light">Search</button>
  </form>
  <div class="stats">
    <div><b>24/7</b><span>Online access</span></div>
    <div><b>100%</b><span>Licensed pharmacists</span></div>
    <div><b>UGX</b><span>Local pricing</span></div>
  </div>
</section>
{% if session.user %}
<div class="grid">
  <div class="card"><div class="icon">℞</div><h3>Your prescriptions</h3>
    {% if prescriptions %}<div class="rows">{% for p in prescriptions %}
      <a class="row" href="/prescriptions/{{ p.id }}"><span><b>{{ p.drug }}</b><br>
      <small>{{ p.dosage }}</small></span><small>#{{ p.id }} →</small></a>{% endfor %}</div>
    {% else %}<p class="muted">You have no prescriptions on file.</p>{% endif %}
  </div>
  <div class="card"><div class="icon">✉</div><h3>Ask the pharmacist</h3>
    <p class="muted">Questions about dosage or side effects? Send a private message.</p>
    <a class="btn" href="/messages">Write a message</a></div>
  <div class="card"><div class="icon">⇩</div><h3>Reports</h3>
    <p class="muted">Monthly stock report for October 2026.</p>
    <a class="btn" href="/reports/download?file=stock-2026-10.txt">Download report</a></div>
</div>
{% if session.role == 'admin' %}
<div class="card"><h2>Admin tools</h2><p class="muted">Pharmacy staff only.</p>
  <div class="grid">
    <div><h3>Patient inbox</h3><p class="muted">Read messages sent by patients.</p>
      <a class="btn" href="/admin/messages">Open inbox</a></div>
    <form action="/admin/ping"><h3>Network check</h3>
      <div class="field"><label for="host">Host to ping</label>
      <input id="host" name="host" value="127.0.0.1"></div><button>Ping</button></form>
    <form method="post" action="/admin/import" enctype="multipart/form-data">
      <h3>Import stock</h3><label for="backup">Backup file</label>
      <input id="backup" type="file" name="backup" required><button>Import</button></form>
  </div>
</div>
{% endif %}
{% else %}
<div class="grid">
  <div class="card"><div class="icon">⌕</div><h3>Find medicines</h3>
    <p class="muted">See what's in stock and what it costs before you visit.</p></div>
  <div class="card"><div class="icon">℞</div><h3>Prescriptions</h3>
    <p class="muted">Your dosage and pharmacist notes, whenever you need them.</p></div>
  <div class="card"><div class="icon">✉</div><h3>Talk to us</h3>
    <p class="muted">Message a licensed pharmacist directly.</p>
    <a class="btn" href="/login">Log in to start</a></div>
</div>
{% endif %}
"""


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
        prescriptions = []
        if "user_id" in session:
            prescriptions = db().execute(
                "SELECT id, drug, dosage FROM prescriptions WHERE user_id = ?",
                (session["user_id"],),
            ).fetchall()
        return render_template_string(page(HOME), prescriptions=prescriptions)

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
            page(
                """<div class="card narrow"><h2>Welcome back</h2>
            <p class="muted">Log in to view your prescriptions.</p>
            {% if error %}<div class="alert alert-error">{{ error }}</div>{% endif %}
            <form method="post" class="stack">
            <div class="field"><label for="username">Username</label>
            <input id="username" name="username" autofocus></div>
            <div class="field"><label for="password">Password</label>
            <input id="password" name="password" type="password"></div>
            <button>Log in</button></form></div>"""
            ),
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
            f"<tr><td><b>{r['name']}</b></td><td>{stock_badge(r['stock'])}</td>"
            f"<td class=num>UGX {fmt_price(r['price'])}</td></tr>"
            for r in rows
        )
        table = (
            "<table class=table><thead><tr><th>Medicine</th><th>Availability</th>"
            f"<th class=num>Price</th></tr></thead><tbody>{items}</tbody></table>"
            if rows else "<p class=empty>No medicines match your search.</p>"
        )
        # [V-02] Server-side template injection + [V-06] reflected XSS:
        # the search term is pasted into the template source itself.
        html = page(
            "<div class=pagehead><h2>Medicines</h2>"
            "<p>Live stock levels and prices at our pharmacy.</p></div><div class=card>"
            "<form class=searchbar><input name=q placeholder='Search by name'>"
            "<button>Search</button></form>"
            + (f"<p class=results-for>Results for: {q}</p>" if q else "")
            + table + "</div>"
        )
        return render_template_string(html)

    @app.route("/prescriptions/<int:pid>")
    def prescription(pid):
        if "user_id" not in session:
            return redirect("/login")
        # [V-07] IDOR: any logged-in user can read any prescription by changing the ID.
        row = db().execute("SELECT * FROM prescriptions WHERE id = ?", (pid,)).fetchone()
        if row is None:
            return "Not found", 404
        return render_template_string(
            page(
                """<div class="pagehead"><a href="/">← Back to dashboard</a></div>
            <div class="card"><span class="badge">Active</span>
            <h2>Prescription #{{ p.id }}</h2><dl class="rx">
            <dt>Medicine</dt><dd><b>{{ p.drug }}</b></dd>
            <dt>Dosage</dt><dd>{{ p.dosage }}</dd>
            <dt>Patient notes</dt><dd>{{ p.notes }}</dd></dl></div>"""
            ),
            p=row,
        )

    @app.route("/messages", methods=["GET", "POST"])
    def messages():
        if "user_id" not in session:
            return redirect("/login")
        # [V-11] No CSRF token on this state-changing form.
        sent = request.method == "POST"
        if sent:
            db().execute(
                "INSERT INTO messages (user_id, body) VALUES (?, ?)",
                (session["user_id"], request.form.get("body", "")),
            )
            db().commit()
        return render_template_string(
            page(
                """<div class="card narrow"><h2>Message the pharmacist</h2>
            <p class="muted">A licensed pharmacist will reply within one working day.</p>
            {% if sent %}<div class="alert alert-success">Message sent.
            We'll get back to you soon.</div>{% endif %}
            <form method="post" class="stack"><div class="field">
            <label for="body">Your message</label><textarea id="body" name="body"></textarea>
            </div><button>Send message</button></form></div>"""
            ),
            sent=sent,
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
            page(
                """<div class="pagehead"><h2>Patient inbox</h2>
            <p>{{ rows|length }} message{{ '' if rows|length == 1 else 's' }}</p></div>
            <div class="card">{% for m in rows %}<div class="msg">
            <div class="avatar">{{ m.username[:1] }}</div>
            <div><b>{{ m.username }}</b><br>{{ m.body|safe }}</div></div>
            {% else %}<p class="empty">No messages yet.</p>{% endfor %}</div>"""
            ),
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
        return render_template_string(
            page(
                """<div class="pagehead"><h2>Network check</h2>
            <p>Result of pinging <b>{{ host }}</b></p></div>
            <div class="card"><pre class="terminal">{{ result }}</pre></div>"""
            ),
            host=host,
            result=out.stdout + out.stderr,
        )

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
        return render_template_string(
            page(
                """<div class="card narrow"><div class="alert alert-success">
            Imported {{ count }} medicines.</div>
            <a class="btn" href="/search">View medicines</a></div>"""
            ),
            count=len(records),
        )

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
