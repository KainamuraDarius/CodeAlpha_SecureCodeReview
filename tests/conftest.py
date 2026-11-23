"""Fixtures that start either version of MediTrack with the same demo data.

Every test in test_findings.py runs twice: once against ``vulnerable`` (the
exploit must work) and once against ``secure`` (the exploit must fail).
"""

import re
import secrets
import sqlite3
from dataclasses import dataclass

import pytest
from flask.testing import FlaskClient

from secure import app as secure_app
from vulnerable import app as vulnerable_app

PASSWORDS = {
    "vulnerable": {"admin": "admin123", "alice": "alice-pass-1", "bob": "bob-pass-2"},
    "secure": {
        "admin": "Adm1n-" + secrets.token_urlsafe(12),
        "alice": "alice-long-passphrase",
        "bob": "bob-long-passphrase",
    },
}
TOKEN_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


@dataclass
class Target:
    name: str
    app: object
    client: FlaskClient
    db_path: str

    @property
    def vulnerable(self):
        return self.name == "vulnerable"

    def password(self, user):
        return PASSWORDS[self.name][user]

    def csrf(self, page="/login"):
        """Read the CSRF token from a form, the way a browser would submit it."""
        m = TOKEN_RE.search(self.client.get(page).get_data(as_text=True))
        return m.group(1) if m else ""

    def post(self, url, data, page=None, **kw):
        data = dict(data)
        data.setdefault("csrf_token", self.csrf(page or url.split("?")[0]))
        return self.client.post(url, data=data, **kw)

    def login(self, user, password=None, next_url=None):
        url = "/login" + (f"?next={next_url}" if next_url else "")
        return self.post(
            url, {"username": user, "password": password or self.password(user)}, page="/login"
        )

    def query(self, sql, *args):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(sql, args).fetchall()


@pytest.fixture(params=["vulnerable", "secure"])
def target(request, tmp_path):
    db_path = str(tmp_path / "meditrack.db")
    if request.param == "vulnerable":
        app = vulnerable_app.create_app(db_path)
    else:
        app = secure_app.create_app(
            {"DATABASE": db_path, "SECRET_KEY": secrets.token_hex(32),
             "SESSION_COOKIE_SECURE": False}
        )
        with sqlite3.connect(db_path) as conn:
            # Same ids as the vulnerable seed data: admin=1, alice=2, bob=3.
            for user, role in (("admin", "admin"), ("alice", "patient"), ("bob", "patient")):
                secure_app.create_user(conn, user, PASSWORDS["secure"][user], role)
            conn.executemany(
                "INSERT INTO prescriptions (user_id, drug, dosage, notes) VALUES (?, ?, ?, ?)",
                [(2, "Amoxicillin 250mg", "3x daily, 7 days", "Penicillin test negative"),
                 (3, "Metformin 500mg", "2x daily", "Type 2 diabetes, HbA1c 8.1%")],
            )
    app.config["TESTING"] = True
    return Target(request.param, app, app.test_client(), db_path)
