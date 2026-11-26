"""AegisAI Lab Site 2 - intentionally vulnerable local Flask app (port 5001).

FOR DEFENSIVE TRAINING ONLY. Binds to 127.0.0.1 and is never exposed publicly.
"""

import os
import sqlite3
from pathlib import Path

from flask import Flask, Response, make_response, redirect, render_template_string, request

app = Flask(__name__)

BASE = Path(__file__).resolve().parent
SANDBOX = BASE / "lab_files"
SANDBOX.mkdir(exist_ok=True)
(SANDBOX / "notes.txt").write_text("AegisAI lab note - public\n", encoding="utf-8")

DEBUG_TOKEN = "DEMO_FAKE_DEBUG_TOKEN_NOT_REAL"
ADMIN_PASSWORD = "DEMO_FAKE_PASSWORD_NOT_REAL"
ORDERS = {
    "1": {"user": "alice", "item": "Laptop", "total": 1200},
    "2": {"user": "bob", "item": "Phone", "total": 800},
    "3": {"user": "carol", "item": "Server", "total": 4500},
}

INDEX = """
<h1>AegisAI LAB SITE 2</h1>
<p>Intentionally vulnerable target for DAST demonstration (localhost only).</p>
<ul>
  <li><a href="/api/search?q=hello">/api/search?q=</a> - reflected XSS</li>
  <li><a href="/api/user?name=alice">/api/user?name=</a> - SQL injection</li>
  <li><a href="/api/order?id=1">/api/order?id=</a> - IDOR</li>
  <li><a href="/download?file=notes.txt">/download?file=</a> - path traversal</li>
  <li><a href="/greet?name=friend">/greet?name=</a> - SSTI</li>
  <li><a href="/redirect?url=https://example.com">/redirect?url=</a> - open redirect</li>
  <li><a href="/debug">/debug</a> - information disclosure</li>
  <li><a href="/login">/login</a> - weak auth / insecure cookie</li>
</ul>
"""


@app.route("/")
def index():
    return INDEX


@app.route("/api/search")
def search():
    q = request.args.get("q", "")
    template = f"<h2>Search results for: {q}</h2>"
    return render_template_string(template)


@app.route("/api/user")
def get_user():
    name = request.args.get("name", "alice")
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT, role TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice', 'admin')")
    conn.execute("INSERT INTO users VALUES (2, 'bob', 'user')")
    query = f"SELECT id, name, role FROM users WHERE name = '{name}'"
    try:
        rows = conn.execute(query).fetchall()
    except sqlite3.Error as exc:
        return {"error": str(exc)}, 500
    return {"results": rows}


@app.route("/api/order")
def get_order():
    order_id = request.args.get("id", "1")
    return ORDERS.get(order_id, {"error": "not found"})


@app.route("/download")
def download():
    name = request.args.get("file", "notes.txt")
    path = SANDBOX / name
    try:
        return Response(path.read_text(encoding="utf-8"), mimetype="text/plain")
    except OSError:
        return "file not found", 404


@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    template = "<h1>Hello " + name + "!</h1>"
    return render_template_string(template)


@app.route("/redirect")
def open_redirect():
    return redirect(request.args.get("url", "/"))


@app.route("/debug")
def debug():
    return {
        "debug_token": DEBUG_TOKEN,
        "admin_password": ADMIN_PASSWORD,
        "env": dict(os.environ),
    }


@app.route("/login")
def login():
    html = """
    <form method="post" action="/login">
      <input name="username" placeholder="username">
      <input name="password" type="password" placeholder="password">
      <button type="submit">Login</button>
    </form>
    """
    resp = make_response(html)
    resp.set_cookie("session", "insecure-session-value")
    return resp


@app.route("/login", methods=["POST"])
def do_login():
    if (request.form.get("username") == "admin"
            and request.form.get("password") == ADMIN_PASSWORD):
        return "Welcome admin"
    return "Invalid credentials", 401


@app.route("/transfer", methods=["POST"])
def transfer():
    return {"status": "ok", "from": request.form.get("from"), "to": request.form.get("to"),
            "amount": request.form.get("amount"), "csrf_protected": False}


HIDDEN_FILES = {
    "/.env": "APP_ENV=lab\nDEBUG=true\nSECRET=dummy-lab-secret-not-real\n",
    "/.git/config": "[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
    "/backup.sql": "-- lab dump\nCREATE TABLE users (id INTEGER, name TEXT, role TEXT);\n",
    "/config.yml": "debug: true\nadmin_token: lab_only_dummy\n",
}


@app.route("/.env")
@app.route("/.git/config")
@app.route("/backup.sql")
@app.route("/config.yml")
def hidden_file():
    return Response(HIDDEN_FILES.get(request.path, ""), mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
