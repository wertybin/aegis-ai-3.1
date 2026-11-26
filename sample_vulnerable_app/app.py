import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Intentional weakness 1: Hardcoded secret key (obviously fake demo value)
API_SECRET_KEY = "DEMO_FAKE_HARDCODED_SECRET_DO_NOT_USE"


def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, username TEXT, role TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'admin', 'superuser')")
    return conn


@app.route("/")
def index():
    # Demo landing page; the address is supplied by the user, never bundled.
    return render_template_string(
        """
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="utf-8" />
          <title>AegisAI Demo Target</title>
          <style>
            body { background:#0b0b12; color:#e5e7eb; font-family:ui-monospace,Consolas,monospace; padding:40px; }
            h1 { color:#c084fc; } a { color:#6ee7b7; } code { color:#fca5a5; }
            li { margin:10px 0; }
          </style>
        </head>
        <body>
          <h1>AegisAI Demo Target</h1>
          <p>This application is <b>intentionally vulnerable</b>. Use the AegisAI panel to
          scan the localhost address you configured yourself.</p>
          <ul>
            <li><a href="/api/user?username=admin">/api/user?username=admin</a> &mdash; SQL Injection (A03)</li>
            <li><a href="/greet?name=Aegis">/greet?name=Aegis</a> &mdash; Reflected XSS (A03)</li>
            <li><a href="/greet?name=%3Cscript%3Ealert(1)%3C/script%3E">/greet?name=&lt;script&gt;alert(1)&lt;/script&gt;</a> &mdash; live XSS test</li>
          </ul>
          <p>Embedded secret: <code>API_SECRET_KEY</code> (hardcoded in source).</p>
        </body>
        </html>
        """
    )


@app.route("/api/user")
def get_user():
    username = request.args.get("username", "")
    conn = get_db()
    # Intentional weakness 2: Unparameterized SQL query
    query = f"SELECT id, username, role FROM users WHERE username = '{username}'"
    cursor = conn.execute(query)
    return {"results": cursor.fetchall()}


@app.route("/greet")
def greet():
    name = request.args.get("name", "Guest")
    # Intentional weakness 3: Unescaped template string (XSS risk)
    template = f"<h1>Welcome back, {name}!</h1>"
    return render_template_string(template)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
