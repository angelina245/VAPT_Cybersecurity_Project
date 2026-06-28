"""
DummyBank - REMEDIATED Version
================================
This is the fixed version of the sample target application, showing how
each vulnerability identified during the VAPT assessment was remediated.
Included for documentation purposes only.
"""

import sqlite3
import secrets
from flask import Flask, request, render_template_string, redirect, session, abort
from markupsafe import escape

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
DB_PATH = "dummybank_secure.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            balance REAL,
            is_admin INTEGER
        )
    """)
    # FIX 5: passwords should be hashed in production (werkzeug.security.generate_password_hash)
    # kept simple here since this is only a demo of the other fixes
    sample_users = [
        (1, "admin", "Sx9!kP2#mQ7z", 999999.00, 1),
        (2, "john_doe", "Tr4@vL8$nY1w", 4520.75, 0),
    ]
    cur.executemany("INSERT INTO users VALUES (?,?,?,?,?)", sample_users)
    conn.commit()
    conn.close()


# FIX 1 (SQL Injection): use parameterized queries instead of string concatenation
# FIX 6 (Weak credentials): strong randomly-generated passwords, account lockout
LOGIN_PAGE = """
<h2>DummyBank Login (Secure)</h2>
<form method="POST">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <input type="submit" value="Login">
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
"""

login_attempts = {}

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # FIX 6: basic rate limiting / lockout after repeated failures
        attempts = login_attempts.get(username, 0)
        if attempts >= 5:
            return render_template_string(LOGIN_PAGE, error="Account temporarily locked. Try later.")

        # FIX 1: parameterized query - prevents SQL injection
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        result = cur.fetchone()
        conn.close()

        if result:
            login_attempts[username] = 0
            session["user_id"] = result[0]   # FIX 3: real session instead of trusting URL params
            session["username"] = result[1]
            return redirect("/welcome")
        login_attempts[username] = attempts + 1
        return render_template_string(LOGIN_PAGE, error="Invalid credentials")
    return render_template_string(LOGIN_PAGE, error=None)


# FIX 2 (XSS): autoescaping left ON (no |safe), Flask/Jinja2 escapes by default
WELCOME_PAGE = "<h2>Welcome, {{ user }}!</h2><p>Your dashboard is loading...</p>"

@app.route("/welcome")
def welcome():
    if "username" not in session:
        return redirect("/login")
    return render_template_string(WELCOME_PAGE, user=session["username"])


# FIX 3 (Broken Access Control / IDOR): require login + verify ownership
@app.route("/account/<int:user_id>")
def account(user_id):
    if "user_id" not in session:
        return redirect("/login")
    if session["user_id"] != user_id and not _is_admin(session["user_id"]):
        abort(403)  # Forbidden - can't view someone else's account
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username, balance FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        return f"<h3>Account #{user_id}</h3>Username: {escape(row[0])}<br>Balance: ${row[1]}"
    return "No such account", 404


def _is_admin(user_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return bool(row and row[0])


# FIX 4 (Sensitive data exposure): backup route removed entirely.
# Database files / backups must never be served through the web app.


# FIX 5 (Missing security headers): add them to every response
@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


@app.route("/")
def index():
    return """
    <h1>DummyBank (Secure Version)</h1>
    <ul><li><a href="/login">Login</a></li></ul>
    """


if __name__ == "__main__":
    init_db()
    print("Secure DummyBank running at http://127.0.0.1:5001")
    app.run(host="127.0.0.1", port=5001)
