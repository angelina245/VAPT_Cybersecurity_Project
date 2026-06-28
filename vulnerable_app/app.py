"""
DummyBank - Intentionally Vulnerable Web Application
======================================================
Built ONLY as a sample/target application for a Vulnerability Assessment
and Penetration Testing (VAPT) internship project. Uses fake/dummy data.

DO NOT deploy this code anywhere real. It deliberately contains
common web application vulnerabilities (OWASP Top 10 style) so they can
be discovered and documented as part of a security assessment exercise.
"""

import sqlite3
from flask import Flask, request, render_template_string, redirect, make_response

app = Flask(__name__)
DB_PATH = "dummybank.db"

# ---------------------------------------------------------------------------
# Sample / dummy data setup
# ---------------------------------------------------------------------------
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
    # Dummy users - note the weak/default credentials (a real finding)
    sample_users = [
        (1, "admin", "admin123", 999999.00, 1),
        (2, "john_doe", "password1", 4520.75, 0),
        (3, "jane_smith", "qwerty123", 1899.10, 0),
        (4, "test", "test", 100.00, 0),
    ]
    cur.executemany("INSERT INTO users VALUES (?,?,?,?,?)", sample_users)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# VULNERABILITY 1: SQL Injection (login form built with string concatenation)
# ---------------------------------------------------------------------------
LOGIN_PAGE = """
<h2>DummyBank Login</h2>
<form method="POST">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <input type="submit" value="Login">
</form>
{% if error %}<p style="color:red">{{ error|safe }}</p>{% endif %}
"""

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABLE: raw string concatenation -> classic SQL Injection
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            cur.execute(query)
            result = cur.fetchone()
        except Exception as e:
            conn.close()
            return render_template_string(LOGIN_PAGE, error=f"DB Error: {e}")
        conn.close()

        if result:
            resp = make_response(redirect("/welcome?user=" + username))
            return resp
        return render_template_string(LOGIN_PAGE, error="Invalid credentials")
    return render_template_string(LOGIN_PAGE, error=None)


# ---------------------------------------------------------------------------
# VULNERABILITY 2: Reflected Cross-Site Scripting (XSS) - unsanitized output
# ---------------------------------------------------------------------------
WELCOME_PAGE = """
<h2>Welcome, {{ user|safe }}!</h2>
<p>Your dashboard is loading...</p>
"""

@app.route("/welcome")
def welcome():
    user = request.args.get("user", "Guest")
    # VULNERABLE: user input echoed back without escaping (|safe disables auto-escaping)
    return render_template_string(WELCOME_PAGE, user=user)


# ---------------------------------------------------------------------------
# VULNERABILITY 3: Broken Access Control / Insecure Direct Object Reference
# ---------------------------------------------------------------------------
@app.route("/account/<int:user_id>")
def account(user_id):
    # VULNERABLE: no authentication/session check, no ownership check.
    # Anyone can view any account by guessing/incrementing the ID.
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username, balance, is_admin FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        return f"<h3>Account #{user_id}</h3>Username: {row[0]}<br>Balance: ${row[1]}<br>Admin: {row[2]}"
    return "No such account", 404


# ---------------------------------------------------------------------------
# VULNERABILITY 4: Sensitive data / directory exposure
# ---------------------------------------------------------------------------
@app.route("/backup/dummybank.db")
def leaked_backup():
    # VULNERABLE: database backup file exposed via predictable path
    try:
        with open(DB_PATH, "rb") as f:
            return f.read(), 200, {"Content-Type": "application/octet-stream"}
    except FileNotFoundError:
        return "Not found", 404


# ---------------------------------------------------------------------------
# VULNERABILITY 5: Missing security headers (checked, not exploited directly)
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    # No CSP, no X-Frame-Options, no X-Content-Type-Options set anywhere
    return """
    <h1>DummyBank (Sample VAPT Target)</h1>
    <ul>
      <li><a href="/login">Login</a></li>
      <li><a href="/account/1">View account #1 (try changing the number)</a></li>
    </ul>
    """


if __name__ == "__main__":
    init_db()
    print("DummyBank sample target running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000)
