"""
VAPT Scanner - Automated Vulnerability Assessment Script
==========================================================
A lightweight Python tool built for this internship project to perform
basic Vulnerability Assessment and Penetration Testing (VAPT) checks
against the sample target application (DummyBank, running locally).

Checks performed:
  1. SQL Injection (login form)
  2. Reflected XSS
  3. Broken Access Control / IDOR
  4. Sensitive file exposure
  5. Missing HTTP security headers
  6. Weak / default credentials (brute force simulation)

Output: prints results to console AND writes a structured report to
results/scan_report.txt for inclusion in the final documentation.
"""

import requests
import datetime

BASE_URL = "http://127.0.0.1:5000"
REPORT_PATH = "../results/scan_report.txt"

findings = []


def log(title, severity, detail, evidence=""):
    findings.append({
        "title": title,
        "severity": severity,
        "detail": detail,
        "evidence": evidence
    })
    print(f"[{severity}] {title}\n    -> {detail}\n")


def test_sql_injection():
    payload = {"username": "admin' OR '1'='1", "password": "anything"}
    r = requests.post(f"{BASE_URL}/login", data=payload, allow_redirects=False)
    if r.status_code in (301, 302) and "/welcome" in r.headers.get("Location", ""):
        log(
            "SQL Injection in Login Form",
            "CRITICAL",
            "The login form is vulnerable to SQL Injection. Using payload "
            "admin' OR '1'='1 as the username bypassed authentication entirely.",
            evidence=f"POST /login -> {r.status_code} redirect to {r.headers.get('Location')}"
        )
    else:
        log("SQL Injection in Login Form", "INFO", "Payload did not bypass login.", "")


def test_xss():
    payload = "<script>alert('XSS')</script>"
    r = requests.get(f"{BASE_URL}/welcome", params={"user": payload})
    if payload in r.text:
        log(
            "Reflected Cross-Site Scripting (XSS)",
            "HIGH",
            "The /welcome endpoint reflects the 'user' parameter into the HTML "
            "response without sanitization or output encoding, allowing arbitrary "
            "JavaScript execution in a victim's browser.",
            evidence=f"GET /welcome?user={payload}  -> payload reflected unescaped in response body"
        )
    else:
        log("Reflected XSS", "INFO", "Payload was sanitized/escaped.", "")


def test_idor():
    hits = []
    for uid in range(1, 6):
        r = requests.get(f"{BASE_URL}/account/{uid}")
        if r.status_code == 200:
            hits.append((uid, r.text.strip()))
    if hits:
        evidence_lines = "\n".join(f"  account/{uid} -> {body[:90]}..." for uid, body in hits)
        log(
            "Broken Access Control / Insecure Direct Object Reference (IDOR)",
            "HIGH",
            "Account details (including balances and admin flags) for ANY user can "
            "be viewed simply by changing the numeric ID in the URL, with no login "
            "or ownership check performed.",
            evidence=evidence_lines
        )


def test_sensitive_file_exposure():
    r = requests.get(f"{BASE_URL}/backup/dummybank.db")
    if r.status_code == 200 and len(r.content) > 0:
        log(
            "Sensitive Data Exposure - Database Backup Accessible",
            "CRITICAL",
            "The raw SQLite database file is directly downloadable from a "
            "predictable URL, exposing all user credentials and balances.",
            evidence=f"GET /backup/dummybank.db -> 200 OK, {len(r.content)} bytes returned"
        )


def test_security_headers():
    r = requests.get(f"{BASE_URL}/")
    required = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"]
    missing = [h for h in required if h not in r.headers]
    if missing:
        log(
            "Missing HTTP Security Headers",
            "MEDIUM",
            "The application does not set important security headers, increasing "
            "exposure to clickjacking, MIME-sniffing, and downgrade attacks.",
            evidence="Missing headers: " + ", ".join(missing)
        )


def test_weak_credentials():
    common_creds = [
        ("admin", "admin123"),
        ("test", "test"),
        ("admin", "admin"),
        ("john_doe", "password1"),
    ]
    valid = []
    for u, p in common_creds:
        r = requests.post(f"{BASE_URL}/login", data={"username": u, "password": p}, allow_redirects=False)
        if r.status_code in (301, 302):
            valid.append((u, p))
    if valid:
        evidence = "\n".join(f"  {u} / {p}  -> login succeeded" for u, p in valid)
        log(
            "Weak / Default Credentials",
            "HIGH",
            "Several accounts (including an administrator account) use common, "
            "easily guessable passwords with no account lockout or rate limiting "
            "in place, making brute-force attacks practical.",
            evidence=evidence
        )


def write_report():
    with open(REPORT_PATH, "w") as f:
        f.write("VAPT SCAN REPORT - DummyBank Sample Target\n")
        f.write(f"Generated: {datetime.datetime.now().isoformat()}\n")
        f.write(f"Target: {BASE_URL}\n")
        f.write("=" * 70 + "\n\n")
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        for item in sorted(findings, key=lambda x: sev_order.get(x["severity"], 9)):
            if item["severity"] == "INFO":
                continue
            f.write(f"[{item['severity']}] {item['title']}\n")
            f.write(f"Description: {item['detail']}\n")
            if item["evidence"]:
                f.write(f"Evidence:\n{item['evidence']}\n")
            f.write("-" * 70 + "\n\n")
    print(f"\nFull report written to {REPORT_PATH}")


if __name__ == "__main__":
    print(f"Starting VAPT scan against {BASE_URL}\n" + "=" * 50)
    test_sql_injection()
    test_xss()
    test_idor()
    test_sensitive_file_exposure()
    test_security_headers()
    test_weak_credentials()
    write_report()
