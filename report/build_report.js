const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, LevelFormat, HeadingLevel, BorderStyle,
  WidthType, ShadingType, VerticalAlign, PageNumber, PageBreak,
  TableOfContents, TabStopType, TabStopPosition
} = require("docx");
const fs = require("fs");

const border = { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" };
const borders = { top: border, bottom: border, left: border, right: border };

const sevColor = {
  "CRITICAL": "C00000",
  "HIGH": "E36C09",
  "MEDIUM": "BF8F00",
  "LOW": "548235",
};

function H1(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(text)] });
}
function H2(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(text)] });
}
function P(text, opts = {}) {
  return new Paragraph({ spacing: { after: 160 }, children: [new TextRun({ text, ...opts })] });
}
function bullet(text) {
  return new Paragraph({
    numbering: { reference: "bullets", level: 0 },
    spacing: { after: 80 },
    children: [new TextRun(text)],
  });
}
function numbered(text) {
  return new Paragraph({
    numbering: { reference: "numbers", level: 0 },
    spacing: { after: 80 },
    children: [new TextRun(text)],
  });
}
function codeBlock(lines) {
  return new Paragraph({
    spacing: { after: 200, before: 100 },
    shading: { fill: "F2F2F2", type: ShadingType.CLEAR },
    children: lines.split("\n").map((l, i) =>
      new TextRun({ text: l, font: "Consolas", size: 18, break: i === 0 ? 0 : 1 })
    ),
  });
}

function cell(text, opts = {}) {
  return new TableCell({
    borders,
    width: opts.width || { size: 2340, type: WidthType.DXA },
    shading: opts.shading ? { fill: opts.shading, type: ShadingType.CLEAR } : undefined,
    verticalAlign: VerticalAlign.CENTER,
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    children: [new Paragraph({
      children: [new TextRun({ text, bold: opts.bold || false, color: opts.color })]
    })],
  });
}

const findings = [
  {
    id: "F-01", title: "SQL Injection in Login Form", severity: "CRITICAL",
    cvss: "9.8 (Critical)",
    desc: "The login endpoint (/login) builds its SQL query by directly concatenating the username and password fields into a query string. This allows an attacker to inject SQL syntax and alter the query's logic.",
    impact: "An attacker can bypass authentication entirely without knowing any valid password, gaining access as any user, including the administrator account.",
    poc: "POST /login\nusername = admin' OR '1'='1\npassword = anything\n\nResult: HTTP 302 redirect to /welcome (login succeeded without a valid password)",
    remediation: "Use parameterized queries / prepared statements for all database access (e.g. cursor.execute(\"SELECT * FROM users WHERE username=? AND password=?\", (username, password))). Never build SQL with string concatenation or f-strings using user input.",
  },
  {
    id: "F-02", title: "Sensitive Data Exposure - Database Backup Accessible", severity: "CRITICAL",
    cvss: "9.1 (Critical)",
    desc: "The route /backup/dummybank.db serves the raw SQLite database file containing all user credentials and account balances, with no authentication required.",
    impact: "Any unauthenticated visitor can download the entire user database, exposing usernames, passwords, and financial data.",
    poc: "GET /backup/dummybank.db\nResult: HTTP 200 OK, full database file (8,192 bytes) returned",
    remediation: "Never expose database files, backups, or configuration files through web-accessible routes. Store backups outside the web root and restrict access at the filesystem/server level.",
  },
  {
    id: "F-03", title: "Reflected Cross-Site Scripting (XSS)", severity: "HIGH",
    cvss: "7.4 (High)",
    desc: "The /welcome endpoint reflects the 'user' query parameter directly into the HTML response with auto-escaping explicitly disabled (the |safe filter), allowing injected JavaScript to execute in the victim's browser.",
    impact: "An attacker can craft a malicious link that, when clicked by a victim, executes arbitrary JavaScript in the context of the site - enabling session hijacking, credential theft, or defacement.",
    poc: "GET /welcome?user=<script>alert('XSS')</script>\nResult: the script tag is reflected unescaped in the page source and executes in the browser",
    remediation: "Remove the |safe filter and rely on Jinja2's default auto-escaping. Validate and encode all user-supplied input before rendering it in HTML. Implement a Content-Security-Policy header as defense in depth.",
  },
  {
    id: "F-04", title: "Broken Access Control / Insecure Direct Object Reference (IDOR)", severity: "HIGH",
    cvss: "8.1 (High)",
    desc: "The /account/<id> endpoint returns account details (username, balance, admin flag) for any numeric ID with no session check or ownership verification.",
    impact: "Any visitor can enumerate account IDs (1, 2, 3...) to view every customer's balance and administrative status without logging in.",
    poc: "GET /account/1, /account/2, /account/3, /account/4\nResult: all return HTTP 200 with full account details, no authentication required",
    remediation: "Require an authenticated session for all account routes, and verify that the logged-in user's ID matches the requested resource (or that they hold an explicit administrative role) before returning data.",
  },
  {
    id: "F-05", title: "Weak / Default Credentials", severity: "HIGH",
    cvss: "7.5 (High)",
    desc: "Several accounts, including the administrator account, use common and easily guessable passwords (e.g. admin123, test, password1) with no account lockout or rate-limiting on the login form.",
    impact: "Attackers can use automated brute-force or credential-stuffing attacks to compromise accounts quickly, including the privileged admin account.",
    poc: "Tried common credential pairs against /login:\nadmin / admin123 -> success\ntest / test -> success\njohn_doe / password1 -> success",
    remediation: "Enforce a strong password policy, hash passwords with a strong algorithm (e.g. bcrypt/argon2), and implement account lockout or rate-limiting after repeated failed login attempts.",
  },
  {
    id: "F-06", title: "Missing HTTP Security Headers", severity: "MEDIUM",
    cvss: "5.3 (Medium)",
    desc: "The application does not set Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, or Strict-Transport-Security headers on any response.",
    impact: "Absence of these headers increases exposure to clickjacking, MIME-type sniffing attacks, and protocol downgrade attacks.",
    poc: "GET /\nResult: response headers contain none of the four security headers checked",
    remediation: "Add security headers to every response (e.g. via an after_request hook or a library such as flask-talisman), including CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and HSTS.",
  },
];

const tocChildren = [];

const doc = new Document({
  styles: {
    default: { document: { run: { font: "Arial", size: 22 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 32, bold: true, font: "Arial", color: "1F3864" },
        paragraph: { spacing: { before: 360, after: 200 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 26, bold: true, font: "Arial", color: "2E75B6" },
        paragraph: { spacing: { before: 240, after: 160 }, outlineLevel: 1 } },
    ],
  },
  numbering: {
    config: [
      { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "numbers", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    ],
  },
  sections: [
    // ---------------- TITLE PAGE ----------------
    {
      properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } } },
      children: [
        new Paragraph({ spacing: { before: 2000 }, alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "VULNERABILITY ASSESSMENT AND", bold: true, size: 44, color: "1F3864" })] }),
        new Paragraph({ alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "PENETRATION TESTING (VAPT)", bold: true, size: 44, color: "1F3864" })] }),
        new Paragraph({ spacing: { before: 200, after: 600 }, alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "Project Report", size: 32, color: "2E75B6" })] }),
        new Paragraph({ spacing: { before: 1200 }, alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "Cybersecurity Internship Project", size: 24, italics: true })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 200 },
          children: [new TextRun({ text: "Target Application: DummyBank (Sample/Dummy Web Application)", size: 22 })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 1600 },
          children: [new TextRun({ text: "Submitted by: [Your Name]", size: 22 })] }),
        new Paragraph({ alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "Internship Domain: Cybersecurity", size: 22 })] }),
        new Paragraph({ alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "Date: July 2026", size: 22 })] }),
      ],
    },
    // ---------------- TABLE OF CONTENTS ----------------
    {
      properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } } },
      children: [
        H1("Table of Contents"),
        new TableOfContents("Table of Contents", { hyperlink: true, headingStyleRange: "1-2" }),
        new Paragraph({ children: [new PageBreak()] }),
      ],
    },
    // ---------------- MAIN CONTENT ----------------
    {
      properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } } },
      headers: {
        default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT,
          children: [new TextRun({ text: "VAPT Project Report", size: 16, color: "808080" })] })] }),
      },
      footers: {
        default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER,
          children: [new TextRun({ children: [PageNumber.CURRENT], size: 18 })] })] }),
      },
      children: [
        H1("1. Introduction"),
        P("This report documents a Vulnerability Assessment and Penetration Testing (VAPT) exercise carried out as part of a self-paced cybersecurity internship project. The objective was to identify, exploit, and remediate common web application security vulnerabilities using a controlled, locally-hosted sample application built specifically for this exercise."),
        P("All testing was performed exclusively against a purpose-built dummy web application ('DummyBank') running on a local environment, using sample/dummy data. No real systems, networks, or third-party assets were involved or scanned at any point."),

        H1("2. Objective"),
        bullet("Build a sample web application containing realistic, common security vulnerabilities."),
        bullet("Perform systematic vulnerability assessment and penetration testing against it."),
        bullet("Identify vulnerabilities aligned with the OWASP Top 10 categories."),
        bullet("Document each finding with evidence, severity rating, business impact, and remediation guidance."),
        bullet("Implement and verify fixes for every identified vulnerability."),

        H1("3. Scope"),
        P("Target: DummyBank - a locally hosted Flask web application created specifically for this project, simulating a simple online banking portal with login, account viewing, and file-serving functionality."),
        P("Testing type: Black-box / grey-box manual and scripted testing of the application's HTTP endpoints. No infrastructure, network, or third-party scanning was performed."),
        P("Data used: 100% dummy/sample data (fictional usernames, passwords, and balances) - no real personal or financial data was used at any stage."),

        H1("4. Tools and Technologies Used"),
        new Table({
          width: { size: 9360, type: WidthType.DXA },
          columnWidths: [3120, 6240],
          rows: [
            new TableRow({ children: [cell("Tool / Technology", { bold: true, shading: "1F3864", color: "FFFFFF", width: { size: 3120, type: WidthType.DXA } }),
                                       cell("Purpose", { bold: true, shading: "1F3864", color: "FFFFFF", width: { size: 6240, type: WidthType.DXA } })] }),
            new TableRow({ children: [cell("Python 3 / Flask", { width: { size: 3120, type: WidthType.DXA } }), cell("Building the intentionally vulnerable sample target application", { width: { size: 6240, type: WidthType.DXA } })] }),
            new TableRow({ children: [cell("Python requests library", { width: { size: 3120, type: WidthType.DXA } }), cell("Writing a custom automated VAPT scanning script", { width: { size: 6240, type: WidthType.DXA } })] }),
            new TableRow({ children: [cell("SQLite3", { width: { size: 3120, type: WidthType.DXA } }), cell("Sample database storing dummy user records", { width: { size: 6240, type: WidthType.DXA } })] }),
            new TableRow({ children: [cell("cURL", { width: { size: 3120, type: WidthType.DXA } }), cell("Manual verification of vulnerabilities and fixes via raw HTTP requests", { width: { size: 6240, type: WidthType.DXA } })] }),
            new TableRow({ children: [cell("OWASP Top 10 (reference)", { width: { size: 3120, type: WidthType.DXA } }), cell("Industry-standard classification used to categorize findings", { width: { size: 6240, type: WidthType.DXA } })] }),
          ],
        }),
        new Paragraph({ text: "" }),

        H1("5. Methodology"),
        numbered("Reconnaissance: Reviewed the application's available pages and endpoints (/, /login, /welcome, /account/<id>, /backup/dummybank.db)."),
        numbered("Vulnerability Identification: Manually and programmatically tested each endpoint for common OWASP Top 10 weaknesses (Injection, Broken Authentication, Sensitive Data Exposure, Broken Access Control, Security Misconfiguration)."),
        numbered("Exploitation / Proof of Concept: Built a custom Python scanning script (vapt_scanner.py) to send crafted payloads and confirm exploitability, capturing evidence for each successful test."),
        numbered("Risk Rating: Assigned a severity (Critical/High/Medium/Low) and approximate CVSS score to each finding based on impact and exploitability."),
        numbered("Remediation: Rewrote the vulnerable code to fix each issue (parameterized queries, output encoding, session-based access control, removing exposed files, adding security headers, credential hardening)."),
        numbered("Verification: Re-ran the same tests against the fixed application to confirm each vulnerability was successfully remediated."),

        H1("6. Target Application Overview"),
        P("DummyBank is a minimal Flask application simulating an online banking portal, created solely for this exercise. It exposes four notable endpoints: a login form, a post-login welcome page, an account details page, and (deliberately, for demonstration) a database backup download route. The application was seeded with dummy users including an 'admin' account, none of which represent real individuals."),

        H1("7. Findings Summary"),
        new Table({
          width: { size: 9360, type: WidthType.DXA },
          columnWidths: [1000, 4760, 1900, 1700],
          rows: [
            new TableRow({ children: [
              cell("ID", { bold: true, shading: "1F3864", color: "FFFFFF", width: { size: 1000, type: WidthType.DXA } }),
              cell("Vulnerability", { bold: true, shading: "1F3864", color: "FFFFFF", width: { size: 4760, type: WidthType.DXA } }),
              cell("Severity", { bold: true, shading: "1F3864", color: "FFFFFF", width: { size: 1900, type: WidthType.DXA } }),
              cell("CVSS (approx.)", { bold: true, shading: "1F3864", color: "FFFFFF", width: { size: 1700, type: WidthType.DXA } }),
            ]}),
            ...findings.map(f => new TableRow({ children: [
              cell(f.id, { width: { size: 1000, type: WidthType.DXA } }),
              cell(f.title, { width: { size: 4760, type: WidthType.DXA } }),
              cell(f.severity, { bold: true, color: sevColor[f.severity], width: { size: 1900, type: WidthType.DXA } }),
              cell(f.cvss, { width: { size: 1700, type: WidthType.DXA } }),
            ]})),
          ],
        }),
        new Paragraph({ text: "" }),

        H1("8. Detailed Findings, Evidence and Remediation"),
        ...findings.flatMap(f => ([
          H2(`${f.id}: ${f.title}  [${f.severity}]`),
          P("Description:", { bold: true }),
          P(f.desc),
          P("Impact:", { bold: true }),
          P(f.impact),
          P("Proof of Concept / Evidence:", { bold: true }),
          codeBlock(f.poc),
          P("Remediation:", { bold: true }),
          P(f.remediation),
        ])),

        H1("9. Remediation Verification"),
        P("After implementing fixes for every finding in a secure version of the application (app_secure.py), each test case was re-executed against the patched application:"),
        bullet("SQL Injection payload (admin' OR '1'='1) -> login correctly rejected (HTTP 200, 'Invalid credentials')."),
        bullet("Account access without login (/account/1) -> correctly redirected to login (HTTP 302)."),
        bullet("XSS payload in /welcome -> route now requires authentication and auto-escaping is enabled; payload no longer reflected unescaped."),
        bullet("Database backup route -> removed entirely; endpoint no longer exists."),
        bullet("HTTP response headers -> Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and Strict-Transport-Security headers all present and correctly set."),
        bullet("Login attempts now tracked per-account with lockout after 5 consecutive failures, mitigating brute-force attacks."),

        H1("10. Conclusion"),
        P("This project demonstrated a complete, hands-on VAPT lifecycle: building a deliberately vulnerable sample application, systematically identifying six distinct vulnerabilities spanning Critical, High, and Medium severity (including SQL Injection, Cross-Site Scripting, Broken Access Control, Sensitive Data Exposure, Weak Credentials, and Missing Security Headers), documenting each with reproducible evidence, and implementing and verifying fixes for all of them."),
        P("The exercise reinforced practical understanding of the OWASP Top 10, secure coding practices (parameterized queries, output encoding, session-based authorization, security headers), and the importance of a structured assessment-to-remediation workflow in real-world application security work."),

        H1("11. References"),
        bullet("OWASP Top 10 - https://owasp.org/www-project-top-ten/"),
        bullet("OWASP Testing Guide - https://owasp.org/www-project-web-security-testing-guide/"),
        bullet("Flask Security Considerations - https://flask.palletsprojects.com/en/stable/security/"),
        bullet("CVSS v3.1 Calculator - https://www.first.org/cvss/calculator/3.1"),
      ],
    },
  ],
});

Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync("/home/claude/VAPT_Project/report/VAPT_Project_Report.docx", buffer);
  console.log("Report generated.");
});
