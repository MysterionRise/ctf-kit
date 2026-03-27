---
name: web
description: >-
  Solve CTF web security challenges: SQL injection, XSS, authentication
  bypass, SSTI, path traversal, and source code audit. Use when given a
  URL, web app source code, or HTTP traffic. Triggers: .php .html .js
  files, "SQL injection", "XSS", "SSTI", "LFI", "RFI", "cookie",
  "JWT", "robots.txt", "directory enumeration", http:// or https://
  targets. Tools: sqlmap, gobuster, ffuf, nikto, burpsuite.
  NOT for network packet analysis (use forensics).
---

# CTF Web

Analyze and solve web security challenges.

## When to Use

Use this command for challenges involving:

- Web applications
- SQL injection
- XSS vulnerabilities
- Authentication bypass
- API exploitation
- Source code analysis

## Bundled Scripts

- [check-tools.sh](scripts/check-tools.sh) — Verify required web tools are installed
- [run-gobuster.sh](scripts/run-gobuster.sh) — Directory enumeration with structured output. Outputs JSON with accessible paths, redirects, and forbidden paths.

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. **For directory/file enumeration** (outputs structured JSON):

   ```bash
   bash scripts/run-gobuster.sh http://target.com
   bash scripts/run-gobuster.sh http://target.com /path/to/wordlist.txt
   bash scripts/run-gobuster.sh http://target.com /path/to/wordlist.txt php,html,txt
   ```

   JSON output includes:
   - `accessible`: paths returning 200 (with size)
   - `redirects`: paths returning 3xx
   - `forbidden`: paths returning 403 (may indicate hidden content)
   - `suggestions`: which paths to investigate

3. For SQL injection:

   ```bash
   sqlmap -u "http://target.com/page?id=1" --dbs
   sqlmap -u "http://target.com/page?id=1" -D database -T table --dump
   ```

4. Manual testing checklist:
   - Check robots.txt, sitemap.xml
   - Look for .git, .svn, backup files
   - Test input fields for injection
   - Examine cookies and headers
   - View page source

## Common Vulnerabilities

| Vulnerability | Test Payload |
|--------------|--------------|
| SQL Injection | `' OR '1'='1` |
| XSS | `<script>alert(1)</script>` |
| Path Traversal | `../../../etc/passwd` |
| SSTI | `{{7*7}}` or `${7*7}` |
| Command Injection | `; id` or `\| id` |

## Team Roles

When using `/ctf-kit:team-solve` with a web challenge, the lead spawns 3 specialists.

**All web teammates require plan approval** before sending requests to the target.

| Role | Teammate Name | Focus | Tools | First Action |
|------|--------------|-------|-------|--------------|
| Recon & Enumeration | `web-recon` | Directory scanning, technology fingerprinting, hidden paths, backup files, robots.txt, source code review | gobuster, ffuf, `scripts/run-gobuster.sh`, curl | Check robots.txt, run gobuster, view page source, identify tech stack |
| Injection | `injection-tester` | SQLi, XSS, SSTI, command injection, path traversal, SSRF, deserialization | sqlmap, manual payloads, curl | Map input fields, test with common payloads from the patterns table above |
| Auth & Logic | `auth-analyst` | JWT manipulation, session handling, IDOR, privilege escalation, business logic flaws, API abuse | jwt_tool, curl, burp | Inspect cookies/tokens, test auth bypass, enumerate API endpoints |

### When to broadcast

- **Recon**: "Found admin panel at /admin" or "Technology: Flask with Jinja2 (SSTI likely)" — injection tester focuses there
- **Injection**: "SQLi confirmed on parameter X, dumping DB" — auth analyst checks for stored creds
- **Auth**: "JWT uses none algorithm" or "IDOR on user ID" — others test with escalated access
- **Any**: "Found the flag" — immediate broadcast, all stop

### Plan approval flow

Before any teammate sends a request to the target:

1. Teammate describes what they want to do and why
2. Lead reviews for safety (no destructive actions, rate limiting)
3. Lead approves or redirects

## Example Usage

```bash
/ctf-kit:web ./webapp-source/
/ctf-kit:web http://challenge.ctf.com
```
