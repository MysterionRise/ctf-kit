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

## Example Usage

```bash
/ctf-kit:web ./webapp-source/
/ctf-kit:web http://challenge.ctf.com
```
