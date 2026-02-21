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

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. Run the web analysis:

   ```bash
   ctf run web $ARGUMENTS
   ```

2. For directory/file enumeration:

   ```bash
   # Directory brute-force
   gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

   # With extensions
   gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt

   # Fast fuzzing
   ffuf -u http://target.com/FUZZ -w wordlist.txt
   ```

3. For SQL injection:

   ```bash
   # Test URL for SQLi
   sqlmap -u "http://target.com/page?id=1" --dbs

   # Enumerate databases
   sqlmap -u "http://target.com/page?id=1" --dbs

   # Dump table
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

## Things to Check

1. **Authentication:**
   - Default credentials
   - JWT token manipulation
   - Cookie tampering

2. **Files:**
   - Source code disclosure
   - Backup files (.bak, ~, .old)
   - Config files exposed

3. **Input:**
   - All parameters in URL
   - POST data fields
   - Headers and cookies

## Performance Notes

- Take your time enumerating the attack surface — missed endpoints mean missed vulnerabilities
- Quality is more important than speed: test each input field and parameter systematically
- Do not skip validation steps — check robots.txt, source code, cookies, and headers before attacking
- Try multiple injection types on each input — SQLi, XSS, SSTI, and command injection
- Always read the page source — comments and hidden fields often contain hints
- For authentication challenges: check JWT structure, cookie values, and default credentials

## Quality Checklist

Before presenting a solution, verify:

- [ ] Checked robots.txt, sitemap.xml, and common hidden paths
- [ ] Viewed page source for comments, hidden fields, and JS files
- [ ] Tested all input parameters for injection vulnerabilities
- [ ] Examined cookies, headers, and authentication tokens
- [ ] For SQLi: confirmed injection type and extracted the target data
- [ ] For authentication bypass: documented the exact bypass method
- [ ] Verified the exploit works and extracted the flag or target data

## Example Usage

```bash
/ctf-kit:web ./webapp-source/
/ctf-kit:web http://challenge.ctf.com
```
