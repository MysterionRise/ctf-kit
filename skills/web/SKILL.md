---
name: web
description: Analyze and solve web security challenges
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

## Instructions

1. Run the web analysis:

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

## Example Usage

```bash
/ctf-kit:web ./webapp-source/
/ctf-kit:web http://challenge.ctf.com
```
