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

1. Check tool availability:

   ```bash
   bash scripts/check-tools.sh
   ```

   Expected: each tool prints `[OK]`. If any show `[MISSING]`, note which are unavailable before proceeding.

2. Run the web analysis:

   ```bash
   ctf run web $ARGUMENTS
   ```

   Expected output: target URL, detected technologies, and initial observations.

3. **CRITICAL: Check for low-hanging fruit first (these often contain the flag directly):**

   ```bash
   curl -s http://target.com/robots.txt
   ```

   Expected: `Disallow:` entries pointing to hidden paths. Visit each disallowed path.

   ```bash
   curl -s http://target.com/.git/HEAD
   ```

   Expected: `ref: refs/heads/main` if a git repo is exposed. If found, dump it with `git-dumper` or manual download.

   ```bash
   curl -sI http://target.com/
   ```

   Expected: HTTP headers. Look for custom headers (`X-Flag:`, `X-Secret:`), server version, and interesting cookies.

   **CRITICAL: If any of the above reveal the flag, stop here. Only continue to automated tools if manual checks found nothing.**

4. Directory and file enumeration:

   ```bash
   gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
   ```

   Expected: list of discovered paths with status codes:
   ```
   /admin (Status: 200)
   /login.php (Status: 200)
   /backup (Status: 403)
   ```

   Visit paths with `200` and note paths with `403` (may need auth bypass). For faster fuzzing:

   ```bash
   ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200,301,302
   ```

5. Test for injection vulnerabilities on discovered pages:

   **SQL Injection:**

   ```bash
   sqlmap -u "http://target.com/page?id=1" --dbs
   ```

   Expected: `available databases [2]: information_schema, challenge_db`. Then dump:

   ```bash
   sqlmap -u "http://target.com/page?id=1" -D challenge_db --tables
   ```

   Expected: table names. Dump the table most likely to contain the flag:

   ```bash
   sqlmap -u "http://target.com/page?id=1" -D challenge_db -T flags --dump
   ```

   **Other injection types** — test manually:

   | Vulnerability | Test payload | Expected if vulnerable |
   |--------------|--------------|----------------------|
   | XSS | `<script>alert(1)</script>` | Alert popup or reflected script |
   | SSTI | `{{7*7}}` | `49` rendered in page |
   | Path Traversal | `../../../etc/passwd` | File contents in response |
   | Command Injection | `; id` | `uid=1000(www-data)` in output |

6. **Validation: Confirm the flag.** The flag is typically found in database dumps, hidden files, server responses, or cookie values. Verify the flag format matches the expected pattern (e.g., `flag{...}`, `CTF{...}`). If no flag found, revisit step 3 — check page source, JavaScript files, and HTTP response headers more carefully.

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
