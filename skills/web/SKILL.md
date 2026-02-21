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

3. Enumerate and test — see [Tool Reference](references/tools.md) for detailed commands:
   - Directory/file enumeration with gobuster or ffuf
   - SQL injection testing with sqlmap
   - Manual testing of input fields

4. Check for common issues:
   - robots.txt, .git exposure, backup files
   - Default credentials, JWT manipulation
   - Input injection in all parameters

## Example Usage

```bash
/ctf-kit:web ./webapp-source/
/ctf-kit:web http://challenge.ctf.com
```

## References

- [Tool Reference](references/tools.md) — gobuster, ffuf, sqlmap, manual testing, JWT analysis
- [Vulnerability Patterns](references/patterns.md) — test payloads, recon checklist, SSTI detection
