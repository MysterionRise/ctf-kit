# Web — Vulnerability Patterns

## Common Vulnerability Test Payloads

| Vulnerability | Test Payload |
|--------------|--------------|
| SQL Injection | `' OR '1'='1` |
| XSS | `<script>alert(1)</script>` |
| Path Traversal | `../../../etc/passwd` |
| SSTI (Jinja2) | `{{7*7}}` |
| SSTI (Mako) | `${7*7}` |
| Command Injection | `; id` or `| id` |
| SSRF | `http://127.0.0.1` or `http://169.254.169.254` |

## Reconnaissance Checklist

### Authentication
- Default credentials (admin/admin, admin/password)
- JWT token manipulation (none algorithm, weak secret)
- Cookie tampering (role=admin, isAdmin=true)
- Session fixation

### Hidden Files & Directories
- `/robots.txt`, `/sitemap.xml`
- `/.git/HEAD`, `/.svn/entries`
- Backup files: `.bak`, `~`, `.old`, `.swp`
- Config files: `.env`, `config.php`, `web.config`

### Input Vectors
- All URL parameters
- POST data fields
- HTTP headers (Host, X-Forwarded-For, Referer)
- Cookies and session tokens
- File upload fields

## SSTI Detection by Framework

| Framework | Test | Result |
|-----------|------|--------|
| Jinja2 | `{{7*7}}` | `49` |
| Twig | `{{7*7}}` | `49` |
| Mako | `${7*7}` | `49` |
| Freemarker | `${7*7}` | `49` |
| Smarty | `{7*7}` | `49` |
