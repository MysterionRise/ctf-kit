# Web — Tool Reference

## Directory/File Enumeration

```bash
# Directory brute-force
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# With extensions
gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt

# Fast fuzzing
ffuf -u http://target.com/FUZZ -w wordlist.txt

# Fuzz parameters
ffuf -u http://target.com/page?FUZZ=value -w wordlist.txt

# Virtual host enumeration
ffuf -u http://target.com -H "Host: FUZZ.target.com" -w wordlist.txt
```

## SQL Injection (sqlmap)

```bash
# Test URL for SQLi
sqlmap -u "http://target.com/page?id=1" --dbs

# Enumerate databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Enumerate tables
sqlmap -u "http://target.com/page?id=1" -D database --tables

# Dump table
sqlmap -u "http://target.com/page?id=1" -D database -T table --dump

# POST request
sqlmap -u "http://target.com/login" --data="user=a&pass=b" --dbs

# With cookies
sqlmap -u "http://target.com/page?id=1" --cookie="session=abc" --dbs
```

## Manual Testing

```bash
# Check robots.txt
curl http://target.com/robots.txt

# Check for .git exposure
curl http://target.com/.git/HEAD

# Check common backup files
curl http://target.com/index.php.bak
curl http://target.com/index.php~
curl http://target.com/index.php.old

# View response headers
curl -I http://target.com

# Send custom headers
curl -H "X-Forwarded-For: 127.0.0.1" http://target.com
```

## JWT Token Analysis

```bash
# Decode JWT (base64)
echo "eyJ..." | cut -d. -f1 | base64 -d  # Header
echo "eyJ..." | cut -d. -f2 | base64 -d  # Payload

# Try "none" algorithm attack
# Try weak secret brute-force with john/hashcat
```
