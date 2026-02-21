---
name: crypto
description: >-
  Solve CTF cryptography challenges including encryption, hashing, and
  encoding. Use when you see: Base64 (trailing ==), hex strings (32/40/64
  chars for MD5/SHA1/SHA256), RSA parameters (n=, e=, c=, p=, q=),
  XOR-encrypted data, .pem .key .enc files, classical ciphers (Caesar,
  Vigenere, substitution), encoding chains, or "crack this hash".
  Tools: xortool, hashid, hashcat, john, RsaCtfTool, openssl.
---

# CTF Crypto

Analyze and solve cryptography challenges.

## When to Use

Use this command for challenges involving:

- Encrypted text or files
- Hash cracking
- RSA/asymmetric cryptography
- XOR encryption
- Classical ciphers (Caesar, Vigenere, etc.)
- Encoding chains (Base64, hex, etc.)

## Bundled Scripts

- [check-tools.sh](scripts/check-tools.sh) — Verify required crypto tools are installed
- [run-xortool.sh](scripts/run-xortool.sh) — Analyze XOR-encrypted files with key length detection
- [identify-hash.sh](scripts/identify-hash.sh) — Identify hash types from strings or files

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. Run the crypto analysis:

   ```bash
   ctf run crypto $ARGUMENTS
   ```

2. Analyze the output for:
   - Detected encoding types (Base64, hex, binary)
   - Hash types identified
   - XOR key length analysis
   - RSA parameters (n, e, c, p, q)

3. Based on findings, use appropriate tools:

   **For Hash Cracking:**

   ```bash
   # Identify hash type
   hashid <hash>

   # Crack with John
   john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

   # Crack with Hashcat
   hashcat -m 0 -a 0 hashes.txt wordlist.txt  # MD5
   ```

   **For RSA:**

   ```bash
   # Attack weak RSA
   RsaCtfTool --publickey key.pem --private

   # With known parameters
   RsaCtfTool -n <modulus> -e <exponent> --uncipher <ciphertext>
   ```

   **For XOR:**

   ```bash
   # Analyze XOR encryption
   xortool encrypted.bin

   # Try with known key length
   xortool -l 8 -c 20 encrypted.bin
   ```

4. Suggest decoding chains for multi-layered encoding:
   - Try CyberChef Magic recipe
   - Manual: Base64 -> Hex -> ASCII, etc.

## Common Patterns

| Pattern | Likely Type |
|---------|-------------|
| 32 hex chars | MD5 hash |
| 40 hex chars | SHA1 hash |
| 64 hex chars | SHA256 hash |
| `==` at end | Base64 |
| All caps + 2-7 | Base32 |
| n=..., e=... | RSA parameters |

## Common Issues

**`hashcat` or `john` not found**
- **Cause:** Hash cracking tools not installed
- **Solution:** Install with `apt install hashcat john` (Debian/Ubuntu) or `brew install hashcat john` (macOS). On macOS, hashcat requires OpenCL/Metal support — if GPU errors occur, try `hashcat --force` to use CPU fallback

**`RsaCtfTool` not found**
- **Cause:** Not packaged in system repos — requires manual install
- **Solution:** Clone and install: `git clone https://github.com/RsaCtfTool/RsaCtfTool && cd RsaCtfTool && pip install -r requirements.txt`. Run with `python RsaCtfTool.py`

**`xortool` not found**
- **Cause:** Not installed or installed in a different Python environment
- **Solution:** Install with `pip install xortool`. Verify with `xortool --help`

**hashcat: "No hashes loaded"**
- **Cause:** Wrong hash mode (`-m`) for the given hash type
- **Solution:** Use `hashid` or `hash-identifier` to determine the hash type first, then match to the correct hashcat mode. Common modes: `-m 0` (MD5), `-m 100` (SHA1), `-m 1400` (SHA256), `-m 1000` (NTLM)

**RsaCtfTool finds no attack that works**
- **Cause:** The RSA parameters may not be vulnerable to known attacks, or key size is too large
- **Solution:** Check if `n` can be factored on factordb.com. Try specifying attacks manually with `--attack`. For custom RSA variants (e.g., multi-prime, small `d`), write a Python script using `sympy` or `gmpy2` instead

**Base64 decode produces garbage**
- **Cause:** The string may not be standard Base64 — could be Base64url, Base32, or a custom alphabet
- **Solution:** Try `base64 -d` first. If garbage, try Base64url (`tr '_-' '/+'`), Base32 (`base32 -d`), or check if the data has another encoding layer on top

**john/hashcat cracking runs forever**
- **Cause:** Hash type is slow (bcrypt, scrypt) or password not in wordlist
- **Solution:** Use `rockyou.txt` first. For slow hashes, try rules: `john --wordlist=rockyou.txt --rules=best64`. Consider the CTF context — passwords are usually simple or hinted at in the challenge description

## Example Usage

```bash
/ctf-kit:crypto cipher.txt
/ctf-kit:crypto encrypted.bin
/ctf-kit:crypto ./challenge/
```
