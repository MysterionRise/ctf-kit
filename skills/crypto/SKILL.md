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

## Performance Notes

- Take your time identifying the cipher or encoding — misidentification wastes all subsequent effort
- Quality is more important than speed: try multiple decoding approaches before concluding
- Do not skip validation steps — always verify decrypted output looks correct (readable text, flag format)
- Check for encoding chains: many challenges layer multiple encodings and stopping at the first decode misses the flag
- When hash cracking, try multiple wordlists and rule sets before giving up

## Quality Checklist

Before presenting a solution, verify:

- [ ] Identified the encoding/cipher type with evidence (not just a guess)
- [ ] Tried all plausible decoding methods for the identified type
- [ ] Checked for multi-layer encoding (decoded output may itself be encoded)
- [ ] Verified the decrypted output is meaningful (text, flag format, etc.)
- [ ] For RSA: checked multiple attack vectors (small e, common factor, Wiener, Fermat)
- [ ] For hashes: tried common wordlists before declaring uncrackable
- [ ] Documented the full decode chain so the user can reproduce it

## Example Usage

```bash
/ctf-kit:crypto cipher.txt
/ctf-kit:crypto encrypted.bin
/ctf-kit:crypto ./challenge/
```
