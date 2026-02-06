---
name: crypto
description: Analyze and solve cryptography challenges
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

## Instructions

1. Run the crypto analysis:

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

## Example Usage

```bash
/ctf-kit:crypto cipher.txt
/ctf-kit:crypto encrypted.bin
/ctf-kit:crypto ./challenge/
```
