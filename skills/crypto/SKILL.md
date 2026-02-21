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

1. Check tool availability:

   ```bash
   bash scripts/check-tools.sh
   ```

   Expected: each tool prints `[OK]`. If any show `[MISSING]`, note which are unavailable before proceeding.

2. Run the crypto analysis:

   ```bash
   ctf run crypto $ARGUMENTS
   ```

   Expected output: detected encoding type, hash format, XOR key length candidates, or RSA parameters.

3. **CRITICAL: Before choosing a tool, confirm which crypto type you are dealing with:**
   - **Hash**: 32 hex chars (MD5), 40 hex chars (SHA1), 64 hex chars (SHA256) → go to step 4a
   - **RSA**: parameters `n=`, `e=`, `c=`, or `.pem` key file → go to step 4b
   - **XOR**: repeating byte patterns, `xortool` suggested key lengths → go to step 4c
   - **Encoding chain**: Base64 (`==` suffix), hex, ROT13, nested layers → go to step 4d

   If none match, re-examine with `file $ARGUMENTS && xxd $ARGUMENTS | head -20`.

4. Apply the matching tool:

   **4a. Hash Cracking:**

   ```bash
   hashid <hash>
   ```

   Expected: `[+] MD5`, `[+] SHA-1`, etc. Then crack:

   ```bash
   john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
   ```

   Expected: `password123 (?)` — the cracked value appears in the output. Verify with:

   ```bash
   john --show hashes.txt
   ```

   **4b. RSA:**

   ```bash
   RsaCtfTool --publickey key.pem --private
   ```

   Expected: `-----BEGIN RSA PRIVATE KEY-----` if the attack succeeds. If it fails, try with known parameters:

   ```bash
   RsaCtfTool -n <modulus> -e <exponent> --uncipher <ciphertext>
   ```

   Expected: `Unciphered data: <plaintext or hex>`

   **4c. XOR:**

   ```bash
   xortool encrypted.bin
   ```

   Expected: `The most probable key lengths: 4, 8, 12...` and candidate keys. Then:

   ```bash
   xortool -l <key_length> -c 20 encrypted.bin
   ```

   Expected: decrypted files written to `xortool_out/`.

   **4d. Encoding Chain:**
   Decode layer by layer. Example:

   ```bash
   echo "SGVsbG8=" | base64 -d          # Base64 → "Hello"
   echo "48656C6C6F" | xxd -r -p        # Hex → "Hello"
   ```

   **CRITICAL: After each decoding step, check if the result is another encoding or the flag.** Look for `flag{`, `CTF{`, or readable text.

5. **Validation: Confirm the solution.** The final output should contain a flag string (e.g., `flag{...}`) or a clearly readable plaintext. If you get binary garbage, revisit step 3 — the crypto type identification may be wrong.

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
