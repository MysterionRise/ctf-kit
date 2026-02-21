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

3. Analyze the output for detected encoding types, hash types, XOR key length, and RSA parameters.

4. Based on findings, use the appropriate tool — see [Tool Reference](references/tools.md) for detailed commands.

5. For multi-layered encoding, try CyberChef Magic or manual layer-by-layer decoding.

## Example Usage

```bash
/ctf-kit:crypto cipher.txt
/ctf-kit:crypto encrypted.bin
/ctf-kit:crypto ./challenge/
```

## References

- [Tool Reference](references/tools.md) — hash cracking, RSA attacks, XOR analysis, classical ciphers
- [Pattern Recognition](references/patterns.md) — hash identification, encoding detection, RSA vulnerabilities
