---
name: analyze
description: >-
  Analyze CTF challenge files to detect category and suggest next steps.
  Use when starting a new challenge, receiving unknown files, or needing
  triage. Triggers: file, strings, xxd, binwalk output, unknown binaries,
  .bin .dat .raw .enc files, "what is this file", "analyze this",
  "identify challenge type". Routes to crypto/forensics/stego/web/pwn/
  reverse/osint/misc skills based on detection.
---

# CTF Analyze

Analyze challenge files to determine type and suggest approaches.

## When to Use

Use this command when you have new challenge files and need to:

- Identify the challenge category (crypto, forensics, stego, web, pwn, reversing, OSINT, misc)
- Detect file types and formats
- Get initial suggestions for tools to use
- Understand what you're working with

## Bundled Scripts

- [check-tools.sh](scripts/check-tools.sh) — Verify required analysis tools are installed

## Instructions

1. Check tool availability:

   ```bash
   bash scripts/check-tools.sh
   ```

   Expected: each tool prints `[OK]`. If any show `[MISSING]`, note which tools are unavailable and adjust later steps accordingly.

2. Run the analysis on the challenge files:

   ```bash
   ctf analyze $ARGUMENTS
   ```

   Expected output includes: file type (e.g., `ELF 64-bit`, `PNG image`, `ASCII text`), magic bytes, embedded file signatures, and printable strings.

3. **CRITICAL: Before proceeding, confirm the analysis produced at least one of these results:**
   - A detected file type (e.g., `file: ELF 64-bit LSB executable`)
   - A suggested challenge category (e.g., `Category: crypto`)
   - Interesting strings (e.g., `flag{`, `CTF{`, Base64 patterns, hex strings)
   - Embedded file signatures (e.g., `JPEG image data`, `Zip archive`)

   If the output is empty or only shows `data`, run manual checks:
   ```bash
   file $ARGUMENTS && xxd $ARGUMENTS | head -20 && strings $ARGUMENTS | head -30
   ```

4. Route to the appropriate specialized skill based on detected category:

   | Detection | Route to |
   |-----------|----------|
   | Encryption, hashes, RSA params, encoding | `/ctf-kit:crypto` |
   | Memory dump, pcap, disk image | `/ctf-kit:forensics` |
   | Image/audio with no obvious content | `/ctf-kit:stego` |
   | URL, HTML, PHP, HTTP traffic | `/ctf-kit:web` |
   | ELF/PE binary with remote service | `/ctf-kit:pwn` |
   | ELF/PE binary, crackme, keygen | `/ctf-kit:reverse` |
   | Username, domain, geolocation task | `/ctf-kit:osint` |
   | Encoding chains, esoteric code, QR | `/ctf-kit:misc` |

5. Explain the findings and recommended next steps to the user, including which specialized skill to invoke and why.

## Example Usage

```bash
/ctf-kit:analyze challenge.bin
/ctf-kit:analyze ./challenge-folder/
```

## Related Commands

- `/ctf-kit:crypto` - Crypto-specific analysis
- `/ctf-kit:forensics` - Forensics analysis
- `/ctf-kit:stego` - Steganography analysis
