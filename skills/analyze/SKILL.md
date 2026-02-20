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

## Instructions

1. Run the analysis on the challenge files:

   ```bash
   ctf analyze $ARGUMENTS
   ```

2. Review the output to understand:
   - Detected file types
   - Suggested challenge category
   - Interesting strings or metadata found
   - Embedded files detected

3. Based on the analysis results, suggest the appropriate specialized command:
   - `/ctf-kit:crypto` for cryptography challenges
   - `/ctf-kit:forensics` for forensics challenges
   - `/ctf-kit:stego` for steganography challenges
   - `/ctf-kit:web` for web security challenges
   - `/ctf-kit:pwn` for binary exploitation challenges
   - `/ctf-kit:reverse` for reverse engineering challenges
   - `/ctf-kit:osint` for OSINT challenges
   - `/ctf-kit:misc` for miscellaneous challenges

4. Explain the findings and recommended next steps to the user.

## Example Usage

```bash
/ctf-kit:analyze challenge.bin
/ctf-kit:analyze ./challenge-folder/
```

## Related Commands

- `/ctf-kit:crypto` - Crypto-specific analysis
- `/ctf-kit:forensics` - Forensics analysis
- `/ctf-kit:stego` - Steganography analysis
