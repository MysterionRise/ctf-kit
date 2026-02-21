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

## Bundled Scripts

- [check-tools.sh](scripts/check-tools.sh) — Verify required analysis tools are installed

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. Run the analysis on the challenge files:

   ```bash
   ctf analyze $ARGUMENTS
   ```

3. Review the output to understand detected file types, suggested category, interesting strings, and embedded files.

4. Based on results, route to the appropriate specialized skill:
   - `/ctf-kit:crypto` — cryptography
   - `/ctf-kit:forensics` — forensics
   - `/ctf-kit:stego` — steganography
   - `/ctf-kit:web` — web security
   - `/ctf-kit:pwn` — binary exploitation
   - `/ctf-kit:reverse` — reverse engineering
   - `/ctf-kit:osint` — OSINT
   - `/ctf-kit:misc` — miscellaneous

5. Explain the findings and recommended next steps to the user.

## Example Usage

```bash
/ctf-kit:analyze challenge.bin
/ctf-kit:analyze ./challenge-folder/
```

## References

- [Tool Reference](references/tools.md) — analysis tools, category routing table, file signatures
