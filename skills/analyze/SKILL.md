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

1. First check tool availability: `bash scripts/check-tools.sh`

2. Run the analysis on the challenge files:

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

## Common Issues

**`file` command not found**
- **Cause:** Core utilities not installed (rare on Linux/macOS, common in minimal containers)
- **Solution:** Install with `apt install file` (Debian/Ubuntu) or `brew install file` (macOS)

**`strings` returns no useful output**
- **Cause:** Binary may use wide-character (UTF-16) strings, or strings are obfuscated
- **Solution:** Try `strings -el` for little-endian UTF-16, or `strings -n 4` to lower the minimum length. For obfuscated binaries, use `/ctf-kit:reverse` instead

**`binwalk` not found or returns no results**
- **Cause:** binwalk not installed, or the file has no recognizable embedded signatures
- **Solution:** Install with `pip install binwalk` or `apt install binwalk`. If no signatures found, try `binwalk -R '\x50\x4b'` to search for specific magic bytes (e.g., ZIP), or examine the file manually with `xxd | head`

**Analysis suggests wrong category**
- **Cause:** Some challenges are intentionally misleading — a "forensics" file may actually be a crypto challenge, or vice versa
- **Solution:** If the suggested skill doesn't yield results, try the next most likely category. Use `file`, `xxd`, and `strings` output to form your own judgment rather than relying solely on automated detection

**Permission denied when analyzing files**
- **Cause:** Challenge file lacks read or execute permissions
- **Solution:** Run `chmod +r challenge_file` to add read permission. For ELF binaries you need to run, use `chmod +x`

## Example Usage

```bash
/ctf-kit:analyze challenge.bin
/ctf-kit:analyze ./challenge-folder/
```

## Related Commands

- `/ctf-kit:crypto` - Crypto-specific analysis
- `/ctf-kit:forensics` - Forensics analysis
- `/ctf-kit:stego` - Steganography analysis
