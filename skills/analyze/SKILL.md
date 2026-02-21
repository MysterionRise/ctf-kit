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

## Performance Notes

- Take your time to do this thoroughly — rushed triage leads to wrong categories and wasted effort downstream
- Quality is more important than speed: a correct category assignment saves significant time later
- Do not skip validation steps — run every applicable detection method before concluding
- When in doubt between categories, run additional checks rather than guessing
- This skill routes to all other skills — your analysis accuracy determines the entire solve path
- Check for multi-category challenges (e.g., forensics + crypto) and note all relevant categories

## Quality Checklist

Before recommending a category and next steps, verify:

- [ ] Ran `file` command on all challenge files
- [ ] Checked `strings` output for readable text, flags, or hints
- [ ] Ran `xxd` / hex dump on first ~256 bytes to check magic bytes
- [ ] Checked for embedded files with `binwalk`
- [ ] Examined file metadata with `exiftool` where applicable
- [ ] Considered at least 2 possible categories before settling on one
- [ ] Provided specific next steps, not just a category name
- [ ] Noted any anomalies or secondary findings that might matter later

## Example Usage

```bash
/ctf-kit:analyze challenge.bin
/ctf-kit:analyze ./challenge-folder/
```

## Related Commands

- `/ctf-kit:crypto` - Crypto-specific analysis
- `/ctf-kit:forensics` - Forensics analysis
- `/ctf-kit:stego` - Steganography analysis
