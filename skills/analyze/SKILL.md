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
- [triage.sh](scripts/triage.sh) — **Multi-step triage pipeline**: file type → strings → binwalk → category suggestion. Produces a JSON summary with detected category, confidence score, and recommended next skill.
- [run-strings.sh](scripts/run-strings.sh) — Extract strings with pattern detection (flags, URLs, hashes, credentials). Outputs JSON with categorized findings.

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. **Recommended: Run the full triage pipeline** for automatic category detection:

   ```bash
   bash scripts/triage.sh $ARGUMENTS
   ```

   The triage script chains: file → strings → binwalk → exiftool, then outputs a JSON summary including:
   - `category`: detected challenge type (crypto, forensics, stego, etc.)
   - `confidence`: detection confidence (0-100%)
   - `suggested_skill`: which `/ctf-kit:*` command to use next
   - `findings`: flags, URLs, hashes, base64 strings found
   - `embedded_signatures`: files hidden inside the challenge file

3. For strings-only analysis with pattern detection:

   ```bash
   bash scripts/run-strings.sh $ARGUMENTS
   ```

4. Or run the CLI analysis:

   ```bash
   ctf analyze $ARGUMENTS
   ```

5. **Read the JSON output** at the end of each script. It contains structured data you can use to decide next steps. The `suggestions` field tells you exactly what to do next.

6. Based on the triage results, use the recommended skill:
   - `/ctf-kit:crypto` for cryptography challenges
   - `/ctf-kit:forensics` for forensics challenges
   - `/ctf-kit:stego` for steganography challenges
   - `/ctf-kit:web` for web security challenges
   - `/ctf-kit:pwn` for binary exploitation challenges
   - `/ctf-kit:reverse` for reverse engineering challenges
   - `/ctf-kit:osint` for OSINT challenges
   - `/ctf-kit:misc` for miscellaneous challenges

## Output Format

All scripts produce a `=== PARSED RESULTS (JSON) ===` section with structured data. Key fields:

| Field | Description |
|-------|-------------|
| `category` | Detected challenge category |
| `confidence` | Detection confidence (0.0-1.0) |
| `suggested_skill` | Which skill to invoke next |
| `findings.flags` | Any flags found in strings |
| `suggestions` | Actionable next steps |

## Example Usage

```bash
/ctf-kit:analyze challenge.bin
/ctf-kit:analyze ./challenge-folder/
```

## Related Commands

- `/ctf-kit:crypto` - Crypto-specific analysis
- `/ctf-kit:forensics` - Forensics analysis
- `/ctf-kit:stego` - Steganography analysis
