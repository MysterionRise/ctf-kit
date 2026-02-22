---
name: here
description: >-
  Set competition context for the current challenge directory.
  Initializes .ctf/ folder, detects files, guesses category, and
  saves metadata. Use when starting work on a new challenge, entering
  a challenge directory, or setting up context for AI analysis.
  Triggers: "start challenge", "set context", "initialize challenge",
  "ctf here", "begin working on", "new challenge".
---

# CTF Here

Set competition context for the current challenge directory.

## When to Use

Use this command when you:

- Start working on a new CTF challenge
- Enter a challenge directory for the first time
- Want to set or update challenge metadata (category, name, points)
- Need to initialize the `.ctf/` folder before using other CTF commands

## Bundled Scripts

- [check-tools.sh](scripts/check-tools.sh) — Verify ctf-kit is installed

## Instructions

1. First verify ctf-kit is available: `bash scripts/check-tools.sh`

2. Set the competition context:

   ```bash
   ctf here $ARGUMENTS
   ```

3. Review the output:
   - Challenge name and detected category
   - Files found in the directory
   - Created `.ctf/` structure (if new)

4. After setting context, suggest next steps:
   - `/ctf-kit:analyze` to examine challenge files in detail
   - The appropriate category skill based on detected category

## Options

- `--category, -c` — Manually set the challenge category
- `--name, -n` — Override the challenge name (default: directory name)
- `--points, -p` — Set the challenge point value
- `--flag-format, -f` — Set expected flag format regex

## Example Usage

```bash
/ctf-kit:here
/ctf-kit:here -c crypto
/ctf-kit:here -n "RSA Baby" -p 200
/ctf-kit:here path/to/challenge
```

## Related Commands

- `/ctf-kit:analyze` — Analyze challenge files after setting context
- `/ctf-kit:status` — View challenge progress
- `/ctf-kit:flag` — Submit a flag when solved
