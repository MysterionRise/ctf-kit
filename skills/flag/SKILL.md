---
name: flag
description: >-
  Submit and validate CTF flags. Saves the flag to flag.txt, marks
  the challenge as solved, and validates against expected flag formats.
  Triggers: "submit flag", "found the flag", "flag is", "capture flag",
  "got the flag", "flag{", "CTF{", "picoCTF{".
---

# CTF Flag

Submit and validate a CTF flag.

## When to Use

Use this command when you:

- Have found or computed a flag for a challenge
- Want to save and validate a flag value
- Need to mark a challenge as solved

## Bundled Scripts

- [check-tools.sh](scripts/check-tools.sh) — Verify ctf-kit is installed

## Instructions

1. First verify ctf-kit is available: `bash scripts/check-tools.sh`

2. Submit the flag:

   ```bash
   ctf flag "$ARGUMENTS"
   ```

3. Review the output:
   - Flag format validation result
   - Confirmation that flag.txt was saved
   - Challenge marked as solved in .ctf/challenge.yaml

4. After submitting a flag:
   - Suggest `/ctf-kit:status` to review progress
   - Suggest `/ctf-kit:writeup` to generate a writeup
   - If in a competition, suggest moving to the next challenge

## Options

- `--path, -p` — Challenge directory (default: current directory)
- `--no-validate` — Skip flag format validation

## Example Usage

```bash
/ctf-kit:flag "flag{s0m3_fl4g_h3r3}"
/ctf-kit:flag "picoCTF{example_flag}" --path ./crypto/rsa-baby
/ctf-kit:flag "non_standard_flag" --no-validate
```

## Related Commands

- `/ctf-kit:here` — Set up challenge context
- `/ctf-kit:status` — View challenge progress after submission
- `/ctf-kit:writeup` — Generate writeup for solved challenge
