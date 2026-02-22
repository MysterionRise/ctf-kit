---
name: status
description: >-
  Show CTF challenge or competition progress dashboard. Displays
  challenge metadata, file listing, solve status, and points.
  For competition directories, shows an overview of all challenges.
  Triggers: "show status", "progress", "dashboard", "how many solved",
  "challenge status", "competition overview", "scoreboard".
---

# CTF Status

Show CTF challenge or competition progress dashboard.

## When to Use

Use this command when you want to:

- Check the current challenge's solve status
- See what files are in the challenge directory
- View a competition-level overview of all challenges
- Check how many challenges are solved and total points

## Bundled Scripts

- [check-tools.sh](scripts/check-tools.sh) — Verify ctf-kit is installed

## Instructions

1. First verify ctf-kit is available: `bash scripts/check-tools.sh`

2. Show challenge or competition status:

   ```bash
   ctf status $ARGUMENTS
   ```

3. Review the output:
   - For single challenges: name, category, files, solve status
   - For competitions: table of all challenges with solve progress

4. Based on the status, suggest next actions:
   - Unsolved challenges: suggest `/ctf-kit:analyze` or category-specific skill
   - Solved challenges: suggest `/ctf-kit:writeup` for documentation

## Options

- `--competition, -C` — Show competition-level dashboard (scans subdirectories)

## Example Usage

```bash
/ctf-kit:status
/ctf-kit:status --competition
/ctf-kit:status path/to/challenge
```

## Related Commands

- `/ctf-kit:here` — Set up challenge context
- `/ctf-kit:flag` — Submit a flag
- `/ctf-kit:analyze` — Analyze challenge files
