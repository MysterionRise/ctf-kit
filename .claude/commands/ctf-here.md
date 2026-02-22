# CTF Here

Set competition context for the current challenge directory.

## When to Use

Use this command when you:

- Start working on a new CTF challenge
- Enter a challenge directory for the first time
- Want to set or update challenge metadata (category, name, points)
- Need to initialize the `.ctf/` folder before using other CTF commands

## Instructions

1. Set the competition context:

   ```bash
   ctf here $ARGUMENTS
   ```

2. Review the output:
   - Challenge name and detected category
   - Files found in the directory
   - Created `.ctf/` structure (if new)

3. After setting context, suggest next steps:
   - `/ctf-analyze` to examine challenge files in detail
   - The appropriate category command based on detected category

## Example Usage

```bash
/ctf-here
/ctf-here -c crypto
/ctf-here -n "RSA Baby" -p 200
```

## Related Commands

- `/ctf-analyze` — Analyze challenge files
- `/ctf-status` — View challenge progress
- `/ctf-flag` — Submit a flag when solved
