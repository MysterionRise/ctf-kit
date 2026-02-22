# CTF Status

Show CTF challenge or competition progress dashboard.

## When to Use

Use this command when you want to:

- Check the current challenge's solve status
- See what files are in the challenge directory
- View a competition-level overview of all challenges
- Check how many challenges are solved and total points

## Instructions

1. Show challenge or competition status:

   ```bash
   ctf status $ARGUMENTS
   ```

2. Review the output:
   - For single challenges: name, category, files, solve status
   - For competitions: table of all challenges with solve progress

3. Based on the status, suggest next actions:
   - Unsolved challenges: suggest `/ctf-analyze` or category-specific command
   - Solved challenges: suggest `/ctf-writeup` for documentation

## Example Usage

```bash
/ctf-status
/ctf-status --competition
/ctf-status path/to/challenge
```

## Related Commands

- `/ctf-here` — Set up challenge context
- `/ctf-flag` — Submit a flag
- `/ctf-analyze` — Analyze challenge files
