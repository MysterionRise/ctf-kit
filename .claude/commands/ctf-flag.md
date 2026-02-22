# CTF Flag

Submit and validate a CTF flag.

## When to Use

Use this command when you:

- Have found or computed a flag for a challenge
- Want to save and validate a flag value
- Need to mark a challenge as solved

## Instructions

1. Submit the flag:

   ```bash
   ctf flag "$ARGUMENTS"
   ```

2. Review the output:
   - Flag format validation result
   - Confirmation that flag.txt was saved
   - Challenge marked as solved in .ctf/challenge.yaml

3. After submitting a flag:
   - Suggest `/ctf-status` to review progress
   - Suggest `/ctf-writeup` to generate a writeup

## Example Usage

```bash
/ctf-flag "flag{s0m3_fl4g_h3r3}"
/ctf-flag "picoCTF{example_flag}" --path ./crypto/rsa-baby
/ctf-flag "non_standard_flag" --no-validate
```

## Related Commands

- `/ctf-here` — Set up challenge context
- `/ctf-status` — View challenge progress
- `/ctf-writeup` — Generate writeup for solved challenge
