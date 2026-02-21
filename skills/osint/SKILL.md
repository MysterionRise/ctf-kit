---
name: osint
description: >-
  Solve CTF OSINT (open source intelligence) challenges: username
  enumeration, domain recon, social media investigation, geolocation
  from images, and public records research. Use when given a username,
  email, domain, or photo to investigate. Triggers: "find this person",
  "username lookup", "who is", "geolocation", "reverse image search",
  "EXIF GPS", "whois", "domain recon", "social media".
  Tools: sherlock, theHarvester, exiftool, whois, dig.
  NOT for web app exploitation (use web).
---

# CTF OSINT

Gather open source intelligence for OSINT challenges.

## When to Use

Use this command for challenges involving:

- Username searching
- Domain reconnaissance
- Social media investigation
- Geolocation from images
- Public records research

## Bundled Scripts

- [check-tools.sh](scripts/check-tools.sh) — Verify required OSINT tools are installed

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. Run the OSINT analysis:

   ```bash
   ctf run osint $ARGUMENTS
   ```

3. Follow the OSINT workflow:
   1. **Collect** all given information
   2. **Identify** unique identifiers (usernames, emails, domains)
   3. **Enumerate** across platforms
   4. **Connect** findings together
   5. **Investigate** leads in depth

4. Use appropriate tools — see [Tool Reference](references/tools.md) for detailed commands:
   - **Usernames** → sherlock
   - **Domains** → theHarvester, dig, whois
   - **Images** → exiftool for GPS/metadata, reverse image search

## Example Usage

```bash
/ctf-kit:osint image.jpg
/ctf-kit:osint challenge.txt
```

## References

- [Tool Reference](references/tools.md) — sherlock, theHarvester, dig, exiftool, online resources
- [Investigation Patterns](references/patterns.md) — OSINT workflow, source tables, image checklist
