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

2. For username enumeration:

   ```bash
   # Search across platforms
   sherlock username

   # Check specific site
   sherlock username --site github
   ```

3. For domain reconnaissance:

   ```bash
   # Gather emails and subdomains
   theHarvester -d target.com -b all

   # DNS lookup
   dig target.com ANY

   # Whois information
   whois target.com
   ```

4. For image geolocation:

   ```bash
   # Extract EXIF data
   exiftool image.jpg

   # Look for GPS coordinates
   exiftool -gps* image.jpg
   ```

5. Online resources:
   - **Maps:** Google Maps, Google Earth
   - **Archive:** web.archive.org
   - **Reverse Image:** Google Images, TinEye
   - **Social:** LinkedIn, Twitter, Facebook
   - **Breach Data:** haveibeenpwned.com

## OSINT Workflow

1. **Collect:** Gather all given information
2. **Identify:** Usernames, emails, domains
3. **Enumerate:** Search across platforms
4. **Connect:** Link findings together
5. **Investigate:** Deep dive on leads

## Common OSINT Sources

| Category | Sources |
|----------|---------|
| Social | LinkedIn, Twitter, Instagram, Facebook |
| Code | GitHub, GitLab, Bitbucket |
| Email | HaveIBeenPwned, Hunter.io |
| Domain | Shodan, Censys, SecurityTrails |
| Archive | Wayback Machine, Archive.today |

## Image OSINT Checklist

1. Check EXIF metadata for:
   - GPS coordinates
   - Camera model
   - Date/time taken
   - Software used
   - Author information

2. Visual analysis:
   - Landmarks visible
   - Signs/text in image
   - Weather/shadows (time of day)
   - Unique features

3. Reverse image search:
   - Google Images
   - TinEye
   - Yandex (good for faces)

## Performance Notes

- Take your time — OSINT is about thoroughness, not speed
- Quality is more important than speed: check multiple sources before concluding
- Do not skip validation steps — cross-reference findings across platforms
- Usernames often appear on many platforms — check all major ones, not just the first hit
- Image geolocation requires careful attention to small visual details
- Always check the Wayback Machine — deleted content often holds the key

## Quality Checklist

Before presenting findings, verify:

- [ ] Searched all major platforms for the given username/email/domain
- [ ] Cross-referenced findings across multiple sources
- [ ] For images: checked EXIF metadata AND performed visual analysis
- [ ] Checked the Wayback Machine for historical content
- [ ] For domains: ran whois, DNS lookups, and subdomain enumeration
- [ ] Verified that findings are connected (not just coincidental matches)
- [ ] Documented the full investigation trail with sources

## Example Usage

```bash
/ctf-kit:osint image.jpg
/ctf-kit:osint challenge.txt
```
