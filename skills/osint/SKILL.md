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

1. Check tool availability:

   ```bash
   bash scripts/check-tools.sh
   ```

   Expected: each tool prints `[OK]`. If any show `[MISSING]`, note which are unavailable before proceeding.

2. Run the OSINT analysis:

   ```bash
   ctf run osint $ARGUMENTS
   ```

   Expected output: identified target type (username, domain, image) and initial findings.

3. **CRITICAL: Before choosing tools, identify the target type:**
   - A username or handle → **Username enumeration** → go to step 4a
   - A domain name or URL → **Domain reconnaissance** → go to step 4b
   - An image file → **Image geolocation** → go to step 4c

   If the target type is unclear, check the arguments: `file $ARGUMENTS 2>/dev/null || echo "Not a file — treat as username or domain"`

4. Apply the matching approach:

   **4a. Username Enumeration:**

   ```bash
   sherlock username
   ```

   Expected: list of `[+] <site>: https://<site>.com/username` for found profiles, `[-]` for not found. Focus on profiles marked `[+]`.

   **CRITICAL: Verify at least one profile was found before investigating further.** If all results are `[-]`, try alternate spellings or related usernames.

   ```bash
   sherlock username --site github
   ```

   Expected: `[+] GitHub: https://github.com/username` — check the profile for repos, commits, or personal info.

   **4b. Domain Reconnaissance:**

   ```bash
   theHarvester -d target.com -b all
   ```

   Expected: tables of `Emails found`, `Hosts found`, `IPs found`. Note all discovered subdomains and email addresses.

   ```bash
   dig target.com ANY
   ```

   Expected: DNS records (A, MX, TXT, NS). Look for TXT records containing flags or hints.

   ```bash
   whois target.com
   ```

   Expected: registrant name, organization, creation date, nameservers. Note any personal information.

   **4c. Image Geolocation:**

   ```bash
   exiftool image.jpg
   ```

   Expected: metadata table with fields like `Camera Model`, `Date/Time`, `GPS Position`. If GPS data exists:

   ```bash
   exiftool -gps* image.jpg
   ```

   Expected: `GPS Latitude: 48 deg 51' 24.00" N`, `GPS Longitude: 2 deg 21' 3.00" E`. Convert to decimal and look up on a map.

   **CRITICAL: If no EXIF GPS data, fall back to visual analysis** — look for landmarks, signs, language on buildings, sun position, and vegetation.

5. **Cross-reference and connect findings.** Look up discovered profiles, domains, or locations using:
   - **Maps:** Google Maps, Google Earth (for coordinates)
   - **Archive:** web.archive.org (for historical versions of sites)
   - **Reverse Image:** Google Images, TinEye (for image origin)
   - **Breach Data:** haveibeenpwned.com (for email-based leads)

6. **Validation: Confirm the flag.** OSINT flags are often GPS coordinates, real names, email addresses, or hidden text found on discovered profiles. Verify your answer matches the expected flag format.

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

## Example Usage

```bash
/ctf-kit:osint image.jpg
/ctf-kit:osint challenge.txt
```
