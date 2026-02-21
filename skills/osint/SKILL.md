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

## Common Issues

**`sherlock` not found**
- **Cause:** Sherlock not installed or not in PATH
- **Solution:** Install with `pip install sherlock-project`. Run with `sherlock` (not `sherlock-project`). Alternatively clone: `git clone https://github.com/sherlock-project/sherlock && cd sherlock && pip install -r requirements.txt`

**Sherlock returns many false positives**
- **Cause:** Some sites return 200 for any username (soft 404s), or rate-limit responses look like valid profiles
- **Solution:** Manually verify flagged profiles by visiting the URLs. Use `sherlock --print-found` to only show detected accounts, and cross-reference with the challenge context to filter relevant results

**`theHarvester` not found or returns no results**
- **Cause:** Not installed, or API keys not configured for data sources
- **Solution:** Install with `pip install theHarvester`. Many sources (Shodan, Hunter, SecurityTrails) require API keys configured in `/etc/theHarvester/api-keys.yaml`. For CTFs, use free sources: `-b google,bing,dnsdumpster`

**`exiftool` shows no GPS data in image**
- **Cause:** GPS metadata was stripped, or the image was taken with a device that doesn't embed location
- **Solution:** Fall back to visual OSINT — look for landmarks, signs, license plates, sun position, language on signs. Use Google Maps Street View to correlate. Check if the image has other metadata (camera model, timestamps) that could help

**`whois` returns limited/redacted information**
- **Cause:** Domain has WHOIS privacy protection enabled
- **Solution:** Try historical WHOIS lookups via whoishistory.com or SecurityTrails. Check web.archive.org for older versions of the site that may reveal ownership. Try related domains or subdomains that may have less privacy

**Rate limiting blocks OSINT tools**
- **Cause:** Too many automated requests to a platform
- **Solution:** Add delays between requests. For sherlock, use `--timeout 10`. Rotate through different search engines. Use cached/archived versions of pages when possible

**Reverse image search finds nothing**
- **Cause:** Image is unique to the CTF, heavily cropped, or modified
- **Solution:** Try multiple engines — Google Images, TinEye, Yandex (best for faces/locations), Bing Visual Search. Crop to specific features (a building, sign, or landmark) and search those separately

## Example Usage

```bash
/ctf-kit:osint image.jpg
/ctf-kit:osint challenge.txt
```
