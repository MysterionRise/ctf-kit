# CTF OSINT

Gather open source intelligence for OSINT challenges.

## When to Use

Use this command for challenges involving:

- Username searching
- Domain reconnaissance
- Social media investigation
- Geolocation from images
- Public records research

## Instructions

1. Run the OSINT analysis:

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

## Example Usage

```bash
/ctf-osint image.jpg
/ctf-osint challenge.txt
```
