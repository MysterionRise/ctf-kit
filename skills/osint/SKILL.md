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
- [run-sherlock.sh](scripts/run-sherlock.sh) — Username enumeration across platforms. Outputs JSON with found profiles categorized by type (social media, code platforms, other).
- [run-exiftool.sh](scripts/run-exiftool.sh) — OSINT-focused metadata extraction with GPS coordinate extraction. Outputs JSON with interesting fields, GPS data, and flag detection.

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. **For username enumeration** (outputs structured JSON):

   ```bash
   bash scripts/run-sherlock.sh <username>
   ```

   JSON output includes:
   - `profiles[]`: all found profiles with site and URL
   - `social_media[]`: social media profiles specifically
   - `code_platforms[]`: GitHub, GitLab, etc.
   - `suggestions`: cross-referencing guidance

3. **For image geolocation** (outputs structured JSON):

   ```bash
   bash scripts/run-exiftool.sh <image>
   ```

   JSON output includes:
   - `gps_data`: GPS coordinates if present
   - `interesting_fields[]`: CTF-relevant metadata (comments, author, etc.)
   - `has_flag`: true if flag pattern found in metadata

4. For domain reconnaissance:

   ```bash
   theHarvester -d target.com -b all
   dig target.com ANY
   whois target.com
   ```

5. Online resources:
   - **Maps:** Google Maps, Google Earth
   - **Archive:** web.archive.org
   - **Reverse Image:** Google Images, TinEye
   - **Social:** LinkedIn, Twitter, Facebook
   - **Breach Data:** haveibeenpwned.com

## OSINT Workflow

1. `run-sherlock.sh username` → check JSON for profiles
2. Cross-reference social and code platforms
3. `run-exiftool.sh image.jpg` → check JSON for GPS, metadata clues
4. Build complete picture from combined findings

## Team Roles

When using `/ctf-kit:team-solve` with an OSINT challenge, the lead spawns 3 specialists.

**All OSINT teammates require plan approval** before querying external services.

| Role | Teammate Name | Focus | Tools | First Action |
|------|--------------|-------|-------|--------------|
| People & Social | `social-investigator` | Username enumeration, social media profiling, identity correlation, breach data | sherlock, `scripts/run-sherlock.sh` | Run sherlock on any usernames, cross-reference profiles across platforms |
| Domain & Infrastructure | `domain-analyst` | WHOIS, DNS records, subdomain enumeration, email harvesting, IP geolocation, certificate transparency | whois, dig, theHarvester | Run whois + dig on domains, check certificate transparency logs |
| Geolocation & Media | `geo-analyst` | EXIF GPS extraction, reverse image search, visual landmark identification, Street View correlation | exiftool, `scripts/run-exiftool.sh` | Extract EXIF GPS, identify visual landmarks, cross-reference with maps |

### When to broadcast

- **Social**: "Username 'target123' has GitHub with a repo containing coordinates" — geo analyst investigates
- **Domain**: "Domain registered to email X, also found on social platform Y" — social investigator digs deeper
- **Geo**: "EXIF GPS points to 48.8584, 2.2945 (Eiffel Tower)" — others search for related context
- **Any**: "Found the flag" — immediate broadcast, all stop

### Plan approval flow

Before any teammate queries an external service:

1. Teammate describes the query and target
2. Lead reviews for scope (only target what the challenge asks for)
3. Lead approves or suggests alternative approach

## Example Usage

```bash
/ctf-kit:osint image.jpg
/ctf-kit:osint challenge.txt
```
