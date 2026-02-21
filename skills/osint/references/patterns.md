# OSINT — Investigation Patterns

## OSINT Workflow

1. **Collect:** Gather all given information (usernames, emails, domains, images)
2. **Identify:** Extract unique identifiers
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

### 1. Metadata Analysis
- GPS coordinates
- Camera model
- Date/time taken
- Software used
- Author information

### 2. Visual Analysis
- Landmarks visible
- Signs/text in image
- Weather/shadows (time of day)
- Unique geographic features
- Language on signs
- Vehicle license plates
- Architecture style

### 3. Reverse Image Search
- Google Images (best general coverage)
- TinEye (exact match tracking)
- Yandex (good for faces and locations)

## Username Investigation Strategy

1. Search username across platforms (sherlock)
2. Check matching profiles for:
   - Real name
   - Location
   - Bio/about text
   - Connected accounts
   - Post history
3. Cross-reference findings
4. Check for reused passwords in breaches (HIBP)
