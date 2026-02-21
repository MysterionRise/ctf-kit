# OSINT — Tool Reference

## Username Enumeration

```bash
# Search across platforms
sherlock username

# Check specific site
sherlock username --site github

# Multiple usernames
sherlock user1 user2 user3
```

## Domain Reconnaissance

```bash
# Gather emails and subdomains
theHarvester -d target.com -b all

# DNS lookup
dig target.com ANY

# Specific records
dig target.com MX
dig target.com TXT
dig target.com NS

# Whois information
whois target.com

# Reverse DNS
dig -x <IP_ADDRESS>

# Zone transfer (if misconfigured)
dig axfr target.com @ns1.target.com
```

## Image Geolocation

```bash
# Extract all EXIF data
exiftool image.jpg

# Look for GPS coordinates
exiftool -gps* image.jpg

# Extract GPS as decimal
exiftool -n -gpslatitude -gpslongitude image.jpg

# Strip metadata (for comparison)
exiftool -all= copy.jpg
```

## Online Resources

| Category | Resources |
|----------|-----------|
| Maps | Google Maps, Google Earth, Google Street View |
| Archive | web.archive.org (Wayback Machine), Archive.today |
| Reverse Image | Google Images, TinEye, Yandex Images |
| Social | LinkedIn, Twitter/X, Facebook, Instagram |
| Breach Data | haveibeenpwned.com |
| Subdomains | crt.sh (certificate transparency) |
| IP/Host | Shodan, Censys, SecurityTrails |
| Email | Hunter.io, phonebook.cz |
