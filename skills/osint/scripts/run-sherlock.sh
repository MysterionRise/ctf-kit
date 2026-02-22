#!/usr/bin/env bash
# Run sherlock username enumeration with structured output.
# Usage: run-sherlock.sh <username>
set -euo pipefail

USERNAME="${1:?Usage: run-sherlock.sh <username>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if ! command -v sherlock &>/dev/null; then
    echo "ERROR: sherlock not installed. Install: pip install sherlock-project" >&2
    exit 1
fi

echo "=== Sherlock Username Search: $USERNAME ==="
RAW=$(sherlock "$USERNAME" --print-found 2>&1) || true
echo "$RAW"

echo ""
echo "=== PARSED RESULTS (JSON) ==="
python3 -c "
import json, re, sys

raw = sys.stdin.read()
username = '$USERNAME'

# Parse sherlock output: [+] SiteName: URL or [*] SiteName: URL
found = []
for line in raw.strip().split('\n'):
    m = re.match(r'\[\+\]\s*(\S+):\s*(https?://\S+)', line.strip())
    if m:
        found.append({'site': m.group(1), 'url': m.group(2)})
    else:
        m2 = re.match(r'\[\*\]\s*(\S+):\s*(https?://\S+)', line.strip())
        if m2:
            found.append({'site': m2.group(1), 'url': m2.group(2)})

# Categorize by platform type
social = []
code = []
other = []
social_sites = {'twitter', 'instagram', 'facebook', 'tiktok', 'reddit', 'linkedin', 'mastodon', 'tumblr', 'pinterest'}
code_sites = {'github', 'gitlab', 'bitbucket', 'stackoverflow', 'codepen', 'replit', 'hackerrank'}

for f in found:
    site_lower = f['site'].lower()
    if any(s in site_lower for s in social_sites):
        social.append(f)
    elif any(s in site_lower for s in code_sites):
        code.append(f)
    else:
        other.append(f)

suggestions = []
if found:
    suggestions.append(f'Found {len(found)} profile(s) for username: {username}')
    if social:
        suggestions.append(f'{len(social)} social media profile(s) - check for personal info, connections')
    if code:
        suggestions.append(f'{len(code)} code platform(s) - check repos for secrets, commits')
    suggestions.append('Cross-reference profiles to build complete picture')
else:
    suggestions.append(f'No profiles found for: {username}')
    suggestions.append('Try variations: underscores, numbers, different spelling')

result = {
    'tool': 'sherlock',
    'username': username,
    'total_found': len(found),
    'profiles': found,
    'social_media': social,
    'code_platforms': code,
    'other': other,
    'suggestions': suggestions,
}
print(json.dumps(result, indent=2))
" <<< "$RAW"
