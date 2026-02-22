#!/usr/bin/env bash
# Run gobuster directory enumeration with structured output.
# Usage: run-gobuster.sh <url> [wordlist] [extensions]
set -euo pipefail

URL="${1:?Usage: run-gobuster.sh <url> [wordlist] [extensions]}"
WORDLIST="${2:-/usr/share/wordlists/dirb/common.txt}"
EXTENSIONS="${3:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if ! command -v gobuster &>/dev/null; then
    echo "ERROR: gobuster not installed. Install: go install github.com/OJ/gobuster/v3@latest" >&2
    exit 1
fi

ARGS=(dir -u "$URL" -w "$WORDLIST" -q)
[ -n "$EXTENSIONS" ] && ARGS+=(-x "$EXTENSIONS")

echo "=== Gobuster Directory Scan: $URL ==="
echo "Wordlist: $WORDLIST"
[ -n "$EXTENSIONS" ] && echo "Extensions: $EXTENSIONS"
echo ""
RAW=$(gobuster "${ARGS[@]}" 2>&1) || true
echo "$RAW"

echo ""
echo "=== PARSED RESULTS (JSON) ==="
python3 -c "
import json, re, sys

raw = sys.stdin.read()
url = '$URL'

# Parse gobuster output: /path (Status: 200) [Size: 1234]
entries = []
for line in raw.strip().split('\n'):
    m = re.match(r'(/\S*)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]', line.strip())
    if m:
        entries.append({'path': m.group(1), 'status': int(m.group(2)), 'size': int(m.group(3))})
    else:
        # Alternate format: /path  [Status=200] [Size=1234]
        m2 = re.match(r'(/\S*)\s.*Status[=:]\s*(\d+).*Size[=:]\s*(\d+)', line.strip())
        if m2:
            entries.append({'path': m2.group(1), 'status': int(m2.group(2)), 'size': int(m2.group(3))})

# Categorize
ok_paths = [e for e in entries if 200 <= e['status'] < 300]
redirect_paths = [e for e in entries if 300 <= e['status'] < 400]
forbidden_paths = [e for e in entries if e['status'] == 403]

suggestions = []
if ok_paths:
    suggestions.append(f'Found {len(ok_paths)} accessible path(s)')
    for p in ok_paths[:5]:
        suggestions.append(f'  {p[\"path\"]} (Status: {p[\"status\"]}, Size: {p[\"size\"]})')
if redirect_paths:
    suggestions.append(f'{len(redirect_paths)} redirect(s) - follow them manually')
if forbidden_paths:
    suggestions.append(f'{len(forbidden_paths)} forbidden path(s) - may indicate hidden content')
if not entries:
    suggestions.append('No paths found - try a larger wordlist or different extensions')

result = {
    'tool': 'gobuster',
    'url': url,
    'total_found': len(entries),
    'entries': entries,
    'accessible': ok_paths,
    'redirects': redirect_paths,
    'forbidden': forbidden_paths,
    'suggestions': suggestions,
}
print(json.dumps(result, indent=2))
" <<< "$RAW"
