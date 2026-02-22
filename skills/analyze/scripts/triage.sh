#!/usr/bin/env bash
# Multi-step triage: file → strings → binwalk → category suggestion.
# Chains tool outputs to produce a comprehensive initial analysis.
# Usage: triage.sh <file>
set -euo pipefail

FILE="${1:?Usage: triage.sh <file>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../../_lib"

echo "=== CTF Challenge Triage: $FILE ==="
echo ""

# Step 1: File type detection
echo "--- Step 1: File Type Detection ---"
if command -v file &>/dev/null; then
    FILE_TYPE=$(file -b "$FILE" 2>&1) || true
    echo "$FILE_TYPE"
    FILE_MIME=$(file -b --mime-type "$FILE" 2>&1) || true
    echo "MIME: $FILE_MIME"
else
    FILE_TYPE="unknown"
    FILE_MIME="unknown"
    echo "WARNING: 'file' command not available"
fi

# Step 2: Strings analysis
echo ""
echo "--- Step 2: Strings Analysis ---"
STRINGS_RAW=""
if command -v strings &>/dev/null; then
    STRINGS_RAW=$(strings -n 4 "$FILE" 2>&1) || true
    TOTAL_STRINGS=$(echo "$STRINGS_RAW" | wc -l | tr -d ' ')
    echo "Total strings: $TOTAL_STRINGS"
    # Show flag-like patterns immediately
    FLAGS=$(echo "$STRINGS_RAW" | grep -oEi '(flag|ctf|picoctf|htb)\{[^}]+\}' || true)
    if [ -n "$FLAGS" ]; then
        echo "FLAG(S) FOUND:"
        echo "$FLAGS"
    fi
    # Show URLs
    URLS=$(echo "$STRINGS_RAW" | grep -oE 'https?://[^ ]+' | head -5 || true)
    if [ -n "$URLS" ]; then
        echo "URLs found:"
        echo "$URLS"
    fi
else
    echo "WARNING: 'strings' command not available"
fi

# Step 3: Binwalk scan
echo ""
echo "--- Step 3: Binwalk Embedded File Scan ---"
BINWALK_RAW=""
if command -v binwalk &>/dev/null; then
    BINWALK_RAW=$(binwalk "$FILE" 2>&1) || true
    echo "$BINWALK_RAW"
else
    echo "WARNING: binwalk not available"
fi

# Step 4: Exiftool metadata (for images/media)
echo ""
echo "--- Step 4: Metadata Check ---"
EXIF_RAW=""
if command -v exiftool &>/dev/null; then
    EXIF_RAW=$(exiftool -j -a "$FILE" 2>/dev/null) || true
    FIELD_COUNT=$(echo "$EXIF_RAW" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d[0]) if isinstance(d,list) and d else 0)" 2>/dev/null || echo "0")
    echo "Metadata fields: $FIELD_COUNT"
else
    echo "WARNING: exiftool not available"
fi

# Comprehensive JSON summary combining all steps
echo ""
echo "=== TRIAGE RESULTS (JSON) ==="
python3 -c "
import json, re, sys, os

file_path = '$FILE'
file_type = '''$FILE_TYPE'''
file_mime = '$FILE_MIME'
file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

# Parse strings findings
strings_raw = sys.stdin.read()
strings_lines = [l for l in strings_raw.strip().split('\n') if l.strip()] if strings_raw.strip() else []

flags = re.findall(r'(?:flag|ctf|picoctf|htb)\{[^}]+\}', strings_raw, re.I)
urls = re.findall(r'https?://\S+', strings_raw)
emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', strings_raw)
hashes = re.findall(r'(?<![0-9a-f])[0-9a-f]{32,64}(?![0-9a-f])', strings_raw, re.I)
b64 = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', strings_raw)

# Parse binwalk
binwalk_raw = '''$(echo "$BINWALK_RAW" | sed "s/'/\\\\'/g")'''
sig_pattern = re.compile(r'(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)')
signatures = []
for line in binwalk_raw.strip().split('\n'):
    m = sig_pattern.match(line.strip())
    if m:
        signatures.append({'offset': int(m.group(1)), 'description': m.group(3).strip()})

# Determine category
category = 'misc'
confidence = 0.0
reasons = []

ft_lower = file_type.lower()
mime_lower = file_mime.lower()

# Forensics indicators
if any(x in ft_lower for x in ['tcpdump', 'pcap', 'capture']):
    category = 'forensics'; confidence = 0.9; reasons.append('PCAP file detected')
elif any(x in ft_lower for x in ['disk image', 'filesystem']):
    category = 'forensics'; confidence = 0.8; reasons.append('Disk image detected')
elif any(x in ft_lower for x in ['hibernation', 'memory dump']):
    category = 'forensics'; confidence = 0.9; reasons.append('Memory dump detected')

# Stego indicators
elif any(x in mime_lower for x in ['image/', 'audio/']):
    category = 'stego'; confidence = 0.6; reasons.append('Media file - likely steganography')
elif any(x in ft_lower for x in ['png', 'jpeg', 'gif', 'bmp', 'wav', 'mp3']):
    category = 'stego'; confidence = 0.6; reasons.append('Media file detected')

# PWN/Reverse indicators
elif 'elf' in ft_lower:
    category = 'pwn'; confidence = 0.5; reasons.append('ELF binary detected')
    if any(x in ft_lower for x in ['executable', 'shared object']):
        reasons.append('Executable binary')
elif 'pe32' in ft_lower or '.exe' in file_path.lower():
    category = 'reverse'; confidence = 0.5; reasons.append('PE executable detected')

# Crypto indicators
elif any(x in ft_lower for x in ['pem', 'key', 'certificate']):
    category = 'crypto'; confidence = 0.8; reasons.append('Cryptographic material detected')
elif hashes or b64:
    category = 'crypto'; confidence = 0.4; reasons.append('Encoded/hashed data detected')

# Web indicators
elif any(x in ft_lower for x in ['html', 'php', 'javascript']):
    category = 'web'; confidence = 0.7; reasons.append('Web source code detected')

# Embedded files → forensics
if len(signatures) > 2:
    if category == 'misc':
        category = 'forensics'
        confidence = 0.5
    reasons.append(f'{len(signatures)} embedded signatures found')

# Flags override everything
if flags:
    reasons.insert(0, f'FLAG FOUND: {\", \".join(flags[:3])}')

# Suggest next skill
skill_map = {
    'crypto': '/ctf-kit:crypto',
    'forensics': '/ctf-kit:forensics',
    'stego': '/ctf-kit:stego',
    'web': '/ctf-kit:web',
    'pwn': '/ctf-kit:pwn',
    'reverse': '/ctf-kit:reverse',
    'osint': '/ctf-kit:osint',
    'misc': '/ctf-kit:misc',
}

suggestions = []
suggestions.append(f'Detected category: {category} (confidence: {confidence:.0%})')
suggestions.append(f'Recommended skill: {skill_map[category]}')
for r in reasons:
    suggestions.append(f'  - {r}')

if flags:
    suggestions.insert(0, f'FLAG(S) FOUND: {\", \".join(flags[:3])}')

result = {
    'tool': 'triage',
    'file': file_path,
    'file_type': file_type,
    'file_mime': file_mime,
    'file_size': file_size,
    'category': category,
    'confidence': confidence,
    'reasons': reasons,
    'strings_count': len(strings_lines),
    'findings': {
        'flags': list(set(flags)),
        'urls': list(set(urls))[:10],
        'emails': list(set(emails))[:10],
        'hashes': list(set(hashes))[:10],
        'base64_strings': b64[:5],
    },
    'embedded_signatures': signatures[:20],
    'suggested_skill': skill_map[category],
    'suggestions': suggestions,
}
print(json.dumps(result, indent=2))
" <<< "$STRINGS_RAW"
