#!/usr/bin/env bash
# Attempt to decode data through common encoding chains.
# Tries Base64, hex, ROT13, URL decoding, and detects encoding type.
# Usage: run-decode.sh <file-or-string>
set -euo pipefail

INPUT="${1:?Usage: run-decode.sh <file-or-string>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Get the data
if [ -f "$INPUT" ]; then
    DATA=$(cat "$INPUT")
    SOURCE="file"
else
    DATA="$INPUT"
    SOURCE="string"
fi

echo "=== Decode Analysis ==="
echo "Input ($SOURCE): ${DATA:0:200}"
echo ""

echo ""
echo "=== PARSED RESULTS (JSON) ==="
python3 -c "
import base64, binascii, json, re, sys, urllib.parse

data = sys.stdin.read().strip()

decodings = []

# Try Base64
try:
    decoded = base64.b64decode(data).decode('utf-8', errors='replace')
    if decoded and len(decoded) > 2 and decoded.isprintable():
        decodings.append({'encoding': 'base64', 'result': decoded[:500], 'confidence': 'high' if data.endswith('=') else 'medium'})
except Exception:
    pass

# Try Base32
try:
    decoded = base64.b32decode(data).decode('utf-8', errors='replace')
    if decoded and len(decoded) > 2 and decoded.isprintable():
        decodings.append({'encoding': 'base32', 'result': decoded[:500], 'confidence': 'medium'})
except Exception:
    pass

# Try hex
try:
    clean = data.replace(' ', '').replace('0x', '').replace(',', '')
    if re.match(r'^[0-9a-fA-F]+$', clean) and len(clean) % 2 == 0:
        decoded = bytes.fromhex(clean).decode('utf-8', errors='replace')
        if decoded and decoded.isprintable():
            decodings.append({'encoding': 'hex', 'result': decoded[:500], 'confidence': 'high'})
except Exception:
    pass

# Try ROT13
rot13 = data.translate(str.maketrans(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
if rot13 != data and any(c.isalpha() for c in data):
    decodings.append({'encoding': 'rot13', 'result': rot13[:500], 'confidence': 'low'})

# Try URL decode
url_decoded = urllib.parse.unquote(data)
if url_decoded != data:
    decodings.append({'encoding': 'url', 'result': url_decoded[:500], 'confidence': 'high'})

# Try binary
if re.match(r'^[01\s]+$', data):
    try:
        clean = data.replace(' ', '')
        chars = [chr(int(clean[i:i+8], 2)) for i in range(0, len(clean), 8)]
        decoded = ''.join(chars)
        if decoded.isprintable():
            decodings.append({'encoding': 'binary', 'result': decoded[:500], 'confidence': 'high'})
    except Exception:
        pass

# Detect encoding type
detected_type = 'unknown'
if re.match(r'^[A-Za-z0-9+/]+=*$', data) and len(data) > 10:
    detected_type = 'base64'
elif re.match(r'^[A-Z2-7]+=*$', data) and len(data) > 10:
    detected_type = 'base32'
elif re.match(r'^[0-9a-fA-F]+$', data):
    detected_type = 'hex'
elif re.match(r'^[01\s]+$', data):
    detected_type = 'binary'
elif '%' in data and re.search(r'%[0-9A-Fa-f]{2}', data):
    detected_type = 'url_encoded'

# Check for flags in any decoding
flags = []
for d in decodings:
    flag_matches = re.findall(r'(?:flag|ctf|picoctf|htb)\{[^}]+\}', d['result'], re.I)
    if flag_matches:
        flags.extend(flag_matches)
        d['has_flag'] = True

# Recursive: try decoding decoded results
chain = []
if decodings:
    first = decodings[0]['result']
    try:
        second = base64.b64decode(first).decode('utf-8', errors='replace')
        if second and second.isprintable() and len(second) > 2:
            chain.append({'step1': decodings[0]['encoding'], 'step2': 'base64', 'result': second[:500]})
            flag_matches = re.findall(r'(?:flag|ctf|picoctf|htb)\{[^}]+\}', second, re.I)
            flags.extend(flag_matches)
    except Exception:
        pass

suggestions = []
if flags:
    suggestions.append(f'FLAG FOUND: {\", \".join(set(flags))}')
if decodings:
    for d in decodings:
        suggestions.append(f'{d[\"encoding\"]}: {d[\"result\"][:100]}')
if chain:
    for c in chain:
        suggestions.append(f'Chain ({c[\"step1\"]} -> {c[\"step2\"]}): {c[\"result\"][:100]}')
if not decodings and not chain:
    suggestions.append('No standard decodings found - try CyberChef Magic recipe')
    suggestions.append('May be: esoteric language, custom cipher, or already plaintext')

result = {
    'tool': 'decode',
    'detected_encoding': detected_type,
    'decodings': decodings,
    'chains': chain,
    'flags': list(set(flags)),
    'has_flag': bool(flags),
    'suggestions': suggestions,
}
print(json.dumps(result, indent=2))
" <<< "$DATA"
