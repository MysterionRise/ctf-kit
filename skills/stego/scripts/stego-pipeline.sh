#!/usr/bin/env bash
# Multi-step stego pipeline: exiftool → binwalk → zsteg/steghide.
# Runs all relevant stego tools in sequence based on file type.
# Usage: stego-pipeline.sh <image>
set -euo pipefail

IMAGE="${1:?Usage: stego-pipeline.sh <image>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../../_lib"

echo "=== Stego Pipeline: $IMAGE ==="

# Detect file type
FILE_TYPE=$(file -b "$IMAGE" 2>/dev/null || echo "unknown")
echo "File type: $FILE_TYPE"
echo ""

# Step 1: Metadata extraction
echo "--- Step 1: Metadata (exiftool) ---"
EXIF_RAW=""
if command -v exiftool &>/dev/null; then
    EXIF_RAW=$(exiftool -j -a "$IMAGE" 2>/dev/null) || true
    # Show interesting fields
    python3 -c "
import json, sys
try:
    data = json.loads(sys.stdin.read())
    if isinstance(data, list) and data:
        meta = data[0]
        keys = ['Comment', 'UserComment', 'Author', 'Artist', 'Copyright', 'Description', 'Title', 'Software']
        for k in keys:
            if k in meta and str(meta[k]).strip():
                print(f'  {k}: {meta[k]}')
        gps = [k for k in meta if 'gps' in k.lower()]
        for k in gps:
            print(f'  {k}: {meta[k]}')
        if not any(k in meta for k in keys) and not gps:
            print('  No notable metadata fields')
except Exception:
    print('  (parse error)')
" <<< "$EXIF_RAW"
else
    echo "  exiftool not available"
fi

# Step 2: Check for appended/embedded data
echo ""
echo "--- Step 2: Embedded data (binwalk) ---"
BINWALK_RAW=""
if command -v binwalk &>/dev/null; then
    BINWALK_RAW=$(binwalk "$IMAGE" 2>&1) || true
    SIG_COUNT=$(echo "$BINWALK_RAW" | grep -cE '^[0-9]+\s+0x' || echo "0")
    echo "  Signatures found: $SIG_COUNT"
    if [ "$SIG_COUNT" -gt 1 ]; then
        echo "$BINWALK_RAW" | grep -E '^[0-9]+\s+0x' | head -10
    fi
else
    echo "  binwalk not available"
fi

# Step 3: LSB analysis (PNG/BMP only)
echo ""
echo "--- Step 3: LSB Analysis ---"
ZSTEG_RAW=""
case "${FILE_TYPE,,}" in
    *png*|*bmp*|*bitmap*)
        if command -v zsteg &>/dev/null; then
            echo "  Running zsteg..."
            ZSTEG_RAW=$(zsteg -a "$IMAGE" 2>&1) || true
            # Show findings with actual content
            ZSTEG_HITS=$(echo "$ZSTEG_RAW" | grep -vE '^\s*$' | grep -E '\.\.' | head -20)
            if [ -n "$ZSTEG_HITS" ]; then
                echo "$ZSTEG_HITS"
            else
                echo "  No LSB data detected"
            fi
        else
            echo "  zsteg not available (gem install zsteg)"
        fi
        ;;
    *)
        echo "  Skipped (not PNG/BMP)"
        ;;
esac

# Step 4: Steghide (JPEG/WAV only)
echo ""
echo "--- Step 4: Steghide Extraction ---"
STEGHIDE_RAW=""
case "${FILE_TYPE,,}" in
    *jpeg*|*jpg*|*wav*|*wave*)
        if command -v steghide &>/dev/null; then
            echo "  Trying common passwords..."
            for pw in "" "password" "steghide" "secret" "hidden" "flag"; do
                RESULT=$(steghide extract -sf "$IMAGE" -p "$pw" -f 2>&1) || true
                if echo "$RESULT" | grep -qi "wrote extracted"; then
                    echo "  SUCCESS with password: '$pw'"
                    STEGHIDE_RAW="SUCCESS with password: '$pw' $RESULT"
                    break
                fi
            done
            if [ -z "$STEGHIDE_RAW" ]; then
                echo "  No extraction with common passwords"
                STEGHIDE_RAW="No extraction with common passwords"
            fi
        else
            echo "  steghide not available"
        fi
        ;;
    *)
        echo "  Skipped (not JPEG/WAV)"
        ;;
esac

# Comprehensive JSON summary
echo ""
echo "=== PIPELINE RESULTS (JSON) ==="
python3 -c "
import json, re, sys

image = '$IMAGE'
file_type = '''$FILE_TYPE'''
exif_raw = '''$(echo "$EXIF_RAW" | sed "s/'/\\\\'/g")'''
binwalk_raw = '''$(echo "$BINWALK_RAW" | sed "s/'/\\\\'/g")'''
zsteg_raw = '''$(echo "$ZSTEG_RAW" | sed "s/'/\\\\'/g")'''
steghide_raw = '''$(echo "$STEGHIDE_RAW" | sed "s/'/\\\\'/g")'''

# Parse each tool's results
results = {'exiftool': {}, 'binwalk': {}, 'zsteg': {}, 'steghide': {}}

# Exiftool
try:
    meta = json.loads(exif_raw)
    if isinstance(meta, list) and meta:
        meta = meta[0]
    interesting = {}
    for k in ['Comment', 'UserComment', 'Author', 'Artist', 'Copyright', 'Description', 'Title']:
        if k in meta and str(meta[k]).strip():
            interesting[k] = str(meta[k])[:500]
    gps = {k: str(meta[k]) for k in meta if 'gps' in k.lower()}
    results['exiftool'] = {'interesting_fields': interesting, 'gps': gps, 'total_fields': len(meta)}
except Exception:
    results['exiftool'] = {'error': 'parse failed'}

# Binwalk
sig_pattern = re.compile(r'(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)')
sigs = []
for line in binwalk_raw.strip().split('\n'):
    m = sig_pattern.match(line.strip())
    if m:
        sigs.append({'offset': int(m.group(1)), 'description': m.group(3).strip()})
results['binwalk'] = {'signatures': sigs, 'has_appended_data': len(sigs) > 1}

# Zsteg
zsteg_findings = []
zsteg_pattern = re.compile(r'^([\w,]+)\s+\.\.\s+(\w+):\s+(.+)', re.M)
for m in zsteg_pattern.finditer(zsteg_raw):
    content = m.group(3).strip().strip('\"')
    if len(content) >= 4:
        zsteg_findings.append({'channel': m.group(1), 'type': m.group(2), 'content': content[:500]})
results['zsteg'] = {'findings': zsteg_findings}

# Steghide
steghide_success = 'success' in steghide_raw.lower()
results['steghide'] = {'extracted': steghide_success, 'raw': steghide_raw[:500]}

# Collect all flags
all_text = exif_raw + binwalk_raw + zsteg_raw + steghide_raw
flags = list(set(re.findall(r'(?:flag|ctf|picoctf|htb)\{[^}]+\}', all_text, re.I)))

# Suggestions
suggestions = []
if flags:
    suggestions.append(f'FLAG FOUND: {\", \".join(flags)}')
if results['exiftool'].get('interesting_fields'):
    suggestions.append('Interesting metadata fields found - check for hidden messages')
if results['exiftool'].get('gps'):
    suggestions.append('GPS data found - try Google Maps with coordinates')
if results['binwalk'].get('has_appended_data'):
    suggestions.append('Data appended after image - extract with: binwalk -e <file>')
if zsteg_findings:
    text_finds = [f for f in zsteg_findings if f['type'] == 'text']
    if text_finds:
        suggestions.append(f'LSB text found: {text_finds[0][\"content\"][:100]}')
    file_finds = [f for f in zsteg_findings if f['type'] == 'file']
    if file_finds:
        suggestions.append(f'Embedded file in LSB: {file_finds[0][\"content\"][:100]}')
        suggestions.append(f'Extract: zsteg -E {file_finds[0][\"channel\"]} <image> > extracted')
if steghide_success:
    suggestions.append('Steghide extracted data successfully!')
if not suggestions:
    suggestions.append('No obvious steganography detected')
    suggestions.append('Try: stegsolve (visual analysis), Audacity spectrogram (audio)')

pipeline = {
    'tool': 'stego-pipeline',
    'file': image,
    'file_type': file_type,
    'steps': results,
    'flags': flags,
    'has_flag': bool(flags),
    'suggestions': suggestions,
}
print(json.dumps(pipeline, indent=2))
"
