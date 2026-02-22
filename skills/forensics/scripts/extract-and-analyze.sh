#!/usr/bin/env bash
# Multi-step forensics: binwalk extract → file type each → strings on interesting.
# Chains extraction with analysis of each extracted file.
# Usage: extract-and-analyze.sh <file>
set -euo pipefail

FILE="${1:?Usage: extract-and-analyze.sh <file>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../../_lib"

echo "=== Forensics Extract & Analyze: $FILE ==="

# Step 1: Binwalk extract
echo ""
echo "--- Step 1: Extract embedded files ---"
if ! command -v binwalk &>/dev/null; then
    echo "ERROR: binwalk not installed" >&2
    exit 1
fi

binwalk -e "$FILE" 2>&1 || true
OUTDIR="_$(basename "$FILE").extracted"

if [ ! -d "$OUTDIR" ]; then
    echo "No files extracted. Trying with recursive extraction..."
    binwalk -eM "$FILE" 2>&1 || true
fi

if [ ! -d "$OUTDIR" ]; then
    echo "No embedded files found."
    echo ""
    echo "=== PARSED RESULTS (JSON) ==="
    echo '{"tool": "extract-and-analyze", "file": "'"$FILE"'", "extracted": [], "suggestions": ["No embedded files found - try foremost or manual analysis"]}'
    exit 0
fi

# Step 2: Analyze each extracted file
echo ""
echo "--- Step 2: Analyze extracted files ---"
ANALYSIS=""
while IFS= read -r extracted_file; do
    echo ""
    echo ">> $extracted_file"
    FTYPE=$(file -b "$extracted_file" 2>/dev/null || echo "unknown")
    echo "   Type: $FTYPE"

    # Run strings on interesting files (not images/archives)
    case "$FTYPE" in
        *"text"*|*"ASCII"*|*"data"*|*"ELF"*|*"script"*)
            INTERESTING=$(strings -n 6 "$extracted_file" 2>/dev/null | grep -iE 'flag|ctf|password|secret|key|token|http' | head -10 || true)
            if [ -n "$INTERESTING" ]; then
                echo "   Interesting strings:"
                echo "$INTERESTING" | sed 's/^/     /'
            fi
            ;;
    esac

    ANALYSIS="${ANALYSIS}${extracted_file}|${FTYPE}"$'\n'
done < <(find "$OUTDIR" -type f 2>/dev/null | sort)

# JSON summary
echo ""
echo "=== PARSED RESULTS (JSON) ==="
python3 -c "
import json, os, re, sys

file_path = '$FILE'
outdir = '$OUTDIR'

extracted = []
flags = []
interesting_files = []

for root, dirs, files in os.walk(outdir):
    for f in sorted(files):
        fpath = os.path.join(root, f)
        try:
            import subprocess
            ftype = subprocess.run(['file', '-b', fpath], capture_output=True, text=True, timeout=5).stdout.strip()
        except Exception:
            ftype = 'unknown'

        entry = {'path': fpath, 'type': ftype, 'size': os.path.getsize(fpath)}

        # Check for flags in text-like files
        if any(x in ftype.lower() for x in ['text', 'ascii', 'data', 'script']):
            try:
                with open(fpath, 'r', errors='replace') as fh:
                    content = fh.read(10000)
                    file_flags = re.findall(r'(?:flag|ctf|picoctf|htb)\{[^}]+\}', content, re.I)
                    if file_flags:
                        entry['flags'] = file_flags
                        flags.extend(file_flags)
                    if re.search(r'password|secret|key|token', content, re.I):
                        entry['has_secrets'] = True
                        interesting_files.append(fpath)
            except Exception:
                pass

        extracted.append(entry)

suggestions = []
if flags:
    suggestions.append(f'FLAG FOUND: {\", \".join(set(flags))}')
suggestions.append(f'Extracted {len(extracted)} file(s) from {file_path}')
if interesting_files:
    suggestions.append(f'{len(interesting_files)} file(s) contain secrets/credentials')
    for f in interesting_files[:5]:
        suggestions.append(f'  Investigate: {f}')

# Suggest next steps based on file types
types_found = set()
for e in extracted:
    t = e['type'].lower()
    if 'image' in t or 'png' in t or 'jpeg' in t:
        types_found.add('image')
    elif 'elf' in t or 'executable' in t:
        types_found.add('binary')
    elif 'zip' in t or 'gzip' in t or 'archive' in t:
        types_found.add('archive')
    elif 'text' in t or 'ascii' in t:
        types_found.add('text')

if 'image' in types_found:
    suggestions.append('Images found - check with /ctf-kit:stego')
if 'binary' in types_found:
    suggestions.append('Binaries found - analyze with /ctf-kit:reverse or /ctf-kit:pwn')
if 'archive' in types_found:
    suggestions.append('Nested archives found - extract recursively')

result = {
    'tool': 'extract-and-analyze',
    'file': file_path,
    'extracted_dir': outdir,
    'file_count': len(extracted),
    'extracted': extracted,
    'flags': list(set(flags)),
    'has_flag': bool(flags),
    'interesting_files': interesting_files,
    'suggestions': suggestions,
}
print(json.dumps(result, indent=2))
"
