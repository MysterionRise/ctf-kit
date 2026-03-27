#!/usr/bin/env bash
# triage-competition.sh — Quick triage of a challenge directory for competition mode
# Usage: bash triage-competition.sh <challenge-directory>
# Outputs a one-line JSON summary suitable for building a priority queue
set -euo pipefail

DIR="${1:-.}"
CHALLENGE_NAME=$(basename "$DIR")

if [ ! -d "$DIR" ]; then
    echo "{\"name\": \"$CHALLENGE_NAME\", \"error\": \"not a directory\"}"
    exit 1
fi

# Count files
FILE_COUNT=$(find "$DIR" -maxdepth 2 -type f 2>/dev/null | wc -l | tr -d ' ')

# Quick category detection
CATEGORY="unknown"
CONFIDENCE=0
DIFFICULTY="medium"
HAS_README="false"
DESCRIPTION=""

# Check for README or description
for readme in "$DIR"/README* "$DIR"/readme* "$DIR"/description* "$DIR"/DESCRIPTION* "$DIR"/*.txt; do
    if [ -f "$readme" ] 2>/dev/null; then
        HAS_README="true"
        DESCRIPTION=$(head -5 "$readme" 2>/dev/null | tr '\n' ' ' | tr '"' "'" | cut -c1-200)
        break
    fi
done

# Quick file type scan
EXTENSIONS=""
TYPES=""
for f in "$DIR"/*; do
    [ -f "$f" ] || continue
    ext="${f##*.}"
    EXTENSIONS="$EXTENSIONS $ext"
    ftype=$(file -b "$f" 2>/dev/null | head -1 || true)
    TYPES="$TYPES $ftype"
done

# Category scoring (fast version)
if echo "$EXTENSIONS" | grep -qiE '(pem|key|enc|aes)'; then
    CATEGORY="crypto"; CONFIDENCE=80
elif echo "$TYPES" | grep -qiE '(pcap|capture)'; then
    CATEGORY="forensics"; CONFIDENCE=85
elif echo "$EXTENSIONS" | grep -qiE '(pcap|pcapng|vmem|dmp)'; then
    CATEGORY="forensics"; CONFIDENCE=80
elif echo "$TYPES" | grep -qiE '(PNG|JPEG|BMP|GIF)' && [ "$FILE_COUNT" -le 3 ]; then
    CATEGORY="stego"; CONFIDENCE=70
elif echo "$EXTENSIONS" | grep -qiE '(php|html|js|sql)'; then
    CATEGORY="web"; CONFIDENCE=75
elif echo "$TYPES" | grep -qiE 'ELF.*executable'; then
    # Could be pwn or reverse — check for service info
    if echo "$DESCRIPTION" | grep -qiE '(nc |netcat|connect|port|service|remote)'; then
        CATEGORY="pwn"; CONFIDENCE=75
    else
        CATEGORY="reverse"; CONFIDENCE=60
    fi
elif echo "$EXTENSIONS" | grep -qiE '(exe|apk|jar|pyc)'; then
    CATEGORY="reverse"; CONFIDENCE=70
elif echo "$DESCRIPTION" | grep -qiE '(find|search|investigate|person|username|domain)'; then
    CATEGORY="osint"; CONFIDENCE=60
else
    CATEGORY="misc"; CONFIDENCE=40
fi

# Estimate difficulty from file count and description
if [ "$FILE_COUNT" -le 1 ]; then
    DIFFICULTY="easy"
elif [ "$FILE_COUNT" -le 3 ]; then
    DIFFICULTY="medium"
else
    DIFFICULTY="hard"
fi

# Check description for difficulty hints
if echo "$DESCRIPTION" | grep -qiE '(easy|beginner|warmup|intro|baby)'; then
    DIFFICULTY="easy"
elif echo "$DESCRIPTION" | grep -qiE '(hard|advanced|expert|insane)'; then
    DIFFICULTY="hard"
fi

# Plan approval needed?
NEEDS_PLAN_APPROVAL="false"
if [[ "$CATEGORY" =~ ^(web|pwn|osint)$ ]]; then
    NEEDS_PLAN_APPROVAL="true"
fi

# Priority score (higher = do first): easy+high-confidence first
case "$DIFFICULTY" in
    easy)   PRIORITY_BASE=30 ;;
    medium) PRIORITY_BASE=20 ;;
    hard)   PRIORITY_BASE=10 ;;
esac
PRIORITY=$((PRIORITY_BASE + CONFIDENCE / 10))

cat <<ENDJSON
{
  "name": "$CHALLENGE_NAME",
  "category": "$CATEGORY",
  "confidence": $CONFIDENCE,
  "difficulty": "$DIFFICULTY",
  "priority": $PRIORITY,
  "file_count": $FILE_COUNT,
  "has_readme": $HAS_README,
  "description": "$DESCRIPTION",
  "needs_plan_approval": $NEEDS_PLAN_APPROVAL
}
ENDJSON
