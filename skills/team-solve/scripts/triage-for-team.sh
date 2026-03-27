#!/usr/bin/env bash
# triage-for-team.sh — Triage a challenge and recommend team composition
# Usage: bash triage-for-team.sh <file-or-directory>
# Compatible with bash 3.2+ (macOS default)
set -euo pipefail

TARGET="${1:-.}"
SIGNALS=""

# --- Category scores ---
SCORE_CRYPTO=0
SCORE_FORENSICS=0
SCORE_STEGO=0
SCORE_WEB=0
SCORE_PWN=0
SCORE_REVERSE=0
SCORE_OSINT=0
SCORE_MISC=0

add_signal() {
    if [ -n "$SIGNALS" ]; then
        SIGNALS="$SIGNALS,\"$1\""
    else
        SIGNALS="\"$1\""
    fi
}

detect_file_type() {
    file -b "$1" 2>/dev/null || echo "unknown"
}

# --- Collect files ---
FILES=""
FILE_COUNT=0
if [ -d "$TARGET" ]; then
    while IFS= read -r f; do
        FILES="$FILES
$f"
        FILE_COUNT=$((FILE_COUNT + 1))
    done <<EOF
$(find "$TARGET" -maxdepth 2 -type f 2>/dev/null)
EOF
else
    FILES="$TARGET"
    FILE_COUNT=1
fi

if [ "$FILE_COUNT" -eq 0 ]; then
    echo '{"error": "No files found", "category": "unknown", "confidence": 0}'
    exit 1
fi

# --- Analyze each file ---
echo "$FILES" | while IFS= read -r f; do
    [ -z "$f" ] && continue
    [ -f "$f" ] || continue

    ftype=$(detect_file_type "$f")
    fname=$(basename "$f")
    ext="${fname##*.}"
    strs=$(strings "$f" 2>/dev/null | head -200 || true)

    # Crypto signals
    if echo "$strs" | grep -qiE '(BEGIN (RSA|PUBLIC|PRIVATE)|n[[:space:]]*=[[:space:]]*[0-9]{10,}|e[[:space:]]*=[[:space:]]*(65537|3|17)|-----BEGIN)'; then
        echo "CRYPTO:30"
        echo "SIGNAL:RSA/crypto parameters detected"
    fi
    if echo "$strs" | grep -qE '^[0-9a-f]{32,128}$'; then
        echo "CRYPTO:15"
        echo "SIGNAL:Hash-like hex string detected"
    fi
    if echo "$ext" | grep -qiE '^(pem|key|enc|aes|des|gpg)$'; then
        echo "CRYPTO:25"
        echo "SIGNAL:Crypto file extension: $ext"
    fi

    # Forensics signals
    if echo "$ftype" | grep -qiE '(pcap|capture|tcpdump)'; then
        echo "FORENSICS:30"
        echo "SIGNAL:PCAP file detected"
    fi
    if echo "$ftype" | grep -qiE '(ELF.*core|Windows.*memory|vmem)'; then
        echo "FORENSICS:30"
        echo "SIGNAL:Memory dump detected"
    fi
    if echo "$ext" | grep -qiE '^(pcap|pcapng|vmem|raw|dmp|dd|E01)$'; then
        echo "FORENSICS:25"
        echo "SIGNAL:Forensics file extension: $ext"
    fi

    # Stego signals
    if echo "$ftype" | grep -qiE '(PNG|JPEG|BMP|GIF|TIFF|WAV|FLAC|Audio)'; then
        echo "STEGO:20"
        echo "SIGNAL:Media file detected"
    fi
    if echo "$ext" | grep -qiE '^(png|jpg|jpeg|bmp|gif|wav|mp3|flac)$'; then
        echo "STEGO:15"
        echo "SIGNAL:Media file extension: $ext"
    fi

    # Web signals
    if echo "$strs" | grep -qiE '(<!DOCTYPE|<html|<?php|SELECT.*FROM|INSERT.*INTO|cookie|jwt|Bearer)'; then
        echo "WEB:25"
        echo "SIGNAL:Web content detected"
    fi
    if echo "$ext" | grep -qiE '^(php|html|js|css|sql|jwt)$'; then
        echo "WEB:20"
        echo "SIGNAL:Web file extension: $ext"
    fi

    # Pwn signals
    if echo "$ftype" | grep -qiE 'ELF.*executable'; then
        echo "PWN:15"
        echo "REVERSE:15"
        echo "SIGNAL:ELF executable detected"
    fi
    if echo "$strs" | grep -qiE '(buffer|overflow|stack|smash|canary)'; then
        echo "PWN:20"
        echo "SIGNAL:Pwn-related strings found"
    fi

    # Reverse signals
    if echo "$ftype" | grep -qiE '(PE32|Mach-O|Java.*class|compiled)'; then
        echo "REVERSE:20"
        echo "SIGNAL:Binary for reversing detected"
    fi
    if echo "$ext" | grep -qiE '^(exe|apk|jar|pyc|class|so|dll)$'; then
        echo "REVERSE:20"
        echo "SIGNAL:Reversing file extension: $ext"
    fi

    # OSINT signals
    if echo "$strs" | grep -qiE '(@[a-zA-Z0-9_]+\.(com|org|net)|username|geolocation|coordinates)'; then
        echo "OSINT:20"
        echo "SIGNAL:OSINT-related content detected"
    fi

    # Misc signals
    if echo "$strs" | grep -qiE '(\+\[->|Ook[.!?])'; then
        echo "MISC:25"
        echo "SIGNAL:Esoteric language detected"
    fi
    if echo "$ftype" | grep -qiE 'QR|barcode'; then
        echo "MISC:20"
        echo "SIGNAL:QR/barcode detected"
    fi
done > /tmp/ctf-triage-$$

# --- Aggregate scores ---
if [ -f /tmp/ctf-triage-$$ ]; then
    while IFS=: read -r cat score; do
        case "$cat" in
            CRYPTO)    SCORE_CRYPTO=$((SCORE_CRYPTO + score)) ;;
            FORENSICS) SCORE_FORENSICS=$((SCORE_FORENSICS + score)) ;;
            STEGO)     SCORE_STEGO=$((SCORE_STEGO + score)) ;;
            WEB)       SCORE_WEB=$((SCORE_WEB + score)) ;;
            PWN)       SCORE_PWN=$((SCORE_PWN + score)) ;;
            REVERSE)   SCORE_REVERSE=$((SCORE_REVERSE + score)) ;;
            OSINT)     SCORE_OSINT=$((SCORE_OSINT + score)) ;;
            MISC)      SCORE_MISC=$((SCORE_MISC + score)) ;;
            SIGNAL)    add_signal "$score" ;;
        esac
    done < /tmp/ctf-triage-$$
    rm -f /tmp/ctf-triage-$$
fi

# --- Find top 2 categories ---
BEST_CAT="misc"
BEST_SCORE=0
SECOND_CAT=""
SECOND_SCORE=0

for entry in \
    "crypto:$SCORE_CRYPTO" \
    "forensics:$SCORE_FORENSICS" \
    "stego:$SCORE_STEGO" \
    "web:$SCORE_WEB" \
    "pwn:$SCORE_PWN" \
    "reverse:$SCORE_REVERSE" \
    "osint:$SCORE_OSINT" \
    "misc:$SCORE_MISC"; do

    cat="${entry%%:*}"
    score="${entry##*:}"

    if [ "$score" -gt "$BEST_SCORE" ]; then
        SECOND_CAT="$BEST_CAT"
        SECOND_SCORE="$BEST_SCORE"
        BEST_CAT="$cat"
        BEST_SCORE="$score"
    elif [ "$score" -gt "$SECOND_SCORE" ]; then
        SECOND_CAT="$cat"
        SECOND_SCORE="$score"
    fi
done

# --- Calculate confidence ---
CONFIDENCE=0
TOTAL=$((SCORE_CRYPTO + SCORE_FORENSICS + SCORE_STEGO + SCORE_WEB + SCORE_PWN + SCORE_REVERSE + SCORE_OSINT + SCORE_MISC))
if [ "$TOTAL" -gt 0 ]; then
    CONFIDENCE=$(( (BEST_SCORE * 100) / TOTAL ))
fi

# --- Determine team type ---
if [ "$CONFIDENCE" -ge 70 ]; then
    TEAM_TYPE="single-category"
    TEAM_CATEGORY="$BEST_CAT"
elif [ "$CONFIDENCE" -ge 40 ] && [ -n "$SECOND_CAT" ]; then
    TEAM_TYPE="cross-category"
    TEAM_CATEGORY="$BEST_CAT+$SECOND_CAT"
else
    TEAM_TYPE="cross-category"
    TEAM_CATEGORY="$BEST_CAT+generalist"
fi

# --- Plan approval check ---
NEEDS_PLAN_APPROVAL="false"
case "$BEST_CAT" in web|pwn|osint) NEEDS_PLAN_APPROVAL="true" ;; esac
case "$SECOND_CAT" in web|pwn|osint) NEEDS_PLAN_APPROVAL="true" ;; esac

# --- Output JSON ---
cat <<ENDJSON
=== TEAM TRIAGE RESULTS (JSON) ===
{
  "category": "$BEST_CAT",
  "confidence": $CONFIDENCE,
  "secondary_category": "$SECOND_CAT",
  "secondary_confidence": $SECOND_SCORE,
  "team_type": "$TEAM_TYPE",
  "team_category": "$TEAM_CATEGORY",
  "needs_plan_approval": $NEEDS_PLAN_APPROVAL,
  "file_count": $FILE_COUNT,
  "signals": [$SIGNALS],
  "scores": {
    "crypto": $SCORE_CRYPTO,
    "forensics": $SCORE_FORENSICS,
    "stego": $SCORE_STEGO,
    "web": $SCORE_WEB,
    "pwn": $SCORE_PWN,
    "reverse": $SCORE_REVERSE,
    "osint": $SCORE_OSINT,
    "misc": $SCORE_MISC
  },
  "recommendation": "Use /ctf-kit:team-solve with $TEAM_TYPE team ($TEAM_CATEGORY). Spawn 3 teammates."
}
ENDJSON
