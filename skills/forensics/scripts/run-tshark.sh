#!/usr/bin/env bash
# Run tshark analysis on network captures with structured output.
# Usage: run-tshark.sh <pcap> [filter]
set -euo pipefail

PCAP="${1:?Usage: run-tshark.sh <pcap-file> [display-filter]}"
FILTER="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../../_lib"

if ! command -v tshark &>/dev/null; then
    echo "ERROR: tshark not installed. Install: brew install wireshark / apt install tshark" >&2
    exit 1
fi

echo "=== Protocol Statistics: $PCAP ==="
STATS=$(tshark -r "$PCAP" -q -z io,phs 2>&1) || true
echo "$STATS"

echo ""
echo "=== Conversation Summary ==="
CONVS=$(tshark -r "$PCAP" -q -z conv,tcp 2>&1) || true
echo "$CONVS"

FILTER_OUTPUT=""
if [ -n "$FILTER" ]; then
    echo ""
    echo "=== Filtered: $FILTER ==="
    FILTER_OUTPUT=$(tshark -r "$PCAP" -Y "$FILTER" 2>&1) || true
    echo "$FILTER_OUTPUT"
fi

# Structured output
echo ""
echo "=== PARSED RESULTS (JSON) ==="
python3 -c "
import json, re, sys

stats = '''$STATS'''
convs = '''$CONVS'''
pcap = '$PCAP'

# Count packets
packet_count = 0
pkt_match = re.search(r'(\d+)\s+packets', stats)
if pkt_match:
    packet_count = int(pkt_match.group(1))

# Parse protocols
protocols = []
for line in stats.split('\n'):
    m = re.match(r'\s+([\w.]+)\s+frames:(\d+)\s+bytes:(\d+)', line)
    if m:
        protocols.append({'protocol': m.group(1), 'frames': int(m.group(2)), 'bytes': int(m.group(3))})

# Parse conversations
conversations = []
for line in convs.split('\n'):
    parts = line.strip().split()
    if len(parts) >= 5 and ':' in parts[0]:
        conversations.append({
            'src': parts[0],
            'dst': parts[2] if len(parts) > 2 else '',
            'frames': parts[3] if len(parts) > 3 else '',
        })

# Suggestions
suggestions = []
http_found = any(p['protocol'] in ('http', 'http2') for p in protocols)
dns_found = any(p['protocol'] == 'dns' for p in protocols)
tls_found = any(p['protocol'] in ('tls', 'ssl') for p in protocols)
ftp_found = any(p['protocol'] == 'ftp' for p in protocols)

if http_found:
    suggestions.append('HTTP traffic found - extract objects: tshark -r <pcap> --export-objects http,./http_export')
    suggestions.append('View requests: tshark -r <pcap> -Y http.request -T fields -e http.host -e http.request.uri')
if dns_found:
    suggestions.append('DNS found - check queries: tshark -r <pcap> -Y dns.qry.name -T fields -e dns.qry.name')
    suggestions.append('DNS exfiltration? Look for long subdomains or TXT records')
if tls_found:
    suggestions.append('TLS/SSL found - check for key file to decrypt')
if ftp_found:
    suggestions.append('FTP found - credentials may be in cleartext: tshark -r <pcap> -Y ftp')
if not suggestions:
    suggestions.append('Follow TCP streams: tshark -r <pcap> -z follow,tcp,ascii,0')

suggestions.append(f'Total packets: {packet_count}')

result = {
    'tool': 'tshark',
    'file': pcap,
    'packet_count': packet_count,
    'protocols': protocols[:20],
    'conversations': conversations[:20],
    'has_http': http_found,
    'has_dns': dns_found,
    'has_tls': tls_found,
    'suggestions': suggestions,
}
print(json.dumps(result, indent=2))
"
