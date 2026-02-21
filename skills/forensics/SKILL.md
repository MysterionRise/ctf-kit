---
name: forensics
description: >-
  Solve CTF forensics challenges: memory dumps, network captures, disk
  images, and file carving. Use when you see: .vmem .raw .dmp memory
  dumps, .pcap .pcapng network captures, .dd .E01 disk images, or
  embedded/hidden files. Triggers: "memory dump", "packet capture",
  "disk image", "file carving", "deleted files", "volatility".
  Tools: volatility3, binwalk, foremost, tshark, sleuthkit.
  NOT for steganography (use stego) or binary exploitation (use pwn).
---

# CTF Forensics

Analyze and solve forensics challenges.

## When to Use

Use this command for challenges involving:

- Memory dumps (.vmem, .raw, .dmp)
- Network captures (.pcap, .pcapng)
- Disk images (.dd, .E01, .raw)
- Embedded/hidden files
- File carving
- Timeline analysis

## Bundled Scripts

- [check-tools.sh](scripts/check-tools.sh) — Verify required forensics tools are installed
- [run-binwalk.sh](scripts/run-binwalk.sh) — Scan and extract embedded files
- [run-volatility.sh](scripts/run-volatility.sh) — Run volatility3 plugins on memory dumps

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. Run the forensics analysis:

   ```bash
   ctf run forensics $ARGUMENTS
   ```

2. Based on file type, use appropriate tools:

   **For Memory Dumps:**

   ```bash
   # Get memory profile info
   vol -f memory.raw windows.info

   # List processes
   vol -f memory.raw windows.pslist

   # Network connections
   vol -f memory.raw windows.netscan

   # Command history
   vol -f memory.raw windows.cmdline

   # Dump password hashes
   vol -f memory.raw windows.hashdump
   ```

   **For Network Captures:**

   ```bash
   # Protocol statistics
   tshark -r capture.pcap -q -z io,phs

   # Follow TCP stream
   tshark -r capture.pcap -z follow,tcp,ascii,0

   # Export HTTP objects
   tshark -r capture.pcap --export-objects http,./extracted

   # Filter specific traffic
   tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
   ```

   **For File Carving:**

   ```bash
   # Scan for embedded files
   binwalk challenge.bin

   # Extract embedded files
   binwalk -e challenge.bin

   # Carve deleted files
   foremost -i disk.img -o output/
   ```

3. Key things to look for:
   - Suspicious processes or network connections
   - Deleted or hidden files
   - Credentials in memory or traffic
   - Unusual timestamps

## Common Volatility Plugins

| Plugin | Purpose |
|--------|---------|
| windows.pslist | List processes |
| windows.pstree | Process tree |
| windows.netscan | Network connections |
| windows.filescan | Find files in memory |
| windows.cmdline | Command line history |
| windows.hashdump | Password hashes |
| windows.malfind | Detect malware |

## Performance Notes

- Take your time with forensics — artifacts are easy to miss on a first pass
- Quality is more important than speed: run multiple volatility plugins, not just the obvious ones
- Do not skip validation steps — correlate findings across different evidence types
- For memory dumps: check process lists, network connections, AND command history before concluding
- For pcaps: examine multiple protocol layers and follow multiple streams
- Deleted or hidden files often contain the flag — always check for carved/recovered content

## Quality Checklist

Before presenting findings, verify:

- [ ] Identified the evidence type correctly (memory dump, pcap, disk image)
- [ ] Ran at least 3-5 relevant plugins/tools for the evidence type
- [ ] Checked for hidden or deleted files
- [ ] Correlated timestamps across different artifacts where applicable
- [ ] Extracted and examined all suspicious files or data blobs
- [ ] Searched for common flag patterns in all extracted content
- [ ] Documented the forensic timeline or chain of events

## Example Usage

```bash
/ctf-kit:forensics memory.raw
/ctf-kit:forensics capture.pcap
/ctf-kit:forensics disk.img
```
