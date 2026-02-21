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

## Common Issues

**`volatility3` not found or `vol` command missing**
- **Cause:** Volatility 3 not installed, or installed as `vol3`/`volatility3` instead of `vol`
- **Solution:** Install with `pip install volatility3`. The command may be `vol`, `vol3`, or `python -m volatility3` depending on install method. Check with `which vol vol3 volatility3`

**Volatility: "Unsatisfied requirement" or no profile found**
- **Cause:** Volatility 3 needs symbol tables for the OS version of the memory dump. Unlike Volatility 2, it downloads them automatically but may fail offline
- **Solution:** For Windows dumps, symbol tables are auto-downloaded. For Linux, you need the exact kernel's symbol table — check the challenge description for OS info. Download ISF files from the [Volatility 3 symbol tables repo](https://github.com/volatilityfoundation/volatility3#symbol-tables) and place in `volatility3/symbols/`

**Volatility plugin returns empty results**
- **Cause:** Wrong OS plugin family (e.g., using `windows.pslist` on a Linux dump)
- **Solution:** First determine the OS: try `vol -f dump.raw banners.Banners` or `strings dump.raw | grep -i 'linux\|windows\|darwin'`. Use `linux.` or `mac.` prefixed plugins for non-Windows dumps

**`tshark` not found**
- **Cause:** Wireshark/tshark not installed
- **Solution:** Install with `apt install tshark` (Debian/Ubuntu) or `brew install wireshark` (macOS, includes tshark)

**`binwalk -e` extracts nothing useful**
- **Cause:** binwalk found signatures but extraction failed, or the embedded data uses a custom format
- **Solution:** Try `binwalk --dd='.*'` to extract all detected types. For specific offsets, use `dd if=file bs=1 skip=<offset> of=extracted` to manually carve. Also try `foremost -i file -o output/` as an alternative carver

**`foremost` not found**
- **Cause:** Not installed (not available via brew on macOS by default)
- **Solution:** Install with `apt install foremost` (Debian/Ubuntu). On macOS, use `brew install foremost` or use `binwalk -e` as a fallback

**PCAP file too large to analyze**
- **Cause:** Large capture files slow down tshark queries
- **Solution:** Filter early: `tshark -r large.pcap -Y "http" -w filtered.pcap` to extract only relevant traffic. Use `tshark -r file.pcap -q -z io,phs` for a quick protocol summary before deep analysis

## Example Usage

```bash
/ctf-kit:forensics memory.raw
/ctf-kit:forensics capture.pcap
/ctf-kit:forensics disk.img
```
