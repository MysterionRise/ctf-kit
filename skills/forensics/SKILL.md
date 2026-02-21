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

3. Based on file type, use appropriate tools — see [Tool Reference](references/tools.md) for detailed commands:
   - **Memory dumps** → Volatility 3 plugins
   - **Network captures** → tshark analysis
   - **File carving** → binwalk, foremost, sleuthkit

4. Key things to look for:
   - Suspicious processes or network connections
   - Deleted or hidden files
   - Credentials in memory or traffic
   - Unusual timestamps

## Example Usage

```bash
/ctf-kit:forensics memory.raw
/ctf-kit:forensics capture.pcap
/ctf-kit:forensics disk.img
```

## References

- [Tool Reference](references/tools.md) — volatility plugins, tshark commands, file carving tools
