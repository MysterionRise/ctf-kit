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
- [run-binwalk.sh](scripts/run-binwalk.sh) — Scan and extract embedded files. Outputs JSON with signatures, file types, and extraction suggestions.
- [run-volatility.sh](scripts/run-volatility.sh) — Run volatility3 plugins on memory dumps. Outputs JSON with parsed table data and suspicious process detection.
- [run-tshark.sh](scripts/run-tshark.sh) — Analyze PCAP files with protocol statistics. Outputs JSON with protocols, conversations, and HTTP/DNS/FTP suggestions.
- [extract-and-analyze.sh](scripts/extract-and-analyze.sh) — **Multi-step pipeline**: binwalk extract → file type each → strings on interesting files → flag search. Chains extraction with analysis automatically.

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. **For quick embedded file detection**:

   ```bash
   bash scripts/run-binwalk.sh $ARGUMENTS
   bash scripts/run-binwalk.sh <file> --extract    # also extract
   ```

   Read the JSON `next_steps` object to decide what to do:
   - `has_archives: true` → extract with `binwalk -e`
   - `has_executables: true` → analyze with strings/disassembler
   - `has_images: true` → check with `/ctf-kit:stego`

3. **For full extract-and-analyze pipeline** (chains binwalk → file → strings):

   ```bash
   bash scripts/extract-and-analyze.sh <file>
   ```

   This automatically extracts embedded files, identifies their types, searches for flags and secrets, and suggests next skills to use.

4. **For memory dumps**:

   ```bash
   bash scripts/run-volatility.sh <dump>                    # system info
   bash scripts/run-volatility.sh <dump> windows.pslist     # processes
   bash scripts/run-volatility.sh <dump> windows.netscan    # network
   bash scripts/run-volatility.sh <dump> windows.cmdline    # commands
   ```

   The JSON output includes parsed table data and flags suspicious processes.

5. **For network captures**:

   ```bash
   bash scripts/run-tshark.sh <pcap>
   bash scripts/run-tshark.sh <pcap> "http.request"    # with filter
   ```

   The JSON includes protocol detection (`has_http`, `has_dns`, `has_tls`) with specific extraction commands.

## Multi-Step Workflow

The scripts are designed to chain. A typical forensics workflow:

1. `run-binwalk.sh challenge.bin` → JSON shows archives inside
2. `extract-and-analyze.sh challenge.bin` → extracts and analyzes each file
3. Based on JSON `suggestions`, follow up with specific tools

## Output Format

All scripts produce `=== PARSED RESULTS (JSON) ===` sections. Key fields:

| Field | Description |
|-------|-------------|
| `signatures` | Embedded file signatures found |
| `file_types` | Types of embedded files |
| `next_steps` | Boolean flags for what was found |
| `suggestions` | Actionable next commands |

## Example Usage

```bash
/ctf-kit:forensics memory.raw
/ctf-kit:forensics capture.pcap
/ctf-kit:forensics disk.img
```
