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

1. Check tool availability:

   ```bash
   bash scripts/check-tools.sh
   ```

   Expected: each tool prints `[OK]`. If any show `[MISSING]`, note which are unavailable before proceeding.

2. Run the forensics analysis:

   ```bash
   ctf run forensics $ARGUMENTS
   ```

   Expected output: file type identification (memory dump, pcap, disk image, or embedded files).

3. **CRITICAL: Before choosing tools, identify the file type:**
   - `file` output contains `data`, `.vmem`, `.raw`, `.dmp` → **Memory dump** → go to step 4a
   - `file` output contains `pcap`, `pcapng`, `tcpdump` → **Network capture** → go to step 4b
   - `file` output contains `disk image`, `DOS/MBR`, or `binwalk` finds embedded files → **File carving** → go to step 4c

   If unclear, run: `file $ARGUMENTS && binwalk $ARGUMENTS | head -10`

4. Apply the matching toolset:

   **4a. Memory Dumps:**

   ```bash
   vol -f memory.raw windows.info
   ```

   Expected: `Variable  Value` table with OS version, kernel base, etc. This confirms the dump is valid. Then:

   ```bash
   vol -f memory.raw windows.pslist
   ```

   Expected: process table with columns `PID PPID ImageFileName`. Look for unusual processes (e.g., `cmd.exe`, `powershell.exe`, unknown names). Then:

   ```bash
   vol -f memory.raw windows.cmdline
   ```

   Expected: command-line arguments for each process. Look for flags, passwords, or file paths.

   ```bash
   vol -f memory.raw windows.hashdump
   ```

   Expected: `Username:RID:LM_hash:NTLM_hash:::` — crack these hashes if needed.

   **4b. Network Captures:**

   ```bash
   tshark -r capture.pcap -q -z io,phs
   ```

   Expected: protocol hierarchy tree showing traffic breakdown (e.g., `TCP: 85%`, `HTTP: 12%`). Focus on the most common protocols. Then:

   ```bash
   tshark -r capture.pcap -z follow,tcp,ascii,0
   ```

   Expected: full TCP conversation in ASCII. Look for credentials, flags, or interesting data. Then:

   ```bash
   tshark -r capture.pcap --export-objects http,./extracted
   ```

   Expected: files saved to `./extracted/`. Check each extracted file for flags.

   **4c. File Carving:**

   ```bash
   binwalk challenge.bin
   ```

   Expected: table of `DECIMAL  HEXADECIMAL  DESCRIPTION` showing embedded file signatures. Then:

   ```bash
   binwalk -e challenge.bin
   ```

   Expected: files extracted to `_challenge.bin.extracted/`. List and examine each file.

   ```bash
   foremost -i disk.img -o output/
   ```

   Expected: carved files sorted by type in `output/` subdirectories (jpg, png, zip, etc.).

5. **Validation: Confirm you found actionable results.** Check for:
   - Suspicious processes or unusual network connections
   - Credentials (hashes, plaintext passwords, tokens)
   - Hidden or deleted files containing flags
   - Unusual timestamps indicating tampering

   If no flag found, revisit step 3 — the file type identification may need a second look.

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

## Example Usage

```bash
/ctf-kit:forensics memory.raw
/ctf-kit:forensics capture.pcap
/ctf-kit:forensics disk.img
```
