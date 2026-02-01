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

## Instructions

1. Run the forensics analysis:

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

## Example Usage

```bash
/ctf-forensics memory.raw
/ctf-forensics capture.pcap
/ctf-forensics disk.img
```
