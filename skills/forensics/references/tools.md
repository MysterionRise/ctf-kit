# Forensics — Tool Reference

## Memory Dump Analysis (Volatility 3)

```bash
# Get memory profile info
vol -f memory.raw windows.info

# List processes
vol -f memory.raw windows.pslist

# Process tree
vol -f memory.raw windows.pstree

# Network connections
vol -f memory.raw windows.netscan

# Command history
vol -f memory.raw windows.cmdline

# Dump password hashes
vol -f memory.raw windows.hashdump

# Find files in memory
vol -f memory.raw windows.filescan

# Detect malware
vol -f memory.raw windows.malfind

# Dump a process
vol -f memory.raw windows.memmap --pid <PID> --dump
```

### Common Volatility Plugins

| Plugin | Purpose |
|--------|---------|
| windows.pslist | List processes |
| windows.pstree | Process tree |
| windows.netscan | Network connections |
| windows.filescan | Find files in memory |
| windows.cmdline | Command line history |
| windows.hashdump | Password hashes |
| windows.malfind | Detect malware |
| windows.dlllist | Loaded DLLs |
| windows.registry.hivelist | Registry hives |

## Network Capture Analysis (tshark)

```bash
# Protocol statistics
tshark -r capture.pcap -q -z io,phs

# Follow TCP stream
tshark -r capture.pcap -z follow,tcp,ascii,0

# Export HTTP objects
tshark -r capture.pcap --export-objects http,./extracted

# Filter specific traffic
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# DNS queries
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name

# Extract credentials
tshark -r capture.pcap -Y "http.authbasic" -T fields -e http.authbasic
```

## File Carving

```bash
# Scan for embedded files
binwalk challenge.bin

# Extract embedded files
binwalk -e challenge.bin

# Carve deleted files
foremost -i disk.img -o output/

# Sleuthkit - list partitions
mmls disk.img

# Sleuthkit - list files
fls -r -o <offset> disk.img

# Sleuthkit - extract file by inode
icat -o <offset> disk.img <inode> > extracted_file
```
