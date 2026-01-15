# /ctf.forensics - Forensics Challenge Assistance

Help solve forensics challenges.

## When to Use

Use this command when:

- Challenge involves disk images, memory dumps, or logs
- Network captures (PCAP/PCAPNG files)
- File carving or data recovery
- Metadata analysis
- Timeline or event reconstruction

## Common Forensics Patterns

### File Analysis

- **Binwalk**: Extract embedded files
- **Foremost**: File carving from raw data
- **Exiftool**: Metadata extraction
- **File signatures**: Identify hidden file types

### Network Analysis

- **Wireshark/tshark**: Protocol analysis
- **tcpdump**: Quick packet filtering
- **NetworkMiner**: Automated extraction
- Follow TCP streams for data reconstruction

### Memory Forensics

- **Volatility3**: Memory analysis
- Look for: processes, network connections, cached credentials
- Common plugins: pslist, netscan, filescan, hashdump

### Disk Forensics

- **Sleuthkit**: Disk analysis
- **Autopsy**: GUI analysis
- Check: deleted files, alternate data streams, slack space

## Key Tools

```bash
# Check available tools
ctf check --category forensics

# Extract embedded files
binwalk -e suspicious_file

# File carving
foremost -i disk.img -o output/

# Metadata
exiftool image.jpg

# PCAP analysis
tshark -r capture.pcap -Y "http"

# Memory analysis
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.filescan
```

## Analysis Steps

1. **Identify file types**
   - Run file command
   - Check magic bytes
   - Look for embedded files

2. **Extract data**
   - Binwalk for embedded files
   - Strings for readable content
   - Carve files from raw data

3. **Analyze content**
   - Network: Follow streams, extract files
   - Memory: List processes, scan for artifacts
   - Disk: Check deleted files, metadata

4. **Look for flags**
   - Common hiding spots
   - Steganography in extracted images
   - Base64/encoded strings

## tshark Quick Reference

```bash
# HTTP requests
tshark -r file.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# FTP credentials
tshark -r file.pcap -Y "ftp" | grep -E "USER|PASS"

# DNS queries
tshark -r file.pcap -Y "dns.qry.name" -T fields -e dns.qry.name

# Export HTTP objects
tshark -r file.pcap --export-objects "http,output_dir"

# TCP stream follow
tshark -r file.pcap -Y "tcp.stream eq 0" -T fields -e tcp.payload
```

## Volatility3 Quick Reference

```bash
# Basic info
vol -f memory.dmp windows.info

# Process list
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.pstree

# Network connections
vol -f memory.dmp windows.netscan

# File scanning
vol -f memory.dmp windows.filescan

# Dump process
vol -f memory.dmp windows.dumpfiles --pid <PID>

# Registry
vol -f memory.dmp windows.registry.hivelist
```

## Response Format

When responding to /ctf.forensics:

1. **File Overview**: What types of evidence we have
2. **Extraction Results**: What was found inside files
3. **Key Artifacts**: Important findings (credentials, files, events)
4. **Timeline**: Sequence of events if applicable
5. **Flag Location**: Where the flag was found or likely hidden

## Related Commands

- `/ctf.analyze` - Initial file analysis
- `/ctf.stego` - For hidden data in images/audio
