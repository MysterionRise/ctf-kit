# Analyze — Tool Reference

## Core Analysis Tools

| Tool | Purpose | Command |
|------|---------|---------|
| `file` | Detect file type | `file challenge.bin` |
| `strings` | Extract readable strings | `strings -n 8 challenge.bin` |
| `xxd` | Hex dump | `xxd challenge.bin \| head -50` |
| `binwalk` | Detect embedded files | `binwalk challenge.bin` |
| `exiftool` | Read metadata | `exiftool challenge.bin` |

## Category Routing

Based on analysis results, route to the appropriate skill:

| Detected Pattern | Skill |
|-----------------|-------|
| Encrypted data, hashes, RSA params | `/ctf-kit:crypto` |
| Memory dump, disk image, pcap | `/ctf-kit:forensics` |
| Image/audio with hidden data | `/ctf-kit:stego` |
| Web app source, URLs, HTTP | `/ctf-kit:web` |
| ELF/PE binary with remote target | `/ctf-kit:pwn` |
| Binary requiring static analysis | `/ctf-kit:reverse` |
| Usernames, domains, geolocation | `/ctf-kit:osint` |
| Encoding chains, esoteric langs | `/ctf-kit:misc` |

## File Signature Quick Reference

| Magic Bytes | File Type |
|-------------|-----------|
| `89 50 4E 47` | PNG image |
| `FF D8 FF` | JPEG image |
| `50 4B 03 04` | ZIP archive |
| `7F 45 4C 46` | ELF binary |
| `4D 5A` | PE (Windows) binary |
| `25 50 44 46` | PDF document |
| `1F 8B` | GZIP compressed |
