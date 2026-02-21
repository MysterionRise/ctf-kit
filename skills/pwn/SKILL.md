---
name: pwn
description: >-
  Solve CTF binary exploitation (pwn) challenges: buffer overflows,
  format strings, ROP chains, heap exploitation, and shellcoding.
  Use when given ELF/PE binaries with a remote service to exploit.
  Triggers: "buffer overflow", "format string", "ROP", "shellcode",
  "checksec", "NX", "canary", "PIE", "GOT overwrite", "ret2libc",
  pwntools scripts, .elf files, nc/netcat connection targets.
  Tools: checksec, ROPgadget, pwntools, gdb, one_gadget.
  NOT for static reverse engineering (use reverse).
---

# CTF Pwn

Analyze and exploit binary exploitation challenges.

## When to Use

Use this command for challenges involving:

- ELF binaries
- Buffer overflows
- Format string vulnerabilities
- ROP chains
- Heap exploitation

## Bundled Scripts

- [check-tools.sh](scripts/check-tools.sh) — Verify required pwn tools are installed
- [run-checksec.sh](scripts/run-checksec.sh) — Check binary protections (CANARY, NX, PIE, RELRO)

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. Run the pwn analysis:

   ```bash
   ctf run pwn $ARGUMENTS
   ```

2. Check binary protections:

   ```bash
   checksec ./binary
   ```

   | Protection | If Disabled |
   |------------|-------------|
   | CANARY | Stack overflow exploitable |
   | NX | Shellcode injection possible |
   | PIE | Fixed addresses for ROP |
   | RELRO | GOT overwrite possible |

3. Find ROP gadgets:

   ```bash
   # Find all gadgets
   ROPgadget --binary ./binary

   # Find specific gadgets
   ROPgadget --binary ./binary --re "pop rdi"

   # For x64: need pop rdi; ret for first argument
   # For x86: arguments on stack
   ```

4. Dynamic analysis:

   ```bash
   # Run binary
   ./binary

   # Trace library calls
   ltrace ./binary

   # Trace system calls
   strace ./binary

   # Debug with GDB
   gdb ./binary
   ```

5. Find offset to return address:

   ```python
   # Generate pattern
   from pwn import *
   print(cyclic(200))

   # Find offset after crash
   cyclic_find(0x61616161)  # Replace with crash value
   ```

## Common Attack Patterns

### Buffer Overflow (No Canary, No PIE)

```python
from pwn import *
p = process('./binary')
payload = b'A' * offset + p64(win_function)
p.sendline(payload)
p.interactive()
```

### Format String

```python
# Leak stack values
payload = b'%p ' * 20

# Write to address
payload = fmtstr_payload(offset, {target: value})
```

### ret2libc

```python
# Leak libc address
# Calculate base
# Call system("/bin/sh")
```

## Exploitation Checklist

1. Run binary, understand behavior
2. Check protections with checksec
3. Find vulnerability (overflow, format string)
4. Find offset to control
5. Build exploit (shellcode or ROP)
6. Test locally, then remote

## Common Issues

**`checksec` not found**
- **Cause:** checksec not installed or wrong version
- **Solution:** The pwntools version is recommended: `pip install pwntools` (includes `checksec` as `pwn checksec`). Alternatively install the standalone: `apt install checksec` or from GitHub. Run as `pwn checksec ./binary` or `checksec --file=./binary`

**`pwntools` not installed or import fails**
- **Cause:** pwntools not installed in current Python environment
- **Solution:** Install with `pip install pwntools`. Requires Python 3.x. On macOS, some features (like `gdb` integration) may not work — use a Linux VM or Docker for full functionality

**`ROPgadget` not found**
- **Cause:** Not installed
- **Solution:** Install with `pip install ROPgadget`. Run with `ROPgadget --binary ./binary`

**Binary won't run: "No such file or directory" on a file that exists**
- **Cause:** 32-bit binary on a 64-bit system without 32-bit libraries, or wrong ELF interpreter
- **Solution:** Install 32-bit libs: `apt install libc6-i386 lib32stdc++6` (Debian/Ubuntu). Check architecture with `file ./binary`. For static binaries, try `qemu-user` to run other architectures

**Exploit works locally but fails remotely**
- **Cause:** Different libc version, ASLR differences, or environment variable differences change stack layout
- **Solution:** Use the provided `libc.so` if given. Find the remote libc version by leaking addresses and checking libc.rip or libc.blukat.me. Adjust offsets accordingly. If no libc given, try leaking with `puts@plt` or `write@plt`

**Segfault but can't find the right offset**
- **Cause:** Offset calculation is wrong, or there are stack alignment issues (x86_64 requires 16-byte alignment)
- **Solution:** Use `cyclic()` and `cyclic_find()` from pwntools for precise offset detection. For x86_64 segfaults at `movaps`, add a `ret` gadget before your ROP chain for stack alignment

**`gdb` not available or GEF/pwndbg not installed**
- **Cause:** GDB extensions make pwn debugging much easier but aren't installed by default
- **Solution:** Install GDB: `apt install gdb`. Then install pwndbg: `git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh`. Alternative: GEF (`pip install gef`) or PEDA

**`one_gadget` not found**
- **Cause:** one_gadget is a Ruby gem, not a Python package
- **Solution:** Install with `gem install one_gadget`. Requires Ruby. Use to find single-gadget RCE in libc: `one_gadget libc.so.6`

## Example Usage

```bash
/ctf-kit:pwn ./challenge
/ctf-kit:pwn ./binary
```
