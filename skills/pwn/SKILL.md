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

## Instructions

1. Run the pwn analysis:

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

## Example Usage

```bash
/ctf-kit:pwn ./challenge
/ctf-kit:pwn ./binary
```
