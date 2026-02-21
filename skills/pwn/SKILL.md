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

## Performance Notes

- Take your time understanding the binary before writing exploits — rushing leads to wrong offsets and broken payloads
- Quality is more important than speed: verify each step (protections, offset, gadgets) independently
- Do not skip validation steps — always run checksec and understand all enabled protections first
- Test exploits locally before targeting remote — debugging blind remote failures wastes time
- When ROP chaining, verify each gadget individually before combining
- Format string exploits require precise offset calculation — double-check with test payloads

## Quality Checklist

Before submitting an exploit, verify:

- [ ] Ran checksec and documented all binary protections
- [ ] Identified the vulnerability type with evidence
- [ ] Calculated the correct offset to return address / control point
- [ ] For ROP: verified gadgets exist and addresses are correct
- [ ] Tested exploit locally and confirmed it works
- [ ] Accounted for remote differences (libc version, ASLR, buffering)
- [ ] Exploit handles both local and remote targets cleanly

## Example Usage

```bash
/ctf-kit:pwn ./challenge
/ctf-kit:pwn ./binary
```
