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

## Team Roles

When using `/ctf-kit:team-solve` with a pwn challenge, the lead spawns 3 specialists.

**Exploit-dev requires plan approval** before connecting to remote targets.

| Role | Teammate Name | Focus | Tools | First Action |
|------|--------------|-------|-------|--------------|
| Static Analyst | `binary-analyst` | checksec, disassembly, vulnerability identification, function mapping, string cross-refs | checksec, radare2, `scripts/run-checksec.sh` | Run checksec, disassemble main + interesting functions, identify vuln class |
| Exploit Developer | `exploit-dev` | Payload crafting, ROP chain building, shellcode, format string exploitation, ret2libc/ret2csu | pwntools, ROPgadget, one_gadget | Build exploit based on static analysis, find gadgets, calculate offsets |
| Dynamic Analyst | `dynamic-analyst` | GDB debugging, offset finding, leak discovery, heap state inspection, ASLR/PIE bypass | gdb, pwntools, ltrace, strace | Run binary with cyclic pattern, find crash offset, identify leakable addresses |

### Workflow coordination

The pwn team has a natural dependency chain:

1. **Static analyst** runs first → identifies protections and vulnerability type
2. **Dynamic analyst** runs in parallel → finds offsets and leaks
3. **Exploit developer** waits for both → builds the final exploit

### When to broadcast

- **Static**: "Binary has no canary + no PIE, vuln in read() at offset 0x40" — exploit dev starts building
- **Dynamic**: "Crash at offset 72, libc leak via puts@GOT" — exploit dev uses these values
- **Exploit dev**: "Exploit works locally, switching to remote" — lead reviews plan before remote connection
- **Any**: "Got shell / found flag" — immediate broadcast, all stop

## Example Usage

```bash
/ctf-kit:pwn ./challenge
/ctf-kit:pwn ./binary
```
