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

3. Check binary protections: `checksec ./binary`

4. Find the vulnerability (overflow, format string, UAF) and determine offset to control.

5. Build exploit using appropriate technique — see [Attack Patterns](references/patterns.md) for templates:
   - Buffer overflow → direct overwrite or ROP
   - Format string → leak/write primitives
   - ret2libc → leak libc, call system()

6. Test locally, then adapt for remote target.

## Example Usage

```bash
/ctf-kit:pwn ./challenge
/ctf-kit:pwn ./binary
```

## References

- [Tool Reference](references/tools.md) — checksec, ROPgadget, GDB, pwntools offset finding
- [Attack Patterns](references/patterns.md) — buffer overflow, format string, ret2libc, heap techniques
