---
name: reverse
description: >-
  Solve CTF reverse engineering challenges: disassembly, decompilation,
  key/password finding, algorithm analysis, and anti-debug bypass.
  Use when given binaries to analyze statically — crackmes, keygens,
  obfuscated code. Triggers: .exe .elf .apk .jar .pyc files,
  "disassemble", "decompile", "keygen", "crackme", "find the password",
  "anti-debugging", radare2/Ghidra output, assembly code.
  Tools: radare2, Ghidra, objdump, ltrace, strace, jadx, uncompyle6.
  NOT for exploitation/pwn (use pwn) or malware triage (use forensics).
---

# CTF Reverse

Analyze and solve reverse engineering challenges.

## When to Use

Use this command for challenges involving:

- ELF/PE binaries requiring analysis
- Algorithm understanding
- Key/password finding
- Malware analysis
- Obfuscated code

## Bundled Scripts

- [check-tools.sh](scripts/check-tools.sh) — Verify required reversing tools are installed
- [run-radare2.sh](scripts/run-radare2.sh) — Initial binary analysis with structured output. Lists functions, strings, and flags interesting functions (main, flag, win, check, verify, password, secret). Outputs JSON with function list and analysis suggestions.

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. **Start with radare2 analysis** (outputs structured JSON):

   ```bash
   bash scripts/run-radare2.sh $ARGUMENTS
   bash scripts/run-radare2.sh <binary> main    # disassemble specific function
   ```

   JSON output includes:
   - `functions[]`: all functions with address, size, name
   - `interesting_functions[]`: functions matching CTF keywords (main, flag, win, check, verify, password, secret, decrypt)
   - `strings[]`: strings found in binary
   - `info`: binary metadata (arch, format, etc.)

3. Based on JSON findings, focus analysis:
   - `interesting_functions` found → decompile them: `r2 -c "aa; pdc @ <function>" <binary>`
   - Strings with flag patterns → trace cross-references
   - Multiple check/verify functions → trace validation logic

4. For different binary types:

   **ELF (Linux):** Use radare2 or Ghidra for analysis
   **PE (Windows):** Check for .NET (use dnSpy)
   **Java/Android:** `jadx app.jar` or `jadx app.apk`
   **Python:** `uncompyle6 file.pyc` or `pycdc file.pyc`

## Analysis Workflow

1. `run-radare2.sh binary` → identify interesting functions from JSON
2. Decompile target functions → understand algorithm
3. Write keygen or patch binary
4. Test solution

## Common Patterns

| Pattern | Meaning |
|---------|---------|
| `strcmp`, `strncmp` | String comparison |
| `memcmp` | Memory comparison |
| XOR loop | Simple encryption |
| `check_`, `verify_` | Validation functions |
| `win`, `flag` | Target functions |

## Team Roles

When using `/ctf-kit:team-solve` with a reverse engineering challenge, the lead spawns 3 specialists:

| Role | Teammate Name | Focus | Tools | First Action |
|------|--------------|-------|-------|--------------|
| Static Analyst | `static-reverser` | Disassembly, decompilation, function listing, string analysis, control flow graphs | radare2, Ghidra, objdump, `scripts/run-radare2.sh` | List functions, find interesting ones (main, check, verify, flag), decompile them |
| Dynamic Analyst | `dynamic-reverser` | Runtime behavior, breakpoints, anti-debug bypass, library call tracing, input/output mapping | gdb, ltrace, strace, LD_PRELOAD | Run with ltrace/strace, set breakpoints on strcmp/memcmp, trace validation logic |
| Algorithm Solver | `algo-solver` | Keygen writing, constraint solving, algorithm reimplementation, z3 SAT solving, symbolic execution | python3, z3, sage | Reimplement the validation algorithm from decompiled code, write solver/keygen |

### Workflow coordination

Reverse engineering has a natural pipeline:

1. **Static analyst** maps the binary → identifies key functions and algorithm structure
2. **Dynamic analyst** confirms behavior → finds actual values, bypasses anti-debug
3. **Algorithm solver** writes the solution → uses both static and dynamic findings

But all 3 can start in parallel — static and dynamic analysis are independent.

### When to broadcast

- **Static**: "Main calls check_password() which XORs input with key at 0x4020" — algo solver starts reimplementing
- **Dynamic**: "strcmp compares against runtime-computed string, anti-debug detected (ptrace)" — static analyst looks for the check
- **Algo solver**: "Constraint solver found valid input: PASSWORD" — others verify
- **Any**: "Found the flag" — immediate broadcast, all stop

## Example Usage

```bash
/ctf-kit:reverse ./crackme
/ctf-kit:reverse ./challenge.exe
/ctf-kit:reverse app.apk
```
