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

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. Run the reversing analysis:

   ```bash
   ctf run reversing $ARGUMENTS
   ```

3. Analysis workflow:
   1. **Identify:** File type and architecture
   2. **Run:** Observe behavior
   3. **Static:** Disassemble, find main, identify key functions
   4. **Understand:** Trace validation logic flow
   5. **Solve:** Write keygen or patch binary

4. Use appropriate tools for the binary type — see [Tool Reference](references/tools.md):
   - **ELF** → radare2, Ghidra, ltrace/strace
   - **PE/.NET** → Ghidra, dnSpy
   - **Java/Android** → jadx, apktool
   - **Python .pyc** → uncompyle6, pycdc

5. Look for validation logic: string comparisons, XOR loops, crypto operations.

## Example Usage

```bash
/ctf-kit:reverse ./crackme
/ctf-kit:reverse ./challenge.exe
/ctf-kit:reverse app.apk
```

## References

- [Tool Reference](references/tools.md) — radare2 commands, binary type tools, Ghidra headless
- [Common Patterns](references/patterns.md) — function indicators, anti-debugging, obfuscation techniques
