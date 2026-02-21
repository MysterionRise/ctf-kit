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

2. Static analysis with radare2:

   ```bash
   # Analyze binary
   r2 -A ./binary

   # List functions
   afl

   # Disassemble main
   pdf @ main

   # Decompile (pseudo-code)
   pdc @ main

   # List strings
   iz

   # Cross-references
   axt @ function_address
   ```

3. For different binary types:

   **ELF (Linux):**
   - Use Ghidra or IDA for decompilation
   - r2 for quick disassembly
   - ltrace/strace for tracing

   **PE (Windows):**
   - x64dbg for debugging
   - IDA or Ghidra for analysis
   - Check for .NET (use dnSpy)

   **Java/Android:**

   ```bash
   # Decompile JAR
   jadx app.jar

   # Decompile APK
   jadx app.apk
   apktool d app.apk
   ```

   **Python:**

   ```bash
   # Decompile .pyc
   uncompyle6 file.pyc
   pycdc file.pyc
   ```

4. Look for:
   - Main validation logic
   - String comparisons
   - Crypto operations
   - Anti-debugging checks

## Anti-Debugging Bypass

Common techniques to patch:

- `ptrace` checks
- `IsDebuggerPresent`
- Timing checks (rdtsc)
- Self-modifying code

## Analysis Workflow

1. **Identify:** File type, architecture
2. **Run:** Observe behavior
3. **Static:** Disassemble, find main
4. **Understand:** Trace logic flow
5. **Solve:** Write keygen or patch

## Common Patterns

| Pattern | Meaning |
|---------|---------|
| `strcmp`, `strncmp` | String comparison |
| `memcmp` | Memory comparison |
| XOR loop | Simple encryption |
| `check_`, `verify_` | Validation functions |
| `win`, `flag` | Target functions |

## Common Issues

**`radare2` (r2) not found**
- **Cause:** radare2 not installed
- **Solution:** Install with `apt install radare2` (Debian/Ubuntu) or `brew install radare2` (macOS). For the latest version, build from source: `git clone https://github.com/radareorg/radare2 && cd radare2 && sys/install.sh`

**radare2 analysis hangs or is very slow**
- **Cause:** Full analysis (`aaaa`) on large binaries can take a long time
- **Solution:** Use `aa` (basic analysis) instead of `aaaa` for initial exploration. Target specific functions: `af @ main` to analyze just main. Use `afl` to list known functions before deep analysis

**`jadx` not found (Java/Android decompilation)**
- **Cause:** jadx not installed
- **Solution:** Install with `apt install jadx`, `brew install jadx`, or download from [GitHub releases](https://github.com/skylot/jadx/releases). For APK files, `apktool` is an alternative: `apt install apktool`

**`uncompyle6` fails on Python 3.9+ .pyc files**
- **Cause:** uncompyle6 only supports up to Python 3.8
- **Solution:** Use `pycdc` (Decompyle++) which supports newer Python versions. Install from source: `git clone https://github.com/zrax/pycdc && cd pycdc && cmake . && make`. Alternatively, use `dis` module to get bytecode: `python -m dis file.pyc`

**Binary is stripped — no function names visible**
- **Cause:** Symbols were removed at compile time
- **Solution:** Focus on `entry0` / `entry_point` and follow calls from there. Look for string cross-references (`iz` in r2, then `axt @ addr`) to locate interesting functions. In Ghidra, the decompiler still produces readable pseudo-code even without symbols

**Anti-debugging prevents analysis**
- **Cause:** Binary uses ptrace checks, timing checks, or environment detection
- **Solution:** In GDB: `catch syscall ptrace` then `set $rax=0` to bypass ptrace. In r2: patch the check with `wa nop` at the conditional jump. For timing checks, use static analysis instead of dynamic

**ELF binary is packed or encrypted**
- **Cause:** UPX or custom packing hides the real code
- **Solution:** Check with `upx -t binary`. If UPX packed: `upx -d binary` to unpack. For custom packers, run the binary under `strace` to see it unpack itself, then dump from memory with `gdb`

**`objdump` output is overwhelming**
- **Cause:** Dumping the entire binary produces too much output
- **Solution:** Target specific sections: `objdump -d -M intel --disassemble=main ./binary`. Use `objdump -t` for symbol table and `objdump -s -j .rodata` for read-only data (often contains strings/keys)

## Example Usage

```bash
/ctf-kit:reverse ./crackme
/ctf-kit:reverse ./challenge.exe
/ctf-kit:reverse app.apk
```
