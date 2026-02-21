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

1. Check tool availability:

   ```bash
   bash scripts/check-tools.sh
   ```

   Expected: each tool prints `[OK]`. If any show `[MISSING]`, note which are unavailable before proceeding.

2. Identify the binary type:

   ```bash
   file $ARGUMENTS
   ```

   Expected: one of:
   - `ELF 64-bit LSB executable` → **ELF (Linux)** → go to step 3a
   - `PE32 executable` or `PE32+ executable` → **PE (Windows)** → go to step 3b
   - `Java archive data (JAR)` or `Android application` → **Java/Android** → go to step 3c
   - `python 3.x byte-compiled` → **Python bytecode** → go to step 3d

   **CRITICAL: The binary type determines which tools to use. Do not skip this step.**

3. Analyze with the appropriate toolset:

   **3a. ELF (Linux) — Static analysis with radare2:**

   ```bash
   r2 -qc "aaa; afl" ./binary
   ```

   Expected: list of functions like `sym.main`, `sym.check_password`, `sym.flag`. Note function names containing `check`, `verify`, `flag`, or `win`. Then decompile the main function:

   ```bash
   r2 -qc "aaa; pdc @ main" ./binary
   ```

   Expected: pseudo-C code showing the program logic. Look for `strcmp`, `strncmp`, `memcmp` calls — these reveal what input is expected.

   ```bash
   r2 -qc "aaa; iz" ./binary
   ```

   Expected: string table with addresses. Look for flag fragments, error/success messages, or hardcoded passwords.

   **3b. PE (Windows):**
   - Use Ghidra or IDA for decompilation
   - Check for .NET: `file` output contains `Mono/.Net assembly` → use dnSpy
   - Look for `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` as anti-debug

   **3c. Java/Android:**

   ```bash
   jadx app.jar    # or: jadx app.apk
   ```

   Expected: decompiled Java source in `app.jar-decompiled/` or `app.apk-decompiled/`. Search for `flag`, `secret`, or `password` in the output.

   **3d. Python bytecode:**

   ```bash
   uncompyle6 file.pyc
   ```

   Expected: reconstructed Python source code. If `uncompyle6` fails, try `pycdc file.pyc`.

4. **CRITICAL: Locate the validation logic.** Search for these patterns in the decompiled output:

   | Pattern | Meaning |
   |---------|---------|
   | `strcmp`, `strncmp` | Direct string comparison — extract the expected value |
   | `memcmp` | Memory comparison — check what buffer is compared |
   | XOR loop | Simple encryption — reverse the XOR to get the key |
   | `check_`, `verify_` | Validation functions — decompile and trace logic |
   | `win`, `flag`, `success` | Target functions — find what triggers them |

   If anti-debugging is present (`ptrace`, `IsDebuggerPresent`, timing checks), patch these checks out before dynamic analysis.

5. **Validation: Verify your solution.** Run the binary with your derived key/password:

   ```bash
   echo "your_answer" | ./binary
   ```

   Expected: success message or flag output. If the binary rejects the input, revisit step 4 — the validation logic analysis may be incomplete.

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

## Example Usage

```bash
/ctf-kit:reverse ./crackme
/ctf-kit:reverse ./challenge.exe
/ctf-kit:reverse app.apk
```
