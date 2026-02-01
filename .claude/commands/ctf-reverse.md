# CTF Reverse

Analyze and solve reverse engineering challenges.

## When to Use

Use this command for challenges involving:

- ELF/PE binaries requiring analysis
- Algorithm understanding
- Key/password finding
- Malware analysis
- Obfuscated code

## Instructions

1. Run the reversing analysis:

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

## Example Usage

```bash
/ctf-reverse ./crackme
/ctf-reverse ./challenge.exe
/ctf-reverse app.apk
```
