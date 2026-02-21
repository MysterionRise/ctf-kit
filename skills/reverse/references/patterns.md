# Reverse — Common Patterns

## Function Name Indicators

| Pattern | Meaning |
|---------|---------|
| `strcmp`, `strncmp` | String comparison (likely password check) |
| `memcmp` | Memory comparison |
| XOR loop | Simple encryption/obfuscation |
| `check_`, `verify_` | Validation functions |
| `win`, `flag`, `success` | Target functions |
| `decrypt`, `decode` | Data transformation |
| `main` → `check` → `verify` | Typical crackme flow |

## Anti-Debugging Techniques

Common techniques to identify and bypass:

| Technique | Detection | Bypass |
|-----------|-----------|--------|
| `ptrace(PTRACE_TRACEME)` | Check for ptrace call | NOP out or patch return value |
| `IsDebuggerPresent` | Windows API call | Patch to return 0 |
| Timing checks (`rdtsc`) | Time measurement between points | Patch out timing code |
| Self-modifying code | Code writes to itself at runtime | Step through carefully |
| Signal handlers | Custom SIGTRAP handler | Understand handler logic |
| `/proc/self/status` | Check TracerPid field | Fake the proc entry |

## Analysis Workflow

1. **Identify:** File type, architecture, compiler
2. **Run:** Observe normal behavior, note I/O
3. **Static:** Disassemble, find main, identify key functions
4. **Understand:** Trace validation logic flow
5. **Solve:** Write keygen, patch binary, or extract key

## Common Obfuscation

| Technique | How to Handle |
|-----------|---------------|
| String encryption | Find decryption routine, apply to all strings |
| Control flow flattening | Identify state variable, reconstruct flow |
| Opaque predicates | Identify always-true/false conditions |
| Dead code insertion | Focus on code paths that affect output |
