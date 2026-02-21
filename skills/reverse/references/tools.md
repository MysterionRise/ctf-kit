# Reverse — Tool Reference

## Radare2

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

# Find string references
axt @@ str.*

# Rename function
afn new_name @ address

# Visual mode
VV @ main
```

## Binary Type-Specific Tools

### ELF (Linux)

```bash
# Basic info
file binary
readelf -h binary

# Decompilation
# Use Ghidra or IDA for full decompilation
# r2 for quick disassembly

# Dynamic tracing
ltrace ./binary
strace ./binary
```

### PE (Windows)

```bash
# x64dbg for debugging
# IDA or Ghidra for analysis

# Check for .NET
file binary.exe  # Look for "Mono" or ".NET"
# If .NET → use dnSpy or ILSpy
```

### Java / Android

```bash
# Decompile JAR
jadx app.jar

# Decompile APK
jadx app.apk
apktool d app.apk
```

### Python (.pyc)

```bash
# Decompile .pyc
uncompyle6 file.pyc
pycdc file.pyc

# Disassemble
python3 -m dis file.pyc
```

## Ghidra (Headless)

```bash
# Analyze binary with Ghidra headless
analyzeHeadless /tmp/ghidra_project project_name \
  -import ./binary \
  -postScript ExportDecompilation.java
```
