# /ctf.reverse - Reverse Engineering Challenge Assistance

Help solve reverse engineering challenges.

## When to Use

Use this command when:

- Challenge provides a binary to analyze
- Need to understand program logic without source
- Challenge involves obfuscation or anti-debugging
- Need to find hidden functionality or keys

## First Steps

1. **Identify the binary**

   ```bash
   file ./binary
   checksec ./binary
   ```

2. **Extract strings**

   ```bash
   strings ./binary | grep -i "flag\|pass\|key\|correct"
   strings -e l ./binary  # 16-bit little-endian
   ```

3. **Quick analysis**

   ```bash
   objdump -d ./binary | less
   nm ./binary  # symbols
   ```

## Key Tools

```bash
# Check available tools
ctf check --category reversing

# Disassembly
objdump -d ./binary
objdump -M intel -d ./binary  # Intel syntax

# radare2
r2 ./binary
# Then: aaa (analyze), pdf @ main (disassemble)

# Ghidra (GUI)
ghidraRun

# ltrace/strace
ltrace ./binary
strace ./binary
```

## radare2 Quick Reference

```bash
# Start analysis
r2 ./binary

# Commands inside r2
aaa            # analyze all
afl            # list functions
s main         # seek to main
pdf            # disassemble function
VV             # visual graph mode
px 100         # hex dump
iz             # strings in data section
ii             # imports
ie             # entry points

# Search
/ flag         # search string
/x 7f454c46    # search hex
```

## Common Patterns

### XOR Encryption

```python
def xor_decrypt(data, key):
    return bytes([d ^ key[i % len(key)] for i, d in enumerate(data)])

# Often the key is visible in strings
```

### Simple Checks

```c
// Look for comparisons
if (strcmp(input, "secret") == 0)
if (input[0] == 'f' && input[1] == 'l')
```

### Custom Algorithms

- Trace the logic step by step
- Use a debugger to see runtime values
- Write a decoder script

## GDB Commands

```bash
# Start
gdb ./binary

# Disassemble
disas main
disas <function>

# Set Intel syntax
set disassembly-flavor intel

# Breakpoints
b main
b *0x401234
b *main+42

# Run
r
r arg1 arg2

# Step
ni    # next instruction
si    # step into
c     # continue

# Examine
x/20x $rsp   # hex at stack pointer
x/s 0x402000 # string at address
p $rax       # print register
```

## Decompiler Tips

### Ghidra

1. Create new project
2. Import binary
3. Analyze (press 'A')
4. Navigate to main() or entry point
5. Read decompiled code in right panel

### Common Decompilation Patterns

```c
// Password check
if (strcmp(user_input, &DAT_00402000) == 0)
// -> Check what's at 0x402000

// XOR loop
for (i = 0; i < len; i++)
    decoded[i] = encoded[i] ^ key[i % keylen];

// Custom hash
hash = 0;
for (i = 0; str[i]; i++)
    hash = hash * 31 + str[i];
```

## Anti-Debugging Techniques

- **ptrace check**: Program detects debugger
- **Timing checks**: Detects slowdown from debugging
- **Self-modifying code**: Changes at runtime

Bypass:

- Patch out checks (NOP)
- Use LD_PRELOAD
- Modify return values in debugger

## Response Format

When responding to /ctf.reverse:

1. **Binary Info**: Architecture, protections, type
2. **Key Functions**: Important functions identified
3. **Logic Analysis**: What the program does
4. **Algorithm**: Any encryption/encoding identified
5. **Solution**: Script or method to get flag

## Related Commands

- `/ctf.analyze` - Initial file analysis
- `/ctf.pwn` - For exploitation after understanding
