# Pwn — Tool Reference

## Binary Protections (checksec)

```bash
checksec ./binary
```

| Protection | If Disabled | Exploitation |
|------------|-------------|--------------|
| CANARY | Stack overflow exploitable | Overwrite return address directly |
| NX | Shellcode injection possible | Write shellcode to stack, jump to it |
| PIE | Fixed addresses for ROP | Use hardcoded addresses |
| RELRO (Partial) | GOT overwrite possible | Overwrite GOT entries |
| RELRO (Full) | GOT read-only | Need other techniques |

## ROP Gadgets

```bash
# Find all gadgets
ROPgadget --binary ./binary

# Find specific gadgets
ROPgadget --binary ./binary --re "pop rdi"

# For x64: need pop rdi; ret for first argument
# For x86: arguments on stack

# One_gadget for libc
one_gadget /lib/x86_64-linux-gnu/libc.so.6
```

## Dynamic Analysis

```bash
# Run binary
./binary

# Trace library calls
ltrace ./binary

# Trace system calls
strace ./binary

# Debug with GDB
gdb ./binary

# GDB + pwndbg/GEF commands
gdb -q ./binary
> checksec
> info functions
> disassemble main
> cyclic 200
> cyclic -l 0x61616161
```

## Pwntools: Finding Offset

```python
from pwn import *

# Generate pattern
print(cyclic(200))

# Find offset after crash
cyclic_find(0x61616161)  # Replace with crash value
```
