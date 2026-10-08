# /ctf.crypto - Cryptography Challenge Assistance

Help solve cryptography challenges.

## When to Use

Use this command when:

- Challenge involves encryption, encoding, or hashing
- Files contain cryptographic data (keys, ciphers, hashes)
- Challenge description mentions cryptography
- Found RSA parameters, encrypted text, or cipher text

## Common Cryptography Patterns

### Classical Ciphers

- **Caesar/ROT**: Single alphabet substitution, try all 26 shifts
- **Vigenere**: Polyalphabetic, look for repeating patterns
- **XOR**: Try xortool for key analysis
- **Base64/32/16**: Look for padding characters (=)

### Modern Crypto

- **RSA**: Look for n, e, c, p, q parameters
  - Small e? Cube root attack
  - Common n? Factor databases
  - Wiener's attack for small d
- **AES**: Look for IV, mode (ECB patterns?)
- **Hash cracking**: Identify hash type with hashid

## Key Tools

```bash
# Check available tools
ctf check --category crypto

# XOR analysis
xortool encrypted_file

# Hash identification
hashid <hash_string>

# Base64 decode
base64 -d encoded.txt

# OpenSSL for RSA
openssl rsa -in key.pem -text -noout
```

## Analysis Steps

1. **Identify the cipher type**
   - Check file magic bytes
   - Look for recognizable patterns
   - Extract strings for hints

2. **Gather parameters**
   - For RSA: n, e, c, p, q, d, dp, dq
   - For symmetric: key, IV, mode
   - For classical: ciphertext patterns

3. **Try common attacks**
   - Frequency analysis for substitution
   - Known plaintext attacks
   - Side-channel hints in code

4. **Use appropriate tools**
   - RsaCtfTool for RSA weaknesses
   - xortool for XOR
   - hashcat/john for hashes

## Python Snippets

### RSA with known factors

```python
from Crypto.Util.number import long_to_bytes, inverse

# Given p, q, e, c
n = p * q
phi = (p-1) * (q-1)
d = inverse(e, phi)
m = pow(c, d, n)
flag = long_to_bytes(m)
```

### XOR with known key

```python
def xor_decrypt(data, key):
    return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))
```

### Base64 variants

```python
import base64

# Standard
decoded = base64.b64decode(encoded)

# URL-safe
decoded = base64.urlsafe_b64decode(encoded)

# Base32
decoded = base64.b32decode(encoded)
```

## Response Format

When responding to /ctf.crypto:

1. **Cipher Identification**: What type of crypto is involved
2. **Parameter Extraction**: List all known values
3. **Attack Strategy**: Which approach to try
4. **Code/Commands**: Actual commands or scripts to run
5. **Results**: What the decryption/solution reveals

## Related Commands

- `/ctf.analyze` - Initial file analysis
- `/ctf.misc` - For encoding challenges
