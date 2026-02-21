# Crypto — Pattern Recognition

## Hash Identification

| Pattern | Likely Type |
|---------|-------------|
| 32 hex chars | MD5 hash |
| 40 hex chars | SHA1 hash |
| 64 hex chars | SHA256 hash |
| 128 hex chars | SHA512 hash |
| `$1$` prefix | MD5crypt |
| `$2a$` / `$2b$` prefix | bcrypt |
| `$5$` prefix | SHA256crypt |
| `$6$` prefix | SHA512crypt |

## Encoding Detection

| Pattern | Encoding |
|---------|----------|
| `=` or `==` at end | Base64 |
| All caps A-Z + 2-7 | Base32 |
| Only 0-9 a-f | Hexadecimal |
| `n=..., e=...` | RSA parameters |
| `-----BEGIN` | PEM format |

## RSA Vulnerability Indicators

| Condition | Attack |
|-----------|--------|
| Small e (e=3) | Cube root attack |
| Same n, different e | Common modulus attack |
| Close p, q (n ≈ p²) | Fermat factorization |
| Small d | Wiener's attack |
| Shared prime across keys | GCD attack |
| Large e | Boneh-Durfee / Wiener |

## Decoding Chain Strategy

Often challenges use multiple encodings layered:

1. Base64 → Hex → ROT13 → Flag
2. URL encoding → Base64 → ASCII → Flag
3. Binary → Decimal → Hex → ASCII → Flag

```bash
# Example multi-layer decode
echo "encoded" | base64 -d | xxd -r -p | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

Try CyberChef "Magic" recipe for auto-detection of encoding chains.
