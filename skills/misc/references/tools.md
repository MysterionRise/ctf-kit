# Misc — Tool Reference

## Encoding / Decoding

```bash
# Base64
echo "SGVsbG8=" | base64 -d

# Hex to ASCII
echo "48656C6C6F" | xxd -r -p

# URL decode
python3 -c "import urllib.parse; print(urllib.parse.unquote('%48%65%6C%6C%6F'))"

# ROT13
echo "Uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Binary to ASCII
python3 -c "print(''.join(chr(int(b,2)) for b in '01001000 01101001'.split()))"

# Multi-layer decode
echo "encoded" | base64 -d | xxd -r -p | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

## QR Codes & Barcodes

```bash
# Decode QR code
zbarimg qrcode.png

# Generate QR (for testing)
qrencode -o test.png "test data"
```

## CyberChef

- All-in-one web-based encoding/decoding tool
- Use "Magic" recipe for auto-detection of encoding chains
- Available at: gchq.github.io/CyberChef

## Useful Online Tools

| Tool | Purpose |
|------|---------|
| CyberChef | Encoding/decoding chains |
| dcode.fr | Various ciphers and encodings |
| Brainfuck interpreters | Esoteric language execution |
| zbarimg | QR code reading (CLI) |
| Factordb | Integer factorization |
