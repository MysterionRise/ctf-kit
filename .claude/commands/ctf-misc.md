# CTF Misc

Analyze and solve miscellaneous challenges.

## When to Use

Use this command for challenges involving:

- Encoding chains
- Esoteric programming languages
- QR codes and barcodes
- Logic puzzles
- Challenges that don't fit other categories

## Instructions

1. Run the misc analysis:

   ```bash
   ctf run misc $ARGUMENTS
   ```

2. For encoding detection and decoding:

   ```bash
   # Use CyberChef (web tool)
   # Try "Magic" recipe for auto-detection

   # Manual decoding
   echo "SGVsbG8=" | base64 -d          # Base64
   echo "48656C6C6F" | xxd -r -p        # Hex
   ```

3. For QR codes:

   ```bash
   # Decode QR code
   zbarimg qrcode.png
   ```

4. For esoteric languages:
   - **Brainfuck:** `++++[>++++++++<-]>.`
   - **Ook!:** `Ook. Ook! Ook.`
   - **Whitespace:** Only spaces, tabs, newlines
   - **JSFuck:** `[]!+()` characters only

   Use online interpreters for these.

## Common Encoding Patterns

| Pattern | Encoding |
|---------|----------|
| `=` or `==` at end | Base64 |
| All caps + 2-7 | Base32 |
| Only 0-9 a-f | Hexadecimal |
| Only 0 and 1 | Binary |
| `%20`, `%3D` | URL encoding |
| `&#65;`, `&#x41;` | HTML entities |

## Decoding Chain Example

Often challenges use multiple encodings:

1. Base64 -> 2. Hex -> 3. ROT13 -> Flag

```bash
# Step by step
echo "encoded" | base64 -d | xxd -r -p | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

## Esoteric Language Detection

| Looks Like | Language |
|------------|----------|
| `+ - < > [ ] . ,` | Brainfuck |
| `Ook.` `Ook!` `Ook?` | Ook! |
| Only whitespace | Whitespace |
| `[]+!()` | JSFuck |
| `moo`, `MOO` | COW |

## Common Misc Patterns

1. **Encoding chains:** Try CyberChef Magic
2. **Esoteric code:** Look up interpreter
3. **Puzzles:** Often need creative thinking
4. **QR/Barcodes:** Use scanning tools
5. **ZIP/Archives:** Check for passwords or corruption

## Useful Tools

- **CyberChef:** All-in-one encoding/decoding
- **dcode.fr:** Various ciphers and encodings
- **Brainfuck interpreters:** Many online options
- **zbarimg:** QR code reading

## Example Usage

```bash
/ctf-misc encoded.txt
/ctf-misc qrcode.png
/ctf-misc challenge.bf
```
