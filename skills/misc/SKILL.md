---
name: misc
description: >-
  Solve CTF misc challenges: encoding chains, esoteric programming
  languages, QR codes, logic puzzles, and anything that doesn't fit
  crypto/forensics/stego/web/pwn/reverse/osint. Use when you see:
  Brainfuck (+[->), Ook!, Whitespace, JSFuck, QR/barcodes, multi-layer
  encoding (Base64->hex->ROT13), or "what encoding is this".
  Triggers: "decode this", "esoteric language", "QR code", "barcode",
  "encoding chain", "CyberChef", unusual character sets.
  Tools: CyberChef, zbarimg, dcode.fr, online interpreters.
---

# CTF Misc

Analyze and solve miscellaneous challenges.

## When to Use

Use this command for challenges involving:

- Encoding chains
- Esoteric programming languages
- QR codes and barcodes
- Logic puzzles
- Challenges that don't fit other categories

## Bundled Scripts

- [check-tools.sh](scripts/check-tools.sh) — Verify required misc tools are installed

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. Run the misc analysis:

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

## Performance Notes

- Take your time — misc challenges are deliberately tricky and reward patience over speed
- Quality is more important than speed: try every plausible encoding/language before moving on
- Do not skip validation steps — verify decoded output makes sense at each layer
- Encoding chains can be deep (5+ layers) — keep decoding until you hit readable text or a flag
- Esoteric languages have subtle syntax — double-check interpreter compatibility
- Think creatively: misc challenges often require lateral thinking

## Quality Checklist

Before presenting a solution, verify:

- [ ] Tried CyberChef Magic / auto-detect on the input
- [ ] Checked for multi-layer encoding and decoded all layers
- [ ] For esoteric languages: verified syntax and ran through a correct interpreter
- [ ] For QR/barcodes: tried multiple scanning tools if first fails
- [ ] Verified final output is meaningful (flag format, readable text)
- [ ] Documented the full decode/solve chain for reproducibility

## Example Usage

```bash
/ctf-kit:misc encoded.txt
/ctf-kit:misc qrcode.png
/ctf-kit:misc challenge.bf
```
