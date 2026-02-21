# Misc — Pattern Recognition

## Encoding Detection

| Pattern | Encoding |
|---------|----------|
| `=` or `==` at end | Base64 |
| All caps A-Z + 2-7 | Base32 |
| Only 0-9 a-f | Hexadecimal |
| Only 0 and 1 (groups of 8) | Binary |
| `%20`, `%3D` | URL encoding |
| `&#65;`, `&#x41;` | HTML entities |
| `\u0041` | Unicode escape |
| `=3D`, `=20` | Quoted-printable |

## Esoteric Language Detection

| Looks Like | Language |
|------------|----------|
| `+ - < > [ ] . ,` | Brainfuck |
| `Ook.` `Ook!` `Ook?` | Ook! |
| Only whitespace (spaces, tabs, newlines) | Whitespace |
| `[]+!()` only | JSFuck |
| `moo`, `MOO`, `moO` | COW |
| `Chicken` repeated | Chicken |
| Musical notes | Velato |

## Common Misc Challenge Types

1. **Encoding chains:** Try CyberChef Magic for auto-detection
2. **Esoteric code:** Identify language, use online interpreter
3. **Logic puzzles:** Often need creative/lateral thinking
4. **QR/Barcodes:** Scan with `zbarimg` or phone
5. **ZIP/Archives:** Check for passwords, corruption, or zip-slip
6. **Pyjails:** Python sandbox escape challenges
7. **Jail breaks:** Restricted shell escape

## Archive Challenges

| Scenario | Approach |
|----------|----------|
| Password-protected ZIP | `fcrackzip`, `zip2john` + `john` |
| Corrupted ZIP | Fix headers, use `zip -FF` |
| Nested archives | Extract recursively |
| Known plaintext | `bkcrack` for ZIP |
