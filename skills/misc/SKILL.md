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

1. Check tool availability:

   ```bash
   bash scripts/check-tools.sh
   ```

   Expected: each tool prints `[OK]`. If any show `[MISSING]`, note which are unavailable before proceeding.

2. Run the misc analysis:

   ```bash
   ctf run misc $ARGUMENTS
   ```

   Expected output: file type, encoding detection hints, or character pattern analysis.

3. **CRITICAL: Before choosing an approach, identify the challenge subtype:**
   - Trailing `=` or `==`, hex-only, nested encodings → **Encoding chain** → go to step 4a
   - Image file containing a barcode/QR pattern → **QR/barcode** → go to step 4b
   - Characters like `+-<>[].,` or `Ook.` or only whitespace → **Esoteric language** → go to step 4c

   If unclear, inspect the raw content: `xxd $ARGUMENTS | head -20 && strings $ARGUMENTS | head -20`

4. Apply the matching approach:

   **4a. Encoding Chain:**

   Decode layer by layer, checking output after each step:

   ```bash
   echo "SGVsbG8=" | base64 -d
   ```

   Expected: readable text or another encoded string. If still encoded, continue:

   ```bash
   echo "48656C6C6F" | xxd -r -p
   ```

   Expected: ASCII text. Apply ROT13 if letters look shifted:

   ```bash
   echo "Uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
   ```

   Expected: `Hello`. **CRITICAL: After each decode step, check for `flag{`, `CTF{`, or readable plaintext before continuing.**

   **4b. QR Codes / Barcodes:**

   ```bash
   zbarimg qrcode.png
   ```

   Expected: `QR-Code:http://example.com` or `QR-Code:flag{...}`. If `zbarimg` is not installed, try reading the image visually and decoding manually.

   **4c. Esoteric Languages:**

   Identify the language by character set:

   | Characters present | Language | Interpreter |
   |--------------------|----------|-------------|
   | `+ - < > [ ] . ,` only | Brainfuck | `beef`, online |
   | `Ook.` `Ook!` `Ook?` | Ook! | Online interpreter |
   | Only spaces, tabs, newlines | Whitespace | Online interpreter |
   | `[]+!()` only | JSFuck | Node.js / browser console |
   | `moo`, `MOO` | COW | Online interpreter |

   Copy the source code and run it through the appropriate interpreter. Expected output: plaintext flag.

5. **Validation: Confirm the solution.** The decoded/executed output should contain a flag string or readable answer. If you get binary garbage or errors, revisit step 3 — the subtype identification may be wrong.

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
/ctf-kit:misc encoded.txt
/ctf-kit:misc qrcode.png
/ctf-kit:misc challenge.bf
```
