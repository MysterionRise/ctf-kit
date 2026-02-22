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
- [run-decode.sh](scripts/run-decode.sh) — Multi-encoding decoder: tries Base64, Base32, hex, ROT13, URL, binary. Detects encoding type, attempts recursive decoding chains, and searches for flags. Outputs JSON with all decoded results.

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. **For encoding detection and decoding** (outputs structured JSON):

   ```bash
   bash scripts/run-decode.sh <encoded-string>
   bash scripts/run-decode.sh encoded.txt
   ```

   JSON output includes:
   - `detected_encoding`: what the input looks like (base64, hex, binary, etc.)
   - `decodings[]`: all successful decodings with confidence levels
   - `chains[]`: multi-step decoding results (e.g., base64 → hex → plaintext)
   - `flags`: any flag patterns found in decoded output
   - `has_flag`: true if flag found

   The script automatically tries chaining: if Base64 decoding produces another encoded string, it tries decoding that too.

3. For QR codes:

   ```bash
   zbarimg qrcode.png
   ```

4. For esoteric languages:
   - **Brainfuck:** `++++[>++++++++<-]>.`
   - **Ook!:** `Ook. Ook! Ook.`
   - **Whitespace:** Only spaces, tabs, newlines
   - **JSFuck:** `[]!+()` characters only

   Use online interpreters for these.

## Encoding Chain Workflow

The `run-decode.sh` script handles multi-step chains automatically:

1. Input → detect encoding type
2. Try all standard decodings (base64, hex, ROT13, URL, binary)
3. For each successful decoding → try decoding the result again
4. Search all intermediate and final results for flag patterns
5. Output unified JSON with all results

## Common Encoding Patterns

| Pattern | Encoding |
|---------|----------|
| `=` or `==` at end | Base64 |
| All caps + 2-7 | Base32 |
| Only 0-9 a-f | Hexadecimal |
| Only 0 and 1 | Binary |
| `%20`, `%3D` | URL encoding |
| `&#65;`, `&#x41;` | HTML entities |

## Esoteric Language Detection

| Looks Like | Language |
|------------|----------|
| `+ - < > [ ] . ,` | Brainfuck |
| `Ook.` `Ook!` `Ook?` | Ook! |
| Only whitespace | Whitespace |
| `[]+!()` | JSFuck |
| `moo`, `MOO` | COW |

## Example Usage

```bash
/ctf-kit:misc encoded.txt
/ctf-kit:misc qrcode.png
/ctf-kit:misc challenge.bf
```
