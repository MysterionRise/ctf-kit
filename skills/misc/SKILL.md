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

3. Identify the challenge type — see [Pattern Recognition](references/patterns.md) for detection tables:
   - **Encoding** → detect encoding type, decode layer by layer
   - **Esoteric language** → identify language, use online interpreter
   - **QR/Barcode** → scan with `zbarimg`
   - **Archive** → check for passwords, corruption

4. For encoding chains, try CyberChef "Magic" recipe for auto-detection, or decode manually layer by layer.

## Example Usage

```bash
/ctf-kit:misc encoded.txt
/ctf-kit:misc qrcode.png
/ctf-kit:misc challenge.bf
```

## References

- [Tool Reference](references/tools.md) — encoding/decoding commands, QR tools, CyberChef, online tools
- [Pattern Recognition](references/patterns.md) — encoding detection, esoteric languages, archive challenges
