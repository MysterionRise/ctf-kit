---
name: stego
description: >-
  Solve CTF steganography challenges: hidden data in images, audio, and
  media files. Use when you see: .png .jpg .bmp .gif images, .wav .mp3
  .flac audio, or suspect LSB encoding, appended data after EOF, hidden
  metadata, spectrogram messages. Triggers: "hidden message", "LSB",
  "steganography", "hidden in image", "zsteg", "steghide", "exiftool".
  Tools: zsteg, steghide, exiftool, binwalk, stegsolve.
  NOT for file carving from disk images (use forensics).
---

# CTF Stego

Analyze and solve steganography challenges.

## When to Use

Use this command for challenges involving:

- Images (PNG, JPG, BMP, GIF)
- Audio files (WAV, MP3, FLAC)
- Hidden data in media files
- LSB encoding
- Metadata hiding

## Bundled Scripts

- [check-tools.sh](scripts/check-tools.sh) — Verify required stego tools are installed
- [run-zsteg.sh](scripts/run-zsteg.sh) — Full LSB analysis on PNG/BMP images
- [run-steghide.sh](scripts/run-steghide.sh) — Extract hidden data from JPEG (tries common passwords)

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. Run the stego analysis:

   ```bash
   ctf run stego $ARGUMENTS
   ```

3. Based on file type, use appropriate tools — see [Tool Reference](references/tools.md) for detailed commands:
   - **PNG/BMP** → zsteg for LSB analysis
   - **JPEG** → steghide extraction
   - **Any image** → exiftool metadata, binwalk for appended data
   - **Audio** → spectrogram analysis, LSB extraction

4. Key things to check:
   - File metadata (comments, author fields)
   - Data appended after file EOF
   - LSB in color channels
   - Spectrogram in audio files

## Example Usage

```bash
/ctf-kit:stego image.png
/ctf-kit:stego audio.wav
/ctf-kit:stego ./media/
```

## References

- [Tool Reference](references/tools.md) — zsteg, steghide, exiftool, audio stego, password lists
- [Pattern Recognition](references/patterns.md) — file type checklist, hiding techniques, channel analysis
