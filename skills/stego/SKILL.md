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

2. Based on file type, use appropriate tools:

   **For PNG/BMP Images (LSB):**

   ```bash
   # Comprehensive LSB analysis
   zsteg -a image.png

   # Check specific channels
   zsteg image.png -b 1

   # Visual analysis with stegsolve
   stegsolve image.png
   ```

   **For JPEG Images:**

   ```bash
   # Check for steghide data
   steghide info image.jpg

   # Extract with password
   steghide extract -sf image.jpg -p "password"

   # Try empty password
   steghide extract -sf image.jpg -p ""

   # Try jsteg
   jsteg reveal image.jpg output.txt
   ```

   **For All Images:**

   ```bash
   # Check metadata
   exiftool image.png

   # Look for appended data
   binwalk image.png

   # Extract appended archives
   binwalk -e image.png
   ```

   **For Audio:**

   ```bash
   # Open in Audacity, view spectrogram
   # Look for visual patterns in spectrum

   # Check for morse code
   # Listen at different speeds

   # LSB in WAV
   # Use audio stego tools
   ```

3. Key things to check:
   - File metadata (comments, author fields)
   - Data appended after file EOF
   - LSB in color channels
   - Spectrogram in audio files

## Quick Checklist

| File Type | First Try |
|-----------|-----------|
| PNG/BMP | zsteg -a |
| JPEG | steghide extract -p "" |
| GIF | Check frames, delays |
| WAV | Spectrogram in Audacity |
| Any | exiftool, binwalk |

## Common Passwords for Steghide

Try these common passwords:

- (empty)
- password
- steghide
- secret
- hidden
- flag
- (the challenge name)

## Example Usage

```bash
/ctf-kit:stego image.png
/ctf-kit:stego audio.wav
/ctf-kit:stego ./media/
```
