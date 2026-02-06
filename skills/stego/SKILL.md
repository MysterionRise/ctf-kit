---
name: stego
description: Analyze and solve steganography challenges
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

## Instructions

1. Run the stego analysis:

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
