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

## Common Issues

**`zsteg` not found**
- **Cause:** zsteg is a Ruby gem, not a system package
- **Solution:** Install with `gem install zsteg`. Requires Ruby. If Ruby is missing: `apt install ruby` (Debian/Ubuntu) or `brew install ruby` (macOS)

**zsteg returns no results on a JPEG**
- **Cause:** zsteg only works on PNG/BMP files — it cannot analyze JPEG images
- **Solution:** Use `steghide` for JPEG files: `steghide extract -sf image.jpg -p ""`. Also try `jsteg reveal image.jpg` or `outguess -r image.jpg output.txt`

**`steghide` not found**
- **Cause:** steghide not installed
- **Solution:** Install with `apt install steghide` (Debian/Ubuntu). On macOS, steghide is not in Homebrew — use Docker (`docker run -it --rm -v .:/data kalilinux/kali steghide`) or try `jsteg` as an alternative: `go install github.com/lukechampine/jsteg@latest`

**steghide: "could not extract any data" with empty password**
- **Cause:** The file has a non-empty password, or no steghide data is embedded
- **Solution:** Try common passwords from the challenge context (challenge name, visible text, hints). Use `stegcracker image.jpg wordlist.txt` for automated password brute-forcing. If no steghide data exists, try other tools (binwalk, exiftool, strings)

**`exiftool` not found**
- **Cause:** ExifTool not installed
- **Solution:** Install with `apt install libimage-exiftool-perl` (Debian/Ubuntu) or `brew install exiftool` (macOS)

**No hidden data found with any tool**
- **Cause:** Data may be hidden in a way standard tools don't detect — visual encoding, specific color channels, or non-standard LSB methods
- **Solution:** Try `stegsolve` for visual analysis of individual color planes. Check if the image has unusual dimensions or pixel patterns. Look at color channel differences. For audio, check the spectrogram in Audacity (switch to spectrogram view)

**Audio spectrogram shows nothing**
- **Cause:** The hidden message may be in a different frequency range, or the audio uses a different stego technique
- **Solution:** Adjust Audacity spectrogram settings — increase max frequency, change window size. Try `sonic-visualiser` for better spectral analysis. Check for DTMF tones, morse code (listen at different speeds), or LSB encoding in WAV samples

**Image appears corrupted or won't open**
- **Cause:** File header may be intentionally damaged as part of the challenge
- **Solution:** Check magic bytes with `xxd image.png | head`. Compare against correct headers (PNG: `89 50 4E 47`, JPEG: `FF D8 FF`). Fix corrupted bytes with a hex editor. Check if the file is actually a different format than the extension suggests

## Example Usage

```bash
/ctf-kit:stego image.png
/ctf-kit:stego audio.wav
/ctf-kit:stego ./media/
```
