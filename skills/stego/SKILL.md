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

1. Check tool availability:

   ```bash
   bash scripts/check-tools.sh
   ```

   Expected: each tool prints `[OK]`. If any show `[MISSING]`, note which are unavailable before proceeding.

2. Identify the file type:

   ```bash
   file $ARGUMENTS
   ```

   Expected: one of:
   - `PNG image data` → go to step 3a
   - `JPEG image data` → go to step 3b
   - `BMP image` → go to step 3a (same as PNG for LSB)
   - `RIFF (little-endian) data, WAVE audio` → go to step 3d
   - `GIF image data` → go to step 3c

   **CRITICAL: The file type determines which stego tools to use. JPEG requires different tools than PNG/BMP.**

3. Always run these checks first (any image type):

   ```bash
   exiftool $ARGUMENTS
   ```

   Expected: metadata table. Look for `Comment`, `Author`, `Description`, or `UserComment` fields containing hidden text or flags.

   ```bash
   binwalk $ARGUMENTS
   ```

   Expected: table of embedded file signatures. If it shows `Zip archive` or `JPEG image` after the main file header, there is appended data:

   ```bash
   binwalk -e $ARGUMENTS
   ```

   Expected: extracted files in `_<filename>.extracted/`. Check each one.

   **CRITICAL: If exiftool or binwalk found the flag, stop here. Only continue to specialized tools if no flag was found.**

   Now apply file-type-specific analysis:

   **3a. PNG/BMP (LSB Analysis):**

   ```bash
   zsteg -a image.png
   ```

   Expected: list of channels and bit planes with detected data. Look for lines containing readable text, `flag{`, or `file` signatures. Example output:
   ```
   b1,rgb,lsb,xy   .. text: "flag{hidden_in_pixels}"
   b1,r,lsb,xy     .. file: PNG image data
   ```

   If `zsteg -a` produces too much noise, try specific channels:

   ```bash
   zsteg image.png -b 1
   ```

   **3b. JPEG (Steghide/Jsteg):**

   ```bash
   steghide info image.jpg
   ```

   Expected: `embedded file "secret.txt"` if data is hidden. Extract it:

   ```bash
   steghide extract -sf image.jpg -p ""
   ```

   Expected: `wrote extracted data to "secret.txt"`. If password-protected, try common passwords: `password`, `steghide`, `secret`, `hidden`, `flag`, or the challenge name.

   If steghide finds nothing:

   ```bash
   jsteg reveal image.jpg output.txt
   ```

   Expected: hidden data written to `output.txt`.

   **3c. GIF:**
   - Check individual frames for differences (frame-by-frame analysis)
   - Check frame delays for encoded data (e.g., morse code in timing)
   - Extract frames and compare pixel differences

   **3d. Audio (WAV/MP3/FLAC):**
   - Open in Audacity → switch to Spectrogram view → look for visual text/patterns
   - Check for morse code in the waveform
   - Try LSB extraction tools for WAV files
   - Listen at different speeds (0.5x, 2x)

4. **Validation: Confirm the extracted data.** The output should be a readable flag, a secondary file containing the flag, or coordinates/text that answers the challenge. If you get binary garbage, try a different channel, bit plane, or tool from step 3.

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
