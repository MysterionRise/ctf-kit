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
- [run-zsteg.sh](scripts/run-zsteg.sh) — Full LSB analysis on PNG/BMP images. Outputs JSON with channel findings, embedded text/files, and extraction commands.
- [run-steghide.sh](scripts/run-steghide.sh) — Extract hidden data from JPEG (tries common passwords). Outputs JSON with extraction status and password used.
- [run-exiftool.sh](scripts/run-exiftool.sh) — Metadata extraction with CTF-relevant field detection. Outputs JSON with interesting fields, GPS data, and flag detection.
- [stego-pipeline.sh](scripts/stego-pipeline.sh) — **Multi-step pipeline**: exiftool → binwalk → zsteg/steghide. Runs all relevant tools in sequence based on file type and combines results.

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. **Recommended: Run the full stego pipeline** for comprehensive analysis:

   ```bash
   bash scripts/stego-pipeline.sh $ARGUMENTS
   ```

   The pipeline automatically:
   - Extracts metadata (exiftool) → checks for hidden comments, GPS, flags
   - Scans for appended data (binwalk) → detects files hidden after EOF
   - Runs LSB analysis (zsteg) → for PNG/BMP images
   - Tries steghide extraction → for JPEG/WAV with common passwords

   The JSON output combines all results with a unified `suggestions` array.

3. **For individual tools**:

   **PNG/BMP (LSB analysis):**
   ```bash
   bash scripts/run-zsteg.sh image.png
   ```
   JSON `findings[]` shows hidden text/files per channel. Use `zsteg -E <channel>` to extract.

   **JPEG (steghide):**
   ```bash
   bash scripts/run-steghide.sh image.jpg
   bash scripts/run-steghide.sh image.jpg "mypassword"
   ```
   JSON shows `extracted_file` and `password_used` on success.

   **Metadata:**
   ```bash
   bash scripts/run-exiftool.sh image.png
   ```
   JSON `interesting_fields[]` highlights CTF-relevant metadata with reasons.

## Multi-Step Workflow

The pipeline handles chaining automatically. For manual chaining:

1. `run-exiftool.sh image.png` → check JSON `interesting_fields` for clues
2. `run-zsteg.sh image.png` → check JSON `findings` for LSB data
3. If zsteg finds embedded file → `zsteg -E <channel> image.png > extracted`
4. Analyze extracted file with `/ctf-kit:analyze`

## Quick Checklist

| File Type | First Try |
|-----------|-----------|
| PNG/BMP | `stego-pipeline.sh` (runs zsteg + exiftool + binwalk) |
| JPEG | `stego-pipeline.sh` (runs steghide + exiftool + binwalk) |
| GIF | Check frames, delays |
| WAV | Spectrogram in Audacity |
| Any | `stego-pipeline.sh` covers metadata + embedded data |

## Output Format

All scripts produce `=== PARSED RESULTS (JSON) ===` or `=== PIPELINE RESULTS (JSON) ===` sections. The `has_flag` field is `true` when a flag pattern is detected.

## Example Usage

```bash
/ctf-kit:stego image.png
/ctf-kit:stego audio.wav
/ctf-kit:stego ./media/
```
