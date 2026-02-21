# Stego — Pattern Recognition

## Quick Checklist by File Type

| File Type | First Try | Second Try |
|-----------|-----------|------------|
| PNG/BMP | `zsteg -a` | `binwalk`, check metadata |
| JPEG | `steghide extract -p ""` | `jsteg reveal`, `binwalk` |
| GIF | Check frames, delays | Frame extraction, interframe diff |
| WAV | Spectrogram in Audacity | LSB extraction, morse code |
| Any | `exiftool`, `binwalk` | `strings`, hex editor |

## Common Hiding Techniques

| Technique | Detection Method |
|-----------|-----------------|
| LSB in image channels | zsteg, stegsolve |
| Steghide embedding | `steghide info` |
| Data appended after EOF | `binwalk`, hex editor |
| Metadata fields | `exiftool` |
| Pixel value encoding | Manual analysis |
| Audio spectrogram | Audacity spectrogram view |
| Frame timing in GIF | Check frame delays for morse/binary |
| EXIF GPS/comments | `exiftool -a -u` |

## Image Channel Analysis

When using stegsolve or manual analysis, check:
- Red, Green, Blue planes individually (bits 0-7)
- Alpha channel (if present)
- Combinations of LSBs across channels
- Row vs column ordering
