# /ctf.stego - Steganography Challenge Assistance

Help solve steganography challenges.

## When to Use

Use this command when:

- Challenge involves images (PNG, JPEG, BMP, GIF)
- Audio files (WAV, MP3, FLAC)
- Hidden data in media files
- Challenge mentions "hidden" or "invisible" data

## Common Steganography Techniques

### Images

- **LSB (Least Significant Bit)**: Data hidden in pixel values
- **Metadata**: EXIF data, comments
- **File appending**: Data after EOF marker
- **Color channels**: Hidden in specific RGB channels

### Audio

- **Spectrograms**: Visual data in frequency domain
- **LSB in samples**: Hidden in audio samples
- **Metadata**: ID3 tags, comments

### File-based

- **Polyglot files**: Valid as multiple formats
- **Appended data**: After file EOF
- **Alternate data streams**: NTFS-specific

## Key Tools

```bash
# Check available tools
ctf check --category stego

# PNG/BMP analysis
zsteg image.png
zsteg -a image.png  # all combinations

# JPEG steganography
steghide extract -sf image.jpg

# Metadata
exiftool image.jpg

# Check for embedded files
binwalk image.png

# View hex
xxd image.png | head -50
```

## Analysis Steps

1. **Check metadata first**

   ```bash
   exiftool image.jpg
   strings image.jpg | head -50
   ```

2. **Look for appended data**

   ```bash
   binwalk image.png
   xxd image.png | tail -20
   ```

3. **Try common stego tools**
   - PNG/BMP: `zsteg -a image.png`
   - JPEG: `steghide extract -sf image.jpg`
   - Audio: Check spectrogram

4. **Analyze bit planes**
   - Use StegSolve or similar
   - Check individual color channels
   - XOR with blank image

5. **For audio**
   - Import into Audacity
   - View spectrogram
   - Look for visual patterns

## zsteg Quick Reference

```bash
# All checks
zsteg -a image.png

# Specific extractions
zsteg -E "b1,rgb,lsb,xy" image.png  # LSB of RGB
zsteg -E "extradata:0" image.png    # Trailing data

# Common patterns
zsteg image.png | grep -i "text\|flag\|ascii"
```

## steghide Commands

```bash
# Extract with empty password
steghide extract -sf image.jpg -p ""

# Extract with password
steghide extract -sf image.jpg -p "password"

# Info about file
steghide info image.jpg
```

## Python for LSB

```python
from PIL import Image

def extract_lsb(image_path):
    img = Image.open(image_path)
    pixels = list(img.getdata())

    bits = ""
    for pixel in pixels:
        for channel in pixel[:3]:  # RGB
            bits += str(channel & 1)

    # Convert bits to bytes
    chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
    return ''.join(chars)
```

## Response Format

When responding to /ctf.stego:

1. **File Analysis**: Image/audio properties and metadata
2. **Tool Results**: Output from zsteg, steghide, etc.
3. **Hidden Data Found**: Any text, files, or patterns discovered
4. **Extraction Method**: How the data was hidden
5. **Flag**: The extracted flag or next steps

## Related Commands

- `/ctf.analyze` - Initial file analysis
- `/ctf.forensics` - For file carving
