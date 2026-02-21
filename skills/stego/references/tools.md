# Stego — Tool Reference

## PNG/BMP Images (LSB Analysis)

```bash
# Comprehensive LSB analysis
zsteg -a image.png

# Check specific bit planes
zsteg image.png -b 1

# Visual analysis with stegsolve
stegsolve image.png
```

## JPEG Images

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

## All Image Types

```bash
# Check metadata
exiftool image.png

# Look for appended data
binwalk image.png

# Extract appended archives
binwalk -e image.png

# Check for trailing data after EOF
python3 -c "
with open('image.png','rb') as f:
    data = f.read()
    # PNG ends with IEND chunk
    idx = data.find(b'IEND')
    if idx > 0:
        trailing = data[idx+8:]
        if trailing:
            print(f'Found {len(trailing)} bytes after EOF')
            open('trailing.bin','wb').write(trailing)
"
```

## Audio Steganography

```bash
# Open in Audacity, view spectrogram
# Look for visual patterns in spectrum

# Decode SSTV (Slow Scan TV)
# Use SSTV decoder software

# LSB in WAV files
# Use wav-steg or similar tools

# Check for morse code
# Listen at different speeds
```

## Steghide Password List

Common passwords to try:

- (empty string)
- password
- steghide
- secret
- hidden
- flag
- (the challenge name)
- (the CTF name)
- (words from challenge description)
