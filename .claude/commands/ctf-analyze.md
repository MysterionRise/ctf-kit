# CTF Analyze

Analyze challenge files to determine type and suggest approaches.

## When to Use

Use this command when you have new challenge files and need to:

- Identify the challenge category (crypto, forensics, stego, web, pwn, reversing, OSINT, misc)
- Detect file types and formats
- Get initial suggestions for tools to use
- Understand what you're working with

## Instructions

1. Run the analysis on the challenge files:

   ```bash
   ctf analyze $ARGUMENTS
   ```

2. Review the output to understand:
   - Detected file types
   - Suggested challenge category
   - Interesting strings or metadata found
   - Embedded files detected

3. Based on the analysis results, suggest the appropriate specialized command:
   - `/ctf-crypto` for cryptography challenges
   - `/ctf-forensics` for forensics challenges
   - `/ctf-stego` for steganography challenges
   - `/ctf-web` for web security challenges
   - `/ctf-pwn` for binary exploitation challenges
   - `/ctf-reverse` for reverse engineering challenges
   - `/ctf-osint` for OSINT challenges
   - `/ctf-misc` for miscellaneous challenges

4. Explain the findings and recommended next steps to the user.

## Example Usage

```bash
/ctf-analyze challenge.bin
/ctf-analyze ./challenge-folder/
```

## Related Commands

- `/ctf-crypto` - Crypto-specific analysis
- `/ctf-forensics` - Forensics analysis
- `/ctf-stego` - Steganography analysis
