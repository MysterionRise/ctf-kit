---
name: crypto
description: >-
  Solve CTF cryptography challenges including encryption, hashing, and
  encoding. Use when you see: Base64 (trailing ==), hex strings (32/40/64
  chars for MD5/SHA1/SHA256), RSA parameters (n=, e=, c=, p=, q=),
  XOR-encrypted data, .pem .key .enc files, classical ciphers (Caesar,
  Vigenere, substitution), encoding chains, or "crack this hash".
  Tools: xortool, hashid, hashcat, john, RsaCtfTool, openssl.
---

# CTF Crypto

Analyze and solve cryptography challenges.

## When to Use

Use this command for challenges involving:

- Encrypted text or files
- Hash cracking
- RSA/asymmetric cryptography
- XOR encryption
- Classical ciphers (Caesar, Vigenere, etc.)
- Encoding chains (Base64, hex, etc.)

## Bundled Scripts

- [check-tools.sh](scripts/check-tools.sh) — Verify required crypto tools are installed
- [run-xortool.sh](scripts/run-xortool.sh) — Analyze XOR-encrypted files with key length detection. Outputs JSON with key lengths, probabilities, and cracking suggestions.
- [identify-hash.sh](scripts/identify-hash.sh) — Identify hash types from strings or files. Outputs JSON with hash type, hashcat mode numbers, and john format names.

## Instructions

1. First check tool availability: `bash scripts/check-tools.sh`

2. Run the crypto analysis:

   ```bash
   ctf run crypto $ARGUMENTS
   ```

3. **For hash identification** (outputs structured JSON with cracking commands):

   ```bash
   bash scripts/identify-hash.sh <hash-string>
   bash scripts/identify-hash.sh hashes.txt
   ```

   The JSON output includes:
   - `hashes[].types[]`: identified hash types with confidence
   - `hashes[].types[].hashcat_mode`: exact hashcat -m number
   - `hashes[].types[].jtr_format`: exact john --format value
   - `suggestions`: ready-to-run cracking commands

4. **For XOR analysis** (outputs structured JSON with key candidates):

   ```bash
   bash scripts/run-xortool.sh <encrypted-file>
   bash scripts/run-xortool.sh <file> 8        # known key length
   bash scripts/run-xortool.sh <file> 8 20     # key length + most frequent char (space=0x20)
   ```

   The JSON output includes:
   - `key_lengths[]`: candidates with probability percentages
   - `best_key_length`: most probable key length
   - `key_found`: actual key if detected
   - `decrypted_files`: paths to decrypted candidates

5. Based on JSON findings, chain to next tool:
   - Hash identified → run hashcat/john with the exact mode from JSON
   - XOR key found → decrypt with `xortool-xor -n -s '<key>' <file>`
   - RSA parameters → run `RsaCtfTool -n <n> -e <e> --uncipher <c>`

## Common Patterns

| Pattern | Likely Type |
|---------|-------------|
| 32 hex chars | MD5 hash |
| 40 hex chars | SHA1 hash |
| 64 hex chars | SHA256 hash |
| `==` at end | Base64 |
| All caps + 2-7 | Base32 |
| n=..., e=... | RSA parameters |

## Output Format

All scripts produce a `=== PARSED RESULTS (JSON) ===` section. Use the `suggestions` array for ready-to-run next commands.

## Team Roles

When using `/ctf-kit:team-solve` with a crypto challenge, the lead spawns 3 specialists:

| Role | Teammate Name | Focus | Tools | First Action |
|------|--------------|-------|-------|--------------|
| Classical & Encoding | `classical-analyst` | Frequency analysis, substitution ciphers, Vigenere, transposition, encoding chains (Base64/hex/ROT13) | CyberChef, `scripts/run-decode.sh`, `scripts/identify-hash.sh`, dcode.fr | Run decode + hash-id on all files, check for known cipher patterns |
| Asymmetric & Math | `rsa-specialist` | RSA factoring (small primes, Fermat, Wiener), padding oracles, Boneh-Durfee, ECC, Diffie-Hellman | RsaCtfTool, openssl, sage, python3 | Extract RSA parameters (n,e,c), try RsaCtfTool, check factordb |
| Symmetric & Hash | `symmetric-cracker` | XOR key recovery, AES mode attacks (ECB/CBC), hash cracking, HMAC | xortool, hashcat, john, `scripts/run-xortool.sh` | Run xortool on binary files, identify and crack any hashes |

### When to broadcast

- **Classical**: "Identified cipher type as Vigenere with key length N" — RSA specialist can ignore
- **RSA**: "Found factors of n" or "Need ciphertext in different format" — others adjust
- **Symmetric**: "XOR key found: KEY" — others try decrypting their findings with it
- **Any**: "Found the flag" — immediate broadcast, all stop

## Example Usage

```bash
/ctf-kit:crypto cipher.txt
/ctf-kit:crypto encrypted.bin
/ctf-kit:crypto ./challenge/
```
