# Crypto — Tool Reference

## Hash Cracking

```bash
# Identify hash type
hashid <hash>

# Crack with John
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Crack with Hashcat
hashcat -m 0 -a 0 hashes.txt wordlist.txt  # MD5
hashcat -m 100 -a 0 hashes.txt wordlist.txt  # SHA1
hashcat -m 1400 -a 0 hashes.txt wordlist.txt  # SHA256
```

## RSA Attacks

```bash
# Attack weak RSA
RsaCtfTool --publickey key.pem --private

# With known parameters
RsaCtfTool -n <modulus> -e <exponent> --uncipher <ciphertext>

# Extract public key info
openssl rsa -pubin -in key.pem -text -noout

# Decrypt with private key
openssl rsautl -decrypt -inkey private.pem -in ciphertext.bin
```

## XOR Analysis

```bash
# Analyze XOR encryption
xortool encrypted.bin

# Try with known key length
xortool -l 8 -c 20 encrypted.bin

# XOR with known key
python3 -c "
import sys
key = b'KEY'
data = open('encrypted.bin','rb').read()
print(bytes([d ^ key[i%len(key)] for i,d in enumerate(data)]))
"
```

## Classical Ciphers

| Cipher | Identification | Approach |
|--------|---------------|----------|
| Caesar | Shifted alphabet | Try all 25 rotations |
| ROT13 | Common shift=13 | `tr 'A-Za-z' 'N-ZA-Mn-za-m'` |
| Vigenere | Repeating key polyalphabetic | Kasiski examination, frequency analysis |
| Substitution | Monoalphabetic | Frequency analysis |
| Rail fence | Zigzag pattern | Try different rail counts |
| Atbash | Reversed alphabet | `tr 'A-Za-z' 'Z-Az-a'` |
