# Sample Challenge Solutions

Known solutions for integration testing. Each challenge has a flag
and known characteristics that skills should detect.

## Web: web_flask_vuln.py
- **Flag**: `flag{web_sqli_ssti_detected}`
- **Vulnerabilities**: SQL injection (cursor.execute with string concat),
  SSTI (render_template_string), hardcoded credentials
- **Technology**: Flask, SQLite
- **Endpoints**: /login, /admin/dashboard, /api/users

## Crypto: crypto_rsa_challenge.txt
- **Flag**: Encrypted as c=2790 with RSA (n=3233, e=17)
- **Detections**: RSA parameters (n, e, c), small modulus
- **Solution**: Factor n=3233 into p=61, q=53, compute d, decrypt

## Crypto: crypto_base64.txt
- **Flag**: `flag{test_base64_decoded}`
- **Encoding**: Base64

## Crypto: crypto_hash.txt
- **Hash**: `5d41402abc4b2a76b9719d911017c592` (MD5 of "hello")

## Crypto: crypto_xor.bin
- **Encoding**: XOR with key 0x4B

## Forensics: forensics_network.pcap
- **Flag**: `flag{forensics_pcap_treasure}` (in HTTP cookie header)
- **Type**: Network capture (pcap format)
- **Detection**: pcap magic bytes, network forensics type

## Forensics: forensics_embedded.bin
- **Type**: General forensics with embedded data

## Reverse: reverse_crackme.pyc
- **Flag**: `flag{reverse_secret_key}` (embedded string)
- **Type**: Python bytecode
- **Detections**: check_password, verify_input, ptrace anti-debug

## Pwn: pwn_vulnerable
- **Flag**: `flag{pwn_overflow_win}` (embedded string)
- **Type**: ELF 64-bit
- **Vulnerabilities**: gets(), strcpy(), system(), /bin/sh available
- **Detections**: Buffer overflow indicators, win function

## Misc: misc_multi_encode.txt
- **Flag**: `flag{misc_encoding_chain}`
- **Encoding chain**: hex string -> base64 encoded
- **Solution**: base64 decode -> hex decode -> ASCII flag

## Stego: stego_test.png
- **Type**: PNG image (100x100)
