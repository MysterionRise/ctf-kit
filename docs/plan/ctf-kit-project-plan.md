# 🏴 CTF Kit - Project Plan

> **AI-Assisted Capture The Flag Challenge Solver**

A toolkit that helps security researchers and CTF players solve challenges faster using AI support, with specialized skills for different challenge categories.

---

## Table of Contents

1. [Vision & Goals](#vision--goals)
2. [Architecture Overview](#architecture-overview)
3. [Challenge Category Analysis](#challenge-category-analysis)
4. [Skills Specification](#skills-specification)
5. [Tool Integrations](#tool-integrations) *(see also: ctf-kit-tool-integrations.md)*
6. [Workflow Design](#workflow-design)
7. [CLI Reference](#cli-reference)
8. [Implementation Phases](#implementation-phases)
9. [Open Questions & Considerations](#open-questions--considerations)

> **Related Documents:**
> - `ctf-kit-skills-analysis.md` - Deep dive into skill requirements by category
> - `ctf-kit-tool-integrations.md` - **Comprehensive tool integration specifications (40+ tools)**

---

## Vision & Goals

### Primary Goals

1. **Accelerate CTF solving** - Reduce time spent on repetitive tasks and pattern recognition
2. **Educational value** - Help learners understand attack vectors and methodologies
3. **Systematic approach** - Bring structure to challenge analysis and documentation
4. **Writeup generation** - Automatically document solutions for knowledge sharing

### Non-Goals

- Fully autonomous flag capture (human-in-the-loop is essential)
- Replacing fundamental security knowledge
- Cheating in competitive CTFs (tool is for learning and practice)

---

## Architecture Overview

### CTF Kit Package Structure

```
ctf-kit/                              # The tool itself
├── cli/                              # CTF Kit CLI (Python/uv)
│   ├── ctf.py                        # Main CLI entry point
│   ├── commands/
│   │   ├── here.py                   # ctf here
│   │   ├── status.py                 # ctf status
│   │   ├── flag.py                   # ctf flag
│   │   └── writeups.py               # ctf writeups
│   └── context.py                    # Directory detection
├── skills/                           # Category-specific skills
│   ├── crypto/
│   ├── forensics/
│   ├── osint/
│   ├── web/
│   ├── pwn/
│   ├── reversing/
│   ├── stego/
│   └── misc/
├── integrations/                     # External tool wrappers
│   ├── base.py                       # BaseTool class
│   ├── crypto/                       # xortool, rsactftool, etc.
│   ├── archive/                      # bkcrack, john, etc.
│   ├── forensics/                    # binwalk, volatility, etc.
│   ├── network/                      # tshark, tcpdump
│   ├── stego/                        # zsteg, steghide, etc.
│   ├── web/                          # sqlmap, gobuster, etc.
│   ├── pwn/                          # pwntools, ropgadget
│   └── reversing/                    # radare2, ghidra
├── templates/                        # Document templates
│   ├── analysis-template.md
│   ├── approach-template.md
│   └── writeup-template.md
└── agents/                           # AI agent configurations
    ├── claude/
    ├── copilot/
    ├── cursor/
    └── gemini/
```

### Your CTF Repo Structure (With CTF Kit)

```
your-ctf-monorepo/                    # YOUR existing repo
├── .venv/                            # Your Python env
├── .ctf-kit.yaml                     # Optional: default settings
└── competitions/
    ├── amateursCTF2025/
    │   ├── .competition.yaml         # Optional: CTF metadata
    │   ├── addition2/
    │   │   ├── solve.py              # Your solution
    │   │   ├── challenge.txt         # Challenge files
    │   │   └── .ctf/                 # CTF Kit workspace
    │   │       ├── config.yaml
    │   │       └── memory/
    │   │           ├── analysis.md
    │   │           └── writeup.md
    │   ├── aescure/
    │   │   └── .ctf/
    │   └── ...
    ├── bcactf-2025/
    ├── bitskrieg-2025/
    └── ...
```

**Key points:**
- CTF Kit installs globally via `uv tool install`
- Your repo structure stays **exactly as-is**
- Each challenge gets a small `.ctf/` folder when you run `ctf here`
- All your existing files are untouched

### Per-Challenge Memory Structure

```
.ctf/
├── config.yaml                       # Challenge metadata
│   # name: aescure
│   # category: crypto
│   # status: solved
│   # flag: flag{...}
│   # solved_at: 2025-01-15T14:30:00Z
└── memory/
    ├── analysis.md                   # Initial analysis
    ├── approach.md                   # Solution strategy
    ├── attempts.md                   # Log of attempts
    ├── artifacts/                    # Extracted/decoded files
    │   ├── decoded.txt
    │   └── key.bin
    └── writeup.md                    # Final writeup
```

---

## Challenge Category Analysis

### Category Breakdown & Complexity

| Category | Subcategories | AI Suitability | Tool Dependency | Skill Complexity |
|----------|---------------|----------------|-----------------|------------------|
| **Crypto** | Classical, Modern, Custom | ⭐⭐⭐⭐⭐ | Medium | High |
| **Forensics** | Disk, Memory, Network, File | ⭐⭐⭐⭐ | High | High |
| **OSINT** | Social, Geolocation, Historical | ⭐⭐⭐⭐⭐ | Medium | Medium |
| **Web** | SQLi, XSS, SSRF, Auth bypass | ⭐⭐⭐⭐ | Medium | High |
| **Pwn** | Stack, Heap, Format string | ⭐⭐⭐ | High | Very High |
| **Reversing** | Static, Dynamic, Obfuscation | ⭐⭐⭐ | Very High | Very High |
| **Stego** | Image, Audio, Text, Network | ⭐⭐⭐⭐ | Medium | Medium |
| **Misc** | Programming, Logic, Encoding | ⭐⭐⭐⭐⭐ | Low | Variable |

### AI Suitability Rationale

**High AI Suitability (⭐⭐⭐⭐⭐):**
- **Crypto**: Pattern recognition in ciphertext, identifying cipher types, mathematical analysis
- **OSINT**: Web research, data correlation, timeline construction
- **Misc**: Code understanding, logic puzzles, encoding chains

**Medium AI Suitability (⭐⭐⭐⭐):**
- **Forensics**: File analysis, artifact identification, timeline correlation
- **Web**: Vulnerability pattern recognition, payload generation
- **Stego**: Detection of anomalies, known hiding technique identification

**Lower AI Suitability (⭐⭐⭐):**
- **Pwn**: Requires precise binary analysis and exploit development
- **Reversing**: Complex control flow, heavy tool dependency

---

## Skills Specification

### 1. Crypto Skill (`/ctf.crypto`)

#### Capabilities
- Cipher identification (classical: Caesar, Vigenère, Substitution, etc.)
- Frequency analysis and statistical attacks
- RSA vulnerability detection (small e, common modulus, Wiener's attack, etc.)
- Hash identification and rainbow table suggestions
- Custom cipher analysis and pattern recognition
- Mathematical computations (modular arithmetic, GCD, factorization)

#### Subcategories & Techniques

| Subcategory | Techniques | Tools/Libraries |
|-------------|------------|-----------------|
| Classical | Caesar, ROT13, Vigenère, Playfair, Enigma | Python, dcode.fr API |
| Symmetric | AES (ECB/CBC attacks), DES, XOR | PyCryptodome, CyberChef |
| Asymmetric | RSA, ECC, Diffie-Hellman | gmpy2, SageMath, RsaCtfTool |
| Hashing | MD5, SHA, bcrypt, custom | hashcat, john, hashid |
| Encoding | Base64/32/58, hex, binary, custom | CyberChef, Python |

#### Example Workflow
```
/ctf.crypto analyze      # Identify cipher type from ciphertext
/ctf.crypto classical    # Apply classical cipher attacks
/ctf.crypto rsa          # Analyze RSA parameters for vulnerabilities
/ctf.crypto decode       # Chain decode operations
```

#### Skill File Structure
```
skills/crypto/
├── SKILL.md                     # Main skill instructions
├── ciphers/
│   ├── classical.md             # Classical cipher reference
│   ├── rsa-attacks.md           # RSA vulnerability catalog
│   └── aes-attacks.md           # AES mode attacks
├── scripts/
│   ├── frequency_analysis.py
│   ├── rsa_attacks.py
│   └── xor_key_finder.py
└── wordlists/
    └── common_keys.txt
```

---

### 2. OSINT Skill (`/ctf.osint`)

#### Capabilities
- Username enumeration across platforms
- Reverse image search guidance
- Geolocation from images (EXIF, visual cues)
- Domain/IP reconnaissance
- Social media timeline analysis
- Wayback Machine and archive research
- Google dorking query generation

#### Subcategories & Techniques

| Subcategory | Techniques | Services/Tools |
|-------------|------------|----------------|
| People | Username search, social profiling | Sherlock, namechk, social-analyzer |
| Geolocation | EXIF extraction, landmark ID, sun position | exiftool, Google Maps, SunCalc |
| Web History | Archive crawling, diff analysis | Wayback Machine API, archive.today |
| Infrastructure | DNS, WHOIS, subdomain enum | Shodan, Censys, SecurityTrails |
| Social Media | Timeline analysis, metadata | Platform APIs, manual analysis |

#### Example Workflow
```
/ctf.osint analyze       # Analyze provided information/images
/ctf.osint username      # Search for username across platforms
/ctf.osint geolocate     # Extract/analyze location data
/ctf.osint timeline      # Build timeline from gathered info
```

#### Skill File Structure
```
skills/osint/
├── SKILL.md
├── techniques/
│   ├── geolocation.md
│   ├── username-enum.md
│   └── web-archives.md
├── services/
│   ├── shodan.md                # Shodan API integration
│   ├── wayback.md               # Wayback Machine usage
│   └── social-platforms.md
└── checklists/
    └── osint-checklist.md
```

---

### 3. Forensics Skill (`/ctf.forensics`)

#### Capabilities
- File type identification and carving
- Memory dump analysis
- Network packet analysis
- Disk image examination
- Log file analysis
- Metadata extraction
- Deleted file recovery

#### Subcategories & Techniques

| Subcategory | Techniques | Tools |
|-------------|------------|-------|
| File Analysis | Magic bytes, carving, headers | file, binwalk, foremost |
| Memory | Process dump, strings, volatility | Volatility 3, strings, grep |
| Network | PCAP analysis, stream extraction | Wireshark/tshark, NetworkMiner |
| Disk | Partition analysis, deleted files | Autopsy, FTK, sleuthkit |
| Logs | Pattern matching, timeline | grep, awk, timeline tools |

#### Example Workflow
```
/ctf.forensics analyze   # Identify file type and structure
/ctf.forensics memory    # Analyze memory dump
/ctf.forensics network   # Analyze PCAP file
/ctf.forensics carve     # Extract embedded files
```

#### Tool Integration Requirements

**Local Tools (must be installed):**
```bash
# Core forensics tools
sudo apt install binwalk foremost sleuthkit autopsy

# Memory analysis
pip install volatility3

# Network analysis
sudo apt install wireshark tshark tcpdump

# File analysis
sudo apt install file exiftool hexedit xxd
```

**Wireshark Integration Strategy:**
```python
# Wrapper for tshark (CLI version of Wireshark)
class WiresharkIntegration:
    def extract_streams(self, pcap_file):
        """Extract TCP/UDP streams from PCAP"""

    def filter_packets(self, pcap_file, display_filter):
        """Apply Wireshark display filters"""

    def export_objects(self, pcap_file, protocol):
        """Export HTTP/SMB/etc objects"""

    def get_statistics(self, pcap_file):
        """Get protocol hierarchy and conversation stats"""
```

#### Skill File Structure
```
skills/forensics/
├── SKILL.md
├── techniques/
│   ├── file-carving.md
│   ├── memory-analysis.md
│   ├── network-forensics.md
│   └── disk-forensics.md
├── tools/
│   ├── volatility-profiles.md
│   ├── wireshark-filters.md
│   └── binwalk-usage.md
└── scripts/
    ├── pcap_analyzer.py
    ├── memory_strings.py
    └── file_carver.py
```

---

### 4. Web Skill (`/ctf.web`)

#### Capabilities
- Vulnerability identification (SQLi, XSS, SSRF, etc.)
- Request/response analysis
- Authentication bypass techniques
- Directory/file enumeration
- API testing
- Cookie/session analysis

#### Subcategories & Techniques

| Subcategory | Techniques | Tools |
|-------------|------------|-------|
| Injection | SQLi, NoSQLi, Command injection | sqlmap, manual |
| XSS | Reflected, Stored, DOM | Manual, XSStrike |
| Auth | JWT attacks, session hijacking | jwt_tool, manual |
| SSRF | Internal scanning, protocol smuggling | Manual, Burp |
| Recon | Dir busting, tech fingerprinting | gobuster, whatweb |

#### Example Workflow
```
/ctf.web analyze         # Analyze target web application
/ctf.web recon           # Perform reconnaissance
/ctf.web inject          # Test injection points
/ctf.web auth            # Analyze authentication mechanisms
```

---

### 5. Pwn Skill (`/ctf.pwn`)

#### Capabilities
- Binary security analysis (checksec)
- Vulnerability identification
- ROP chain generation
- Format string exploitation
- Heap exploitation guidance
- Shellcode generation

#### Subcategories & Techniques

| Subcategory | Techniques | Tools |
|-------------|------------|-------|
| Stack | Buffer overflow, ROP, ret2libc | pwntools, ROPgadget |
| Heap | Use-after-free, double-free, tcache | pwndbg, heapinspect |
| Format | Format string read/write | pwntools |
| Shellcode | Custom shellcode, encoding | msfvenom, pwntools |

#### Example Workflow
```
/ctf.pwn analyze         # Analyze binary security properties
/ctf.pwn overflow        # Identify buffer overflow potential
/ctf.pwn rop             # Generate ROP chain
/ctf.pwn exploit         # Generate exploit template
```

#### Skill File Structure
```
skills/pwn/
├── SKILL.md
├── techniques/
│   ├── stack-overflow.md
│   ├── heap-exploitation.md
│   ├── format-strings.md
│   └── rop-chains.md
├── scripts/
│   ├── exploit_template.py
│   ├── rop_finder.py
│   └── shellcode_gen.py
└── references/
    ├── syscall-table.md
    └── common-gadgets.md
```

---

### 6. Reversing Skill (`/ctf.reverse`)

#### Capabilities
- Static analysis guidance
- Decompilation assistance
- Anti-debugging detection
- Obfuscation identification
- Algorithm recognition
- Key/flag location hints

#### Subcategories & Techniques

| Subcategory | Techniques | Tools |
|-------------|------------|-------|
| Static | Disassembly, decompilation | Ghidra, IDA, radare2 |
| Dynamic | Debugging, tracing | gdb, x64dbg, strace |
| .NET/Java | Decompilation | dnSpy, JD-GUI, jadx |
| Obfuscation | Unpacking, deobfuscation | Manual, specific tools |

#### Example Workflow
```
/ctf.reverse analyze     # Initial binary analysis
/ctf.reverse strings     # Extract and analyze strings
/ctf.reverse functions   # Identify key functions
/ctf.reverse deobfuscate # Guidance on deobfuscation
```

---

### 7. Stego Skill (`/ctf.stego`)

#### Capabilities
- Steganography detection
- LSB extraction
- Audio spectrum analysis
- File structure anomaly detection
- Multi-layer stego identification

#### Subcategories & Techniques

| Subcategory | Techniques | Tools |
|-------------|------------|-------|
| Image | LSB, palette, EXIF | zsteg, stegsolve, exiftool |
| Audio | Spectrum, LSB, phase | Audacity, Sonic Visualizer |
| Text | Whitespace, zero-width, unicode | Manual, stegsnow |
| Network | Protocol stego, covert channels | Wireshark, manual |

#### Example Workflow
```
/ctf.stego analyze       # Detect potential steganography
/ctf.stego image         # Image-specific analysis
/ctf.stego audio         # Audio-specific analysis
/ctf.stego extract       # Attempt extraction with various tools
```

---

### 8. Misc Skill (`/ctf.misc`)

#### Capabilities
- Encoding chain detection and decoding
- Programming puzzle assistance
- Logic puzzle analysis
- Esoteric language identification
- QR code and barcode processing

#### Example Workflow
```
/ctf.misc analyze        # Analyze challenge type
/ctf.misc decode         # Decode encoding chains
/ctf.misc programming    # Assist with programming challenges
/ctf.misc esoteric       # Identify and interpret esoteric languages
```

---

## Tool Integrations

> **📖 See `ctf-kit-tool-integrations.md` for complete integration specifications including Python wrapper code for 40+ tools.**

### Tool Summary by Category

| Category | Key Tools | Integration Level |
|----------|-----------|-------------------|
| **Crypto** | xortool, RsaCtfTool, SageMath, hashcat, john, hashid | L3: Interactive |
| **Archive** | bkcrack, john/*2john, fcrackzip | L3: Interactive |
| **Forensics** | binwalk, foremost, volatility3, sleuthkit, tshark | L4: Orchestrated |
| **Network** | tshark, tcpdump, NetworkMiner | L2: Parsed |
| **Stego** | zsteg, steghide, stegsolve, exiftool | L2: Parsed |
| **Web** | sqlmap, gobuster, ffuf, nikto | L3: Interactive |
| **Pwn** | pwntools, ROPgadget, one_gadget, gdb | L3: Interactive |
| **Reversing** | radare2, ghidra (headless), objdump | L4: Orchestrated |
| **OSINT** | sherlock, theHarvester, exiftool | L2: Parsed |
| **Encoding** | CyberChef (Python impl) | L2: Parsed |

### Integration Levels

| Level | Description | Example |
|-------|-------------|---------|
| **L1: Basic** | Simple CLI wrapper | `file`, `strings` |
| **L2: Parsed** | Output parsing to structured data | `binwalk`, `exiftool` |
| **L3: Interactive** | Multi-step interaction | `john`, `hashcat` |
| **L4: Orchestrated** | AI-guided tool sequences | `volatility` workflows |

### Highlighted Tool Integrations

#### Crypto: xortool (XOR Key Analysis)
```python
class XORToolIntegration(BaseTool):
    def analyze_key_length(self, file_path, max_key_length=65) -> ToolResult:
        """Analyze file to determine probable XOR key length"""

    def decrypt_with_char(self, file_path, most_frequent_char=" ") -> ToolResult:
        """Decrypt assuming most frequent plaintext character"""
```

#### Archive: bkcrack (ZIP Known Plaintext Attack)
```python
class BkcrackIntegration(BaseTool):
    def attack_with_plaintext_bytes(self, cipher_zip, entry, plaintext) -> ToolResult:
        """Attack using known file headers (PNG: 89504E47...)"""

    def decrypt_with_keys(self, cipher_zip, keys, output_zip) -> ToolResult:
        """Decrypt ZIP using recovered internal keys"""

    # Built-in file headers for known plaintext attacks
    KNOWN_HEADERS = {
        "png": bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A...]),
        "jpeg": bytes([0xFF, 0xD8, 0xFF, 0xE0...]),
        "pdf": b"%PDF-1.",
        "zip": bytes([0x50, 0x4B, 0x03, 0x04]),
    }
```

#### Forensics: Volatility 3 (Memory Analysis)
```python
class Volatility3Integration(BaseTool):
    def identify_os(self, dump_path) -> ToolResult:
        """Identify OS of memory dump"""

    def get_processes(self, dump_path) -> ToolResult:
        """Get process list"""

    def get_password_hashes(self, dump_path) -> ToolResult:
        """Extract password hashes (Windows)"""
```

#### Network: tshark (Wireshark CLI)
```python
class WiresharkIntegration(BaseTool):
    def follow_stream(self, pcap, protocol, stream_index) -> ToolResult:
        """Follow and extract a protocol stream"""

    def export_objects(self, pcap, protocol, output_dir) -> ToolResult:
        """Export transferred objects (http, smb, etc.)"""

    def extract_credentials(self, pcap) -> ToolResult:
        """Extract potential credentials from various protocols"""
```

### Service Integrations

| Service | Purpose | Authentication | Rate Limits |
|---------|---------|----------------|-------------|
| **CyberChef** | Encoding/Decoding | None (local) | None |
| **Shodan** | Infrastructure OSINT | API Key | Free tier limited |
| **Censys** | Certificate search | API Key | 250/month free |
| **VirusTotal** | Malware analysis | API Key | 4/min free |
| **Wayback Machine** | Web archives | None | Polite crawling |
| **FactorDB** | Integer factorization | None | None |
| **dcode.fr** | Cipher tools | None | Manual guidance |

### Tool Orchestration Patterns

```python
# Pattern 1: Sequential Pipeline
def analyze_encrypted_zip(zip_path):
    # 1. List entries and check encryption
    bkcrack = BkcrackIntegration()
    info = bkcrack.list_entries(zip_path)

    # 2. If ZipCrypto, try known plaintext attack
    if has_known_file_type(info):
        result = bkcrack.attack_with_plaintext_bytes(...)
        if result.success:
            return bkcrack.decrypt_with_keys(...)

    # 3. Fall back to password cracking
    john = JohnIntegration()
    hash_result = john.extract_hash(zip_path, "zip")
    return john.crack(hash_result.artifacts[0], wordlist)

# Pattern 2: Parallel Analysis
def analyze_stego_image(image_path):
    with ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(zsteg.analyze, image_path),
            executor.submit(exiftool.extract_all, image_path),
            executor.submit(binwalk.scan, image_path),
        ]
    return {f.result().tool_name: f.result() for f in futures}
```

---

## Workflow Design

### Core Slash Commands

| Command | Description |
|---------|-------------|
| `/ctf.analyze` | Analyze challenge files and categorize |
| `/ctf.approach` | Generate solution approach based on analysis |
| `/ctf.solve` | Execute solution attempts |
| `/ctf.writeup` | Generate writeup documentation |
| `/ctf.tools` | Check and suggest required tools |

### Category-Specific Commands

| Command | Description |
|---------|-------------|
| `/ctf.crypto` | Cryptography-specific analysis and attacks |
| `/ctf.osint` | OSINT investigation workflow |
| `/ctf.forensics` | Forensics analysis workflow |
| `/ctf.web` | Web exploitation workflow |
| `/ctf.pwn` | Binary exploitation workflow |
| `/ctf.reverse` | Reverse engineering workflow |
| `/ctf.stego` | Steganography detection and extraction |
| `/ctf.misc` | Miscellaneous challenge assistance |

### Workflow Stages

```
┌─────────────────────────────────────────────────────────────────────┐
│                          CTF Kit Workflow                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐     │
│  │ ANALYZE  │───▶│ APPROACH │───▶│  SOLVE   │───▶│ WRITEUP  │     │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘     │
│       │               │               │               │            │
│       ▼               ▼               ▼               ▼            │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐     │
│  │analysis  │    │approach  │    │attempts  │    │writeup   │     │
│  │.md       │    │.md       │    │.md       │    │.md       │     │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘     │
│                                                                     │
│  Category Skills: /ctf.crypto, /ctf.osint, /ctf.forensics, etc.   │
│  Can be invoked at any stage for specialized analysis              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Analysis Template (`analysis.md`)

```markdown
# Challenge Analysis

## Metadata
- **Name**: {challenge_name}
- **Category**: {detected_category}
- **Points**: {points}
- **Difficulty**: {estimated_difficulty}
- **Source**: {ctf_name/platform}

## Files Provided
| File | Type | Size | Magic Bytes | Notes |
|------|------|------|-------------|-------|

## Initial Observations
{ai_generated_observations}

## Category-Specific Analysis
{category_specific_findings}

## Potential Approaches
1. {approach_1}
2. {approach_2}
3. {approach_3}

## Required Tools
- [ ] {tool_1}
- [ ] {tool_2}

## Similar Challenges
{references_to_similar_challenges}
```

### Approach Template (`approach.md`)

```markdown
# Solution Approach

## Selected Strategy
{primary_approach}

## Step-by-Step Plan
1. [ ] {step_1}
2. [ ] {step_2}
3. [ ] {step_3}

## Key Insights
{insights_from_analysis}

## Potential Pitfalls
- {pitfall_1}
- {pitfall_2}

## Resources
- {resource_1}
- {resource_2}
```

### Writeup Template (`writeup.md`)

```markdown
# {Challenge Name} - Writeup

## Challenge Info
- **Category**: {category}
- **Points**: {points}
- **Solves**: {solve_count}

## Description
> {original_description}

## TL;DR
{one_sentence_solution}

## Solution

### Step 1: Initial Analysis
{analysis_description}

### Step 2: {step_name}
{step_description}

```{language}
{code_if_applicable}
```

### Step N: Getting the Flag
{final_steps}

## Flag
`{flag}`

## Lessons Learned
- {lesson_1}
- {lesson_2}

## References
- {reference_1}
```

---

## CLI Reference

> **📖 See `ctf-kit-competition-workflow.md` for real-world competition usage patterns.**

### Design Philosophy

CTF Kit is designed to **fit your existing workflow**, not replace it. The tool:
- Works inside your existing monorepo structure
- Adds a small `.ctf/` folder per challenge (non-intrusive)
- Provides instant initialization with `ctf here`
- Never moves or reorganizes your files

### Commands

#### Quick Commands (Competition Speed)

| Command | Description | Use Case |
|---------|-------------|----------|
| `ctf here` | Initialize in current directory | Start working on a challenge |
| `ctf status` | Show challenge status | Quick check |
| `ctf flag "<flag>"` | Record flag, mark solved | After solving |

#### Setup Commands

| Command | Description |
|---------|-------------|
| `ctf here` | Initialize CTF Kit in current directory |
| `ctf here --category crypto` | Initialize with category hint |
| `ctf check` | Verify tool availability |
| `ctf check --category forensics` | Check tools for specific category |

#### Competition Management

| Command | Description |
|---------|-------------|
| `ctf status` | Show current challenge status |
| `ctf status --all` | Show all challenges in competition |
| `ctf writeups` | Export all writeups |
| `ctf writeups --format html` | Export as HTML |

### Slash Commands (AI Agent)

#### Core Commands

| Command | Description |
|---------|-------------|
| `/ctf.analyze` | Auto-detect category, analyze all files |
| `/ctf.approach` | Generate/update solution strategy |
| `/ctf.hint` | Get contextual hints based on progress |
| `/ctf.writeup` | Generate writeup from session |
| `/ctf.notes <text>` | Quick note capture |

#### Category-Specific Commands

| Command | Description |
|---------|-------------|
| `/ctf.crypto` | Cryptography analysis (xortool, RSA attacks, etc.) |
| `/ctf.forensics` | Forensics tools (binwalk, volatility, strings) |
| `/ctf.stego` | Steganography detection (zsteg, steghide, exiftool) |
| `/ctf.web` | Web exploitation (SQLi, XSS, enumeration) |
| `/ctf.pwn` | Binary exploitation (checksec, ROP, pwntools) |
| `/ctf.reverse` | Reverse engineering (radare2, ghidra, strings) |
| `/ctf.osint` | OSINT investigation (sherlock, image analysis) |
| `/ctf.misc` | Encoding chains, esoteric languages |

### Directory Structure

```
your-ctf-repo/
├── .ctf-kit.yaml                    # Optional: root config
└── competitions/
    └── some-ctf-2025/
        ├── .competition.yaml        # Optional: competition config
        └── challenge-name/
            ├── [your files]         # Challenge files (untouched)
            └── .ctf/                # CTF Kit workspace
                ├── config.yaml      # Challenge metadata
                └── memory/
                    ├── analysis.md  # Challenge analysis
                    ├── approach.md  # Solution strategy
                    ├── attempts.md  # Attempt log
                    └── writeup.md   # Final writeup
```

### Examples

```bash
# Typical competition flow
cd ~/ctf-repo/competitions
mkdir newctf-2025 && cd newctf-2025

# First challenge
mkdir crypto-easy && cd crypto-easy
# ... download challenge files ...
ctf here
# Launch AI agent, use /ctf.analyze, /ctf.crypto, etc.
ctf flag "flag{s0lv3d}"

# Next challenge
cd .. && mkdir web-hard && cd web-hard
ctf here
# ... solve ...

# End of CTF
cd ..
ctf status --all
ctf writeups --format markdown
git add -A && git commit -m "NewCTF 2025 solutions"
```

---

## Implementation Phases

### Phase 1: Foundation (Weeks 1-2)
- [ ] CLI skeleton with `uv` packaging
- [ ] Basic project structure
- [ ] Agent configuration templates (Claude, Copilot, Gemini)
- [ ] Core workflow: `init`, `analyze`, `writeup`
- [ ] Analysis and writeup templates

### Phase 2: Core Skills (Weeks 3-5)
- [ ] **Crypto skill** - Classical ciphers, encoding detection
- [ ] **OSINT skill** - Basic web research, image analysis
- [ ] **Misc skill** - Encoding chains, basic programming

### Phase 3: Advanced Skills (Weeks 6-8)
- [ ] **Forensics skill** - File analysis, basic memory forensics
- [ ] **Web skill** - Vulnerability detection, request analysis
- [ ] **Stego skill** - Image and audio analysis

### Phase 4: Expert Skills (Weeks 9-12)
- [ ] **Pwn skill** - Binary analysis, exploit templates
- [ ] **Reversing skill** - Static analysis guidance
- [ ] Advanced forensics (memory, network, disk)

### Phase 5: Integrations (Weeks 13-16)
- [ ] Local tool wrappers (Wireshark, Volatility, etc.)
- [ ] Service integrations (Shodan, CyberChef, etc.)
- [ ] Cross-skill workflows

### Phase 6: Polish (Weeks 17-20)
- [ ] Documentation and examples
- [ ] Test suite with sample challenges
- [ ] Performance optimization
- [ ] Community feedback integration

---

## Open Questions & Considerations

### Technical Questions

1. **Offline Mode**: How to handle challenges without internet access?
   - Bundle essential tools and wordlists
   - Local CyberChef instance option

2. **File Safety**: How to safely analyze potentially malicious files?
   - Sandbox recommendations
   - Docker container option for analysis

3. **Large Files**: How to handle large memory dumps or disk images?
   - Streaming analysis
   - Chunk-based processing

4. **Binary Interaction**: How to integrate with debuggers like GDB?
   - pwntools integration
   - Remote debugging support

### Ethical Considerations

1. **Competition Integrity**: Clear guidelines against using during live CTFs
2. **Educational Focus**: Emphasis on learning over automation
3. **Responsible Disclosure**: Guidance for real-world findings

### Community Features (Future)

1. **Challenge Database**: Store and share analyzed challenges
2. **Technique Library**: Community-contributed attack patterns
3. **Writeup Repository**: Searchable solution archive

---

## Comparison: Skills by Category

| Aspect | Crypto | OSINT | Forensics | Web | Pwn | Reverse | Stego |
|--------|--------|-------|-----------|-----|-----|---------|-------|
| **AI Value** | Very High | Very High | High | High | Medium | Medium | High |
| **Tool Deps** | Medium | Medium | High | Medium | Very High | Very High | Medium |
| **Automation** | High | Medium | Medium | Medium | Low | Low | Medium |
| **Skill Size** | Large | Medium | Large | Large | Large | Large | Medium |
| **Learning Curve** | Medium | Low | High | Medium | Very High | Very High | Low |

---

## Next Steps

1. **Validate architecture** with sample implementation
2. **Prioritize skills** based on AI suitability and demand
3. **Define tool requirements** and installation scripts
4. **Create sample challenges** for testing each skill
5. **Gather feedback** from CTF community

---

## Appendix: Tool Installation Scripts

### Ubuntu/Debian Quick Install

```bash
#!/bin/bash
# ctf-tools-install.sh

# Essential tools
sudo apt update
sudo apt install -y \
    file binwalk foremost exiftool \
    tshark wireshark \
    python3 python3-pip \
    gdb radare2 \
    hashcat john \
    steghide

# Python tools
pip3 install pwntools volatility3 z3-solver pycryptodome

# Ruby tools (stego)
gem install zsteg
```

### Tool Verification Script

```python
#!/usr/bin/env python3
# check_tools.py

TOOLS = {
    'essential': ['file', 'strings', 'python3', 'tshark'],
    'crypto': ['openssl', 'hashcat', 'john'],
    'forensics': ['binwalk', 'foremost', 'volatility3', 'exiftool'],
    'web': ['gobuster', 'nikto', 'sqlmap'],
    'pwn': ['gdb', 'objdump', 'ropper'],
    'reverse': ['radare2', 'objdump'],
    'stego': ['zsteg', 'steghide', 'exiftool'],
}

def check_tool(name):
    """Check if tool is installed and return version"""
    # Implementation
    pass
```

---

*This document serves as the foundation for CTF Kit development and will be updated as the project evolves.*
