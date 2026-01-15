# CTF Kit - Skills Deep Dive Analysis

> Detailed comparison of skill requirements across CTF categories

---

## Executive Summary

This document analyzes the specific requirements for building AI-assisted skills for different CTF challenge categories. The key insight is that **different categories require fundamentally different AI interaction patterns**:

| Pattern | Categories | Characteristics |
|---------|------------|-----------------|
| **Knowledge-Heavy** | Crypto, OSINT, Misc | AI provides analysis, patterns, techniques |
| **Tool-Heavy** | Forensics, Stego | AI orchestrates external tools |
| **Code-Heavy** | Pwn, Web | AI generates exploit code |
| **Hybrid** | Reversing | AI guides, tools execute |

---

## Category Deep Dives

### 🔐 Cryptography: The Pattern Recognition Powerhouse

**Why AI excels here:**
- Cipher identification from statistical properties
- Mathematical relationship detection
- Vulnerability pattern matching in RSA/AES
- Encoding chain recognition

**Skill Architecture:**
```
/ctf.crypto
├── analyze      # Identify cipher type, encoding
├── classical    # Caesar, Vigenère, substitution attacks
├── modern       # RSA, AES, DH vulnerability detection
├── hash         # Hash identification, cracking guidance
└── decode       # Multi-layer decode chains
```

**Example AI Value:**
```
Input: "Guvf vf n frperg zrffntr"

AI Analysis:
→ Statistical analysis: letter frequencies match English
→ Pattern: "Guvf" (4 letters) could be "This" or "That"
→ Hypothesis: ROT13 cipher (self-reciprocal)
→ Decode attempt: "This is a secret message"
→ Confidence: 95%
```

**Key Knowledge the Skill Needs:**
- Cipher fingerprints (index of coincidence, frequency patterns)
- RSA vulnerability catalog (30+ attack types)
- Common encoding patterns (Base64 padding, hex patterns)
- Mathematical libraries for number theory

**Tool Dependencies:** Low
- Python with pycryptodome, gmpy2
- SageMath for advanced math
- CyberChef (can run locally)

---

### 🔍 OSINT: The Research Orchestrator

**Why AI excels here:**
- Web research and information correlation
- Pattern recognition in images (landmarks, text)
- Username/identity pivot strategies
- Timeline construction from scattered data

**Skill Architecture:**
```
/ctf.osint
├── analyze      # Analyze given info, suggest pivots
├── image        # EXIF extraction, reverse image search guidance
├── username     # Cross-platform username investigation
├── domain       # Domain/IP reconnaissance
├── timeline     # Construct timeline from evidence
└── archive      # Wayback Machine, web archive research
```

**Example AI Value:**
```
Input: Image of a street scene

AI Analysis:
→ EXIF data: None (stripped)
→ Visual clues detected:
  - Street sign: "Via Roma" (Italian)
  - Store name: "Farmacia"
  - Architecture: Mediterranean style
  - Sun position: High angle (midday)
  - Shadows: Pointing North (Southern hemisphere? No, likely summer)
→ Pivot suggestions:
  1. Google Street View: "Via Roma" + visible landmarks
  2. Check for business names in image
  3. Estimate time from sun angle
```

**Integration with Services:**

| Service | Use Case | API Required |
|---------|----------|--------------|
| Google Maps | Street view, satellite | Optional |
| Shodan | IP/Infrastructure | Yes (free tier) |
| Wayback Machine | Historical pages | No |
| WHOIS | Domain info | No |
| Social platforms | Username search | Various |

**Service Integration Example:**
```python
# skills/osint/services/shodan_integration.py

class ShodanService:
    """Shodan API wrapper for infrastructure OSINT"""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('SHODAN_API_KEY')

    def analyze_ip(self, ip: str) -> dict:
        """Get detailed info about an IP address"""
        return {
            'ip': ip,
            'hostnames': [...],
            'ports': [...],
            'vulns': [...],
            'location': {...},
            'services': [...]
        }

    def search(self, query: str) -> list:
        """Run a Shodan search query"""
        # "apache country:US port:443"
```

---

### 🔬 Forensics: The Tool Orchestrator

**Why this category is different:**
The AI's primary role is **orchestrating tools** rather than performing analysis directly. The skill must know:
1. Which tool to use when
2. How to interpret tool output
3. How to chain tool outputs together

**Skill Architecture:**
```
/ctf.forensics
├── analyze      # File type detection, tool recommendation
├── memory       # Memory dump analysis (Volatility 3)
├── network      # PCAP analysis (Wireshark/tshark)
├── disk         # Disk image analysis (sleuthkit)
├── carve        # File carving (binwalk, foremost)
└── timeline     # Event timeline construction
```

**Wireshark Integration Deep Dive:**

```python
# integrations/local/wireshark.py

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Optional

class WiresharkIntegration:
    """
    Wireshark/tshark integration for network forensics.
    Uses tshark (CLI) for programmatic access.
    """

    def __init__(self):
        self.tshark_path = self._find_tshark()

    def _find_tshark(self) -> str:
        """Locate tshark binary"""
        # Check common locations
        for path in ['/usr/bin/tshark', '/usr/local/bin/tshark']:
            if Path(path).exists():
                return path
        raise ToolNotFoundError("tshark not found. Install with: apt install tshark")

    def get_protocol_hierarchy(self, pcap_file: Path) -> Dict:
        """Get protocol statistics from PCAP"""
        cmd = [
            self.tshark_path, '-r', str(pcap_file),
            '-z', 'io,phs', '-q'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return self._parse_protocol_hierarchy(result.stdout)

    def extract_http_objects(self, pcap_file: Path, output_dir: Path) -> List[Path]:
        """Extract HTTP objects (files) from PCAP"""
        output_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            self.tshark_path, '-r', str(pcap_file),
            '--export-objects', f'http,{output_dir}'
        ]
        subprocess.run(cmd)
        return list(output_dir.iterdir())

    def follow_tcp_stream(self, pcap_file: Path, stream_index: int) -> str:
        """Follow and extract a TCP stream"""
        cmd = [
            self.tshark_path, '-r', str(pcap_file),
            '-z', f'follow,tcp,ascii,{stream_index}', '-q'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout

    def extract_credentials(self, pcap_file: Path) -> List[Dict]:
        """Extract potential credentials from various protocols"""
        credentials = []

        # HTTP Basic Auth
        cmd = [
            self.tshark_path, '-r', str(pcap_file),
            '-Y', 'http.authorization',
            '-T', 'fields', '-e', 'http.authorization'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        for line in result.stdout.strip().split('\n'):
            if line.startswith('Basic '):
                credentials.append({
                    'protocol': 'HTTP Basic',
                    'data': line
                })

        # FTP credentials
        cmd = [
            self.tshark_path, '-r', str(pcap_file),
            '-Y', 'ftp.request.command == "USER" || ftp.request.command == "PASS"',
            '-T', 'fields', '-e', 'ftp.request.command', '-e', 'ftp.request.arg'
        ]
        # ... parse FTP creds

        return credentials

    def get_conversations(self, pcap_file: Path) -> List[Dict]:
        """Get TCP/UDP conversation statistics"""
        cmd = [
            self.tshark_path, '-r', str(pcap_file),
            '-z', 'conv,tcp', '-q'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return self._parse_conversations(result.stdout)

    def filter_packets(self, pcap_file: Path, display_filter: str) -> str:
        """Apply a display filter and return matching packets"""
        cmd = [
            self.tshark_path, '-r', str(pcap_file),
            '-Y', display_filter
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout

    def export_specific_fields(
        self,
        pcap_file: Path,
        display_filter: str,
        fields: List[str]
    ) -> List[Dict]:
        """Export specific fields from filtered packets"""
        field_args = []
        for field in fields:
            field_args.extend(['-e', field])

        cmd = [
            self.tshark_path, '-r', str(pcap_file),
            '-Y', display_filter,
            '-T', 'fields'
        ] + field_args

        result = subprocess.run(cmd, capture_output=True, text=True)
        # Parse tab-separated output
        return self._parse_field_output(result.stdout, fields)
```

**Volatility 3 Integration:**

```python
# integrations/local/volatility.py

class VolatilityIntegration:
    """Volatility 3 integration for memory forensics"""

    COMMON_PLUGINS = [
        'windows.info',
        'windows.pslist',
        'windows.pstree',
        'windows.cmdline',
        'windows.netscan',
        'windows.filescan',
        'windows.dumpfiles',
        'windows.hashdump',
        'linux.bash',
        'linux.pslist',
    ]

    def __init__(self):
        self._check_volatility()

    def analyze_memory(self, dump_file: Path) -> Dict:
        """Run initial memory analysis"""
        results = {
            'os_info': self._run_plugin(dump_file, 'windows.info'),
            'processes': self._run_plugin(dump_file, 'windows.pslist'),
            'network': self._run_plugin(dump_file, 'windows.netscan'),
        }
        return results

    def find_suspicious_processes(self, dump_file: Path) -> List[Dict]:
        """Identify potentially suspicious processes"""
        processes = self._run_plugin(dump_file, 'windows.pslist')
        suspicious = []

        # Check for known suspicious indicators
        suspicious_names = ['mimikatz', 'pwdump', 'procdump', 'nc.exe']
        hidden_processes = self._find_hidden_processes(dump_file)

        return suspicious

    def extract_strings(self, dump_file: Path, pid: int = None) -> str:
        """Extract strings from memory"""
        if pid:
            # Dump specific process memory first
            pass
        # Run strings on dump
```

**Tool Orchestration Pattern:**

```
User: "Analyze this memory dump"
                │
                ▼
┌───────────────────────────────────────┐
│         AI Orchestrator               │
│                                       │
│  1. Identify dump type                │
│  2. Select appropriate tools          │
│  3. Run tools in sequence             │
│  4. Correlate outputs                 │
│  5. Report findings                   │
└───────────────────────────────────────┘
                │
    ┌───────────┼───────────┐
    ▼           ▼           ▼
┌───────┐  ┌───────┐  ┌───────┐
│ file  │  │ vol3  │  │strings│
└───────┘  └───────┘  └───────┘
    │           │           │
    └───────────┴───────────┘
                │
                ▼
        Correlated Report
```

---

### 🌐 Web: The Vulnerability Scanner

**Why AI excels here:**
- Pattern recognition in responses
- Payload generation and mutation
- Authentication flow analysis
- Request/response correlation

**Skill Architecture:**
```
/ctf.web
├── analyze      # Fingerprint technology, identify endpoints
├── recon        # Directory enumeration, tech detection
├── sqli         # SQL injection testing and exploitation
├── xss          # XSS detection and payload crafting
├── auth         # Authentication mechanism analysis
├── api          # API endpoint discovery and testing
└── ssrf         # SSRF detection and exploitation
```

**Example Workflow:**
```
/ctf.web analyze https://target.ctf

AI Analysis:
→ Technology: PHP 7.4, Apache, MySQL
→ Endpoints found: /login, /admin, /api/v1/users
→ Potential vulnerabilities:
  - /login: No CSRF token, possible brute force
  - /api/v1/users: No authentication required?
→ Suggested tests:
  1. SQL injection on login form
  2. API endpoint enumeration
  3. Directory bruteforce
```

---

### 💥 Pwn: The Exploit Generator

**Why this is challenging for AI:**
- Requires precise binary understanding
- Exploit development needs exact offsets
- Heavy reliance on debugging tools
- Memory layouts vary

**AI Role:** Assist rather than automate
- Identify vulnerability type
- Generate exploit templates
- Suggest gadgets and techniques
- Explain exploit concepts

**Skill Architecture:**
```
/ctf.pwn
├── analyze      # checksec, identify protections
├── overflow     # Buffer overflow analysis
├── rop          # ROP chain assistance
├── format       # Format string exploitation
├── heap         # Heap exploitation guidance
└── template     # Generate pwntools template
```

**Integration with pwntools:**

```python
# skills/pwn/templates/exploit_template.py

EXPLOIT_TEMPLATE = '''
#!/usr/bin/env python3
from pwn import *

# Configuration
BINARY = "{binary_path}"
HOST = "{host}"
PORT = {port}
LIBC = "{libc_path}"  # Optional

# Setup
context.binary = elf = ELF(BINARY)
context.log_level = 'debug'

{libc_setup}

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    elif args.GDB:
        return gdb.debug(BINARY, """
            {gdb_script}
        """)
    else:
        return process(BINARY)

def exploit():
    io = conn()

    # === EXPLOIT CODE HERE ===
    {exploit_code}
    # =========================

    io.interactive()

if __name__ == "__main__":
    exploit()
'''

class PwnTemplateGenerator:
    """Generate pwntools exploit templates"""

    def generate(
        self,
        binary_path: str,
        vulnerability_type: str,
        protections: Dict,
        offset: int = None
    ) -> str:
        """Generate exploit template based on analysis"""

        if vulnerability_type == "buffer_overflow":
            return self._generate_bof_template(binary_path, protections, offset)
        elif vulnerability_type == "format_string":
            return self._generate_fmt_template(binary_path, protections)
        # ...
```

---

### 🔄 Reversing: The Guided Explorer

**AI Role:** Guide analysis, explain code patterns
- Identify interesting functions
- Explain decompiled code
- Recognize common algorithms
- Suggest debugging strategies

**Integration Challenge:**
Reversing tools (Ghidra, IDA) are GUI-heavy. Solutions:
1. Ghidra headless mode for scripting
2. radare2 CLI interface
3. Binary Ninja API

**Ghidra Headless Integration:**

```python
# integrations/local/ghidra.py

class GhidraIntegration:
    """Ghidra headless mode integration"""

    def __init__(self, ghidra_path: str = None):
        self.ghidra_path = ghidra_path or self._find_ghidra()
        self.project_dir = Path.home() / '.ctf-kit' / 'ghidra_projects'

    def analyze_binary(self, binary_path: Path) -> Dict:
        """Run Ghidra analysis and extract info"""
        script = self._create_analysis_script()

        cmd = [
            f"{self.ghidra_path}/support/analyzeHeadless",
            str(self.project_dir),
            "CTFProject",
            "-import", str(binary_path),
            "-postScript", str(script),
            "-deleteProject"  # Clean up after
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        return self._parse_analysis_output(result.stdout)

    def decompile_function(self, binary_path: Path, function_name: str) -> str:
        """Decompile a specific function"""
        script = self._create_decompile_script(function_name)
        # Run headless with decompile script

    def list_functions(self, binary_path: Path) -> List[Dict]:
        """List all functions in binary"""
```

---

### 🖼️ Steganography: The Hidden Data Finder

**Why AI excels here:**
- Recognizing stego indicators
- Knowing which tools to try
- Interpreting tool output
- Multi-layer detection

**Skill Architecture:**
```
/ctf.stego
├── analyze      # Detect potential stego
├── image        # Image-specific analysis
├── audio        # Audio-specific analysis
├── lsb          # LSB extraction attempts
└── extract      # Try multiple extraction methods
```

**Tool Chain Example:**

```python
# skills/stego/analyzer.py

class StegoAnalyzer:
    """Analyze files for steganography"""

    IMAGE_TOOLS = ['exiftool', 'zsteg', 'steghide', 'stegsolve', 'binwalk']
    AUDIO_TOOLS = ['exiftool', 'sonic-visualizer', 'deepsound']

    def analyze_image(self, image_path: Path) -> Dict:
        """Run multiple stego detection tools on image"""
        results = {
            'metadata': self._run_exiftool(image_path),
            'zsteg': self._run_zsteg(image_path),
            'binwalk': self._run_binwalk(image_path),
            'strings': self._extract_strings(image_path),
            'anomalies': self._detect_anomalies(image_path),
        }
        return results

    def _run_zsteg(self, image_path: Path) -> Dict:
        """Run zsteg for LSB analysis"""
        if image_path.suffix.lower() != '.png':
            return {'error': 'zsteg only works with PNG files'}

        cmd = ['zsteg', '-a', str(image_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return self._parse_zsteg_output(result.stdout)

    def _detect_anomalies(self, image_path: Path) -> List[str]:
        """Detect visual/structural anomalies"""
        anomalies = []

        # Check file size vs dimensions
        # Check for appended data
        # Check color histogram
        # Check LSB plane

        return anomalies
```

---

## Skill Comparison Matrix

| Feature | Crypto | OSINT | Forensics | Web | Pwn | Reverse | Stego |
|---------|--------|-------|-----------|-----|-----|---------|-------|
| **AI provides solutions** | ✅ | ✅ | ⚠️ | ⚠️ | ❌ | ❌ | ⚠️ |
| **AI orchestrates tools** | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **AI generates code** | ✅ | ❌ | ⚠️ | ✅ | ✅ | ⚠️ | ❌ |
| **Requires local tools** | ⚠️ | ⚠️ | ✅ | ⚠️ | ✅ | ✅ | ✅ |
| **Requires services** | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Human verification** | Low | Medium | Medium | High | High | High | Medium |

Legend: ✅ Primary role | ⚠️ Secondary role | ❌ Not applicable

---

## Recommended Implementation Order

Based on AI suitability and skill complexity:

### Tier 1: Start Here (Highest ROI)
1. **Crypto** - Highest AI value, moderate tool dependency
2. **Misc** - High AI value, low tool dependency
3. **OSINT** - High AI value, service integration showcase

### Tier 2: Core Expansion
4. **Stego** - Good AI value, clear tool integration pattern
5. **Web** - High demand, good AI value for reconnaissance
6. **Forensics** - Complex but valuable tool orchestration example

### Tier 3: Advanced
7. **Reversing** - Complex tool integration, lower AI autonomy
8. **Pwn** - Most complex, requires deep binary analysis

---

## Integration Architecture Summary

```
┌────────────────────────────────────────────────────────────────────┐
│                         CTF Kit Architecture                        │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                      AI Agent Layer                          │  │
│  │  Claude / Copilot / Gemini / Cursor / etc.                  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                              │                                     │
│                              ▼                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                      Skills Layer                            │  │
│  │  /ctf.crypto  /ctf.osint  /ctf.forensics  /ctf.web  ...    │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                              │                                     │
│          ┌───────────────────┼───────────────────┐                 │
│          ▼                   ▼                   ▼                 │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐           │
│  │ Local Tools  │   │  Services    │   │   Scripts    │           │
│  │              │   │              │   │              │           │
│  │ • tshark     │   │ • Shodan     │   │ • Python     │           │
│  │ • volatility │   │ • VirusTotal │   │ • pwntools   │           │
│  │ • binwalk    │   │ • Wayback    │   │ • Custom     │           │
│  │ • zsteg      │   │ • CyberChef  │   │              │           │
│  │ • radare2    │   │              │   │              │           │
│  └──────────────┘   └──────────────┘   └──────────────┘           │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

---

*This analysis should guide the development of skills with appropriate AI interaction patterns for each category.*
