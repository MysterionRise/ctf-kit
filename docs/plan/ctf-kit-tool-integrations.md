# CTF Kit - Comprehensive Tool Integration Plan

> Detailed integration specifications for 50+ CTF tools across all categories

---

## Table of Contents

1. [Integration Philosophy](#integration-philosophy)
2. [Tool Integration Framework](#tool-integration-framework)
3. [Cryptography Tools](#cryptography-tools)
4. [Archive & Password Cracking Tools](#archive--password-cracking-tools)
5. [Forensics Tools](#forensics-tools)
6. [Network Analysis Tools](#network-analysis-tools)
7. [Steganography Tools](#steganography-tools)
8. [Web Exploitation Tools](#web-exploitation-tools)
9. [Binary Exploitation Tools](#binary-exploitation-tools)
10. [Reverse Engineering Tools](#reverse-engineering-tools)
11. [OSINT Tools](#osint-tools)
12. [Encoding & Utility Tools](#encoding--utility-tools)
13. [Installation & Dependency Management](#installation--dependency-management)
14. [Tool Orchestration Patterns](#tool-orchestration-patterns)

---

## Integration Philosophy

### Design Principles

1. **Wrapper Consistency**: All tools share a common interface
2. **Output Parsing**: Structured output from every tool
3. **Error Handling**: Graceful degradation when tools fail
4. **Chaining Support**: Tools can feed into each other
5. **Progress Reporting**: Long-running tools report status
6. **Caching**: Avoid re-running expensive operations

### Integration Levels

| Level | Description | Example |
|-------|-------------|---------|
| **L1: Basic** | Simple CLI wrapper | `file`, `strings` |
| **L2: Parsed** | Output parsing to structured data | `binwalk`, `exiftool` |
| **L3: Interactive** | Multi-step interaction | `john`, `hashcat` |
| **L4: Orchestrated** | AI-guided tool sequences | `volatility` workflows |

---

## Tool Integration Framework

### Base Classes

```python
# integrations/base.py

from abc import ABC, abstractmethod
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional, Union
from enum import Enum
import subprocess
import shutil
import json

class ToolStatus(Enum):
    NOT_INSTALLED = "not_installed"
    INSTALLED = "installed"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class ToolResult:
    """Standard result format for all tool operations"""
    success: bool
    tool_name: str
    command: str
    stdout: str
    stderr: str
    parsed_data: Optional[Dict] = None
    artifacts: Optional[List[Path]] = None
    suggestions: Optional[List[str]] = None
    error_message: Optional[str] = None
    execution_time: float = 0.0

class BaseTool(ABC):
    """Base class for all tool integrations"""

    name: str = "base_tool"
    description: str = ""
    category: str = "misc"
    install_commands: Dict[str, str] = {}  # OS -> command
    binary_names: List[str] = []  # Possible binary names

    def __init__(self):
        self.binary_path = self._find_binary()

    def _find_binary(self) -> Optional[str]:
        """Locate the tool binary"""
        for name in self.binary_names:
            path = shutil.which(name)
            if path:
                return path
        return None

    @property
    def is_installed(self) -> bool:
        return self.binary_path is not None

    def get_version(self) -> Optional[str]:
        """Get tool version"""
        if not self.is_installed:
            return None
        try:
            result = subprocess.run(
                [self.binary_path, "--version"],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip() or result.stderr.strip()
        except:
            return "unknown"

    def get_install_instructions(self) -> str:
        """Get installation instructions for current OS"""
        import platform
        system = platform.system().lower()
        if system in self.install_commands:
            return self.install_commands[system]
        return f"Please install {self.name} manually"

    def _run(
        self,
        args: List[str],
        timeout: int = 300,
        input_data: str = None
    ) -> subprocess.CompletedProcess:
        """Execute tool with arguments"""
        cmd = [self.binary_path] + args
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data
        )

    @abstractmethod
    def run(self, *args, **kwargs) -> ToolResult:
        """Main entry point - implement in subclasses"""
        pass

    @abstractmethod
    def parse_output(self, stdout: str, stderr: str) -> Dict:
        """Parse tool output into structured data"""
        pass


class ToolChain:
    """Chain multiple tools together"""

    def __init__(self, tools: List[BaseTool]):
        self.tools = tools
        self.results: List[ToolResult] = []

    def run(self, initial_input: Path) -> List[ToolResult]:
        """Run tools in sequence, passing outputs forward"""
        current_input = initial_input

        for tool in self.tools:
            result = tool.run(current_input)
            self.results.append(result)

            if not result.success:
                break

            # Use artifacts as next input if available
            if result.artifacts:
                current_input = result.artifacts[0]

        return self.results
```

---

## Cryptography Tools

### 1. XORTool - XOR Cipher Analysis

**Purpose**: Analyze XOR-encrypted data, find key length and key

```python
# integrations/crypto/xortool.py

class XORToolIntegration(BaseTool):
    """
    xortool - XOR cipher analysis tool
    https://github.com/hellman/xortool
    """

    name = "xortool"
    description = "Analyze XOR-encrypted files to find key length and key"
    category = "crypto"
    binary_names = ["xortool"]
    install_commands = {
        "linux": "pip install xortool",
        "darwin": "pip install xortool",
        "windows": "pip install xortool"
    }

    def analyze_key_length(
        self,
        file_path: Path,
        max_key_length: int = 65
    ) -> ToolResult:
        """Analyze file to determine probable XOR key length"""
        args = [
            str(file_path),
            "-l", str(max_key_length),
            "-c", "20"  # Show top 20 key lengths
        ]

        result = self._run(args)
        parsed = self.parse_key_length_output(result.stdout)

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"xortool {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=parsed,
            suggestions=self._generate_suggestions(parsed)
        )

    def decrypt_with_char(
        self,
        file_path: Path,
        most_frequent_char: str = " ",
        key_length: int = None
    ) -> ToolResult:
        """
        Attempt decryption assuming most frequent plaintext character.
        Common choices: ' ' (space) for text, '\x00' for binary
        """
        args = [str(file_path), "-c", most_frequent_char]

        if key_length:
            args.extend(["-l", str(key_length)])
        else:
            args.append("-b")  # Brute-force key length

        result = self._run(args)

        # xortool creates output files
        output_dir = Path("xortool_out")
        artifacts = list(output_dir.glob("*")) if output_dir.exists() else []

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"xortool {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_decrypt_output(result.stdout),
            artifacts=artifacts
        )

    def decrypt_with_known_key(
        self,
        file_path: Path,
        key: bytes
    ) -> ToolResult:
        """Decrypt file with known XOR key using xortool-xor"""
        # xortool-xor is a companion tool
        args = ["-r", key.hex(), "-f", str(file_path)]

        result = subprocess.run(
            ["xortool-xor"] + args,
            capture_output=True
        )

        return ToolResult(
            success=result.returncode == 0,
            tool_name="xortool-xor",
            command=f"xortool-xor {' '.join(args)}",
            stdout=result.stdout.decode('latin-1'),
            stderr=result.stderr.decode('latin-1'),
            parsed_data={"decrypted": result.stdout}
        )

    def parse_key_length_output(self, stdout: str) -> Dict:
        """Parse xortool key length analysis output"""
        results = {
            "probable_key_lengths": [],
            "fitness_scores": {}
        }

        for line in stdout.split('\n'):
            # Parse "Key length: N, fitness: X.XX"
            if "Key length:" in line:
                import re
                match = re.search(r'Key length:\s*(\d+).*fitness:\s*([\d.]+)', line)
                if match:
                    length = int(match.group(1))
                    fitness = float(match.group(2))
                    results["probable_key_lengths"].append(length)
                    results["fitness_scores"][length] = fitness

        return results

    def parse_decrypt_output(self, stdout: str) -> Dict:
        """Parse xortool decryption output"""
        results = {
            "key_found": None,
            "key_hex": None,
            "output_files": []
        }

        for line in stdout.split('\n'):
            if "Key:" in line:
                # Extract key
                key_part = line.split("Key:")[-1].strip()
                results["key_found"] = key_part
                results["key_hex"] = key_part.encode().hex()

        return results

    def _generate_suggestions(self, parsed_data: Dict) -> List[str]:
        """Generate next-step suggestions based on analysis"""
        suggestions = []

        if parsed_data.get("probable_key_lengths"):
            top_length = parsed_data["probable_key_lengths"][0]
            suggestions.append(
                f"Try decryption with key length {top_length}: "
                f"xortool file -l {top_length} -c ' '"
            )
            suggestions.append(
                "If plaintext is binary, try: xortool file -c '\\x00'"
            )

        return suggestions
```

### 2. RsaCtfTool - RSA Attack Toolkit

**Purpose**: Automated RSA vulnerability exploitation

```python
# integrations/crypto/rsactftool.py

class RsaCtfToolIntegration(BaseTool):
    """
    RsaCtfTool - RSA attack toolkit
    https://github.com/RsaCtfTool/RsaCtfTool
    """

    name = "RsaCtfTool"
    description = "Automated RSA attacks (40+ attack types)"
    category = "crypto"
    binary_names = ["RsaCtfTool", "rsactftool"]
    install_commands = {
        "linux": "git clone https://github.com/RsaCtfTool/RsaCtfTool && cd RsaCtfTool && pip install -r requirements.txt",
        "darwin": "git clone https://github.com/RsaCtfTool/RsaCtfTool && pip install -r requirements.txt"
    }

    # Available attack types
    ATTACKS = [
        "wiener", "hastads", "factordb", "noveltyprimes", "smallq",
        "fermat", "pollard_p_1", "pollard_rho", "williams_p_1",
        "comfact", "cube_root", "boneh_durfee", "small_crt_exp",
        "common_factors", "same_n_huge_e", "partial_d", "londahl",
        "SQUFOF", "qicheng", "ecm", "ecm2", "mersenne_primes",
        "siqs", "smallfraction", "binary_polinomial_factoring",
        "euler", "roca", "nsif", "z3_solver", "dixon", "kraitchik"
    ]

    def attack_public_key(
        self,
        pubkey_path: Path = None,
        n: int = None,
        e: int = None,
        attacks: List[str] = None,
        ciphertext: bytes = None
    ) -> ToolResult:
        """
        Run RSA attacks against a public key.
        Can provide either pubkey file or n,e directly.
        """
        args = []

        if pubkey_path:
            args.extend(["--publickey", str(pubkey_path)])
        elif n and e:
            args.extend(["-n", str(n), "-e", str(e)])
        else:
            raise ValueError("Must provide either pubkey_path or (n, e)")

        if attacks:
            args.extend(["--attack", ",".join(attacks)])
        else:
            args.append("--attackall")

        if ciphertext:
            # Write ciphertext to temp file
            ct_file = Path("/tmp/ct.bin")
            ct_file.write_bytes(ciphertext)
            args.extend(["--uncipher", str(ct_file)])

        args.append("--private")  # Output private key if found

        result = self._run(args, timeout=600)  # RSA attacks can be slow

        return ToolResult(
            success="d=" in result.stdout or "Private key" in result.stdout,
            tool_name=self.name,
            command=f"RsaCtfTool {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_output(result.stdout, result.stderr)
        )

    def attack_specific(
        self,
        attack_name: str,
        **kwargs
    ) -> ToolResult:
        """Run a specific RSA attack"""
        if attack_name not in self.ATTACKS:
            return ToolResult(
                success=False,
                tool_name=self.name,
                command="",
                stdout="",
                stderr="",
                error_message=f"Unknown attack: {attack_name}. Available: {self.ATTACKS}"
            )

        kwargs['attacks'] = [attack_name]
        return self.attack_public_key(**kwargs)

    def factor_n(self, n: int) -> ToolResult:
        """Attempt to factor modulus N"""
        args = ["-n", str(n), "--attack", "factordb,ecm,siqs", "--timeout", "120"]
        result = self._run(args, timeout=180)

        parsed = self.parse_output(result.stdout, result.stderr)

        return ToolResult(
            success=parsed.get("p") is not None,
            tool_name=self.name,
            command=f"RsaCtfTool {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=parsed
        )

    def parse_output(self, stdout: str, stderr: str) -> Dict:
        """Parse RsaCtfTool output"""
        import re

        results = {
            "p": None,
            "q": None,
            "d": None,
            "phi": None,
            "plaintext": None,
            "attack_used": None
        }

        patterns = {
            "p": r'p\s*=\s*(\d+)',
            "q": r'q\s*=\s*(\d+)',
            "d": r'd\s*=\s*(\d+)',
            "phi": r'phi\s*=\s*(\d+)'
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, stdout)
            if match:
                results[key] = int(match.group(1))

        # Check for decrypted plaintext
        if "Decrypted" in stdout or "Plain" in stdout:
            # Extract plaintext
            pt_match = re.search(r'(?:Plain|Decrypted).*?:\s*(.+)', stdout)
            if pt_match:
                results["plaintext"] = pt_match.group(1)

        # Identify which attack succeeded
        for attack in self.ATTACKS:
            if f"Attack: {attack}" in stdout and results["d"]:
                results["attack_used"] = attack
                break

        return results
```

### 3. SageMath Integration

**Purpose**: Advanced mathematical computations for crypto

```python
# integrations/crypto/sage.py

class SageMathIntegration(BaseTool):
    """
    SageMath - Mathematical software system
    Used for advanced crypto attacks requiring number theory
    """

    name = "sage"
    description = "Advanced mathematical computations"
    category = "crypto"
    binary_names = ["sage", "sagemath"]
    install_commands = {
        "linux": "sudo apt install sagemath",
        "darwin": "brew install --cask sage"
    }

    def run_script(self, script: str) -> ToolResult:
        """Run a SageMath script"""
        result = self._run(["--python", "-c", script])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"sage -c '{script[:50]}...'",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data={"output": result.stdout}
        )

    def factor_large_number(self, n: int) -> ToolResult:
        """Factor a large number using Sage's algorithms"""
        script = f"""
from sage.all import *
n = {n}
factors = factor(n)
print(list(factors))
"""
        return self.run_script(script)

    def solve_discrete_log(
        self,
        g: int,
        h: int,
        p: int,
        algorithm: str = "pohlig_hellman"
    ) -> ToolResult:
        """Solve discrete logarithm: find x where g^x = h (mod p)"""
        script = f"""
from sage.all import *
F = GF({p})
g = F({g})
h = F({h})
x = discrete_log(h, g)
print(x)
"""
        return self.run_script(script)

    def coppersmith_attack(
        self,
        n: int,
        e: int,
        known_high_bits: int,
        unknown_bits: int
    ) -> ToolResult:
        """
        Coppersmith's attack for partial key exposure
        Useful when you know part of the plaintext/key
        """
        script = f"""
from sage.all import *
n = {n}
e = {e}
known = {known_high_bits}
X = 2**{unknown_bits}

P.<x> = PolynomialRing(Zmod(n))
f = (known + x)^e - c
roots = f.small_roots(X=X, beta=0.5)
print(list(roots))
"""
        return self.run_script(script)

    def lattice_attack(
        self,
        params: Dict
    ) -> ToolResult:
        """Generic lattice-based attack (LLL algorithm)"""
        # Build lattice and run LLL
        pass
```

### 4. Hash Analysis Tools

```python
# integrations/crypto/hash_tools.py

class HashIDIntegration(BaseTool):
    """hashid - Hash identification tool"""

    name = "hashid"
    description = "Identify hash types"
    category = "crypto"
    binary_names = ["hashid"]
    install_commands = {"linux": "pip install hashid"}

    def identify(self, hash_string: str) -> ToolResult:
        """Identify the type of a hash"""
        result = self._run([hash_string])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"hashid {hash_string}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_output(result.stdout, result.stderr)
        )

    def parse_output(self, stdout: str, stderr: str) -> Dict:
        """Parse hashid output"""
        hash_types = []
        for line in stdout.split('\n'):
            if '[+]' in line:
                hash_type = line.split('[+]')[-1].strip()
                hash_types.append(hash_type)

        return {
            "possible_types": hash_types,
            "most_likely": hash_types[0] if hash_types else None
        }


class HashcatIntegration(BaseTool):
    """hashcat - Advanced password recovery"""

    name = "hashcat"
    description = "GPU-accelerated hash cracking"
    category = "crypto"
    binary_names = ["hashcat", "hashcat64.bin"]
    install_commands = {
        "linux": "sudo apt install hashcat",
        "darwin": "brew install hashcat"
    }

    # Common hash modes
    HASH_MODES = {
        "md5": 0,
        "sha1": 100,
        "sha256": 1400,
        "sha512": 1700,
        "bcrypt": 3200,
        "ntlm": 1000,
        "mysql": 300,
        "md5crypt": 500,
        "sha512crypt": 1800,
        "wpa": 22000,
        "kerberos_tgs": 13100,
        "jwt": 16500,
    }

    def crack(
        self,
        hash_file: Path,
        hash_mode: Union[int, str],
        attack_mode: int = 0,  # 0=dict, 1=combo, 3=bruteforce, 6=hybrid
        wordlist: Path = None,
        rules: Path = None,
        mask: str = None,
        output_file: Path = None
    ) -> ToolResult:
        """
        Run hashcat attack.

        Attack modes:
        - 0: Straight (dictionary)
        - 1: Combination
        - 3: Brute-force
        - 6: Hybrid wordlist + mask
        - 7: Hybrid mask + wordlist
        """
        if isinstance(hash_mode, str):
            hash_mode = self.HASH_MODES.get(hash_mode, hash_mode)

        args = [
            "-m", str(hash_mode),
            "-a", str(attack_mode),
            str(hash_file)
        ]

        if attack_mode == 0 and wordlist:
            args.append(str(wordlist))
        if attack_mode == 3 and mask:
            args.append(mask)
        if rules:
            args.extend(["-r", str(rules)])
        if output_file:
            args.extend(["-o", str(output_file)])

        args.append("--force")  # Ignore warnings

        result = self._run(args, timeout=3600)

        return ToolResult(
            success="Cracked" in result.stdout or result.returncode == 0,
            tool_name=self.name,
            command=f"hashcat {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_output(result.stdout, result.stderr)
        )

    def show_cracked(self, hash_file: Path, hash_mode: int) -> ToolResult:
        """Show previously cracked hashes from potfile"""
        args = ["-m", str(hash_mode), str(hash_file), "--show"]
        result = self._run(args)

        return ToolResult(
            success=True,
            tool_name=self.name,
            command=f"hashcat {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data={"cracked": result.stdout.strip().split('\n')}
        )

    def parse_output(self, stdout: str, stderr: str) -> Dict:
        """Parse hashcat output"""
        results = {
            "cracked_count": 0,
            "cracked_hashes": [],
            "status": "unknown"
        }

        for line in stdout.split('\n'):
            if "Recovered" in line:
                import re
                match = re.search(r'Recovered.*?(\d+)/(\d+)', line)
                if match:
                    results["cracked_count"] = int(match.group(1))
            if "Status" in line:
                results["status"] = line.split(":")[-1].strip()

        return results
```

---

## Archive & Password Cracking Tools

### 5. bkcrack - ZIP Known Plaintext Attack

**Purpose**: Crack encrypted ZIP files using known plaintext attack

```python
# integrations/archive/bkcrack.py

class BkcrackIntegration(BaseTool):
    """
    bkcrack - Crack legacy zip encryption with known plaintext attack
    https://github.com/kimci86/bkcrack
    """

    name = "bkcrack"
    description = "ZIP known plaintext attack (ZipCrypto)"
    category = "archive"
    binary_names = ["bkcrack"]
    install_commands = {
        "linux": "git clone https://github.com/kimci86/bkcrack && cd bkcrack && cmake -S . -B build && cmake --build build",
        "darwin": "brew install bkcrack"
    }

    def list_entries(self, zip_path: Path) -> ToolResult:
        """List entries in a ZIP file with encryption info"""
        args = ["-L", str(zip_path)]
        result = self._run(args)

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"bkcrack {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_list_output(result.stdout)
        )

    def attack_with_plaintext_file(
        self,
        cipher_zip: Path,
        cipher_entry: str,
        plain_file: Path,
        plain_offset: int = 0
    ) -> ToolResult:
        """
        Attack using a known plaintext file.

        Requirements:
        - At least 12 bytes of known plaintext
        - Plaintext must be contiguous
        - Must know offset in encrypted file
        """
        args = [
            "-C", str(cipher_zip),
            "-c", cipher_entry,
            "-P", str(plain_file),
            "-p", cipher_entry,  # plaintext entry name
        ]

        if plain_offset:
            args.extend(["-o", str(plain_offset)])

        result = self._run(args, timeout=7200)  # Can take hours

        return ToolResult(
            success="Keys" in result.stdout,
            tool_name=self.name,
            command=f"bkcrack {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_attack_output(result.stdout)
        )

    def attack_with_plaintext_bytes(
        self,
        cipher_zip: Path,
        cipher_entry: str,
        plaintext: bytes,
        offset: int = 0
    ) -> ToolResult:
        """
        Attack using known plaintext bytes.

        Common known plaintexts:
        - PNG header: 89 50 4E 47 0D 0A 1A 0A
        - JPEG header: FF D8 FF E0
        - PDF header: 25 50 44 46
        - PK (nested ZIP): 50 4B 03 04
        - XML: 3C 3F 78 6D 6C
        """
        # Write plaintext to temp file
        plain_file = Path("/tmp/known_plain.bin")
        plain_file.write_bytes(plaintext)

        args = [
            "-C", str(cipher_zip),
            "-c", cipher_entry,
            "-p", str(plain_file),
            "-o", str(offset)
        ]

        result = self._run(args, timeout=7200)

        return ToolResult(
            success="Keys" in result.stdout,
            tool_name=self.name,
            command=f"bkcrack {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_attack_output(result.stdout)
        )

    def decrypt_with_keys(
        self,
        cipher_zip: Path,
        keys: tuple,  # (key0, key1, key2)
        output_zip: Path
    ) -> ToolResult:
        """Decrypt ZIP using recovered internal keys"""
        args = [
            "-C", str(cipher_zip),
            "-k", hex(keys[0]), hex(keys[1]), hex(keys[2]),
            "-D", str(output_zip)
        ]

        result = self._run(args)

        return ToolResult(
            success=output_zip.exists(),
            tool_name=self.name,
            command=f"bkcrack {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            artifacts=[output_zip] if output_zip.exists() else []
        )

    def recover_password(
        self,
        keys: tuple,
        max_length: int = 10,
        charset: str = None
    ) -> ToolResult:
        """
        Attempt to recover original password from internal keys.
        Only works for short/simple passwords.
        """
        args = [
            "-k", hex(keys[0]), hex(keys[1]), hex(keys[2]),
            "-r", str(max_length)
        ]

        if charset:
            args.extend(["--charset", charset])
        else:
            args.append("?a")  # All printable ASCII

        result = self._run(args, timeout=3600)

        return ToolResult(
            success="Password" in result.stdout,
            tool_name=self.name,
            command=f"bkcrack {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_password_output(result.stdout)
        )

    def parse_list_output(self, stdout: str) -> Dict:
        """Parse ZIP entry listing"""
        entries = []
        for line in stdout.split('\n'):
            if line.strip() and not line.startswith('Index'):
                parts = line.split()
                if len(parts) >= 4:
                    entries.append({
                        "name": parts[-1],
                        "size": parts[1] if len(parts) > 1 else None,
                        "encrypted": "ZipCrypto" in line
                    })
        return {"entries": entries}

    def parse_attack_output(self, stdout: str) -> Dict:
        """Parse attack output for keys"""
        import re

        results = {"keys": None, "success": False}

        key_match = re.search(
            r'Keys:\s*([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)',
            stdout, re.IGNORECASE
        )
        if key_match:
            results["keys"] = (
                int(key_match.group(1), 16),
                int(key_match.group(2), 16),
                int(key_match.group(3), 16)
            )
            results["success"] = True

        return results

    def parse_password_output(self, stdout: str) -> Dict:
        """Parse password recovery output"""
        import re

        match = re.search(r'Password:\s*(.+)', stdout)
        return {
            "password": match.group(1) if match else None
        }

    # Common file headers for known plaintext attacks
    KNOWN_HEADERS = {
        "png": bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
                      0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52]),
        "jpeg": bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46,
                       0x49, 0x46, 0x00, 0x01]),
        "pdf": b"%PDF-1.",
        "zip": bytes([0x50, 0x4B, 0x03, 0x04]),
        "xml": b"<?xml version=",
        "docx": bytes([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00]),
    }
```

### 6. John the Ripper

**Purpose**: Multi-format password cracker

```python
# integrations/archive/john.py

class JohnIntegration(BaseTool):
    """
    John the Ripper - Password cracker
    https://www.openwall.com/john/
    """

    name = "john"
    description = "Multi-format password cracker"
    category = "archive"
    binary_names = ["john", "john-the-ripper"]
    install_commands = {
        "linux": "sudo apt install john",
        "darwin": "brew install john"
    }

    # Hash extraction tools (john suite)
    EXTRACTORS = {
        "zip": "zip2john",
        "rar": "rar2john",
        "7z": "7z2john",
        "pdf": "pdf2john",
        "ssh": "ssh2john",
        "gpg": "gpg2john",
        "keepass": "keepass2john",
        "office": "office2john",
        "bitcoin": "bitcoin2john",
        "ethereum": "ethereum2john",
        "luks": "luks2john",
        "veracrypt": "veracrypt2john",
    }

    def extract_hash(
        self,
        file_path: Path,
        file_type: str = None
    ) -> ToolResult:
        """
        Extract crackable hash from a file.
        Auto-detects type if not specified.
        """
        if file_type is None:
            file_type = self._detect_type(file_path)

        extractor = self.EXTRACTORS.get(file_type)
        if not extractor:
            return ToolResult(
                success=False,
                tool_name=self.name,
                command="",
                stdout="",
                stderr="",
                error_message=f"Unknown file type: {file_type}"
            )

        # Run extractor
        result = subprocess.run(
            [extractor, str(file_path)],
            capture_output=True, text=True
        )

        # Save hash to file
        hash_file = file_path.with_suffix('.hash')
        hash_file.write_text(result.stdout)

        return ToolResult(
            success=result.returncode == 0,
            tool_name=extractor,
            command=f"{extractor} {file_path}",
            stdout=result.stdout,
            stderr=result.stderr,
            artifacts=[hash_file],
            parsed_data={"hash": result.stdout.strip()}
        )

    def crack(
        self,
        hash_file: Path,
        wordlist: Path = None,
        rules: str = None,
        format: str = None,
        incremental: bool = False,
        mask: str = None
    ) -> ToolResult:
        """
        Crack password hashes.

        Modes:
        - Wordlist: --wordlist=<file>
        - Incremental: --incremental
        - Mask: --mask=?a?a?a?a
        - Single: --single (uses info from hash)
        """
        args = [str(hash_file)]

        if format:
            args.extend(["--format", format])

        if wordlist:
            args.append(f"--wordlist={wordlist}")
            if rules:
                args.append(f"--rules={rules}")
        elif incremental:
            args.append("--incremental")
        elif mask:
            args.append(f"--mask={mask}")
        else:
            args.append("--single")  # Default: single crack mode

        result = self._run(args, timeout=3600)

        # Get cracked passwords
        show_result = self._run([str(hash_file), "--show"])

        return ToolResult(
            success=show_result.stdout.strip() != "",
            tool_name=self.name,
            command=f"john {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_output(show_result.stdout)
        )

    def show_cracked(self, hash_file: Path, format: str = None) -> ToolResult:
        """Show cracked passwords"""
        args = [str(hash_file), "--show"]
        if format:
            args.extend(["--format", format])

        result = self._run(args)

        return ToolResult(
            success=True,
            tool_name=self.name,
            command=f"john {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_output(result.stdout)
        )

    def parse_output(self, stdout: str) -> Dict:
        """Parse john output"""
        cracked = []
        for line in stdout.strip().split('\n'):
            if ':' in line and line.strip():
                parts = line.split(':')
                if len(parts) >= 2:
                    cracked.append({
                        "hash_id": parts[0],
                        "password": parts[1]
                    })

        return {
            "cracked_count": len(cracked),
            "cracked": cracked
        }

    def _detect_type(self, file_path: Path) -> str:
        """Auto-detect file type for hash extraction"""
        suffix = file_path.suffix.lower()

        type_map = {
            ".zip": "zip",
            ".rar": "rar",
            ".7z": "7z",
            ".pdf": "pdf",
            ".kdbx": "keepass",
            ".docx": "office",
            ".xlsx": "office",
            ".pptx": "office",
        }

        return type_map.get(suffix, None)


class Zip2JohnIntegration(BaseTool):
    """Specialized ZIP hash extractor"""

    name = "zip2john"
    description = "Extract password hashes from ZIP files"
    category = "archive"
    binary_names = ["zip2john"]

    def extract(self, zip_path: Path) -> ToolResult:
        """Extract hash from password-protected ZIP"""
        result = self._run([str(zip_path)])

        hash_file = zip_path.with_suffix('.hash')
        if result.stdout:
            hash_file.write_text(result.stdout)

        return ToolResult(
            success=bool(result.stdout),
            tool_name=self.name,
            command=f"zip2john {zip_path}",
            stdout=result.stdout,
            stderr=result.stderr,
            artifacts=[hash_file] if result.stdout else [],
            parsed_data={"hash": result.stdout.strip()}
        )
```

### 7. fcrackzip - Fast ZIP Password Cracker

```python
# integrations/archive/fcrackzip.py

class FcrackzipIntegration(BaseTool):
    """
    fcrackzip - Fast ZIP password cracker
    Good for bruteforce of short passwords
    """

    name = "fcrackzip"
    description = "Fast ZIP password brute-force"
    category = "archive"
    binary_names = ["fcrackzip"]
    install_commands = {"linux": "sudo apt install fcrackzip"}

    def bruteforce(
        self,
        zip_path: Path,
        min_length: int = 1,
        max_length: int = 8,
        charset: str = "aA1"  # a=lower, A=upper, 1=digits, !=special
    ) -> ToolResult:
        """Brute-force ZIP password"""
        args = [
            "-b",  # brute-force mode
            "-c", charset,
            "-l", f"{min_length}-{max_length}",
            "-u",  # unzip to verify
            str(zip_path)
        ]

        result = self._run(args, timeout=3600)

        return ToolResult(
            success="PASSWORD FOUND" in result.stdout,
            tool_name=self.name,
            command=f"fcrackzip {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_output(result.stdout)
        )

    def dictionary_attack(
        self,
        zip_path: Path,
        wordlist: Path
    ) -> ToolResult:
        """Dictionary attack on ZIP"""
        args = [
            "-D",  # dictionary mode
            "-p", str(wordlist),
            "-u",  # verify
            str(zip_path)
        ]

        result = self._run(args, timeout=3600)

        return ToolResult(
            success="PASSWORD FOUND" in result.stdout,
            tool_name=self.name,
            command=f"fcrackzip {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_output(result.stdout)
        )

    def parse_output(self, stdout: str) -> Dict:
        """Parse fcrackzip output"""
        import re
        match = re.search(r'PASSWORD FOUND.*?:\s*(.+)', stdout)
        return {
            "password": match.group(1).strip() if match else None
        }
```

---

## Forensics Tools

### 8. Binwalk - Firmware Analysis

```python
# integrations/forensics/binwalk.py

class BinwalkIntegration(BaseTool):
    """
    binwalk - Firmware analysis and extraction
    https://github.com/ReFirmLabs/binwalk
    """

    name = "binwalk"
    description = "Firmware analysis and file carving"
    category = "forensics"
    binary_names = ["binwalk"]
    install_commands = {"linux": "sudo apt install binwalk"}

    def scan(self, file_path: Path) -> ToolResult:
        """Scan file for embedded files and signatures"""
        result = self._run([str(file_path)])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"binwalk {file_path}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_scan_output(result.stdout)
        )

    def extract(
        self,
        file_path: Path,
        output_dir: Path = None,
        depth: int = 8
    ) -> ToolResult:
        """Extract embedded files recursively"""
        args = ["-e", "--depth", str(depth)]

        if output_dir:
            args.extend(["-C", str(output_dir)])

        args.append(str(file_path))

        result = self._run(args)

        # Find extracted files
        extract_dir = output_dir or file_path.parent / f"_{file_path.name}.extracted"
        artifacts = list(extract_dir.rglob("*")) if extract_dir.exists() else []

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"binwalk {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            artifacts=artifacts,
            parsed_data={"extracted_count": len(artifacts)}
        )

    def entropy_analysis(self, file_path: Path) -> ToolResult:
        """Analyze file entropy (detect encryption/compression)"""
        args = ["-E", str(file_path)]
        result = self._run(args)

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"binwalk {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_entropy_output(result.stdout),
            suggestions=self._entropy_suggestions(result.stdout)
        )

    def parse_scan_output(self, stdout: str) -> Dict:
        """Parse binwalk scan output"""
        entries = []
        for line in stdout.split('\n'):
            if line.strip() and not line.startswith('DECIMAL'):
                parts = line.split(None, 2)
                if len(parts) >= 3 and parts[0].isdigit():
                    entries.append({
                        "offset_dec": int(parts[0]),
                        "offset_hex": parts[1],
                        "description": parts[2]
                    })

        return {
            "entries": entries,
            "file_types": list(set(e["description"].split(',')[0] for e in entries))
        }

    def parse_entropy_output(self, stdout: str) -> Dict:
        """Parse entropy analysis"""
        # High entropy (>0.9) suggests encryption/compression
        return {"raw_output": stdout}

    def _entropy_suggestions(self, stdout: str) -> List[str]:
        """Generate suggestions based on entropy"""
        suggestions = []
        if "Rising entropy edge" in stdout:
            suggestions.append("High entropy region detected - may be encrypted or compressed")
        return suggestions
```

### 9. Volatility 3 - Memory Forensics

```python
# integrations/forensics/volatility.py

class Volatility3Integration(BaseTool):
    """
    Volatility 3 - Memory forensics framework
    https://github.com/volatilityfoundation/volatility3
    """

    name = "volatility3"
    description = "Memory dump analysis"
    category = "forensics"
    binary_names = ["vol", "vol3", "volatility3"]
    install_commands = {"linux": "pip install volatility3"}

    # Common plugins organized by OS
    WINDOWS_PLUGINS = [
        "windows.info", "windows.pslist", "windows.pstree",
        "windows.cmdline", "windows.dlllist", "windows.handles",
        "windows.filescan", "windows.dumpfiles", "windows.netscan",
        "windows.registry.hivelist", "windows.hashdump",
        "windows.cachedump", "windows.lsadump", "windows.malfind",
        "windows.vadinfo", "windows.memmap"
    ]

    LINUX_PLUGINS = [
        "linux.pslist", "linux.pstree", "linux.bash",
        "linux.check_syscall", "linux.elfs", "linux.envvars",
        "linux.keyboard_notifiers", "linux.lsmod", "linux.malfind",
        "linux.proc_maps", "linux.tty_check"
    ]

    def identify_os(self, dump_path: Path) -> ToolResult:
        """Identify OS of memory dump"""
        # Try windows.info first
        result = self.run_plugin(dump_path, "windows.info")
        if result.success:
            return ToolResult(
                success=True,
                tool_name=self.name,
                command=result.command,
                stdout=result.stdout,
                stderr=result.stderr,
                parsed_data={"os": "windows", "info": result.parsed_data}
            )

        # Try linux
        result = self.run_plugin(dump_path, "linux.pslist")
        if result.success:
            return ToolResult(
                success=True,
                tool_name=self.name,
                command=result.command,
                stdout=result.stdout,
                stderr=result.stderr,
                parsed_data={"os": "linux"}
            )

        return ToolResult(
            success=False,
            tool_name=self.name,
            command="",
            stdout="",
            stderr="",
            error_message="Could not identify OS"
        )

    def run_plugin(
        self,
        dump_path: Path,
        plugin: str,
        extra_args: List[str] = None
    ) -> ToolResult:
        """Run a Volatility plugin"""
        args = ["-f", str(dump_path), plugin]
        if extra_args:
            args.extend(extra_args)

        result = self._run(args, timeout=600)

        return ToolResult(
            success=result.returncode == 0 and "Error" not in result.stderr,
            tool_name=self.name,
            command=f"vol {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_plugin_output(plugin, result.stdout)
        )

    def get_processes(self, dump_path: Path) -> ToolResult:
        """Get process list"""
        result = self.run_plugin(dump_path, "windows.pslist")
        if not result.success:
            result = self.run_plugin(dump_path, "linux.pslist")
        return result

    def get_network_connections(self, dump_path: Path) -> ToolResult:
        """Get network connections"""
        return self.run_plugin(dump_path, "windows.netscan")

    def find_malware(self, dump_path: Path) -> ToolResult:
        """Run malfind to detect injected code"""
        return self.run_plugin(dump_path, "windows.malfind")

    def dump_process(
        self,
        dump_path: Path,
        pid: int,
        output_dir: Path
    ) -> ToolResult:
        """Dump process memory"""
        return self.run_plugin(
            dump_path,
            "windows.memmap",
            ["--pid", str(pid), "--dump", "--output", str(output_dir)]
        )

    def extract_files(
        self,
        dump_path: Path,
        output_dir: Path,
        physaddr: int = None
    ) -> ToolResult:
        """Extract files from memory"""
        args = ["--output", str(output_dir)]
        if physaddr:
            args.extend(["--physaddr", str(physaddr)])

        return self.run_plugin(dump_path, "windows.dumpfiles", args)

    def get_password_hashes(self, dump_path: Path) -> ToolResult:
        """Extract password hashes (Windows)"""
        return self.run_plugin(dump_path, "windows.hashdump")

    def parse_plugin_output(self, plugin: str, stdout: str) -> Dict:
        """Parse plugin-specific output"""
        lines = stdout.strip().split('\n')

        if not lines:
            return {"raw": stdout}

        # Most plugins output tabular data
        # First line is usually headers
        if len(lines) > 1:
            headers = lines[0].split()
            data = []
            for line in lines[1:]:
                if line.strip():
                    values = line.split()
                    if len(values) >= len(headers):
                        data.append(dict(zip(headers, values)))
            return {"entries": data, "count": len(data)}

        return {"raw": stdout}
```

### 10. Foremost - File Carving

```python
# integrations/forensics/foremost.py

class ForemostIntegration(BaseTool):
    """
    Foremost - File carving tool
    """

    name = "foremost"
    description = "Recover files based on headers/footers"
    category = "forensics"
    binary_names = ["foremost"]
    install_commands = {"linux": "sudo apt install foremost"}

    def carve(
        self,
        input_file: Path,
        output_dir: Path = None,
        file_types: List[str] = None
    ) -> ToolResult:
        """
        Carve files from disk/memory image.

        File types: jpg, gif, png, bmp, avi, exe, mpg, wav,
                   riff, wmv, mov, pdf, ole, doc, zip, rar, htm, cpp
        """
        output_dir = output_dir or input_file.parent / "foremost_output"

        args = ["-o", str(output_dir), "-i", str(input_file)]

        if file_types:
            args.extend(["-t", ",".join(file_types)])
        else:
            args.append("-a")  # All file types

        result = self._run(args)

        # Collect carved files
        artifacts = list(output_dir.rglob("*.*")) if output_dir.exists() else []

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"foremost {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            artifacts=artifacts,
            parsed_data=self.parse_audit(output_dir / "audit.txt")
        )

    def parse_audit(self, audit_file: Path) -> Dict:
        """Parse foremost audit file"""
        if not audit_file.exists():
            return {}

        content = audit_file.read_text()
        return {"audit": content}
```

### 11. Sleuthkit - Disk Forensics

```python
# integrations/forensics/sleuthkit.py

class SleuthkitIntegration(BaseTool):
    """
    The Sleuth Kit - Disk forensics toolkit
    """

    name = "sleuthkit"
    description = "Disk image analysis"
    category = "forensics"
    binary_names = ["fls", "icat", "mmls", "fsstat"]
    install_commands = {"linux": "sudo apt install sleuthkit"}

    def list_partitions(self, image_path: Path) -> ToolResult:
        """List partitions in disk image (mmls)"""
        result = subprocess.run(
            ["mmls", str(image_path)],
            capture_output=True, text=True
        )

        return ToolResult(
            success=result.returncode == 0,
            tool_name="mmls",
            command=f"mmls {image_path}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_mmls_output(result.stdout)
        )

    def list_files(
        self,
        image_path: Path,
        offset: int = 0,
        directory: str = "/",
        recursive: bool = False,
        deleted: bool = False
    ) -> ToolResult:
        """List files in filesystem (fls)"""
        args = []

        if offset:
            args.extend(["-o", str(offset)])
        if recursive:
            args.append("-r")
        if deleted:
            args.append("-d")

        args.extend([str(image_path), directory])

        result = subprocess.run(
            ["fls"] + args,
            capture_output=True, text=True
        )

        return ToolResult(
            success=result.returncode == 0,
            tool_name="fls",
            command=f"fls {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_fls_output(result.stdout)
        )

    def extract_file(
        self,
        image_path: Path,
        inode: int,
        output_path: Path,
        offset: int = 0
    ) -> ToolResult:
        """Extract file by inode (icat)"""
        args = []
        if offset:
            args.extend(["-o", str(offset)])
        args.extend([str(image_path), str(inode)])

        result = subprocess.run(
            ["icat"] + args,
            capture_output=True
        )

        output_path.write_bytes(result.stdout)

        return ToolResult(
            success=result.returncode == 0,
            tool_name="icat",
            command=f"icat {' '.join(args)} > {output_path}",
            stdout="",
            stderr=result.stderr.decode(),
            artifacts=[output_path]
        )

    def get_filesystem_info(self, image_path: Path, offset: int = 0) -> ToolResult:
        """Get filesystem information (fsstat)"""
        args = []
        if offset:
            args.extend(["-o", str(offset)])
        args.append(str(image_path))

        result = subprocess.run(
            ["fsstat"] + args,
            capture_output=True, text=True
        )

        return ToolResult(
            success=result.returncode == 0,
            tool_name="fsstat",
            command=f"fsstat {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data={"info": result.stdout}
        )

    def parse_mmls_output(self, stdout: str) -> Dict:
        """Parse partition table"""
        partitions = []
        for line in stdout.split('\n'):
            parts = line.split()
            if len(parts) >= 6 and parts[0].isdigit():
                partitions.append({
                    "slot": parts[0],
                    "start": int(parts[2]),
                    "end": int(parts[3]),
                    "length": int(parts[4]),
                    "description": ' '.join(parts[5:])
                })
        return {"partitions": partitions}

    def parse_fls_output(self, stdout: str) -> Dict:
        """Parse file listing"""
        files = []
        for line in stdout.split('\n'):
            if line.strip():
                # Format: type/name inode name
                parts = line.split('\t')
                if len(parts) >= 2:
                    files.append({
                        "type": parts[0].split()[0] if parts[0] else "unknown",
                        "inode": parts[0].split()[-1].rstrip(':') if ':' in parts[0] else None,
                        "name": parts[-1],
                        "deleted": parts[0].startswith('*')
                    })
        return {"files": files}
```

---

## Network Analysis Tools

### 12. Wireshark/tshark - Network Protocol Analysis

```python
# integrations/network/wireshark.py

class WiresharkIntegration(BaseTool):
    """
    Wireshark/tshark - Network protocol analyzer
    """

    name = "tshark"
    description = "Network packet analysis"
    category = "network"
    binary_names = ["tshark", "wireshark"]
    install_commands = {"linux": "sudo apt install tshark"}

    def get_statistics(self, pcap_path: Path) -> ToolResult:
        """Get protocol hierarchy statistics"""
        result = self._run([
            "-r", str(pcap_path),
            "-z", "io,phs",
            "-q"
        ])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"tshark -r {pcap_path} -z io,phs -q",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data={"statistics": result.stdout}
        )

    def get_conversations(self, pcap_path: Path, layer: str = "tcp") -> ToolResult:
        """Get conversation statistics (tcp, udp, ip)"""
        result = self._run([
            "-r", str(pcap_path),
            "-z", f"conv,{layer}",
            "-q"
        ])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"tshark -r {pcap_path} -z conv,{layer} -q",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_conversations(result.stdout)
        )

    def filter_packets(
        self,
        pcap_path: Path,
        display_filter: str,
        fields: List[str] = None
    ) -> ToolResult:
        """Filter packets with display filter"""
        args = ["-r", str(pcap_path), "-Y", display_filter]

        if fields:
            args.append("-T")
            args.append("fields")
            for field in fields:
                args.extend(["-e", field])

        result = self._run(args)

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"tshark {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_fields_output(result.stdout, fields) if fields else None
        )

    def follow_stream(
        self,
        pcap_path: Path,
        protocol: str,  # tcp, udp, http, tls
        stream_index: int,
        output_format: str = "ascii"  # ascii, hex, raw
    ) -> ToolResult:
        """Follow and extract a protocol stream"""
        result = self._run([
            "-r", str(pcap_path),
            "-z", f"follow,{protocol},{output_format},{stream_index}",
            "-q"
        ])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"tshark -r {pcap_path} -z follow,{protocol},{output_format},{stream_index}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data={"stream_data": result.stdout}
        )

    def export_objects(
        self,
        pcap_path: Path,
        protocol: str,  # http, smb, imf, tftp, dicom
        output_dir: Path
    ) -> ToolResult:
        """Export transferred objects from protocol"""
        output_dir.mkdir(parents=True, exist_ok=True)

        result = self._run([
            "-r", str(pcap_path),
            "--export-objects", f"{protocol},{output_dir}"
        ])

        artifacts = list(output_dir.iterdir()) if output_dir.exists() else []

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"tshark -r {pcap_path} --export-objects {protocol},{output_dir}",
            stdout=result.stdout,
            stderr=result.stderr,
            artifacts=artifacts
        )

    def extract_credentials(self, pcap_path: Path) -> ToolResult:
        """Extract potential credentials from various protocols"""
        credentials = []

        # HTTP Basic Auth
        http_auth = self.filter_packets(
            pcap_path,
            "http.authorization",
            ["http.authorization", "ip.src", "ip.dst"]
        )
        if http_auth.stdout:
            credentials.append({"protocol": "HTTP Basic", "data": http_auth.stdout})

        # FTP
        ftp_creds = self.filter_packets(
            pcap_path,
            'ftp.request.command == "USER" or ftp.request.command == "PASS"',
            ["ftp.request.command", "ftp.request.arg"]
        )
        if ftp_creds.stdout:
            credentials.append({"protocol": "FTP", "data": ftp_creds.stdout})

        # HTTP POST (potential login forms)
        http_post = self.filter_packets(
            pcap_path,
            "http.request.method == POST",
            ["http.file_data", "http.request.uri"]
        )
        if http_post.stdout:
            credentials.append({"protocol": "HTTP POST", "data": http_post.stdout})

        return ToolResult(
            success=True,
            tool_name=self.name,
            command="Multiple credential extraction filters",
            stdout=str(credentials),
            stderr="",
            parsed_data={"credentials": credentials}
        )

    def find_flag_pattern(
        self,
        pcap_path: Path,
        pattern: str = "CTF|flag|FLAG"
    ) -> ToolResult:
        """Search for flag-like patterns in packet data"""
        result = self._run([
            "-r", str(pcap_path),
            "-Y", f'frame contains "{pattern}"',
            "-V"  # Verbose
        ])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f'tshark -r {pcap_path} -Y \'frame contains "{pattern}"\'',
            stdout=result.stdout,
            stderr=result.stderr
        )

    # Common display filters for CTF
    COMMON_FILTERS = {
        "http_requests": "http.request",
        "http_responses": "http.response",
        "dns_queries": "dns.qry.name",
        "ftp_traffic": "ftp",
        "telnet_traffic": "telnet",
        "smtp_traffic": "smtp",
        "ssh_traffic": "ssh",
        "tls_traffic": "tls",
        "icmp_traffic": "icmp",
        "arp_traffic": "arp",
        "tcp_syn": "tcp.flags.syn==1 and tcp.flags.ack==0",
        "tcp_rst": "tcp.flags.reset==1",
        "large_packets": "frame.len > 1000",
    }

    def parse_conversations(self, stdout: str) -> Dict:
        """Parse conversation statistics"""
        conversations = []
        # Parse tshark conversation output
        return {"conversations": conversations}

    def parse_fields_output(self, stdout: str, fields: List[str]) -> Dict:
        """Parse field extraction output"""
        rows = []
        for line in stdout.strip().split('\n'):
            if line:
                values = line.split('\t')
                if len(values) == len(fields):
                    rows.append(dict(zip(fields, values)))
        return {"rows": rows}
```

### 13. tcpdump - Packet Capture

```python
# integrations/network/tcpdump.py

class TcpdumpIntegration(BaseTool):
    """tcpdump - CLI packet analyzer"""

    name = "tcpdump"
    description = "Command-line packet analyzer"
    category = "network"
    binary_names = ["tcpdump"]
    install_commands = {"linux": "sudo apt install tcpdump"}

    def read_pcap(
        self,
        pcap_path: Path,
        filter_expr: str = None,
        count: int = None,
        verbose: int = 1
    ) -> ToolResult:
        """Read and filter PCAP file"""
        args = ["-r", str(pcap_path)]

        if verbose:
            args.append("-" + "v" * min(verbose, 3))
        if count:
            args.extend(["-c", str(count)])
        if filter_expr:
            args.append(filter_expr)

        result = self._run(args)

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"tcpdump {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr
        )

    def extract_ascii(self, pcap_path: Path) -> ToolResult:
        """Extract ASCII data from packets"""
        result = self._run([
            "-r", str(pcap_path),
            "-A"  # Print in ASCII
        ])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"tcpdump -r {pcap_path} -A",
            stdout=result.stdout,
            stderr=result.stderr
        )
```

---

## Steganography Tools

### 14. zsteg - PNG/BMP Analysis

```python
# integrations/stego/zsteg.py

class ZstegIntegration(BaseTool):
    """
    zsteg - PNG/BMP steganography detector
    https://github.com/zed-0xff/zsteg
    """

    name = "zsteg"
    description = "Detect hidden data in PNG/BMP images"
    category = "stego"
    binary_names = ["zsteg"]
    install_commands = {"linux": "gem install zsteg"}

    def analyze(self, image_path: Path) -> ToolResult:
        """Run all detection methods"""
        result = self._run(["-a", str(image_path)])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"zsteg -a {image_path}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_output(result.stdout)
        )

    def extract_channel(
        self,
        image_path: Path,
        channel: str,  # e.g., "b1,r,lsb,xy" or "b1,rgb,lsb,xy"
    ) -> ToolResult:
        """Extract data from specific channel"""
        result = self._run(["-E", channel, str(image_path)])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"zsteg -E {channel} {image_path}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data={"extracted": result.stdout}
        )

    def check_lsb(self, image_path: Path) -> ToolResult:
        """Check LSB planes specifically"""
        result = self._run(["-b", "1", str(image_path)])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"zsteg -b 1 {image_path}",
            stdout=result.stdout,
            stderr=result.stderr
        )

    def parse_output(self, stdout: str) -> Dict:
        """Parse zsteg output for findings"""
        findings = []

        for line in stdout.split('\n'):
            if line.strip() and ':' in line:
                parts = line.split(':', 1)
                channel = parts[0].strip()
                data = parts[1].strip() if len(parts) > 1 else ""

                # Filter interesting findings
                if any(x in data.lower() for x in ['text', 'flag', 'ctf', 'http', 'file']):
                    findings.append({
                        "channel": channel,
                        "data": data[:200],  # Truncate long data
                        "interesting": True
                    })
                elif len(data) > 0 and data[0].isprintable():
                    findings.append({
                        "channel": channel,
                        "data": data[:200],
                        "interesting": False
                    })

        return {
            "findings": findings,
            "interesting_count": len([f for f in findings if f.get("interesting")])
        }
```

### 15. Steghide - JPEG/WAV/BMP/AU Steganography

```python
# integrations/stego/steghide.py

class SteghideIntegration(BaseTool):
    """
    steghide - Hide data in images/audio
    """

    name = "steghide"
    description = "Embed/extract data in JPEG, WAV, BMP, AU"
    category = "stego"
    binary_names = ["steghide"]
    install_commands = {"linux": "sudo apt install steghide"}

    def get_info(self, file_path: Path) -> ToolResult:
        """Get information about embedded data"""
        result = self._run([
            "info", str(file_path),
            "-p", ""  # Empty passphrase first
        ])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"steghide info {file_path}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_info(result.stdout)
        )

    def extract(
        self,
        stego_file: Path,
        output_file: Path = None,
        passphrase: str = ""
    ) -> ToolResult:
        """Extract hidden data"""
        args = ["extract", "-sf", str(stego_file), "-p", passphrase]

        if output_file:
            args.extend(["-xf", str(output_file)])

        result = self._run(args)

        # Determine output file
        if not output_file and result.returncode == 0:
            # steghide extracts to original filename
            pass

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"steghide {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            artifacts=[output_file] if output_file and output_file.exists() else []
        )

    def bruteforce_passphrase(
        self,
        stego_file: Path,
        wordlist: Path
    ) -> ToolResult:
        """Try wordlist of passphrases"""
        with open(wordlist) as f:
            for line in f:
                passphrase = line.strip()
                result = self.extract(stego_file, passphrase=passphrase)
                if result.success:
                    return ToolResult(
                        success=True,
                        tool_name=self.name,
                        command=f"steghide bruteforce",
                        stdout=f"Passphrase found: {passphrase}",
                        stderr="",
                        parsed_data={"passphrase": passphrase}
                    )

        return ToolResult(
            success=False,
            tool_name=self.name,
            command="steghide bruteforce",
            stdout="",
            stderr="No passphrase found",
            error_message="Exhausted wordlist"
        )

    def parse_info(self, stdout: str) -> Dict:
        """Parse steghide info output"""
        info = {}
        for line in stdout.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                info[key.strip().lower()] = value.strip()
        return info
```

### 16. ExifTool - Metadata Analysis

```python
# integrations/stego/exiftool.py

class ExiftoolIntegration(BaseTool):
    """
    ExifTool - Read/write metadata
    """

    name = "exiftool"
    description = "Read/write file metadata"
    category = "stego"
    binary_names = ["exiftool"]
    install_commands = {"linux": "sudo apt install exiftool"}

    def extract_all(self, file_path: Path) -> ToolResult:
        """Extract all metadata"""
        result = self._run(["-j", str(file_path)])  # JSON output

        try:
            import json
            parsed = json.loads(result.stdout)[0] if result.stdout else {}
        except:
            parsed = {"raw": result.stdout}

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"exiftool -j {file_path}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=parsed
        )

    def extract_gps(self, file_path: Path) -> ToolResult:
        """Extract GPS coordinates"""
        result = self._run([
            "-gpslatitude", "-gpslongitude",
            "-gpsposition", "-j",
            str(file_path)
        ])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"exiftool -gps* {file_path}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_gps(result.stdout)
        )

    def extract_thumbnail(self, file_path: Path, output: Path) -> ToolResult:
        """Extract embedded thumbnail"""
        result = self._run([
            "-b", "-ThumbnailImage",
            str(file_path)
        ])

        if result.stdout:
            output.write_bytes(result.stdout.encode('latin-1'))

        return ToolResult(
            success=result.returncode == 0 and output.exists(),
            tool_name=self.name,
            command=f"exiftool -b -ThumbnailImage {file_path}",
            stdout="",
            stderr=result.stderr,
            artifacts=[output] if output.exists() else []
        )

    def search_for_flag(self, file_path: Path) -> ToolResult:
        """Search metadata for flag-like strings"""
        result = self.extract_all(file_path)

        flag_candidates = []
        if result.parsed_data:
            for key, value in result.parsed_data.items():
                value_str = str(value).lower()
                if any(x in value_str for x in ['flag', 'ctf', 'secret', 'hidden']):
                    flag_candidates.append({key: value})

        result.parsed_data["flag_candidates"] = flag_candidates
        return result

    def parse_gps(self, stdout: str) -> Dict:
        """Parse GPS coordinates"""
        try:
            import json
            data = json.loads(stdout)[0] if stdout else {}
            return {
                "latitude": data.get("GPSLatitude"),
                "longitude": data.get("GPSLongitude"),
                "position": data.get("GPSPosition")
            }
        except:
            return {}
```

### 17. StegSolve - Image Analysis (Wrapper)

```python
# integrations/stego/stegsolve.py

class StegsolveIntegration(BaseTool):
    """
    StegSolve - Visual image analysis
    Note: StegSolve is GUI-based, this provides equivalent CLI operations
    """

    name = "stegsolve"
    description = "Visual image analysis (color planes, XOR)"
    category = "stego"
    binary_names = []  # GUI tool - we simulate with PIL

    @property
    def is_installed(self) -> bool:
        try:
            from PIL import Image
            return True
        except ImportError:
            return False

    def extract_color_planes(
        self,
        image_path: Path,
        output_dir: Path
    ) -> ToolResult:
        """Extract individual color bit planes"""
        from PIL import Image
        import numpy as np

        output_dir.mkdir(parents=True, exist_ok=True)
        img = Image.open(image_path)

        if img.mode != 'RGB':
            img = img.convert('RGB')

        data = np.array(img)
        artifacts = []

        # Extract each bit plane for each channel
        for channel_idx, channel_name in enumerate(['red', 'green', 'blue']):
            for bit in range(8):
                plane = (data[:, :, channel_idx] >> bit) & 1
                plane_img = Image.fromarray((plane * 255).astype(np.uint8))

                output_path = output_dir / f"{channel_name}_bit{bit}.png"
                plane_img.save(output_path)
                artifacts.append(output_path)

        return ToolResult(
            success=True,
            tool_name=self.name,
            command=f"extract_color_planes {image_path}",
            stdout=f"Extracted {len(artifacts)} bit planes",
            stderr="",
            artifacts=artifacts
        )

    def xor_images(
        self,
        image1_path: Path,
        image2_path: Path,
        output_path: Path
    ) -> ToolResult:
        """XOR two images together"""
        from PIL import Image
        import numpy as np

        img1 = np.array(Image.open(image1_path))
        img2 = np.array(Image.open(image2_path))

        # Ensure same size
        min_h = min(img1.shape[0], img2.shape[0])
        min_w = min(img1.shape[1], img2.shape[1])

        result = img1[:min_h, :min_w] ^ img2[:min_h, :min_w]
        Image.fromarray(result).save(output_path)

        return ToolResult(
            success=True,
            tool_name=self.name,
            command=f"xor {image1_path} {image2_path}",
            stdout="",
            stderr="",
            artifacts=[output_path]
        )

    def analyze_lsb_visual(
        self,
        image_path: Path,
        output_path: Path
    ) -> ToolResult:
        """Create visual representation of LSB"""
        from PIL import Image
        import numpy as np

        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')

        data = np.array(img)

        # Extract LSB and amplify
        lsb = (data & 1) * 255

        Image.fromarray(lsb.astype(np.uint8)).save(output_path)

        return ToolResult(
            success=True,
            tool_name=self.name,
            command=f"lsb_visual {image_path}",
            stdout="",
            stderr="",
            artifacts=[output_path]
        )
```

---

## Web Exploitation Tools

### 18. sqlmap - SQL Injection

```python
# integrations/web/sqlmap.py

class SqlmapIntegration(BaseTool):
    """
    sqlmap - Automated SQL injection
    """

    name = "sqlmap"
    description = "Automated SQL injection"
    category = "web"
    binary_names = ["sqlmap"]
    install_commands = {"linux": "sudo apt install sqlmap"}

    def test_url(
        self,
        url: str,
        method: str = "GET",
        data: str = None,
        cookie: str = None,
        level: int = 1,
        risk: int = 1
    ) -> ToolResult:
        """Test URL for SQL injection"""
        args = [
            "-u", url,
            "--level", str(level),
            "--risk", str(risk),
            "--batch"  # Non-interactive
        ]

        if method.upper() == "POST" and data:
            args.extend(["--data", data])
        if cookie:
            args.extend(["--cookie", cookie])

        result = self._run(args, timeout=300)

        return ToolResult(
            success="is vulnerable" in result.stdout,
            tool_name=self.name,
            command=f"sqlmap {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_output(result.stdout)
        )

    def dump_database(
        self,
        url: str,
        database: str = None,
        table: str = None,
        columns: List[str] = None
    ) -> ToolResult:
        """Dump database contents"""
        args = ["-u", url, "--batch", "--dump"]

        if database:
            args.extend(["-D", database])
        if table:
            args.extend(["-T", table])
        if columns:
            args.extend(["-C", ",".join(columns)])

        result = self._run(args, timeout=600)

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"sqlmap {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr
        )

    def parse_output(self, stdout: str) -> Dict:
        """Parse sqlmap output"""
        vulnerabilities = []

        for line in stdout.split('\n'):
            if "is vulnerable" in line or "injectable" in line:
                vulnerabilities.append(line.strip())

        return {
            "vulnerable": len(vulnerabilities) > 0,
            "findings": vulnerabilities
        }
```

### 19. gobuster/ffuf - Directory Bruteforce

```python
# integrations/web/gobuster.py

class GobusterIntegration(BaseTool):
    """
    gobuster - Directory/DNS bruteforcing
    """

    name = "gobuster"
    description = "Directory and DNS bruteforce"
    category = "web"
    binary_names = ["gobuster"]
    install_commands = {"linux": "sudo apt install gobuster"}

    def dir_bruteforce(
        self,
        url: str,
        wordlist: Path,
        extensions: List[str] = None,
        threads: int = 10,
        status_codes: List[int] = None
    ) -> ToolResult:
        """Bruteforce directories"""
        args = [
            "dir",
            "-u", url,
            "-w", str(wordlist),
            "-t", str(threads),
            "-q"  # Quiet
        ]

        if extensions:
            args.extend(["-x", ",".join(extensions)])
        if status_codes:
            args.extend(["-s", ",".join(map(str, status_codes))])
        else:
            args.extend(["-s", "200,204,301,302,307,401,403"])

        result = self._run(args, timeout=600)

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"gobuster {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_dir_output(result.stdout)
        )

    def vhost_bruteforce(
        self,
        url: str,
        wordlist: Path
    ) -> ToolResult:
        """Bruteforce virtual hosts"""
        args = [
            "vhost",
            "-u", url,
            "-w", str(wordlist),
            "-q"
        ]

        result = self._run(args, timeout=600)

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"gobuster {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr
        )

    def parse_dir_output(self, stdout: str) -> Dict:
        """Parse directory bruteforce output"""
        found = []
        for line in stdout.split('\n'):
            if '(Status:' in line:
                found.append(line.strip())
        return {"found": found, "count": len(found)}


class FfufIntegration(BaseTool):
    """
    ffuf - Fast web fuzzer
    """

    name = "ffuf"
    description = "Fast web fuzzer"
    category = "web"
    binary_names = ["ffuf"]
    install_commands = {"linux": "go install github.com/ffuf/ffuf/v2@latest"}

    def fuzz(
        self,
        url: str,  # Use FUZZ keyword for injection point
        wordlist: Path,
        method: str = "GET",
        data: str = None,
        headers: Dict[str, str] = None,
        filter_status: List[int] = None,
        filter_size: int = None
    ) -> ToolResult:
        """General purpose fuzzing"""
        args = [
            "-u", url,
            "-w", str(wordlist),
            "-X", method
        ]

        if data:
            args.extend(["-d", data])
        if headers:
            for key, value in headers.items():
                args.extend(["-H", f"{key}: {value}"])
        if filter_status:
            args.extend(["-fc", ",".join(map(str, filter_status))])
        if filter_size:
            args.extend(["-fs", str(filter_size)])

        result = self._run(args, timeout=600)

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"ffuf {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr
        )
```

---

## Binary Exploitation Tools

### 20. pwntools - Exploit Development

```python
# integrations/pwn/pwntools_wrapper.py

class PwntoolsIntegration(BaseTool):
    """
    pwntools - CTF framework and exploit development library
    """

    name = "pwntools"
    description = "Exploit development framework"
    category = "pwn"
    binary_names = []  # Python library
    install_commands = {"linux": "pip install pwntools"}

    @property
    def is_installed(self) -> bool:
        try:
            import pwn
            return True
        except ImportError:
            return False

    def checksec(self, binary_path: Path) -> ToolResult:
        """Check binary security properties"""
        from pwn import ELF

        elf = ELF(str(binary_path), checksec=False)

        security = {
            "arch": elf.arch,
            "bits": elf.bits,
            "endian": elf.endian,
            "canary": elf.canary,
            "nx": elf.nx,
            "pie": elf.pie,
            "relro": elf.relro,
            "rpath": elf.rpath,
            "runpath": elf.runpath,
        }

        return ToolResult(
            success=True,
            tool_name=self.name,
            command=f"checksec {binary_path}",
            stdout=str(security),
            stderr="",
            parsed_data=security
        )

    def find_gadgets(
        self,
        binary_path: Path,
        gadget_type: str = None
    ) -> ToolResult:
        """Find ROP gadgets"""
        from pwn import ELF, ROP

        elf = ELF(str(binary_path), checksec=False)
        rop = ROP(elf)

        gadgets = {
            "pop_rdi": None,
            "pop_rsi": None,
            "pop_rdx": None,
            "ret": None,
            "syscall": None,
        }

        try:
            gadgets["pop_rdi"] = hex(rop.find_gadget(['pop rdi', 'ret'])[0])
        except:
            pass
        try:
            gadgets["pop_rsi"] = hex(rop.find_gadget(['pop rsi', 'ret'])[0])
        except:
            pass
        try:
            gadgets["ret"] = hex(rop.find_gadget(['ret'])[0])
        except:
            pass

        return ToolResult(
            success=True,
            tool_name=self.name,
            command=f"find_gadgets {binary_path}",
            stdout=str(gadgets),
            stderr="",
            parsed_data=gadgets
        )

    def generate_exploit_template(
        self,
        binary_path: Path,
        vuln_type: str,
        offset: int = None,
        target_function: str = None
    ) -> str:
        """Generate exploit template code"""
        template = f'''#!/usr/bin/env python3
from pwn import *

# Binary setup
binary_path = "{binary_path}"
elf = ELF(binary_path)
context.binary = elf
context.log_level = "debug"

# Remote connection (update as needed)
# HOST = "challenge.ctf.com"
# PORT = 1337

def exploit():
    # p = remote(HOST, PORT)
    p = process(binary_path)

'''

        if vuln_type == "buffer_overflow" and offset:
            template += f'''    # Buffer overflow exploit
    offset = {offset}

    # Build payload
    payload = b"A" * offset
    # payload += p64(elf.symbols['win'])  # Overwrite return address

    p.sendline(payload)
    p.interactive()
'''
        elif vuln_type == "format_string":
            template += '''    # Format string exploit
    # Leak addresses
    payload = b"%p." * 20
    p.sendline(payload)
    leaks = p.recvline()
    print(f"Leaks: {leaks}")

    p.interactive()
'''

        template += '''
if __name__ == "__main__":
    exploit()
'''
        return template

    def create_cyclic_pattern(self, length: int) -> ToolResult:
        """Generate cyclic pattern for offset finding"""
        from pwn import cyclic

        pattern = cyclic(length)

        return ToolResult(
            success=True,
            tool_name=self.name,
            command=f"cyclic({length})",
            stdout=pattern.decode(),
            stderr="",
            parsed_data={"pattern": pattern, "length": length}
        )

    def find_offset(self, crash_value: int) -> ToolResult:
        """Find offset from crash value"""
        from pwn import cyclic_find

        offset = cyclic_find(crash_value)

        return ToolResult(
            success=offset != -1,
            tool_name=self.name,
            command=f"cyclic_find({hex(crash_value)})",
            stdout=str(offset),
            stderr="",
            parsed_data={"offset": offset}
        )
```

### 21. ROPgadget - ROP Chain Builder

```python
# integrations/pwn/ropgadget.py

class ROPgadgetIntegration(BaseTool):
    """
    ROPgadget - ROP chain builder
    """

    name = "ROPgadget"
    description = "Search ROP gadgets in binaries"
    category = "pwn"
    binary_names = ["ROPgadget"]
    install_commands = {"linux": "pip install ROPgadget"}

    def search_gadgets(
        self,
        binary_path: Path,
        filter_str: str = None
    ) -> ToolResult:
        """Search for gadgets"""
        args = ["--binary", str(binary_path)]

        if filter_str:
            args.extend(["--only", filter_str])

        result = self._run(args)

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"ROPgadget {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_gadgets(result.stdout)
        )

    def build_rop_chain(
        self,
        binary_path: Path,
    ) -> ToolResult:
        """Attempt automatic ROP chain generation"""
        result = self._run([
            "--binary", str(binary_path),
            "--ropchain"
        ])

        return ToolResult(
            success="ROP chain" in result.stdout,
            tool_name=self.name,
            command=f"ROPgadget --binary {binary_path} --ropchain",
            stdout=result.stdout,
            stderr=result.stderr
        )

    def parse_gadgets(self, stdout: str) -> Dict:
        """Parse gadget listing"""
        gadgets = []
        for line in stdout.split('\n'):
            if ' : ' in line:
                parts = line.split(' : ')
                if len(parts) == 2:
                    gadgets.append({
                        "address": parts[0].strip(),
                        "instructions": parts[1].strip()
                    })
        return {"gadgets": gadgets, "count": len(gadgets)}
```

### 22. one_gadget - Magic Gadget Finder

```python
# integrations/pwn/one_gadget.py

class OneGadgetIntegration(BaseTool):
    """
    one_gadget - Find one-shot RCE gadgets in libc
    """

    name = "one_gadget"
    description = "Find execve('/bin/sh') gadgets in libc"
    category = "pwn"
    binary_names = ["one_gadget"]
    install_commands = {"linux": "gem install one_gadget"}

    def find_gadgets(self, libc_path: Path) -> ToolResult:
        """Find one-gadgets in libc"""
        result = self._run([str(libc_path)])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"one_gadget {libc_path}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_output(result.stdout)
        )

    def parse_output(self, stdout: str) -> Dict:
        """Parse one_gadget output"""
        gadgets = []
        current_gadget = None

        for line in stdout.split('\n'):
            if line.startswith('0x'):
                if current_gadget:
                    gadgets.append(current_gadget)
                current_gadget = {
                    "offset": line.strip(),
                    "constraints": []
                }
            elif current_gadget and line.strip():
                current_gadget["constraints"].append(line.strip())

        if current_gadget:
            gadgets.append(current_gadget)

        return {"gadgets": gadgets}
```

---

## Reverse Engineering Tools

### 23. radare2 - Binary Analysis

```python
# integrations/reversing/radare2.py

class Radare2Integration(BaseTool):
    """
    radare2 - Reverse engineering framework
    """

    name = "radare2"
    description = "Binary analysis and disassembly"
    category = "reversing"
    binary_names = ["r2", "radare2"]
    install_commands = {"linux": "sudo apt install radare2"}

    def analyze(self, binary_path: Path) -> ToolResult:
        """Run full analysis"""
        # Use r2pipe or command mode
        result = self._run([
            "-q",  # Quiet
            "-c", "aaa; afl; q",  # Analyze all, list functions, quit
            str(binary_path)
        ])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"r2 -c 'aaa; afl' {binary_path}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_function_list(result.stdout)
        )

    def disassemble_function(
        self,
        binary_path: Path,
        function: str
    ) -> ToolResult:
        """Disassemble a specific function"""
        result = self._run([
            "-q",
            "-c", f"aaa; s {function}; pdf; q",
            str(binary_path)
        ])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"r2 -c 'pdf @ {function}' {binary_path}",
            stdout=result.stdout,
            stderr=result.stderr
        )

    def find_strings(self, binary_path: Path) -> ToolResult:
        """Find strings in binary"""
        result = self._run([
            "-q",
            "-c", "iz; q",
            str(binary_path)
        ])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"r2 -c 'iz' {binary_path}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_strings(result.stdout)
        )

    def get_imports(self, binary_path: Path) -> ToolResult:
        """Get imported functions"""
        result = self._run([
            "-q",
            "-c", "ii; q",
            str(binary_path)
        ])

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"r2 -c 'ii' {binary_path}",
            stdout=result.stdout,
            stderr=result.stderr
        )

    def parse_function_list(self, stdout: str) -> Dict:
        """Parse function listing"""
        functions = []
        for line in stdout.split('\n'):
            if '0x' in line:
                parts = line.split()
                if len(parts) >= 4:
                    functions.append({
                        "address": parts[0],
                        "size": parts[1] if len(parts) > 1 else None,
                        "name": parts[-1]
                    })
        return {"functions": functions}

    def parse_strings(self, stdout: str) -> Dict:
        """Parse strings output"""
        strings = []
        for line in stdout.split('\n'):
            if ' ' in line:
                parts = line.split(None, 3)
                if len(parts) >= 4:
                    strings.append({
                        "address": parts[1],
                        "string": parts[3] if len(parts) > 3 else ""
                    })
        return {"strings": strings}
```

### 24. Ghidra Headless - Decompilation

```python
# integrations/reversing/ghidra.py

class GhidraHeadlessIntegration(BaseTool):
    """
    Ghidra headless analyzer
    """

    name = "ghidra"
    description = "Ghidra headless decompilation"
    category = "reversing"
    binary_names = ["analyzeHeadless"]
    install_commands = {
        "linux": "Download from https://ghidra-sre.org/"
    }

    def __init__(self, ghidra_path: str = None):
        self.ghidra_home = ghidra_path or os.environ.get('GHIDRA_HOME', '/opt/ghidra')
        self.analyzer = Path(self.ghidra_home) / "support" / "analyzeHeadless"

    @property
    def is_installed(self) -> bool:
        return self.analyzer.exists()

    def analyze_and_decompile(
        self,
        binary_path: Path,
        output_dir: Path
    ) -> ToolResult:
        """Analyze binary and export decompilation"""
        project_dir = output_dir / "ghidra_project"
        project_dir.mkdir(parents=True, exist_ok=True)

        # Create post-analysis script
        script_content = '''
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

decomp = DecompInterface()
decomp.openProgram(currentProgram)

funcs = currentProgram.getFunctionManager().getFunctions(True)
for func in funcs:
    results = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
    if results.decompileCompleted():
        print(f"=== {func.getName()} ===")
        print(results.getDecompiledFunction().getC())
'''

        script_path = output_dir / "decompile_all.py"
        script_path.write_text(script_content)

        result = subprocess.run([
            str(self.analyzer),
            str(project_dir),
            "CTFProject",
            "-import", str(binary_path),
            "-postScript", str(script_path),
            "-deleteProject"
        ], capture_output=True, text=True, timeout=300)

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"analyzeHeadless ... -import {binary_path}",
            stdout=result.stdout,
            stderr=result.stderr
        )
```

---

## OSINT Tools

### 25. Sherlock - Username Search

```python
# integrations/osint/sherlock.py

class SherlockIntegration(BaseTool):
    """
    Sherlock - Hunt usernames across social networks
    """

    name = "sherlock"
    description = "Search usernames across social networks"
    category = "osint"
    binary_names = ["sherlock"]
    install_commands = {"linux": "pip install sherlock-project"}

    def search_username(
        self,
        username: str,
        sites: List[str] = None,
        output_file: Path = None
    ) -> ToolResult:
        """Search for username across platforms"""
        args = [username]

        if sites:
            args.extend(["--site", ",".join(sites)])
        if output_file:
            args.extend(["--output", str(output_file)])

        args.append("--print-found")  # Only print found

        result = self._run(args, timeout=300)

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"sherlock {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_output(result.stdout)
        )

    def parse_output(self, stdout: str) -> Dict:
        """Parse sherlock output"""
        found = []
        for line in stdout.split('\n'):
            if 'http' in line:
                found.append(line.strip())
        return {"found": found, "count": len(found)}
```

### 26. theHarvester - Email/Domain OSINT

```python
# integrations/osint/theharvester.py

class TheHarvesterIntegration(BaseTool):
    """
    theHarvester - Gather emails, subdomains, hosts, etc.
    """

    name = "theHarvester"
    description = "Gather OSINT about a domain"
    category = "osint"
    binary_names = ["theHarvester"]
    install_commands = {"linux": "pip install theHarvester"}

    def search_domain(
        self,
        domain: str,
        sources: List[str] = None
    ) -> ToolResult:
        """Search for domain information"""
        args = ["-d", domain]

        if sources:
            args.extend(["-b", ",".join(sources)])
        else:
            args.extend(["-b", "all"])

        result = self._run(args, timeout=300)

        return ToolResult(
            success=result.returncode == 0,
            tool_name=self.name,
            command=f"theHarvester {' '.join(args)}",
            stdout=result.stdout,
            stderr=result.stderr,
            parsed_data=self.parse_output(result.stdout)
        )

    def parse_output(self, stdout: str) -> Dict:
        """Parse theHarvester output"""
        results = {
            "emails": [],
            "hosts": [],
            "ips": []
        }

        current_section = None
        for line in stdout.split('\n'):
            if 'Emails found' in line:
                current_section = 'emails'
            elif 'Hosts found' in line:
                current_section = 'hosts'
            elif 'IPs found' in line:
                current_section = 'ips'
            elif current_section and line.strip() and not line.startswith('['):
                results[current_section].append(line.strip())

        return results
```

---

## Encoding & Utility Tools

### 27. CyberChef (Local/API)

```python
# integrations/encoding/cyberchef.py

class CyberChefIntegration(BaseTool):
    """
    CyberChef - Data transformation
    Can use local node.js version or implement common operations
    """

    name = "cyberchef"
    description = "Data encoding/decoding transformations"
    category = "encoding"

    @property
    def is_installed(self) -> bool:
        return True  # We implement operations in Python

    def magic(self, data: bytes) -> ToolResult:
        """Auto-detect and decode data"""
        results = []

        # Try various decodings
        decodings = [
            ("base64", self._try_base64),
            ("base32", self._try_base32),
            ("hex", self._try_hex),
            ("rot13", self._try_rot13),
            ("url", self._try_url_decode),
        ]

        for name, func in decodings:
            try:
                decoded = func(data)
                if decoded and decoded != data:
                    results.append({
                        "encoding": name,
                        "decoded": decoded[:200]  # Truncate
                    })
            except:
                pass

        return ToolResult(
            success=len(results) > 0,
            tool_name=self.name,
            command="magic decode",
            stdout=str(results),
            stderr="",
            parsed_data={"decodings": results}
        )

    def decode_chain(self, data: bytes, operations: List[str]) -> ToolResult:
        """Apply a chain of decode operations"""
        current = data
        steps = []

        for op in operations:
            try:
                if op == "base64":
                    current = base64.b64decode(current)
                elif op == "base32":
                    current = base64.b32decode(current)
                elif op == "hex":
                    current = bytes.fromhex(current.decode())
                elif op == "rot13":
                    current = current.decode().translate(
                        str.maketrans(
                            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
                        )
                    ).encode()
                elif op == "url":
                    import urllib.parse
                    current = urllib.parse.unquote(current.decode()).encode()
                elif op == "reverse":
                    current = current[::-1]

                steps.append({"operation": op, "result": current[:100]})
            except Exception as e:
                steps.append({"operation": op, "error": str(e)})
                break

        return ToolResult(
            success=True,
            tool_name=self.name,
            command=f"decode_chain: {' -> '.join(operations)}",
            stdout=current.decode('latin-1'),
            stderr="",
            parsed_data={"steps": steps, "final": current}
        )

    def _try_base64(self, data: bytes) -> bytes:
        import base64
        return base64.b64decode(data)

    def _try_base32(self, data: bytes) -> bytes:
        import base64
        return base64.b32decode(data)

    def _try_hex(self, data: bytes) -> bytes:
        return bytes.fromhex(data.decode().strip())

    def _try_rot13(self, data: bytes) -> bytes:
        import codecs
        return codecs.decode(data.decode(), 'rot_13').encode()

    def _try_url_decode(self, data: bytes) -> bytes:
        import urllib.parse
        return urllib.parse.unquote(data.decode()).encode()
```

---

## Installation & Dependency Management

### Complete Installation Script

```bash
#!/bin/bash
# install_ctf_tools.sh - Complete CTF toolkit installation

set -e

echo "=== CTF Kit Tool Installation ==="

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     OS_TYPE=Linux;;
    Darwin*)    OS_TYPE=Mac;;
    *)          OS_TYPE="UNKNOWN"
esac

echo "Detected OS: $OS_TYPE"

# Update package manager
if [ "$OS_TYPE" = "Linux" ]; then
    sudo apt update
fi

# === TIER 1: Essential Tools ===
echo "Installing Tier 1 (Essential) tools..."

# Core utilities
sudo apt install -y file binwalk foremost exiftool strings xxd

# Python environment
sudo apt install -y python3 python3-pip python3-venv

# Network tools
sudo apt install -y tshark tcpdump

# === TIER 2: Category Tools ===
echo "Installing Tier 2 (Category) tools..."

# Crypto
pip3 install --user pycryptodome gmpy2 z3-solver hashid
pip3 install --user xortool
sudo apt install -y hashcat john

# Forensics
pip3 install --user volatility3
sudo apt install -y sleuthkit autopsy

# Stego
sudo apt install -y steghide
gem install zsteg || echo "zsteg installation failed - requires Ruby"

# Web
sudo apt install -y sqlmap nikto gobuster
pip3 install --user requests beautifulsoup4

# PWN
pip3 install --user pwntools ROPgadget
gem install one_gadget || echo "one_gadget installation failed"

# Reversing
sudo apt install -y radare2 gdb
pip3 install --user capstone keystone-engine unicorn

# OSINT
pip3 install --user sherlock-project theHarvester

# === TIER 3: Optional/Advanced ===
echo "Installing Tier 3 (Advanced) tools..."

# bkcrack (build from source)
if ! command -v bkcrack &> /dev/null; then
    echo "Building bkcrack..."
    git clone https://github.com/kimci86/bkcrack.git /tmp/bkcrack
    cd /tmp/bkcrack
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    sudo cp build/bkcrack /usr/local/bin/
    cd -
fi

# RsaCtfTool
if [ ! -d "$HOME/tools/RsaCtfTool" ]; then
    echo "Installing RsaCtfTool..."
    mkdir -p ~/tools
    git clone https://github.com/RsaCtfTool/RsaCtfTool.git ~/tools/RsaCtfTool
    pip3 install --user -r ~/tools/RsaCtfTool/requirements.txt
fi

# fcrackzip
sudo apt install -y fcrackzip

# ffuf
if ! command -v ffuf &> /dev/null; then
    echo "Installing ffuf..."
    go install github.com/ffuf/ffuf/v2@latest 2>/dev/null || echo "ffuf requires Go"
fi

echo ""
echo "=== Installation Complete ==="
echo "Run 'ctf check' to verify tool availability"
```

### Tool Verification

```python
# cli/check_tools.py

TOOL_REGISTRY = {
    "essential": {
        "file": {"binary": "file", "verify": "--version"},
        "strings": {"binary": "strings", "verify": "--version"},
        "xxd": {"binary": "xxd", "verify": "-v"},
        "python3": {"binary": "python3", "verify": "--version"},
        "tshark": {"binary": "tshark", "verify": "--version"},
    },
    "crypto": {
        "xortool": {"binary": "xortool", "verify": "--help"},
        "hashcat": {"binary": "hashcat", "verify": "--version"},
        "john": {"binary": "john", "verify": "--help"},
        "hashid": {"binary": "hashid", "verify": "--help"},
    },
    "archive": {
        "bkcrack": {"binary": "bkcrack", "verify": "--help"},
        "zip2john": {"binary": "zip2john", "verify": None},
        "fcrackzip": {"binary": "fcrackzip", "verify": "--version"},
    },
    "forensics": {
        "binwalk": {"binary": "binwalk", "verify": "--help"},
        "foremost": {"binary": "foremost", "verify": "-V"},
        "volatility3": {"binary": "vol", "verify": "--help"},
        "sleuthkit": {"binary": "fls", "verify": "-V"},
    },
    "stego": {
        "zsteg": {"binary": "zsteg", "verify": "--help"},
        "steghide": {"binary": "steghide", "verify": "--version"},
        "exiftool": {"binary": "exiftool", "verify": "-ver"},
    },
    "web": {
        "sqlmap": {"binary": "sqlmap", "verify": "--version"},
        "gobuster": {"binary": "gobuster", "verify": "version"},
        "ffuf": {"binary": "ffuf", "verify": "-V"},
    },
    "pwn": {
        "pwntools": {"python": "pwn", "verify": None},
        "ROPgadget": {"binary": "ROPgadget", "verify": "--version"},
        "one_gadget": {"binary": "one_gadget", "verify": "--version"},
    },
    "reversing": {
        "radare2": {"binary": "r2", "verify": "-v"},
        "gdb": {"binary": "gdb", "verify": "--version"},
    },
    "osint": {
        "sherlock": {"binary": "sherlock", "verify": "--help"},
        "exiftool": {"binary": "exiftool", "verify": "-ver"},
    }
}

def check_tools(category: str = None) -> Dict[str, Dict[str, bool]]:
    """Check which tools are installed"""
    results = {}

    categories = [category] if category else TOOL_REGISTRY.keys()

    for cat in categories:
        results[cat] = {}
        for tool_name, tool_info in TOOL_REGISTRY.get(cat, {}).items():
            if "binary" in tool_info:
                results[cat][tool_name] = shutil.which(tool_info["binary"]) is not None
            elif "python" in tool_info:
                try:
                    __import__(tool_info["python"])
                    results[cat][tool_name] = True
                except ImportError:
                    results[cat][tool_name] = False

    return results
```

---

## Tool Orchestration Patterns

### Pattern 1: Sequential Pipeline

```python
class SequentialPipeline:
    """Run tools in sequence, passing output forward"""

    def run_crypto_analysis(self, data: bytes):
        # 1. Identify encoding
        cyberchef = CyberChefIntegration()
        magic_result = cyberchef.magic(data)

        if magic_result.parsed_data.get("decodings"):
            # Apply detected decoding
            decoded = magic_result.parsed_data["decodings"][0]["decoded"]

            # 2. Check if XOR encrypted
            xortool = XORToolIntegration()
            key_analysis = xortool.analyze_key_length(decoded)

            if key_analysis.parsed_data.get("probable_key_lengths"):
                # 3. Attempt decryption
                decrypt_result = xortool.decrypt_with_char(decoded)
                return decrypt_result

        return magic_result
```

### Pattern 2: Parallel Analysis

```python
import concurrent.futures

class ParallelAnalyzer:
    """Run multiple tools in parallel"""

    def analyze_image(self, image_path: Path):
        tools = [
            (ZstegIntegration(), "analyze"),
            (ExiftoolIntegration(), "extract_all"),
            (BinwalkIntegration(), "scan"),
        ]

        results = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(getattr(tool, method), image_path): name
                for tool, method in tools
                for name in [tool.name]
            }

            for future in concurrent.futures.as_completed(futures):
                tool_name = futures[future]
                results[tool_name] = future.result()

        return results
```

### Pattern 3: Conditional Branching

```python
class ConditionalWorkflow:
    """Choose tools based on analysis results"""

    def analyze_archive(self, archive_path: Path):
        suffix = archive_path.suffix.lower()

        if suffix == ".zip":
            # Check encryption type
            bkcrack = BkcrackIntegration()
            info = bkcrack.list_entries(archive_path)

            if info.parsed_data.get("entries"):
                encrypted = any(e.get("encrypted") for e in info.parsed_data["entries"])

                if encrypted:
                    # Try known plaintext attack first
                    for entry in info.parsed_data["entries"]:
                        if entry["name"].endswith(".png"):
                            return bkcrack.attack_with_plaintext_bytes(
                                archive_path,
                                entry["name"],
                                bkcrack.KNOWN_HEADERS["png"]
                            )

                    # Fall back to password cracking
                    john = JohnIntegration()
                    hash_result = john.extract_hash(archive_path, "zip")
                    return john.crack(hash_result.artifacts[0])
```

---

## Summary: Tool Count by Category

| Category | Tools | Primary Use |
|----------|-------|-------------|
| **Crypto** | 6 | xortool, RsaCtfTool, SageMath, hashid, hashcat, john |
| **Archive** | 4 | bkcrack, john/*2john, fcrackzip, 7z |
| **Forensics** | 6 | binwalk, foremost, volatility3, sleuthkit, exiftool, strings |
| **Network** | 3 | tshark, tcpdump, NetworkMiner |
| **Stego** | 5 | zsteg, steghide, stegsolve, exiftool, binwalk |
| **Web** | 4 | sqlmap, gobuster, ffuf, nikto |
| **Pwn** | 4 | pwntools, ROPgadget, one_gadget, gdb |
| **Reversing** | 3 | radare2, ghidra, objdump |
| **OSINT** | 3 | sherlock, theHarvester, exiftool |
| **Encoding** | 1 | CyberChef (Python impl) |

**Total: ~40 integrated tools**

---

*This document provides the foundation for building comprehensive tool integrations in CTF Kit.*
