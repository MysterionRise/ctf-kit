<div align="center">
    <h1>🏴 CTF Kit</h1>
    <h3><em>Solve CTF challenges faster with AI assistance.</em></h3>
</div>

<p align="center">
    <strong>A toolkit that integrates with AI coding agents to help you analyze, solve, and document CTF challenges.</strong>
</p>

---

## ⚡ Quick Start

### 1. Install CTF Kit

```bash
uv tool install ctf-kit --from git+https://github.com/MysterionRise/ctf-kit.git
```

### 2. Initialize in your CTF repo

```bash
cd ~/ctf-dangerzone-2026
ctf init --repo
```

### 3. Start solving challenges

```bash
cd competitions/somectf/crypto-challenge
ctf init

# Launch your AI agent (Claude Code, Cursor, Copilot, etc.)
claude

# Use slash commands
> /ctf-analyze challenge.bin
> /ctf-crypto
```

---

## 🎯 Features

| Feature | Description |
|---------|-------------|
| **AI-Powered Analysis** | Automatic challenge categorization and vulnerability detection |
| **20+ Tool Integrations** | xortool, binwalk, volatility, zsteg, RsaCtfTool, and more |
| **Claude Code Integration** | Native slash commands for challenge-solving workflows |
| **Competition Workflow** | Designed for speed during live CTFs |
| **Writeup Generation** | Auto-generate writeups from your solve process |

---

## 🔄 How It Works

CTF Kit has a two-tier architecture:

### CLI Commands (`ctf`)

The standalone CLI for direct tool access:

```bash
ctf analyze challenge.bin    # Analyze files and detect category
ctf check --category crypto  # Check which crypto tools are installed
ctf run xortool file.enc     # Run a specific tool directly
ctf tools                    # List all available tools
```

### Claude Code Commands (`/ctf-*`)

AI-powered slash commands that guide you through solving challenges:

| Command | What it does |
|---------|--------------|
| `/ctf-analyze` | Analyzes files, detects challenge type, suggests next steps |
| `/ctf-crypto` | Guides crypto challenges (RSA, XOR, hashing, etc.) |
| `/ctf-forensics` | Memory dumps, PCAPs, disk images, file carving |
| `/ctf-stego` | Hidden data in images, audio, and other media |
| `/ctf-web` | SQLi, XSS, directory enumeration, auth bypass |
| `/ctf-pwn` | Binary exploitation, ROP chains, format strings |
| `/ctf-reverse` | Static/dynamic analysis, decompilation |
| `/ctf-osint` | Username enumeration, domain recon |
| `/ctf-misc` | Encoding chains, esoteric languages, QR codes |

The slash commands run the CLI tools under the hood and help you interpret results.

---

## 💡 Usage Examples

### Example 1: Crypto Challenge

```bash
# Start Claude Code in your challenge directory
cd competitions/somectf/rsa-challenge
claude

# In Claude Code:
> /ctf-analyze encrypted.txt public_key.pem
# Output: Detected RSA challenge with small public exponent

> /ctf-crypto
# Claude guides you through attacking the weak RSA parameters
```

### Example 2: Forensics Challenge

```bash
cd competitions/somectf/memory-dump
claude

> /ctf-analyze memory.raw
# Output: Detected memory dump (Windows), suggests volatility3

> /ctf-forensics
# Claude helps extract credentials, processes, and artifacts
```

### Example 3: Steganography

```bash
cd competitions/somectf/hidden-message
claude

> /ctf-analyze image.png
# Output: PNG image, suggests checking for LSB steganography

> /ctf-stego
# Claude runs zsteg, exiftool, and other tools to find hidden data
```

---

## 📚 Slash Commands Reference

### Analysis

| Command | Description |
|---------|-------------|
| `/ctf-analyze` | Analyze challenge files and auto-detect category |

### Category-Specific

| Command | Tools Used |
|---------|------------|
| `/ctf-crypto` | xortool, RsaCtfTool, hashcat, john |
| `/ctf-forensics` | volatility3, binwalk, foremost, tshark |
| `/ctf-stego` | zsteg, steghide, exiftool |
| `/ctf-web` | sqlmap, gobuster, ffuf |
| `/ctf-pwn` | checksec, ROPgadget |
| `/ctf-reverse` | radare2, ghidra (headless) |
| `/ctf-osint` | sherlock, theHarvester |
| `/ctf-misc` | Encoding detection, file analysis |

---

## 🔧 CLI Reference

```bash
# Initialize CTF Kit in repo (one-time)
ctf init --repo

# Initialize for a challenge
ctf init [--category <category>]

# Analyze challenge files
ctf analyze <path> [--verbose]

# Check installed tools
ctf check [--category <category>]

# List all tools and their status
ctf tools

# Run a tool directly
ctf run <tool> [args...]

# Create a new challenge folder
ctf new <name> [--category <category>]

# Generate writeup
ctf writeup [--format md|html]
```

---

## 📁 Project Structure

CTF Kit integrates with your existing workflow:

```text
your-ctf-repo/
├── .ctf-kit/                    # Repo-level config (one-time)
│   └── config.yaml
└── competitions/
    └── somectf2026/
        └── crypto-challenge/
            ├── .ctf/            # CTF Kit memory (per-challenge)
            │   ├── analysis.md
            │   └── writeup.md
            ├── challenge.txt    # Your files (unchanged)
            └── solve.py         # Your solution (unchanged)
```

---

## 🛠️ Tool Requirements

### Essential (auto-checked)

- Python 3.11+
- file, strings, xxd

### Check Installed Tools

```bash
# See all tools and their installation status
ctf tools

# Check specific category
ctf check --category crypto
ctf check --category forensics
```

---

## 📖 Documentation

- [Project Plan](docs/plan/ctf-kit-project-plan.md)
- [Competition Workflow Guide](docs/plan/ctf-kit-competition-workflow.md)
- [Tool Integrations](docs/plan/ctf-kit-tool-integrations.md)
- [Skills Analysis](docs/plan/ctf-kit-skills-analysis.md)

---

## 🤝 Contributing

Contributions welcome! Please open an issue or pull request.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.
