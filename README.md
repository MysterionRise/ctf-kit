<div align="center">
    <h1>🏴 CTF Kit</h1>
    <h3><em>Solve CTF challenges faster with AI assistance.</em></h3>
</div>

<p align="center">
    <strong>A toolkit that integrates with AI coding agents to help you analyze, solve, and document CTF challenges.</strong>
</p>

---

## ⚡ Quick Start

### 1. Install the Claude Code Plugin

Inside Claude Code, add the marketplace and install the plugin:

```bash
/plugin marketplace add MysterionRise/ctf-kit
/plugin install ctf-kit@ctf-kit
```

Or from a local checkout:

```bash
/plugin marketplace add /path/to/ctf-kit
/plugin install ctf-kit@ctf-kit
```

This makes all `/ctf-kit:*` skills available in **any** project.

After pulling new changes, refresh with `/plugin marketplace update ctf-kit`.
For plugin development, load the checkout for a single session with
`claude --plugin-dir /path/to/ctf-kit`.

### 2. Install the CLI (optional)

```bash
uv tool install ctf-kit --from git+https://github.com/MysterionRise/ctf-kit.git
```

### 3. Initialize in your CTF repo

```bash
cd ~/ctf-dangerzone-2026
ctf init --repo
```

### 4. Start solving challenges

```bash
cd competitions/somectf/crypto-challenge
ctf init

# Launch your AI agent
claude

# Use slash commands (plugin format)
> /ctf-kit:analyze challenge.bin
> /ctf-kit:crypto
```

---

## 🎯 Features

| Feature | Description |
|---------|-------------|
| **AI-Powered Analysis** | Automatic challenge categorization and vulnerability detection |
| **20+ Tool Integrations** | xortool, binwalk, volatility, zsteg, RsaCtfTool, and more |
| **Claude Code Plugin** | Install once, use `/ctf-kit:*` skills in any project |
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

### Claude Code Plugin Skills (`/ctf-kit:*`)

AI-powered skills available in any project after installing the plugin:

| Command | What it does |
|---------|--------------|
| `/ctf-kit:analyze` | Analyzes files, detects challenge type, suggests next steps |
| `/ctf-kit:crypto` | Guides crypto challenges (RSA, XOR, hashing, etc.) |
| `/ctf-kit:forensics` | Memory dumps, PCAPs, disk images, file carving |
| `/ctf-kit:stego` | Hidden data in images, audio, and other media |
| `/ctf-kit:web` | SQLi, XSS, directory enumeration, auth bypass |
| `/ctf-kit:pwn` | Binary exploitation, ROP chains, format strings |
| `/ctf-kit:reverse` | Static/dynamic analysis, decompilation |
| `/ctf-kit:osint` | Username enumeration, domain recon |
| `/ctf-kit:misc` | Encoding chains, esoteric languages, QR codes |

The skills run the CLI tools under the hood and help you interpret results.

---

## 💡 Usage Examples

### Example 1: Crypto Challenge

```bash
# Start Claude Code in your challenge directory
cd competitions/somectf/rsa-challenge
claude

# In Claude Code:
> /ctf-kit:analyze encrypted.txt public_key.pem
# Output: Detected RSA challenge with small public exponent

> /ctf-kit:crypto
# Claude guides you through attacking the weak RSA parameters
```

### Example 2: Forensics Challenge

```bash
cd competitions/somectf/memory-dump
claude

> /ctf-kit:analyze memory.raw
# Output: Detected memory dump (Windows), suggests volatility3

> /ctf-kit:forensics
# Claude helps extract credentials, processes, and artifacts
```

### Example 3: Steganography

```bash
cd competitions/somectf/hidden-message
claude

> /ctf-kit:analyze image.png
# Output: PNG image, suggests checking for LSB steganography

> /ctf-kit:stego
# Claude runs zsteg, exiftool, and other tools to find hidden data
```

---

## 📚 Skills Reference

### Analysis

| Command | Description |
|---------|-------------|
| `/ctf-kit:analyze` | Analyze challenge files and auto-detect category |

### Category-Specific

| Command | Tools Used |
|---------|------------|
| `/ctf-kit:crypto` | xortool, RsaCtfTool, hashcat, john |
| `/ctf-kit:forensics` | volatility3, binwalk, foremost, tshark |
| `/ctf-kit:stego` | zsteg, steghide, exiftool |
| `/ctf-kit:web` | sqlmap, gobuster, ffuf |
| `/ctf-kit:pwn` | checksec, ROPgadget |
| `/ctf-kit:reverse` | radare2, ghidra (headless) |
| `/ctf-kit:osint` | sherlock, theHarvester |
| `/ctf-kit:misc` | Encoding detection, file analysis |

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

### Python Version

CTF Kit requires **Python 3.11+**. A runtime check will raise `RuntimeError` on older versions.

#### Using uv (recommended)

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and install
git clone https://github.com/MysterionRise/ctf-kit.git
cd ctf-kit
uv sync --dev          # Reads .python-version (3.14) and installs deps
uv run pytest          # Run tests
```

#### Using pyenv

```bash
# Install pyenv (macOS)
brew install pyenv

# Install the pinned Python version
pyenv install 3.14      # Or any 3.11+
pyenv local 3.14         # Sets .python-version

# Then use uv or pip
uv sync --dev
# or: pip install -e ".[dev]"
```

Contributions welcome! Please open an issue or pull request.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.
