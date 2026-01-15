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
> /ctf.analyze
> /ctf.crypto rsa
```

---

## 🎯 Features

| Feature | Description |
|---------|-------------|
| **AI-Powered Analysis** | Automatic challenge categorization and vulnerability detection |
| **40+ Tool Integrations** | xortool, bkcrack, volatility, zsteg, RsaCtfTool, and more |
| **Multi-Agent Support** | Works with Claude Code, Cursor, Copilot, Gemini CLI |
| **Competition Workflow** | Designed for speed during live CTFs |
| **Writeup Generation** | Auto-generate writeups from your solve process |

---

## 🤖 Supported AI Agents

| Agent | Status | Notes |
|-------|--------|-------|
| [Claude Code](https://www.anthropic.com/claude-code) | ✅ | Primary development target |
| [Cursor](https://cursor.sh/) | ✅ | |
| [GitHub Copilot](https://github.com/features/copilot) | ✅ | |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | ✅ | |

---

## 📚 Slash Commands

### Core Commands

| Command | Description |
|---------|-------------|
| `/ctf.analyze` | Analyze challenge files and auto-detect category |
| `/ctf.approach` | Generate solution strategy |
| `/ctf.solve` | Execute solution attempts |
| `/ctf.writeup` | Generate writeup documentation |

### Category-Specific Commands

| Command | Tools Used |
|---------|------------|
| `/ctf.crypto` | xortool, RsaCtfTool, hashcat, john, SageMath |
| `/ctf.forensics` | volatility3, binwalk, foremost, sleuthkit, tshark |
| `/ctf.stego` | zsteg, steghide, exiftool, stegsolve |
| `/ctf.web` | sqlmap, gobuster, ffuf |
| `/ctf.pwn` | pwntools, ROPgadget, one_gadget |
| `/ctf.reverse` | radare2, ghidra (headless) |
| `/ctf.osint` | sherlock, theHarvester |
| `/ctf.misc` | CyberChef operations, encoding chains |

---

## 🔧 CLI Reference

```bash
# Initialize CTF Kit in repo (one-time)
ctf init --repo

# Initialize for a challenge
ctf init [--category <category>]

# Check installed tools
ctf check [--category <category>]

# Run a tool directly
ctf run <tool> [args...]

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

### Recommended

```bash
# Install common CTF tools
./scripts/install-tools.sh

# Or install specific categories
ctf install --category crypto
ctf install --category forensics
```

---

## 📖 Documentation

- [Competition Workflow Guide](docs/plan/competition-workflow.md)
- [Tool Integrations](docs/plan/tool-integrations.md)
- [Skills Analysis](docs/plan/skills-analysis.md)

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.
