# CTF Kit

A CLI and a Claude Code plugin for working through CTF challenges with an AI coding agent.
The CLI wraps about 30 common security tools (xortool, binwalk, volatility3, zsteg, RsaCtfTool,
sqlmap and others) behind one interface; the plugin adds `/ctf-kit:*` skills that run those tools
and help you read the results.

## Quick start

### 1. Install the Claude Code plugin

Inside Claude Code:

```bash
/plugin install --from https://github.com/MysterionRise/ctf-kit
```

Or from a local checkout:

```bash
/plugin install --from /path/to/ctf-kit
```

The `/ctf-kit:*` skills are then available in every project.

### 2. Install the CLI (optional)

```bash
uv tool install ctf-kit --from git+https://github.com/MysterionRise/ctf-kit.git
```

### 3. Initialise your CTF repo

```bash
cd ~/your-ctf-repo
ctf init --repo
```

### 4. Work on a challenge

```bash
cd competitions/somectf/crypto-challenge
ctf init

claude
> /ctf-kit:analyze challenge.bin
> /ctf-kit:crypto
```

## How it works

There are two layers. The `ctf` CLI calls the tools directly. The plugin skills call the CLI and
help you interpret its output inside Claude Code.

### Skills

| Command | What it covers | Tools it uses |
|---------|----------------|---------------|
| `/ctf-kit:analyze` | Detects the challenge type and suggests next steps | file, strings, category detection |
| `/ctf-kit:crypto` | RSA, XOR, hashing | xortool, RsaCtfTool, hashcat, john |
| `/ctf-kit:forensics` | Memory dumps, PCAPs, disk images, file carving | volatility3, binwalk, foremost, tshark |
| `/ctf-kit:stego` | Hidden data in images, audio and other media | zsteg, steghide, exiftool |
| `/ctf-kit:web` | SQLi, XSS, directory enumeration, auth bypass | sqlmap, gobuster, ffuf |
| `/ctf-kit:pwn` | Binary exploitation, ROP chains, format strings | checksec, ROPgadget |
| `/ctf-kit:reverse` | Static and dynamic analysis, decompilation | radare2, ghidra (headless) |
| `/ctf-kit:osint` | Username enumeration, domain recon | sherlock, theHarvester |
| `/ctf-kit:misc` | Encoding chains, esoteric languages, QR codes | encoding detection, file analysis |

### CLI

```bash
ctf init --repo                     # one-time setup for a CTF repo
ctf init [--category <category>]    # set up a challenge folder
ctf new <name> [--category <cat>]   # create a new challenge folder
ctf analyze <path> [--verbose]      # inspect files and guess the category
ctf check [--category <category>]   # which tools are installed
ctf tools                           # all tools and their status
ctf run <tool> [args...]            # run one tool directly
ctf writeup                         # Markdown writeup from the .ctf/ notes (HTML not yet)
```

### Example

The output lines below are illustrative, not captured from a real run.

```bash
cd competitions/somectf/rsa-challenge
claude

> /ctf-kit:analyze encrypted.txt public_key.pem
# e.g. "RSA challenge, small public exponent"

> /ctf-kit:crypto
# walks through attacks on the weak parameters, running RsaCtfTool where it applies
```

## What it writes

CTF Kit leaves your files alone and keeps its notes next to them:

```text
your-ctf-repo/
├── .ctf-kit/                    # repo-level config (one-time)
│   └── config.yaml
└── competitions/
    └── somectf2026/
        └── crypto-challenge/
            ├── .ctf/            # per-challenge notes
            │   ├── analysis.md
            │   └── writeup.md
            ├── challenge.txt    # your files
            └── solve.py         # your solution
```

## Requirements

Python 3.11+ and the basic `file`, `strings` and `xxd` utilities. Everything else is optional;
`ctf tools` and `ctf check --category <category>` show what is installed.

## Scope and limits

- Use it on CTF challenges and systems you are authorised to test. Several wrapped tools
  (sqlmap, gobuster, ffuf, nikto) send traffic to whatever target you give them.
- Tools run locally with your permissions; there is no sandbox.
- Category detection and the agent's suggestions are hints and can be wrong. Check results
  before relying on them, especially during a live competition.

## Documentation

Design and planning notes:

- [Project plan](docs/plan/ctf-kit-project-plan.md)
- [Competition workflow](docs/plan/ctf-kit-competition-workflow.md)
- [Tool integrations](docs/plan/ctf-kit-tool-integrations.md)
- [Skills analysis](docs/plan/ctf-kit-skills-analysis.md)

## Contributing

Setup, quality checks and workflow are in [DEVELOPMENT.md](DEVELOPMENT.md). Issues and pull
requests are welcome.

## License

MIT, see [LICENSE](LICENSE).
