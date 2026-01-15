# CTF Kit - Competition Workflow Guide

> How CTF Kit integrates with your existing monorepo workflow

---

## Your Existing Structure (Preserved!)

CTF Kit is designed to **work with your existing workflow**, not replace it.

```
ctf-dangerzone-2026/                    # Your yearly repo
├── .venv/                              # Your Python environment (unchanged)
├── .ctf-kit/                           # NEW: Repo-level config (one-time setup)
│   ├── config.yaml                     # Global settings, API keys, tool paths
│   ├── templates/                      # Your custom templates
│   └── wordlists/                      # Shared wordlists
│
└── competitions/
    ├── amateursCTF2026/                # Competition folder (you create as usual)
    │   ├── .ctf-competition.yaml       # NEW: Optional competition metadata
    │   │
    │   ├── addition2/                  # Challenge folder (you create as usual)
    │   │   ├── .ctf/                   # NEW: CTF Kit memory for this challenge
    │   │   │   ├── analysis.md
    │   │   │   ├── approach.md
    │   │   │   └── writeup.md
    │   │   ├── challenge.txt           # Your files (unchanged)
    │   │   ├── solve.py                # Your solution (unchanged)
    │   │   └── flag.txt                # Your flag (unchanged)
    │   │
    │   ├── aescure/
    │   │   ├── .ctf/
    │   │   └── ...
    │   └── ...
    │
    ├── bcactf-2026/
    └── ...
```

**Key principle**: CTF Kit adds `.ctf/` folders inside your existing challenge folders. Your structure stays exactly as you like it.

---

## Initial Setup (Once Per Year)

### Step 1: Create your yearly repo as usual

```bash
mkdir ctf-dangerzone-2026
cd ctf-dangerzone-2026
git init
python -m venv .venv
source .venv/bin/activate
mkdir competitions
```

### Step 2: Initialize CTF Kit at repo level

```bash
ctf init --repo
```

This creates:
```
.ctf-kit/
├── config.yaml          # Your preferences
├── templates/           # Writeup templates, etc.
└── skills/              # AI agent skills (auto-downloaded)
```

**config.yaml** example:
```yaml
# CTF Kit Configuration
version: "1.0"

# Your preferred AI agent
ai_agent: claude  # or: copilot, gemini, cursor

# Default flag format (regex) - used for auto-detection
flag_formats:
  - "flag{.*}"
  - "CTF{.*}"
  - "picoCTF{.*}"

# Tool paths (if not in PATH)
tools:
  ghidra: /opt/ghidra
  ida: null  # Not installed

# API keys for services (or use env vars)
api_keys:
  shodan: ${SHODAN_API_KEY}
  virustotal: ${VT_API_KEY}

# Your preferences
preferences:
  auto_commit: false           # Don't auto-commit solutions
  writeup_format: markdown     # or: html, latex
  include_failed_attempts: true
```

---

## Competition Day Workflow

### Scenario: AmateursCTF 2026 just started!

#### Step 1: Create competition folder (your normal workflow)

```bash
cd competitions
mkdir amateursCTF2026
cd amateursCTF2026
```

#### Step 2: (Optional) Register competition with CTF Kit

```bash
ctf competition init --name "AmateursCTF 2026" --url "https://ctf.example.com" --flag-format "amateursCTF{.*}"
```

This creates `.ctf-competition.yaml`:
```yaml
name: AmateursCTF 2026
url: https://ctf.example.com
start_time: 2026-01-15T00:00:00Z
flag_format: "amateursCTF{.*}"
challenges_solved: 0
total_points: 0
```

**This step is optional** - you can skip it and just create challenge folders directly.

---

### Scenario: You download a crypto challenge "rsa-baby"

#### Step 1: Create challenge folder (your normal workflow)

```bash
mkdir rsa-baby
cd rsa-baby
# Download/copy challenge files
wget https://ctf.example.com/files/rsa-baby.zip
unzip rsa-baby.zip
```

Your folder now has:
```
rsa-baby/
├── challenge.txt
├── output.txt
└── encrypt.py
```

#### Step 2: Initialize CTF Kit for this challenge

```bash
ctf init
```

Or with category hint:
```bash
ctf init --category crypto
```

This creates:
```
rsa-baby/
├── .ctf/
│   ├── analysis.md      # Will be filled by AI
│   ├── approach.md      # Will be filled by AI
│   ├── attempts.md      # Track what you've tried
│   └── artifacts/       # Extracted files, decoded data
├── challenge.txt
├── output.txt
└── encrypt.py
```

#### Step 3: Launch your AI agent and analyze

```bash
# If using Claude Code
claude

# If using Cursor
cursor .

# If using GitHub Copilot in VS Code
code .
```

Now use the slash commands:

```
/ctf.analyze

AI Response:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Challenge: rsa-baby
📂 Category: Crypto (RSA)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Files detected:
  • challenge.txt - Challenge description
  • output.txt - Contains n, e, c values
  • encrypt.py - Encryption script

Initial Analysis:
  • RSA encryption with small public exponent (e=3)
  • n = 1234567890... (2048 bits)
  • Potential vulnerability: Small e attack (cube root)

Suggested approach:
  1. Check if c^(1/3) gives plaintext directly
  2. If not, try Håstad's broadcast attack
  3. Check FactorDB for known factorization

Required tools: ✅ gmpy2, ✅ pycryptodome

Shall I proceed with the cube root attack?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

#### Step 4: Let AI help solve

```
/ctf.crypto rsa

AI: Running RSA analysis...

[Tool: RsaCtfTool] Checking for vulnerabilities...
[Tool: FactorDB] Checking if n is in database...
[Tool: gmpy2] Attempting cube root attack...

✅ SUCCESS! Cube root attack worked.

Decrypted message: amateursCTF{sm4ll_e_1s_d4ng3r0us}

Writing solution to solve.py...
```

#### Step 5: Save your flag and move on

```bash
echo "amateursCTF{sm4ll_e_1s_d4ng3r0us}" > flag.txt
git add -A && git commit -m "Solve rsa-baby (crypto)"
```

---

## Quick Commands Reference

### During Competition (Speed Mode)

```bash
# In competition folder - create and analyze new challenge quickly
ctf new forensics/memory-dump
# Creates: forensics/memory-dump/.ctf/ and opens AI agent

# Quick analyze without full init
ctf analyze .

# Check what tools you need for a challenge type
ctf tools --category forensics

# Run specific tool directly
ctf run volatility pslist memory.dmp
ctf run zsteg -a image.png
ctf run bkcrack -L encrypted.zip
```

### Slash Commands (In AI Agent)

| Command | Use When |
|---------|----------|
| `/ctf.analyze` | First look at a challenge |
| `/ctf.approach` | After analysis, plan your attack |
| `/ctf.solve` | Execute solution attempts |
| `/ctf.crypto` | Crypto-specific tools (xortool, RsaCtfTool, etc.) |
| `/ctf.forensics` | Forensics analysis (volatility, binwalk, etc.) |
| `/ctf.stego` | Steganography (zsteg, steghide, etc.) |
| `/ctf.web` | Web exploitation |
| `/ctf.pwn` | Binary exploitation |
| `/ctf.osint` | OSINT investigation |
| `/ctf.writeup` | Generate writeup after solving |

---

## Realistic Competition Timeline

### Hour 0: Competition starts

```bash
cd ~/projects/ctf-dangerzone-2026/competitions
mkdir newctf2026 && cd newctf2026
ctf competition init --name "NewCTF 2026"
```

### Hour 0-1: Grab easy challenges

```bash
# Quick crypto challenge
mkdir crypto/base64-hell && cd crypto/base64-hell
# paste challenge content
ctf init && claude
> /ctf.analyze
> /ctf.crypto decode   # AI chains Base64 -> ROT13 -> Hex -> Flag
# Solved in 2 minutes!

cd ../..
mkdir misc/sanity-check && cd misc/sanity-check
# ... repeat
```

### Hour 1-4: Medium challenges

```bash
mkdir forensics/memory-mystery && cd forensics/memory-mystery
wget challenge-files.zip && unzip challenge-files.zip
ctf init --category forensics

# In AI agent:
> /ctf.analyze
# AI: Memory dump detected. Running volatility3 to identify OS...
# AI: Windows 10 memory dump. Found suspicious process "evil.exe" (PID 1337)
# AI: Extracting process memory...

> /ctf.forensics memory --dump-process 1337
# AI extracts process, finds encrypted config

> /ctf.crypto analyze extracted_config.bin
# AI identifies XOR encryption, runs xortool
# Flag found!
```

### Hour 4+: Hard challenges (iterative)

```bash
mkdir pwn/heap-hell && cd pwn/heap-hell
ctf init --category pwn

# AI helps with analysis but you drive the exploitation
> /ctf.analyze
# AI: Binary analysis complete. Protections: Full RELRO, Canary, NX, PIE
# AI: Detected heap operations. Potential tcache poisoning.

> /ctf.pwn checksec
> /ctf.pwn template   # Generates pwntools exploit template

# You work on exploit, AI helps debug
> The exploit crashes at this point: [paste error]
# AI: The offset looks wrong. Based on the decompilation, try offset 0x48 instead of 0x40
```

---

## Folder Structure After a Competition

```
competitions/amateursCTF2026/
├── .ctf-competition.yaml
│
├── crypto/
│   ├── rsa-baby/
│   │   ├── .ctf/
│   │   │   ├── analysis.md      # AI's analysis
│   │   │   ├── approach.md      # Solution strategy
│   │   │   ├── attempts.md      # What was tried
│   │   │   └── writeup.md       # Final writeup
│   │   ├── challenge.txt
│   │   ├── output.txt
│   │   ├── encrypt.py
│   │   ├── solve.py             # Your solution script
│   │   └── flag.txt             # The flag
│   │
│   └── aes-secure/
│       └── ...
│
├── forensics/
│   └── memory-mystery/
│       ├── .ctf/
│       │   └── artifacts/       # Extracted files
│       │       ├── evil.exe
│       │       └── config.bin
│       ├── memory.dmp
│       └── solve.py
│
├── pwn/
│   └── heap-hell/
│       ├── .ctf/
│       ├── vuln
│       ├── libc.so.6
│       └── exploit.py
│
└── web/
    └── sqli-101/
        └── ...
```

---

## Post-Competition: Generate Writeups

```bash
# Generate writeups for all solved challenges
cd competitions/amateursCTF2026
ctf writeup --all --format markdown --output writeups/

# Or for a specific challenge
cd crypto/rsa-baby
ctf writeup --format markdown
```

Generated writeup includes:
- Challenge description
- Your analysis notes
- Solution approach
- Code snippets
- What you learned

---

## Configuration Options

### Minimal Setup (Just start using it)

```bash
ctf init  # In any challenge folder, that's it!
```

### Full Setup (Recommended for serious CTF players)

```yaml
# .ctf-kit/config.yaml

# Competition defaults
defaults:
  organize_by_category: true    # Auto-create crypto/, pwn/, etc. folders
  auto_init_challenges: true    # Run ctf init when entering new folder

# Solve tracking
tracking:
  log_time_spent: true
  log_tools_used: true
  export_to_ctftime: true       # Auto-update CTFTime profile

# Writeup generation
writeups:
  auto_generate: true           # Generate after each solve
  include_code: true
  include_failed_attempts: false
  template: "default"           # or path to custom template
```

---

## FAQ

### Q: Do I have to change my existing folder structure?
**A: No!** CTF Kit adds `.ctf/` folders inside your existing structure. Your workflow stays the same.

### Q: What if I don't want to use the AI features?
**A: That's fine!** You can use just the CLI tools:
```bash
ctf run zsteg image.png
ctf run bkcrack -L file.zip
ctf run volatility -f dump.raw windows.pslist
```

### Q: Can I use CTF Kit during live competitions?
**A: Yes, that's the primary use case.** The tool is designed for speed during competitions, then more detailed analysis/writeups after.

### Q: What if a challenge doesn't fit a category?
**A: Use `/ctf.analyze` and it will auto-detect**, or use `/ctf.misc` for challenges that don't fit neatly.

### Q: How does it handle challenges I've already solved?
**A: CTF Kit doesn't overwrite your work.** If you already have a `solve.py` or `flag.txt`, it will use those as context.

### Q: Can teammates use it simultaneously?
**A: Yes!** Each person's `.ctf/` analysis is local. You can share approaches via git:
```bash
git add crypto/rsa-baby/.ctf/approach.md
git commit -m "Share approach for rsa-baby"
git push
```

---

## Comparison: With vs Without CTF Kit

### Without CTF Kit (Your Current Flow)

```bash
mkdir rsa-baby && cd rsa-baby
# Download files
cat output.txt
# Hmm, RSA... let me try factordb manually
# Open browser, paste n, not found
# Try RsaCtfTool... what were the flags again?
python3 ~/tools/RsaCtfTool/RsaCtfTool.py --help
python3 ~/tools/RsaCtfTool/RsaCtfTool.py -n 123... -e 3 --attack smallfraction
# Didn't work, try another attack...
# 30 minutes later, try cube root manually
python3 -c "import gmpy2; print(gmpy2.iroot(c, 3))"
# Got it!
```

### With CTF Kit

```bash
mkdir rsa-baby && cd rsa-baby
# Download files
ctf init && claude

> /ctf.crypto rsa
# AI: Small e detected (e=3). Running cube root attack...
# AI: ✅ Flag found: CTF{...}
# 30 seconds later, solved.
```

The difference: **CTF Kit automates the "which tool, which flags, which attack" decision tree** that you normally do mentally.

---

## Alternative: Flat Structure (If You Prefer)

If you prefer flat challenge folders without category subfolders:

```
competitions/amateursCTF2026/
├── rsa-baby/           # No crypto/ prefix
├── memory-mystery/     # No forensics/ prefix
├── heap-hell/
└── sqli-101/
```

CTF Kit works exactly the same way. Category detection is automatic based on file analysis, not folder names.

---

## Shell Integration (Optional Power Feature)

Add to your `.bashrc` or `.zshrc`:

```bash
# Auto-init CTF Kit when entering a challenge folder
ctf_auto_init() {
    if [[ -f "challenge.txt" || -f "*.zip" ]] && [[ ! -d ".ctf" ]]; then
        echo "💡 CTF challenge detected. Run 'ctf init' to start analysis."
    fi
}

# Hook into cd
cd() {
    builtin cd "$@" && ctf_auto_init
}

# Quick aliases
alias ca="ctf analyze"
alias ci="ctf init"
alias cr="ctf run"
```

---

*CTF Kit: Keep your workflow. Accelerate your solving.*
