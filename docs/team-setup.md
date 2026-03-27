# CTF Kit Team Setup Guide

How to set up CTF Kit with multi-agent teams in your CTF workspace.

## Quick Start

### 1. Install the Plugin

In your CTF workspace (the repo where you solve challenges):

```text
/plugin install --from https://github.com/MysterionRise/ctf-kit
```

This makes all `/ctf-kit:*` skills available globally.

### 2. Enable Agent Teams

Create or update `.claude/settings.json` in your CTF workspace:

```json
{
  "env": {
    "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1"
  },
  "permissions": {
    "allow": [
      "Read",
      "Edit",
      "Write",

      "Bash(file *)",
      "Bash(strings *)",
      "Bash(xxd *)",
      "Bash(hexdump *)",
      "Bash(binwalk *)",
      "Bash(foremost *)",
      "Bash(exiftool *)",
      "Bash(zsteg *)",
      "Bash(steghide *)",

      "Bash(python *)",
      "Bash(python3 *)",
      "Bash(pip install *)",
      "Bash(pip3 install *)",
      "Bash(sage *)",

      "Bash(xortool *)",
      "Bash(xortool-xor *)",
      "Bash(hashid *)",
      "Bash(hashcat *)",
      "Bash(john *)",
      "Bash(RsaCtfTool *)",
      "Bash(openssl *)",

      "Bash(volatility3 *)",
      "Bash(vol.py *)",
      "Bash(tshark *)",

      "Bash(checksec *)",
      "Bash(ROPgadget *)",
      "Bash(one_gadget *)",
      "Bash(r2 *)",
      "Bash(radare2 *)",
      "Bash(rabin2 *)",
      "Bash(objdump *)",
      "Bash(readelf *)",
      "Bash(nm *)",
      "Bash(ltrace *)",
      "Bash(strace *)",

      "Bash(zbarimg *)",
      "Bash(qrencode *)",

      "Bash(ctf *)",
      "Bash(bash *scripts/*)",
      "Bash(ls *)",
      "Bash(cat *)",
      "Bash(head *)",
      "Bash(tail *)",
      "Bash(wc *)",
      "Bash(sort *)",
      "Bash(uniq *)",
      "Bash(grep *)",
      "Bash(find *)",
      "Bash(mkdir *)",
      "Bash(cp *)",
      "Bash(mv *)",
      "Bash(base64 *)",
      "Bash(sha256sum *)",
      "Bash(md5sum *)",

      "Bash(git status *)",
      "Bash(git diff *)",
      "Bash(git log *)",
      "Bash(git add *)",
      "Bash(git commit *)"
    ],
    "deny": [
      "Bash(rm -rf /*)",
      "Bash(rm -rf ~*)",
      "Bash(sudo *)"
    ]
  }
}
```

### 3. Directory Structure

Organize your CTF workspace like this:

```text
my-ctf-workspace/
├── .claude/
│   └── settings.json          # From step 2
├── competition-name/
│   ├── crypto-100/
│   │   ├── challenge.enc
│   │   └── pubkey.pem
│   ├── web-200/
│   │   └── README.md          # Contains target URL
│   ├── forensics-300/
│   │   └── memory.raw
│   └── ...
└── CLAUDE.md                  # Optional: competition-specific instructions
```

### 4. Using Team Solve (Single Challenge)

Navigate to a challenge directory and invoke team-solve:

```text
/ctf-kit:team-solve challenge.enc
```

The skill will:

1. Triage the challenge files
2. Determine the best 3-teammate composition
3. Instruct you (the lead) on how to spawn the team

### 5. Using Competition Mode (Multiple Challenges)

From the competition root directory:

```text
/ctf-kit:compete
```

The skill will:

1. Scan all challenge subdirectories
2. Auto-triage each challenge
3. Build a priority queue
4. Spawn 3 generalist teammates
5. Auto-assign challenges from the queue

## Permission Tiers

### Tier 1: Local Analysis (auto-allowed)

These tools only read local files. Safe for all teammates:

| Tool | Purpose |
|------|---------|
| file, strings, xxd | Basic file inspection |
| binwalk, foremost | File carving and extraction |
| exiftool | Metadata extraction |
| zsteg, steghide | Steganography analysis |
| hashid, xortool | Crypto identification |
| volatility3, tshark | Forensic analysis |
| checksec, ROPgadget | Binary analysis |
| radare2, objdump | Disassembly |
| zbarimg | QR/barcode reading |

### Tier 2: Target Interaction (plan approval)

These tools connect to external targets. Teammates using them should be spawned with **plan approval required**:

| Tool | Risk | Mitigation |
|------|------|------------|
| sqlmap | Can modify target DB | Lead reviews target URL and flags |
| gobuster, ffuf | Can DoS with aggressive scanning | Lead sets rate limits |
| nikto | Active scanning, triggers alerts | Lead reviews scope |
| pwntools (remote) | Sends exploit to target | Lead reviews payload |
| curl/wget to targets | Sends requests | Lead reviews before first request |

### Tier 3: External Services (user confirmation)

These hit third-party services. User should confirm scope:

| Tool | Service |
|------|---------|
| sherlock | Queries 300+ social platforms |
| theHarvester | Queries search engines, DNS |
| hashcat --gpu | Resource-intensive, not a security risk |

## Optional: CLAUDE.md for Your Workspace

Add a `CLAUDE.md` at your workspace root with competition-specific instructions:

```markdown
# Competition: ExampleCTF 2026

## Flag Format
Flag format is `flag{...}` (case-sensitive)

## Target Scope
- Web challenges: only target *.example-ctf.com
- Do NOT scan any other domains
- Rate limit: max 10 requests/second

## Team Preferences
- Use 3 teammates for team-solve
- Speed over thoroughness
- Try easy challenges first
- Broadcast all flags immediately to the lead

## Known Info
- Challenges unlock in waves (check for new ones periodically)
- Some challenges share themes (cross-reference findings)
```

This file is automatically loaded by all teammates when they spawn.

## Troubleshooting

### Skills not found after plugin install

Verify the plugin is installed:

```text
/plugin list
```

If ctf-kit is not listed, reinstall:

```text
/plugin install --from https://github.com/MysterionRise/ctf-kit
```

### Agent teams not spawning

Check that the env var is set:

```bash
echo $CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS
```

Should output `1`. If not, verify `.claude/settings.json` has the `env` block.

### Teammates can't run tools

Teammates inherit the lead's permissions. Make sure your `.claude/settings.json` allows the tools you need (see the permissions block in Step 2).

### Too many permission prompts during competition

Pre-approve all Tier 1 tools in settings.json. For Tier 2, use plan-approval mode instead of per-action prompts — the lead reviews once, then the teammate proceeds.

### tmux / split pane issues

For live CTFs, in-process mode is recommended (simpler, fewer issues):

```json
{
  "teammateMode": "in-process"
}
```

Or use split panes for better visibility:

```json
{
  "teammateMode": "tmux"
}
```

Install tmux: `brew install tmux` (macOS) or `apt install tmux` (Linux).
