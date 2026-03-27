---
name: team-solve
description: >-
  Orchestrate a multi-agent team to solve a CTF challenge. Use when a
  challenge is complex enough to benefit from parallel investigation —
  multiple possible approaches, layered encoding, or unclear category.
  Spawns 3 specialized teammates based on triage results. Each teammate
  gets a focused role within the detected category. Requires agent teams
  enabled (CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1).
  Triggers: "team solve", "parallel solve", "spawn team", "multi-agent",
  "use a team for this".
---

# CTF Team Solve

Orchestrate a team of 3 specialized teammates to solve a CTF challenge in parallel.

## When to Use

Use this when:

- A challenge is complex or multi-layered
- Initial triage shows mixed signals or low confidence
- You want to try multiple approaches simultaneously
- Time pressure demands parallel investigation
- The challenge has multiple files or stages

Do NOT use when:

- The challenge is straightforward (single encoding, obvious category)
- You already know exactly what tool to run
- Agent teams are not enabled

## Prerequisites

Agent teams must be enabled. Verify `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` is set in `.claude/settings.json` or environment.

## Instructions

### Step 1: Triage the Challenge

Run the triage pipeline first to determine the category:

```bash
bash scripts/triage-for-team.sh $ARGUMENTS
```

Or use the analyze skill's triage:

```bash
# From the ctf-kit plugin
bash scripts/triage.sh $ARGUMENTS
```

Read the JSON output. Key fields: `category`, `confidence`, `secondary_categories`.

### Step 2: Decide Team Composition

Based on triage results, select the appropriate 3-teammate composition from the category tables below. If triage shows mixed signals (confidence < 70% or multiple secondary categories), use the **Cross-Category Team** composition.

### Step 3: Spawn the Team

Create an agent team with 3 teammates. For each teammate:

1. **Name** them by role (e.g., "rsa-specialist", "hash-cracker")
2. **Set the prompt** using the role description and the challenge context
3. **Set plan approval** for teammates using offensive tools (web, pwn, osint)
4. **Create initial tasks** in the shared task list — one per teammate

Example spawn prompt to the lead:

```text
Create an agent team with 3 teammates to solve this crypto challenge.

Teammate 1 — "classical-analyst":
  Focus on classical ciphers and encoding chains.
  Tools: frequency analysis, dcode.fr patterns, CyberChef recipes.
  Start by running: bash scripts/identify-hash.sh and bash scripts/run-decode.sh

Teammate 2 — "rsa-specialist":
  Focus on RSA and asymmetric crypto attacks.
  Tools: RsaCtfTool, openssl, sage/python for math.
  Start by extracting any RSA parameters (n, e, c, p, q).

Teammate 3 — "symmetric-cracker":
  Focus on XOR, AES, and hash cracking.
  Tools: xortool, hashcat, john.
  Start by running: bash scripts/run-xortool.sh on any binary files.

Each teammate should broadcast findings to others when they discover something
that changes the understanding of the challenge. If a teammate finds a flag,
broadcast immediately and all teammates should verify.
```

### Step 4: Coordinate

- **Let teammates self-claim tasks** after their initial assignment
- **Monitor progress** — check in if a teammate is stuck for more than a few minutes
- **Broadcast discoveries** — tell a teammate to broadcast when they find something that shifts the approach
- **Synthesize** — once 2+ teammates have findings, combine and identify the solution path
- **Shut down early** — if one teammate solves it, shut down the others

## Team Compositions by Category

### Crypto Team

| Role | Name | Focus | First Action |
|------|------|-------|--------------|
| Classical & Encoding | `classical-analyst` | Frequency analysis, substitution ciphers, Vigenere, encoding chains, CyberChef | Run `scripts/run-decode.sh` and `scripts/identify-hash.sh` on all challenge files |
| Asymmetric & Math | `rsa-specialist` | RSA factoring, padding oracles, Wiener/Boneh-Durfee, ECC, Diffie-Hellman | Extract RSA parameters, run `RsaCtfTool`, try sage/python math attacks |
| Symmetric & Hash | `symmetric-cracker` | XOR key recovery, AES mode attacks, hash cracking with hashcat/john | Run `scripts/run-xortool.sh`, identify and crack any hashes |

### Forensics Team

| Role | Name | Focus | First Action |
|------|------|-------|--------------|
| File & Disk | `file-carver` | binwalk, foremost, file carving, disk image mounting, deleted file recovery | Run `scripts/run-binwalk.sh` and `scripts/extract-and-analyze.sh` |
| Memory | `memory-analyst` | volatility3 plugins, process trees, registry, command history, malware detection | Run `scripts/run-volatility.sh` with pslist, netscan, cmdline |
| Network | `network-analyst` | tshark, protocol analysis, stream extraction, DNS exfil detection | Run `scripts/run-tshark.sh`, extract HTTP objects and DNS queries |

### Web Team (plan approval required for Tier 2 tools)

| Role | Name | Focus | First Action |
|------|------|-------|--------------|
| Recon & Enumeration | `web-recon` | Directory scanning, technology fingerprinting, hidden paths, robots.txt | Run `scripts/run-gobuster.sh`, check robots.txt, view source |
| Injection | `injection-tester` | SQLi, XSS, SSTI, command injection, path traversal | Test input fields with common payloads, run sqlmap on parameters |
| Auth & Logic | `auth-analyst` | JWT attacks, session handling, IDOR, privilege escalation, API abuse | Inspect cookies/tokens, test auth bypass, check API endpoints |

**Important**: Spawn web teammates with **plan approval required**. The lead must review before any teammate sends requests to a target.

### Pwn Team (plan approval required for remote connections)

| Role | Name | Focus | First Action |
|------|------|-------|--------------|
| Static Analyst | `binary-analyst` | checksec, disassembly, vulnerability ID, function mapping | Run `scripts/run-checksec.sh`, map interesting functions |
| Exploit Developer | `exploit-dev` | Payload crafting, ROP chains, shellcode, ret2libc, format strings | Build exploit based on static analyst's findings |
| Dynamic Analyst | `dynamic-analyst` | GDB debugging, leak finding, heap state, ASLR bypass | Run binary in debugger, find offsets, verify leaks |

**Important**: Spawn the exploit-dev teammate with **plan approval required** before connecting to remote targets.

### Reverse Team

| Role | Name | Focus | First Action |
|------|------|-------|--------------|
| Static Analyst | `static-reverser` | radare2, Ghidra, decompilation, function listing, string analysis | Run `scripts/run-radare2.sh`, identify interesting functions |
| Dynamic Analyst | `dynamic-reverser` | ltrace, strace, GDB, breakpoints, anti-debug bypass, runtime behavior | Run binary with ltrace/strace, set breakpoints on check functions |
| Algorithm Solver | `algo-solver` | Keygen writing, constraint solving (z3), algorithm reimplementation | Reimplement validation logic, write solver script |

### Stego Team

| Role | Name | Focus | First Action |
|------|------|-------|--------------|
| Image Analyst | `image-analyst` | zsteg LSB, steghide extraction, visual inspection, color plane analysis | Run `scripts/run-zsteg.sh` and `scripts/run-steghide.sh` |
| Metadata & Structure | `metadata-analyst` | exiftool, binwalk appended data, file structure, IHDR manipulation | Run `scripts/run-exiftool.sh` and `scripts/run-binwalk.sh` |
| Audio & Advanced | `audio-analyst` | Spectrogram messages, audio LSB, DTMF tones, video frame analysis | Open in Audacity spectrogram view, check audio LSB encoding |

### OSINT Team (plan approval for external queries)

| Role | Name | Focus | First Action |
|------|------|-------|--------------|
| People & Social | `social-investigator` | Sherlock username enum, social media profiling, identity correlation | Run `scripts/run-sherlock.sh`, cross-reference platforms |
| Domain & Infra | `domain-analyst` | whois, DNS records, subdomain enum, theHarvester, IP geolocation | Run whois, dig, theHarvester on target domains |
| Geo & Media | `geo-analyst` | EXIF GPS extraction, reverse image search, visual landmark ID | Run `scripts/run-exiftool.sh`, identify visual clues |

**Important**: Spawn OSINT teammates with **plan approval required** before hitting external services.

### Misc Team

| Role | Name | Focus | First Action |
|------|------|-------|--------------|
| Encoding Specialist | `decoder` | CyberChef recipes, encoding chains, base conversions, custom encodings | Run `scripts/run-decode.sh`, try multi-layer decoding |
| Esoteric & Code | `esoteric-analyst` | Brainfuck, Whitespace, JSFuck, custom languages, polyglots | Identify language from character set, find interpreter |
| Puzzle & Logic | `puzzle-solver` | Pattern recognition, math puzzles, QR/barcodes, game theory | Run `zbarimg` on images, analyze patterns, solve constraints |

### Cross-Category Team (mixed signals or unclear category)

Use when triage confidence is below 70% or multiple categories are detected.

| Role | Name | Focus | First Action |
|------|------|-------|--------------|
| Analyst A | `analyst-a` | Primary detected category | Use the primary category's skill |
| Analyst B | `analyst-b` | Secondary detected category | Use the secondary category's skill |
| Generalist | `generalist` | Broad investigation: strings, metadata, structure, encoding | Run full triage, check all common patterns |

## Communication Patterns

### When teammates should broadcast

- Found a flag or flag fragment
- Discovered a new file or layer (e.g., extracted an embedded file)
- Identified the challenge type with high confidence
- Hit a dead end — other teammates should deprioritize this approach
- Found a password, key, or credential that others might need

### When the lead should intervene

- Two teammates are pursuing the same approach (redirect one)
- A teammate has been stuck for >3 minutes
- New information changes the strategy (reassign tasks)
- One teammate solved it (shut down others)

## Permissions Model

### Tier 1 — Auto-allow (local analysis)

All teammates get these automatically:

```text
file, strings, xxd, binwalk, foremost, exiftool, hashid, xortool,
zsteg, steghide, volatility3, tshark, checksec, ropgadget, radare2,
python3, zbarimg, ctf (CLI)
```

### Tier 2 — Plan approval (connects to targets)

Teammates using these tools must have plan approval enabled:

```text
sqlmap, gobuster, ffuf, nikto, pwntools (remote), nmap,
sherlock, theHarvester, curl/wget to targets
```

The lead reviews the plan before the teammate executes.

### Tier 3 — User confirmation (resource-heavy or destructive)

These should prompt the user:

```text
hashcat --gpu (resource-intensive), any write to target systems
```

## Example Full Workflow

```text
User: /ctf-kit:team-solve challenge.zip

Lead:
1. Runs triage → category=crypto, confidence=65%, secondary=stego
2. Low confidence → uses Cross-Category Team
3. Spawns:
   - "crypto-analyst" with crypto skill focus
   - "stego-analyst" with stego skill focus
   - "generalist" running broad analysis
4. Creates tasks:
   - Task 1: Crypto analysis of challenge files (crypto-analyst)
   - Task 2: Stego analysis of any images found (stego-analyst)
   - Task 3: Deep file analysis and strings search (generalist)
5. Generalist finds hidden PNG inside challenge file → broadcasts
6. Stego-analyst claims the PNG → finds LSB-encoded text
7. LSB text is a key → crypto-analyst uses it to decrypt
8. Flag found → broadcast → team shutdown
```

## Related Skills

- `/ctf-kit:analyze` — Triage a challenge (always run first)
- `/ctf-kit:compete` — Competition mode (multiple challenges)
- `/ctf-kit:crypto` through `/ctf-kit:misc` — Individual category skills
