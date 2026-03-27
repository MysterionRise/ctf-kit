---
name: compete
description: >-
  Manage a live CTF competition with an agent team. Auto-triages challenges,
  assigns them to teammates, and tracks progress. Use during live CTF
  competitions when you have multiple challenges to solve in parallel.
  Triggers: "competition mode", "live CTF", "start competition",
  "manage CTF", "assign challenges". Requires agent teams enabled.
---

# CTF Compete

Manage a live CTF competition with a team of AI agents.

## When to Use

Use during a live CTF when:

- You have multiple challenges to solve simultaneously
- You want auto-assignment based on challenge category and difficulty
- You need a centralized view of progress across all challenges
- Time pressure requires parallel work on independent challenges

## Prerequisites

- Agent teams enabled: `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`
- Competition directory initialized: `ctf init` or challenges in known folders
- Challenge files organized by folder (one folder per challenge)

## Instructions

### Step 1: Scan and Triage All Challenges

First, map out the competition. For each challenge directory:

```bash
# List all challenge directories
ls -d */

# Triage each one
for dir in */; do
  echo "=== $dir ==="
  bash scripts/triage-competition.sh "$dir"
done
```

Or let the lead scan manually:

```text
Scan the current directory. Each subdirectory is a CTF challenge.
For each one, run /ctf-kit:analyze to determine the category and difficulty.
Build a priority list.
```

### Step 2: Build the Priority Queue

After triage, sort challenges by expected solve speed:

**Priority factors** (in order):

1. **Point value / estimated difficulty** — easy high-value challenges first
2. **Category confidence** — high-confidence triage = faster solve
3. **Tool availability** — skip challenges requiring tools we don't have
4. **Dependencies** — some challenges unlock hints for others

Create a task for each challenge in the shared task list.

### Step 3: Spawn the Competition Team

Spawn 3 teammates. Each teammate is a **generalist** that uses the appropriate category skill for their assigned challenge.

```text
Create an agent team for this CTF competition.

Teammate 1 — "solver-1":
  You are a CTF solver. Pick challenges from the task list and solve them.
  Use /ctf-kit:analyze to triage, then the appropriate category skill.
  When you solve a challenge, mark the task complete and broadcast the flag.
  Then claim the next unclaimed challenge.

Teammate 2 — "solver-2":
  [same as above]

Teammate 3 — "solver-3":
  [same as above]

The task list has all challenges sorted by priority. Each teammate should
claim the highest-priority unclaimed challenge. Do NOT work on a challenge
another teammate is already solving.

When a teammate gets stuck for more than 5 minutes, they should broadcast
for help. Another teammate who finishes their challenge can assist.
```

### Step 4: Manage During Competition

The lead's job during competition:

1. **Monitor progress** — check which challenges are solved, in-progress, or stuck
2. **Reprioritize** — if a new hint is released, update task priorities
3. **Reassign** — if a teammate is stuck, give them a different challenge
4. **Cross-pollinate** — if one challenge's solution gives clues to another, broadcast
5. **Track flags** — maintain a list of solved challenges and submitted flags

### Step 5: Handle Stuck Teammates

When a teammate is stuck:

**Option A**: Swap challenges between teammates (fresh eyes):

```text
Tell solver-2 to stop working on "crypto-hard" and swap with solver-3's
"web-easy". Sometimes a different perspective helps.
```

**Option B**: Escalate to team-solve mode for one challenge:

```text
Solver-1 just finished "misc-1". Have all 3 teammates collaborate on
"crypto-hard" using /ctf-kit:team-solve approach with crypto team roles.
```

**Option C**: Ask user for hints:

```text
Solver-2 is stuck on "forensics-2". The memory dump analysis found nothing
suspicious. Do you have any hints from the competition platform?
```

### Step 6: End Competition

When time is up or all challenges are solved:

```text
Competition over. Summarize:
- Challenges solved (with flags)
- Challenges attempted but unsolved (with progress notes)
- Total points scored
Clean up the team.
```

## Assignment Strategy

### Auto-Assignment Rules

The lead assigns challenges based on:

| Signal | Action |
|--------|--------|
| Triage confidence > 80% | Assign to next available teammate |
| Triage confidence 50-80% | Assign, but flag for possible reassignment |
| Triage confidence < 50% | Run /ctf-kit:team-solve instead of single assignment |
| Web/pwn category | Teammate gets plan-approval mode |
| Challenge has dependencies | Block task until dependency is resolved |

### Balancing Load

- Track each teammate's active time vs idle time
- Assign faster challenges to teammates who just finished (keep momentum)
- If one teammate is consistently faster, give them harder challenges
- Never assign more than 1 challenge at a time to a teammate

### When to Switch from Compete to Team-Solve

If a high-value challenge is the last unsolved and all teammates are free:

```text
All other challenges are solved. Let's focus all 3 teammates on "crypto-500"
using /ctf-kit:team-solve with crypto team roles.
```

This transitions from breadth (competition mode) to depth (team-solve mode) for the final push.

## Progress Tracking

The lead maintains a scoreboard. After each solve:

```text
=== Competition Progress ===
[SOLVED] misc-100    — solver-1 — flag{example1}     — 3 min
[SOLVED] web-200     — solver-2 — flag{example2}     — 8 min
[IN PROGRESS] crypto-300 — solver-3 — trying RSA attacks
[QUEUED] forensics-400
[QUEUED] pwn-500
=== Score: 300 / 1500 ===
```

## Task List Structure

Each challenge becomes a task with metadata:

```text
Task: Solve "crypto-300"
  Category: crypto
  Points: 300
  Priority: 2 (medium)
  Triage: RSA parameters found, confidence 85%
  Files: challenge/n.txt, challenge/e.txt, challenge/c.txt
  Assigned to: solver-3
  Status: in_progress
  Dependencies: none
```

## Communication Patterns

### Teammate broadcasts

- **Flag found**: "SOLVED crypto-300: flag{...}" → lead records it
- **Stuck**: "STUCK on forensics-400 after 5 min: volatility shows no processes" → lead reassigns or sends help
- **Discovery**: "NOTE: web-200 login page leaks version info, might help with pwn-500" → cross-challenge intel

### Lead broadcasts

- **New hint**: "Competition hint released for crypto-300: think small primes"
- **Priority change**: "pwn-500 just got a hint, bump priority"
- **Time warning**: "30 minutes left, focus on queued challenges with highest point/time ratio"

## Permissions for Competition Mode

All teammates start with Tier 1 (local analysis) auto-allowed. The lead applies Tier 2 (plan approval) when assigning web, pwn, or osint challenges:

```text
Solver-2, take "web-200". I'm enabling plan approval for your session
since you'll be sending requests to the target. Show me your recon plan
before hitting the target.
```

## Example Full Competition

```text
User: /ctf-kit:compete

Lead:
1. Scans directory → finds 8 challenges
2. Triages each:
   - misc-100 (easy, encoding chain)
   - web-100 (easy, robots.txt)
   - crypto-200 (medium, XOR)
   - web-200 (medium, SQLi)
   - forensics-200 (medium, pcap)
   - crypto-300 (hard, RSA)
   - pwn-400 (hard, buffer overflow)
   - misc-500 (hard, multi-layer)
3. Creates priority queue: misc-100, web-100, crypto-200, web-200, forensics-200, ...
4. Spawns solver-1, solver-2, solver-3
5. Auto-assigns:
   - solver-1 → misc-100
   - solver-2 → web-100 (plan approval on)
   - solver-3 → crypto-200
6. solver-1 finishes misc-100 in 2 min → claims web-200
7. solver-3 finishes crypto-200 → claims forensics-200
8. solver-2 finishes web-100 → claims crypto-300
9. ...continues until time or all solved
10. Final scoreboard + team cleanup
```

## Related Skills

- `/ctf-kit:team-solve` — Deep parallel solve for a single challenge
- `/ctf-kit:analyze` — Triage a single challenge
- `/ctf-kit:status` — Check challenge progress
- `/ctf-kit:flag` — Submit and track flags
