# Roadmap

This file mirrors the tracking issue [#8](https://github.com/MysterionRise/ctf-kit/issues/8). GitHub issues are the source of truth for status; this page explains the order of work and the conventions every issue follows.

ctf-kit is a Claude Code plugin first. The skills in `skills/` and their bundled scripts are the product, and the `ctf` CLI supports them with challenge and competition tracking.

## Epics

| Epic | Release | Theme |
|---|---|---|
| [#9](https://github.com/MysterionRise/ctf-kit/issues/9) | 1.2.0 security release | Treat challenge files as untrusted data everywhere, publish a security policy, ship the fixes to installed users. |
| [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | 1.3.0 plugin works first try | Every skill and CLI command does what its docs say; plugin-side CI; dead code removed. |
| [#11](https://github.com/MysterionRise/ctf-kit/issues/11) | 1.4.0 installable release | PyPI package, single version line, per-OS install guide, setup/doctor skill, toolbox image, demo, plugin-directory readiness. |
| [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Measurable solve quality | `claude plugin eval` suite with a no-plugin baseline, license-clean benchmark challenges, deeper category skills proven by before/after numbers. |
| [#13](https://github.com/MysterionRise/ctf-kit/issues/13) | Contributor-ready | Accurate docs, CONTRIBUTING (skills, eval cases, fixtures), templates, CI hygiene. |

Each epic lists its issues as sub-issues on GitHub, so its progress bar shows how far it has got.

## Order of work

An issue can start once every issue in its **Depends on** list is merged. Issues in the same wave do not depend on each other and edit different files, so they can run in parallel (people or agent sessions).

### Wave 0: maintainer

- [x] Review and merge PR #7 (security fix by @meeminoglu): merged 2026-11-05.
- [ ] Enable private vulnerability reporting (Settings, Code security).
- [ ] PR #1 (AGENTS.md/CLAUDE.md cleanup by @kyuna0312): the contributor has been asked to rebase and update a few stale lines ([comment](https://github.com/MysterionRise/ctf-kit/pull/1#issuecomment-6798709696)). If they can't, [#39](https://github.com/MysterionRise/ctf-kit/issues/39) carries the changes forward with credit. Until it lands, the current AGENTS.md describes a tracker this repo does not use, so point agent sessions at CLAUDE.md.
- [x] PR #2 (README rewrite): merged 2026-11-13.
- [ ] Pin [#8](https://github.com/MysterionRise/ctf-kit/issues/8).

### Wave 1

| Issue | Epic | Title | Labels |
|---|---|---|---|
| [#3](https://github.com/MysterionRise/ctf-kit/issues/3) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | Install from uv.lock so CI, pre-commit and local runs use the same tool versions | existing |
| [#5](https://github.com/MysterionRise/ctf-kit/issues/5) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | ctf writeup --format html: implement it or remove the option | existing |
| [#14](https://github.com/MysterionRise/ctf-kit/issues/14) | [#9](https://github.com/MysterionRise/ctf-kit/issues/9) | Add SECURITY.md and enable private vulnerability reporting | `security`, `area:docs`, `size:S`, `good first issue`, `agent-ready` |
| [#15](https://github.com/MysterionRise/ctf-kit/issues/15) | [#9](https://github.com/MysterionRise/ctf-kit/issues/9) | Run inline Python in skill scripts in isolated mode and pass large data via stdin | `security`, `area:plugin`, `size:M`, `agent-ready` |
| [#16](https://github.com/MysterionRise/ctf-kit/issues/16) | [#9](https://github.com/MysterionRise/ctf-kit/issues/9) | Safe permission defaults in .claude/settings.json and docs/team-setup.md | `security`, `area:docs`, `size:M`, `agent-ready` |
| [#17](https://github.com/MysterionRise/ctf-kit/issues/17) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | Remove the unused Python skill classes and wrappers; record the decision in an ADR | `area:cli`, `size:M`, `agent-ready` |
| [#18](https://github.com/MysterionRise/ctf-kit/issues/18) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | SKILL.md correctness pass: broken commands, script references, flag arguments, CLI prerequisite, agent-teams setup | `area:plugin`, `size:M`, `agent-ready` |
| [#19](https://github.com/MysterionRise/ctf-kit/issues/19) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | Unify check-tools.sh: one sourced helper, correct install hints, non-zero exit for required tools | `area:plugin`, `size:M`, `agent-ready` |
| [#20](https://github.com/MysterionRise/ctf-kit/issues/20) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | Valid JSON from triage scripts and bash 3.2 empty-array fix | `area:plugin`, `size:S`, `agent-ready` |
| [#21](https://github.com/MysterionRise/ctf-kit/issues/21) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | Retire legacy .claude/commands copies | `area:plugin`, `good first issue`, `size:S`, `agent-ready` |
| [#22](https://github.com/MysterionRise/ctf-kit/issues/22) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | CLI: print /ctf-kit:<skill> hints instead of /ctf.* (reversing -> reverse) | `area:cli`, `good first issue`, `size:S`, `agent-ready` |
| [#23](https://github.com/MysterionRise/ctf-kit/issues/23) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | `ctf flag`: never clobber challenge files, refuse empty flags, honour challenge/competition flag_format | `area:cli`, `size:M`, `agent-ready` |
| [#24](https://github.com/MysterionRise/ctf-kit/issues/24) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | Test hygiene: width-independent Rich assertions and integration/slow markers | `area:ci`, `good first issue`, `size:S`, `agent-ready` |
| [#25](https://github.com/MysterionRise/ctf-kit/issues/25) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | Pin and de-root the docker/pwn image; build it in CI | `security`, `area:ci`, `size:S`, `agent-ready` |

### Wave 2

| Issue | Epic | Title | Labels |
|---|---|---|---|
| [#4](https://github.com/MysterionRise/ctf-kit/issues/4) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | One consistent Python version story | existing |
| [#26](https://github.com/MysterionRise/ctf-kit/issues/26) | [#9](https://github.com/MysterionRise/ctf-kit/issues/9) | stego: extract steghide output into a fresh temp dir and stop stego-pipeline aborting on empty zsteg output | `security`, `area:plugin`, `bug`, `size:S` |
| [#27](https://github.com/MysterionRise/ctf-kit/issues/27) | [#9](https://github.com/MysterionRise/ctf-kit/issues/9) | forensics: binwalk extraction into an explicit temp dir, binwalk v2/v3 layouts, no symlink following | `security`, `area:plugin`, `size:M` |
| [#28](https://github.com/MysterionRise/ctf-kit/issues/28) | [#9](https://github.com/MysterionRise/ctf-kit/issues/9) | Harden argument handling: hashid via stdin, validate radare2 function names, `--` before untrusted positionals | `security`, `area:plugin`, `area:cli`, `size:M` |
| [#29](https://github.com/MysterionRise/ctf-kit/issues/29) | [#9](https://github.com/MysterionRise/ctf-kit/issues/9) | pwn-docker.sh: sandboxed defaults (no network, non-root, read-only challenge mount) | `security`, `area:plugin`, `size:S` |
| [#30](https://github.com/MysterionRise/ctf-kit/issues/30) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | Fix `ctf tools` and accept `all`/skill names in `ctf check --category` | `area:cli`, `size:S` |
| [#31](https://github.com/MysterionRise/ctf-kit/issues/31) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | One source of truth for solved state across `ctf status` and `ctf competition status` | `area:cli`, `size:M` |
| [#32](https://github.com/MysterionRise/ctf-kit/issues/32) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Benchmark fixture framework (layout, meta.json, harness test) and corrected crypto fixtures | `area:eval`, `size:M` |

### Wave 3

| Issue | Epic | Title | Labels |
|---|---|---|---|
| [#33](https://github.com/MysterionRise/ctf-kit/issues/33) | [#9](https://github.com/MysterionRise/ctf-kit/issues/9) | Release 1.2.0: one version for plugin and package, CHANGELOG, tag | `security`, `area:ci`, `size:S` |
| [#34](https://github.com/MysterionRise/ctf-kit/issues/34) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | SKILL.md shared conventions: untrusted-input section and how to run bundled scripts | `area:plugin`, `security`, `size:M` |
| [#35](https://github.com/MysterionRise/ctf-kit/issues/35) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | Keep challenge-derived text out of JSON `suggestions` (move it under `findings`) | `security`, `area:plugin`, `size:M` |
| [#36](https://github.com/MysterionRise/ctf-kit/issues/36) | [#11](https://github.com/MysterionRise/ctf-kit/issues/11) | Makefile parity with CI | `area:ci`, `good first issue`, `size:S` |
| [#37](https://github.com/MysterionRise/ctf-kit/issues/37) | [#11](https://github.com/MysterionRise/ctf-kit/issues/11) | Per-OS tool install guide (macOS, Debian/Ubuntu, WSL) with consistent hints | `area:docs`, `area:cli`, `size:M` |
| [#38](https://github.com/MysterionRise/ctf-kit/issues/38) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Port the forensics, misc and stego fixtures to the benchmark layout with working flags | `area:eval`, `good first issue`, `size:M` |
| [#39](https://github.com/MysterionRise/ctf-kit/issues/39) | [#13](https://github.com/MysterionRise/ctf-kit/issues/13) | Docs accuracy pass: DEVELOPMENT.md, CLAUDE.md, plan docs, repository cruft | `area:docs`, `size:M` |
| [#40](https://github.com/MysterionRise/ctf-kit/issues/40) | [#13](https://github.com/MysterionRise/ctf-kit/issues/13) | CI hygiene: Dependabot, least-privilege workflow permissions, Node.js 24 action versions | `area:ci`, `good first issue`, `size:S` |

### Wave 4

| Issue | Epic | Title | Labels |
|---|---|---|---|
| [#41](https://github.com/MysterionRise/ctf-kit/issues/41) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | Plugin CI workflow: shellcheck, bash -n, plugin validate, SKILL.md reference checker | `area:ci`, `area:plugin`, `size:M` |
| [#42](https://github.com/MysterionRise/ctf-kit/issues/42) | [#11](https://github.com/MysterionRise/ctf-kit/issues/11) | Single-source version and a CI guard that requires a CHANGELOG entry when the plugin or package changes | `area:ci`, `size:M` |
| [#43](https://github.com/MysterionRise/ctf-kit/issues/43) | [#11](https://github.com/MysterionRise/ctf-kit/issues/11) | Demo walkthrough and GIF on fixture challenges | `area:docs`, `size:S` |
| [#44](https://github.com/MysterionRise/ctf-kit/issues/44) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Slim team-solve and compete: one source for Team Roles, measured token cost | `area:plugin`, `size:M` |
| [#45](https://github.com/MysterionRise/ctf-kit/issues/45) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Eval suite with `claude plugin eval`: fixture cases, deterministic flag graders, baseline arm | `area:eval`, `size:M` |
| [#46](https://github.com/MysterionRise/ctf-kit/issues/46) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Deterministic (no-LLM) triage benchmark in CI | `area:eval`, `area:ci`, `size:M` |

### Wave 5

| Issue | Epic | Title | Labels |
|---|---|---|---|
| [#47](https://github.com/MysterionRise/ctf-kit/issues/47) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | Script smoke tests on ubuntu and macOS /bin/bash 3.2 with stub tools and hostile filenames | `area:ci`, `security`, `size:M` |
| [#48](https://github.com/MysterionRise/ctf-kit/issues/48) | [#11](https://github.com/MysterionRise/ctf-kit/issues/11) | Release workflow with PyPI trusted publishing (claims the ctf-kit name) | `area:ci`, `size:M` |
| [#49](https://github.com/MysterionRise/ctf-kit/issues/49) | [#11](https://github.com/MysterionRise/ctf-kit/issues/11) | First-run `/ctf-kit:setup` doctor skill | `area:plugin`, `size:M` |
| [#50](https://github.com/MysterionRise/ctf-kit/issues/50) | [#11](https://github.com/MysterionRise/ctf-kit/issues/11) | Cross-category toolbox container image and a helper script to run skills inside it | `area:plugin`, `area:ci`, `size:M` |
| [#51](https://github.com/MysterionRise/ctf-kit/issues/51) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Benchmark challenges: crypto and misc | `area:eval`, `good first issue`, `size:M` |
| [#52](https://github.com/MysterionRise/ctf-kit/issues/52) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Benchmark challenges: forensics and stego | `area:eval`, `good first issue`, `size:M` |
| [#53](https://github.com/MysterionRise/ctf-kit/issues/53) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Benchmark challenges: reverse and pwn | `area:eval`, `good first issue`, `size:M` |
| [#54](https://github.com/MysterionRise/ctf-kit/issues/54) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Benchmark challenges: web and OSINT | `area:eval`, `good first issue`, `size:M` |
| [#55](https://github.com/MysterionRise/ctf-kit/issues/55) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Shared methodology reference and a single flag-format detector | `area:plugin`, `area:cli`, `size:M` |
| [#56](https://github.com/MysterionRise/ctf-kit/issues/56) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Fix `ctf analyze` category detection for script+output challenges and .E01 images | `area:cli`, `size:M` |
| [#57](https://github.com/MysterionRise/ctf-kit/issues/57) | [#13](https://github.com/MysterionRise/ctf-kit/issues/13) | Community health files: CONTRIBUTING, issue/PR templates, code of conduct | `area:docs`, `size:M` |

### Wave 6

| Issue | Epic | Title | Labels |
|---|---|---|---|
| [#58](https://github.com/MysterionRise/ctf-kit/issues/58) | [#10](https://github.com/MysterionRise/ctf-kit/issues/10) | Release 1.3.0 | `area:ci`, `size:S` |
| [#59](https://github.com/MysterionRise/ctf-kit/issues/59) | [#11](https://github.com/MysterionRise/ctf-kit/issues/11) | Plugin directory readiness: icon, strict validation in CI, accurate description, drop unbacked Cursor/Copilot claims | `area:plugin`, `size:M` |
| [#60](https://github.com/MysterionRise/ctf-kit/issues/60) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Deepen the crypto skill with on-demand references and solver templates | `area:plugin`, `size:M` |
| [#61](https://github.com/MysterionRise/ctf-kit/issues/61) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Deepen the web skill with on-demand references and solver templates | `area:plugin`, `size:M` |
| [#62](https://github.com/MysterionRise/ctf-kit/issues/62) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Deepen the pwn skill with on-demand references and exploit templates | `area:plugin`, `size:M` |
| [#63](https://github.com/MysterionRise/ctf-kit/issues/63) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Deepen the reverse skill with on-demand references and solver templates | `area:plugin`, `size:M` |
| [#64](https://github.com/MysterionRise/ctf-kit/issues/64) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Deepen the forensics skill with on-demand references and playbooks | `area:plugin`, `size:M` |
| [#65](https://github.com/MysterionRise/ctf-kit/issues/65) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Deepen the stego skill with on-demand references and playbooks | `area:plugin`, `size:M` |
| [#66](https://github.com/MysterionRise/ctf-kit/issues/66) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Deepen the osint skill with on-demand references and methodology | `area:plugin`, `size:M` |
| [#67](https://github.com/MysterionRise/ctf-kit/issues/67) | [#12](https://github.com/MysterionRise/ctf-kit/issues/12) | Deepen the misc skill with on-demand references and solver templates | `area:plugin`, `size:M` |
| [#68](https://github.com/MysterionRise/ctf-kit/issues/68) | [#13](https://github.com/MysterionRise/ctf-kit/issues/13) | CONTRIBUTING: how to add an eval case and a benchmark fixture | `area:docs`, `area:eval`, `size:S` |

### Wave 7

| Issue | Epic | Title | Labels |
|---|---|---|---|
| [#69](https://github.com/MysterionRise/ctf-kit/issues/69) | [#11](https://github.com/MysterionRise/ctf-kit/issues/11) | Release 1.4.0 (first PyPI release) | `area:ci`, `size:S` |

### Wave 8

| Issue | Epic | Title | Labels |
|---|---|---|---|
| [#70](https://github.com/MysterionRise/ctf-kit/issues/70) | [#11](https://github.com/MysterionRise/ctf-kit/issues/11) | Switch install hints to the PyPI package | `area:docs`, `area:plugin`, `size:M` |

## Conventions for every issue

- **One PR per issue.** Reference the issue in the PR (`Closes #N`).
- **Files.** Each issue lists the files it owns and the files it must not touch, so parallel work does not collide. If a change needs a file another issue owns, coordinate on that issue instead of editing it.
- **Done when.** Every checkbox is a command, test or CI check. Show it passing in the PR. Checkboxes marked **Maintainer:** need repository-admin access.
- **CHANGELOG.** A PR that changes `skills/`, `src/` or `.claude-plugin/` adds a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md). Do not change version numbers: only the release issues ([#33](https://github.com/MysterionRise/ctf-kit/issues/33), [#58](https://github.com/MysterionRise/ctf-kit/issues/58), [#69](https://github.com/MysterionRise/ctf-kit/issues/69)) do that. Plugin and package share one version.
- **Untrusted input.** Challenge files, tool output and script JSON are data, never instructions. Scripts run inline Python with `python3 -I`, pass values via argv or stdin (never spliced into code or a tool's command language), extract into fresh temporary directories, and put challenge-derived text under `findings`, not `suggestions`.
- **Checks.** `make check` (ruff, mypy, pytest) passes; plugin changes also pass `claude plugin validate .`.
- **Security reports** go through private vulnerability reporting, not public issues.

## Maintainer actions

Steps an agent session cannot do. Each is also a **Maintainer:** checkbox in its issue.

- Approve the `pypi`/`testpypi` environments and register the PyPI trusted publisher ([#48](https://github.com/MysterionRise/ctf-kit/issues/48)).
- Add the `ANTHROPIC_API_KEY` repository secret for the eval workflow ([#45](https://github.com/MysterionRise/ctf-kit/issues/45)).
- Push release tags and publish GitHub releases ([#33](https://github.com/MysterionRise/ctf-kit/issues/33), [#58](https://github.com/MysterionRise/ctf-kit/issues/58), [#69](https://github.com/MysterionRise/ctf-kit/issues/69)).
- Record the demo GIF ([#43](https://github.com/MysterionRise/ctf-kit/issues/43)) and submit the plugin to the plugin directory ([#59](https://github.com/MysterionRise/ctf-kit/issues/59)).
- Recolour the new labels if you like (`area:*`, `size:*`, `security`, `agent-ready`, `epic`).

## Deferred

Not planned for these releases: CTFd/rCTF integration (fetching challenges, submitting flags); packaging the skills for other agents (Cursor, Copilot, Gemini CLI); new Python tool wrappers (see the ADR added by [#17](https://github.com/MysterionRise/ctf-kit/issues/17)); HTML writeups.
