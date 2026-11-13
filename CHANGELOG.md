# Changelog

All notable changes to ctf-kit (the Claude Code plugin and the `ctf` CLI) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The plugin and the Python package share one version.

Every pull request that changes `skills/`, `src/` or `.claude-plugin/` adds a line under `## [Unreleased]`. Only release issues move those lines under a version heading and change version numbers.

## [Unreleased]

### Added

- `SECURITY.md` security policy with private vulnerability reporting, scope, and response targets (#14).
- `.github/dependabot.yml` for weekly `pip` and `github-actions` dependency updates (part of #40).

### Fixed

- CLI next-step hints use the plugin command names `/ctf-kit:<skill>` (reversing -> `reverse`) and point to `ctf check -v`, instead of the pre-plugin `/ctf.*` and `ctf check --category all` (#22).

### Removed

- Legacy `.claude/commands/` slash-command copies; load the in-repo plugin with `claude --plugin-dir .` (#21).

### Security

- Skill scripts pass challenge-derived values to inline Python via argv instead of splicing them into source code (#7, reported and fixed by @meeminoglu).
