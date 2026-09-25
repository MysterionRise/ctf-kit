# AGENTS.md — Codex / other harnesses

The rules for this repo live in [CLAUDE.md](CLAUDE.md). Read it first; everything there applies here.

- Skills under `skills/<name>/SKILL.md` are portable (`$ctf-kit:<name>` in Codex). `.claude/commands/` and `agents/claude/` are Claude Code only; read for context, do not port.
- Verify with `make check` (ruff + mypy + pytest). It needs the dev install: `pip install -e ".[dev]"`.
- Issue tracking is GitHub Issues via `gh`. There is no other tracker.
