# Security policy

CTF Kit is a Claude Code plugin and CLI that helps analyse CTF challenge files. By design, its
skills and scripts run third-party tools over untrusted challenge input, so the safety of that
boundary matters. This policy covers what is supported, how to report a vulnerability, what is in
scope, and how quickly to expect a response.

## Supported versions

Security fixes land on the latest release and the `main` branch. There is no long-term support
branch yet, so please reproduce an issue against the most recent release or `main` before
reporting it.

| Version | Supported |
| --- | --- |
| latest release / `main` | yes |
| older releases | no |

## Reporting a vulnerability

Please report security issues privately through GitHub's private vulnerability reporting:

- Open a report at <https://github.com/MysterionRise/ctf-kit/security/advisories/new>.

Do not open a public issue or a public pull request for a vulnerability. A short description, the
affected file or command, and the impact are enough to start; there is no need to include a
working exploit.

## Scope

In scope:

- The skill scripts under `skills/` and the shared output parsers in `skills/_lib`.
- The `SKILL.md` instructions that tell the agent how to run those scripts.
- The plugin manifests under `.claude-plugin`.
- The `ctf` CLI under `src/ctf_kit`.
- The pwn sandbox image under `docker/pwn` and its `pwn-docker.sh` launcher.

Out of scope:

- Vulnerabilities in the third-party tools themselves; report those to their own projects.
- The intentionally vulnerable practice challenges under `tests/fixtures/challenges`, which are
  deliberately insecure test material.

## Response

- Acknowledgement: within 3 business days of a report.
- Fix or coordinated disclosure: target within 30 days, depending on severity and complexity.

If a report does not get a response within that window, please send a reminder through the same
private advisory thread.
