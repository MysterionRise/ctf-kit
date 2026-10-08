#!/usr/bin/env bash
# Run a command inside the ctf-pwn linux/amd64 container with the current
# directory mounted at /chal. Use this when the host cannot run or debug
# x86-64 ELF binaries natively (e.g. Apple Silicon macOS).
# Usage: pwn-docker.sh [command...]   (default: interactive bash)
# Examples:
#   pwn-docker.sh ./chall
#   pwn-docker.sh pwndbg ./chall
#   pwn-docker.sh python3 solve.py
set -euo pipefail

IMAGE="${CTF_PWN_IMAGE:-ctf-pwn}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCKERFILE_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)/docker/pwn"

if ! command -v docker &>/dev/null; then
    echo "ERROR: docker not installed." >&2
    exit 1
fi

if ! docker image inspect "$IMAGE" &>/dev/null; then
    echo "ERROR: image '$IMAGE' not found." >&2
    echo "  Build: docker build --platform linux/amd64 -t $IMAGE $DOCKERFILE_DIR" >&2
    exit 1
fi

if [ $# -eq 0 ]; then
    set -- bash
fi

TTY_FLAGS=(-i)
if [ -t 0 ] && [ -t 1 ]; then
    TTY_FLAGS=(-it)
fi

exec docker run --rm "${TTY_FLAGS[@]}" --platform linux/amd64 \
    --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v "$PWD":/chal -w /chal "$IMAGE" "$@"
