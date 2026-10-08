# Linux/amd64 pwn toolbox for running and debugging x86-64 ELF challenges
# on hosts that cannot do it natively (e.g. Apple Silicon macOS).
#
# Build:  docker build --platform linux/amd64 -t ctf-pwn docker/pwn
# Use:    skills/pwn/scripts/pwn-docker.sh [command...]
#
# Under amd64 emulation on Apple Silicon, ptrace does not work, so gdb/gdbserver
# cannot run or attach to processes directly. Debug through qemu's gdb stub:
#   qemu-x86_64 -g 1234 ./chall &  then  pwndbg -ex 'target remote :1234' ./chall
# and trace syscalls with `qemu-x86_64 -strace ./chall` instead of strace/ltrace.
FROM --platform=linux/amd64 ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    TERM=xterm-256color \
    PATH=/opt/venv/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        gdb gdbserver gdb-multiarch qemu-user strace ltrace patchelf file binutils \
        python3 python3-venv python3-dev build-essential ruby ruby-dev \
        curl ca-certificates git netcat-openbsd socat xz-utils less vim-tiny tmux libc6-dbg steghide \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv \
    && pip install --no-cache-dir pwntools ROPgadget ropper

RUN gem install --no-document one_gadget seccomp-tools

# pwndbg (portable build); `pwndbg ./chall` starts gdb with pwndbg loaded
RUN curl -qsL https://install.pwndbg.re | sh -s -- -t pwndbg-gdb

WORKDIR /chal
CMD ["bash"]
