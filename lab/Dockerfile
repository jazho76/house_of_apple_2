FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev make gdb git curl ca-certificates tmux neovim \
        python3 python3-pip python3-dev \
    && pip3 install --no-cache-dir --break-system-packages pwntools \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ctf

RUN git clone --depth 1 https://github.com/pwndbg/pwndbg /opt/pwndbg \
    && cd /opt/pwndbg && ./setup.sh \
    && mkdir -p /etc/gdb \
    && echo "source /opt/pwndbg/gdbinit.py" > /etc/gdb/gdbinit \
    && chown -R ctf:ctf /opt/pwndbg

ENV LANG=C.UTF-8

WORKDIR /lab

COPY Makefile   /lab/Makefile
COPY README.md  /lab/README.md
COPY pwn.conf   /home/ctf/.pwn.conf
COPY gdbinit    /home/ctf/.gdbinit

RUN --mount=type=bind,source=src/lab.c,target=/lab/src/lab.c \
    make -C /lab build \
    && chown ctf:ctf /lab /lab/lab /lab/Makefile /lab/README.md \
    && chown ctf:ctf /home/ctf/.pwn.conf /home/ctf/.gdbinit
USER ctf

RUN mkdir -p /home/ctf/.local/share /home/ctf/.local/state /home/ctf/.cache

RUN gdb --batch -ex quit /lab/lab >/dev/null 2>&1 || true

CMD ["bash"]
