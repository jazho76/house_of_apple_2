#!/usr/bin/env bash

set -euo pipefail

current="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
img="${IMG:-filestructlab}"

docker image inspect "$img" >/dev/null 2>&1 || "$current/build.sh"

args=(-v "$current/exp:/lab/exp:rw")
mount_ro() { if [ -e "$1" ]; then args+=(-v "$1:$2:ro"); fi; }
mount_ro "$HOME/.config/tmux/tmux.conf"    /home/user/.config/tmux/tmux.conf
mount_ro "$HOME/.tmux.conf"                /home/user/.tmux.conf
mount_ro "$HOME/.local/share/tmux/plugins" /home/user/.local/share/tmux/plugins
mount_ro "$HOME/.tmux/plugins"             /home/user/.tmux/plugins

cmd=(tmux new-session -A -s lab)
[ -n "${NOTMUX:-}" ] && cmd=(bash)

exec docker run -it --rm "${args[@]}" "$img" "${cmd[@]}"
