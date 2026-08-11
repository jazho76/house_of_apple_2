#!/usr/bin/env bash

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
img="${IMG:-filestructlab}"

docker image inspect "$img" >/dev/null 2>&1 || "$here/build.sh"

args=()
mount_ro() { if [ -e "$1" ]; then args+=(-v "$1:$2:ro"); fi; }
mount_ro "$HOME/.config/tmux/tmux.conf"    /home/ctf/.config/tmux/tmux.conf
mount_ro "$HOME/.tmux.conf"                /home/ctf/.tmux.conf
mount_ro "$HOME/.local/share/tmux/plugins" /home/ctf/.local/share/tmux/plugins
mount_ro "$HOME/.tmux/plugins"             /home/ctf/.tmux/plugins

exec docker run -it --rm "${args[@]}" "$img"
