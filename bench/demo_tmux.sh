#!/usr/bin/env bash
# =============================================================================
# demo_tmux.sh -- build the four-pane layout used in the demo video if required.
#
# A single ssh session cannot show the firewall working: we need the live
# control plane, the counters, a traffic generator, and a shell for commands,
# all visible at once. tmux gives us that in one terminal window, which is
# also the only practical way to record it.
#
#   +---------------------------------+-------------------------+
#   |                                 |                         |
#   |  0: control plane (live TUI)    |  1: fwctl stats --watch |
#   |                                 |                         |
#   |                                 +-------------------------+
#   |                                 |                         |
#   |                                 |  2: traffic generator   |
#   |                                 |     (client namespace)  |
#   +---------------------------------+-------------------------+
#   |  3: command pane -- where you type during the demo        |
#   +-----------------------------------------------------------+
#
# Usage:  ./bench/demo_tmux.sh        then follow docs/DEMO.md
# Detach: Ctrl-b d     Switch pane: Ctrl-b <arrow>     Kill: Ctrl-b &
# =============================================================================
set -uo pipefail

SESSION="${SESSION:-xdpdemo}"
NS="${NS:-fwtest}"
IFACE="${IFACE:-veth-fw}"
FW_IP="${FW_IP:-10.10.1.1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

command -v tmux >/dev/null || { echo "error: tmux not installed (sudo apt install tmux)" >&2; exit 1; }

tmux kill-session -t "$SESSION" 2>/dev/null || true

# Pane 0 (left): the adaptive control plane.
tmux new-session -d -s "$SESSION" -x 200 -y 50 -c "$ROOT"
tmux send-keys -t "$SESSION" \
  "clear; echo '[pane 0] control plane -- start with:'; echo '  sudo python3 -m control.controller --iface $IFACE --dry-run'" C-m

# Pane 1 (top right): raw counters.
tmux split-window -h -t "$SESSION" -p 45 -c "$ROOT"
tmux send-keys -t "$SESSION" \
  "clear; echo '[pane 1] counters -- start with:'; echo '  sudo python3 -m control.fwctl stats --watch'" C-m

# Pane 2 (bottom right): traffic generation, pre-entered into the namespace.
tmux split-window -v -t "$SESSION" -p 55 -c "$ROOT"
tmux send-keys -t "$SESSION" \
  "clear; echo '[pane 2] traffic generator (client side)'; echo '  sudo ip netns exec $NS ping $FW_IP'; echo '  sudo ./bench/gen_traffic.sh syn_flood 60 10.10.1.3'" C-m

# Pane 3 (bottom, full width): where you type.
tmux select-pane -t "$SESSION".0
tmux split-window -v -t "$SESSION" -p 22 -c "$ROOT"
tmux send-keys -t "$SESSION" "clear; echo '[pane 3] command pane -- follow docs/DEMO.md here'" C-m

tmux select-pane -t "$SESSION".3
echo "attaching to tmux session '$SESSION' (Ctrl-b d to detach)"
tmux attach -t "$SESSION"
