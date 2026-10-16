#!/bin/bash
# End to end on one Linux box with real OS users. Two daemons stand in for two machines:
# "ws" hosts boundaries work and vault, "laptop" hosts work. They use the defaults (n0 relays and
# DNS). Covers the circle and invite flow, OS-user boundaries, MCP over stdio, the hook, the waker.
# Needs passwordless sudo. Creates and removes the users tme-work, tme-vault and tme-lap.
# Usage: cargo build --release && tests/e2e-linux.sh
set -uo pipefail
BIN=$(cd "$(dirname "$0")/.." && pwd)/target/release/tearmesh
[ -x "$BIN" ] || { echo "build first: cargo build --release" >&2; exit 2; }
cd /
T=$(mktemp -d /tmp/tm-e2e.XXXX)
chmod 0755 "$T"
USERS="tme-work tme-vault tme-lap"
FAILED=0
cleanup() {
  kill $(jobs -p) 2>/dev/null
  sleep 0.5
  for u in $USERS; do sudo userdel -r "$u" 2>/dev/null; done
  rm -rf "$T"
}
trap cleanup EXIT
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAILED=1; }
check() { local what=$1; shift; if "$@"; then pass "$what"; else fail "$what"; fi; }
wait_for() { for _ in $(seq 1 40); do "$@" && return 0; sleep 0.5; done; return 1; }

for u in $USERS; do sudo useradd --create-home --shell /bin/bash "$u" && sudo chmod 0700 "/home/$u"; done
cp "$BIN" "$T/tearmesh" && chmod 0755 "$T/tearmesh"
TM=$T/tearmesh
ssh-keygen -q -t ed25519 -N '' -f "$T/owner"
ssh-keygen -q -t ed25519 -N '' -f "$T/backup"

cat > "$T/ws.toml" <<EOF
machine = "ws"
state_dir = "$T/ws"
socket = "$T/ws.sock"
sync_interval_secs = 2
[users]
tme-work = "work"
tme-vault = "vault"
EOF
cat > "$T/laptop.toml" <<EOF
machine = "laptop"
state_dir = "$T/laptop"
socket = "$T/laptop.sock"
sync_interval_secs = 2
[users]
tme-lap = "work"
EOF

WS_ID=$("$TM" id --config "$T/ws.toml")
LAP_ID=$("$TM" id --config "$T/laptop.toml")
"$TM" circle new "$T/circle.toml" --name home --owner-key "$T/owner.pub" --owner-key "$T/backup.pub" --boundary work --boundary vault >/dev/null
"$TM" circle add "$T/circle.toml" ws "$WS_ID" --boundary work --boundary vault >/dev/null
"$TM" circle add "$T/circle.toml" laptop "$LAP_ID" --boundary work >/dev/null
"$TM" circle sign "$T/circle.toml" --key "$T/owner" >/dev/null

"$TM" daemon --config "$T/ws.toml" 2>"$T/ws.log" &
"$TM" daemon --config "$T/laptop.toml" 2>"$T/laptop.log" &
wait_for test -S "$T/ws.sock" && wait_for test -S "$T/laptop.sock"
TEARMESH_SOCKET=$T/ws.sock "$TM" circle apply "$T/circle.toml" >/dev/null
CODE=$(TEARMESH_SOCKET=$T/ws.sock "$TM" invite)
check "laptop joins with an invite" bash -c "TEARMESH_SOCKET=$T/laptop.sock $TM join '$CODE' --yes >/dev/null"

# run USER SOCKET MAILBOX tearmesh-args...
run() { local u=$1 s=$2 m=$3; shift 3; sudo -u "$u" env TEARMESH_SOCKET="$s" TEARMESH_MAILBOX="$m" "$TM" "$@"; }
lap_inbox_has() { run tme-lap "$T/laptop.sock" admin inbox --all 2>/dev/null | grep -q "$1"; }

ID1=$(run tme-work "$T/ws.sock" builder post --to admin@laptop --subject "work note" --body "hello laptop")
run tme-vault "$T/ws.sock" builder post --to '*' --subject "vault secret" --body "do not leak" >/dev/null
check "work letter crosses machines" wait_for lap_inbox_has "work note"
sleep 3 # several more sync rounds
LAP_ALL=$(run tme-lap "$T/laptop.sock" admin inbox --all)
lap_ok() { grep -q 'work note' <<<"$LAP_ALL" && ! grep -q vault <<<"$LAP_ALL"; }
check "vault letter is absent from laptop's inbox" lap_ok
check "vault letter is stored on ws" grep -rqa "vault secret" "$T/ws/boundaries"
check "no vault bytes anywhere on laptop's disk" bash -c "[ ! -e $T/laptop/boundaries/vault.db ] && ! grep -rqa 'vault secret' $T/laptop"
# Each refusal must come with its own reason, not just a non-zero exit.
refused() { local want=$1; shift; local out; out=$("$@" 2>&1) && return 1; grep -q "$want" <<<"$out"; }
check "vault session can't address a work-only machine" refused "is not in boundary vault" run tme-vault "$T/ws.sock" builder post --to admin@laptop --subject x --body x
check "vault session can't read work mail on the same machine" refused "no letter" run tme-vault "$T/ws.sock" builder read "${ID1:0:12}"
check "work user can't read the vault user's home" refused "Permission denied" sudo -u tme-work ls /home/tme-vault
check "boundary users can't read the daemon's state" refused "Permission denied" sudo -u tme-vault cat "$T/ws/boundaries/vault.db"
check "an unmapped OS user is refused" bash -c "sudo -u nobody env TEARMESH_SOCKET=$T/ws.sock $TM who 2>&1 | grep -q \"isn't mapped\""

MCP_OUT=$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"inbox","arguments":{"all":true}}}' \
  | (cat; sleep 2) | sudo -u tme-lap env TEARMESH_SOCKET="$T/laptop.sock" TEARMESH_MAILBOX=admin "$TM" mcp 2>/dev/null)
mcp_ok() { grep -q '"name":"post"' <<<"$MCP_OUT" && grep -q 'work note' <<<"$MCP_OUT"; }
check "MCP server lists tools and reads the inbox over stdio" mcp_ok

run tme-work "$T/ws.sock" builder post --to admin@laptop --subject "hook test" --body x >/dev/null
wait_for lap_inbox_has "hook test"
HOOK=$(echo '{"hook_event_name":"UserPromptSubmit"}' | run tme-lap "$T/laptop.sock" admin hook)
check "hook announces new mail" grep -q "hook test" <<<"$HOOK"
HOOK2=$(echo '{"hook_event_name":"UserPromptSubmit"}' | run tme-lap "$T/laptop.sock" admin hook)
once() { [ -n "$HOOK" ] && [ -z "$HOOK2" ]; }
check "hook announces each letter only once" once

cat > "$T/reply.sh" <<EOF
#!/bin/sh
# Stand-in agent: replies to the first letter it was woken for.
exec $TM post --to builder@ws --subject "re: wake" --body pong --thread "\${TEARMESH_WAKE_IDS%%,*}"
EOF
chmod 0755 "$T/reply.sh"
cat > "$T/lap-mailboxes.toml" <<EOF
[helper]
dir = "/home/tme-lap"
command = ["$T/reply.sh"]
EOF
sudo -u tme-lap env TEARMESH_SOCKET="$T/laptop.sock" "$TM" waker --config "$T/lap-mailboxes.toml" 2>"$T/waker.log" &
sleep 1
PING=$(run tme-work "$T/ws.sock" builder post --to helper@laptop --subject ping --body ping)
ws_has_reply() { run tme-work "$T/ws.sock" builder inbox 2>/dev/null | grep -q "re: wake"; }
check "mail to an empty mailbox wakes a session, which replies" wait_for ws_has_reply
REPLY_ID=$(run tme-work "$T/ws.sock" builder inbox | grep "re: wake" | cut -c1-12)
check "the reply is on the same thread" bash -c "sudo -u tme-work env TEARMESH_SOCKET=$T/ws.sock TEARMESH_MAILBOX=builder $TM read $REPLY_ID | grep -q 'thread:  $PING'"
sleep 3
check "one letter wakes once" test "$(grep -c 'waking helper@laptop' "$T/waker.log")" = 1

# The terminal UI, driven through tmux as the laptop's boundary user.
if command -v tmux >/dev/null; then
  TS="tme2e-$$"
  tmux new-session -d -s "$TS" -x 140 -y 30 "sudo -u tme-lap env TEARMESH_SOCKET=$T/laptop.sock TEARMESH_MAILBOX=admin $TM tui"
  pane_has() { tmux capture-pane -p -t "$TS" 2>/dev/null | grep -q "$1"; }
  check "tui shows the address and inbox" wait_for pane_has "admin@laptop · boundary work"
  check "tui lists letters newest first" bash -c "tmux capture-pane -p -t $TS | grep -n 'hook test\|work note' | head -1 | grep -q 'hook test'"
  tmux send-keys -t "$TS" j Enter
  check "tui opens a letter" wait_for pane_has "hello laptop"
  tmux send-keys -t "$TS" r
  wait_for pane_has "Reply · To"
  tmux send-keys -t "$TS" -l "pong from the tui"
  tmux send-keys -t "$TS" C-s
  check "tui shows the send result" wait_for pane_has "sent "
  ws_has_tui_reply() { run tme-work "$T/ws.sock" builder inbox 2>/dev/null | grep -q "Re: work note"; }
  check "tui reply reaches the sender" wait_for ws_has_tui_reply
  TUI_ID=$(run tme-work "$T/ws.sock" builder inbox | grep "Re: work note" | cut -c1-12)
  tui_body() { local out; out=$(run tme-work "$T/ws.sock" builder read "$TUI_ID"); grep -q "pong from the tui" <<<"$out" && grep -q "thread:  $ID1" <<<"$out"; }
  check "tui reply body and thread are right" tui_body
  tmux send-keys -t "$TS" q
  tui_gone() { ! tmux has-session -t "$TS" 2>/dev/null; }
  check "tui quits cleanly" wait_for tui_gone
  tmux kill-session -t "$TS" 2>/dev/null
else
  echo "SKIP tui checks (no tmux)"
fi

if [ $FAILED = 0 ]; then echo "ALL PASSED"; else echo "--- ws.log"; tail -20 "$T/ws.log"; echo "--- laptop.log"; tail -20 "$T/laptop.log"; echo "--- waker.log"; cat "$T/waker.log"; exit 1; fi
