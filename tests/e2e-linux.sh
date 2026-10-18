#!/bin/bash
# End to end on one Linux box with real OS users. Two daemons stand in for two machines:
# "ws" hosts boundaries work and vault, "laptop" hosts work. They use the default network (n0
# relays and DNS, plus mDNS). Covers the membership file and ticket join, OS-user boundaries,
# grants, MCP over stdio, a tool call to another machine's offered server through the steward,
# shell forwarding, bios, the hook, the steward waking a mailbox, the connector and the TUI.
# Needs passwordless sudo, python3 and curl. Creates and removes the users tme-work, tme-vault
# tme-lap and tme-none (mapped to no boundary).
# Usage: cargo build --release && tests/e2e-linux.sh
set -uo pipefail
BIN=${TEARMESH_BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/release/tearmesh}
[ -x "$BIN" ] || { echo "build first: cargo build --release" >&2; exit 2; }
cd /
T=$(mktemp -d /tmp/tm-e2e.XXXX)
chmod 0755 "$T"
USERS="tme-work tme-vault tme-lap tme-none"
FAILED=0
cleanup() {
  kill $(jobs -p) 2>/dev/null
  sudo pkill -u tme-work -f "$T/tearmesh" 2>/dev/null
  sudo pkill -u tme-lap -f "$T/tearmesh" 2>/dev/null
  sleep 0.5
  for u in $USERS; do sudo userdel -r "$u" 2>/dev/null; done
  rm -rf "$T"
}
trap cleanup EXIT
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAILED=1; }
check() { local what=$1; shift; if "$@"; then pass "$what"; else fail "$what"; fi; }
wait_for() { for _ in $(seq 1 60); do "$@" && return 0; sleep 0.5; done; return 1; }
# Each refusal must come with its own reason, not just a non-zero exit.
refused() { local want=$1; shift; local out; out=$("$@" 2>&1) && return 1; grep -q "$want" <<<"$out" || { echo "  got: $out"; return 1; }; }

for u in $USERS; do sudo useradd --create-home --shell /bin/bash "$u" && sudo chmod 0700 "/home/$u"; done
cp "$BIN" "$T/tearmesh" && chmod 0755 "$T/tearmesh"
TM=$T/tearmesh
ssh-keygen -q -t ed25519 -N '' -f "$T/owner"
ssh-keygen -q -t ed25519 -N '' -f "$T/backup"

# A stand-in sshd for the shell check: answers with an SSH banner.
SSHD_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
python3 - "$SSHD_PORT" >/dev/null 2>&1 <<'EOF' &
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen()
while True:
    c, _ = s.accept(); c.sendall(b"SSH-2.0-fake\r\n"); c.close()
EOF

cat > "$T/ws.toml" <<EOF
machine = "ws"
state_dir = "$T/ws"
socket = "$T/ws.sock"
sync_interval_secs = 2
shell_port = $SSHD_PORT
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
"$TM" mesh new "$T/mesh.toml" --name home --owner-key "$T/owner.pub" --owner-key "$T/backup.pub" --boundary work --boundary vault >/dev/null
"$TM" mesh add ws "$WS_ID" --boundary work --boundary vault --file "$T/mesh.toml" --key "$T/owner" >/dev/null

"$TM" daemon --config "$T/ws.toml" 2>"$T/ws.log" &
"$TM" daemon --config "$T/laptop.toml" 2>"$T/laptop.log" &
wait_for test -S "$T/ws.sock" && wait_for test -S "$T/laptop.sock"
WS="env TEARMESH_SOCKET=$T/ws.sock $TM"
LAP="env TEARMESH_SOCKET=$T/laptop.sock $TM"
$WS mesh apply "$T/mesh.toml" >/dev/null

# Join with a ticket: the code on both sides must match, then the owner approves.
TICKET=$($WS mesh invite laptop --boundary work 2>/dev/null)
check "a ticket is about 200 characters or less" test "${#TICKET}" -lt 260
$LAP join "$TICKET" >"$T/join.out" 2>&1 &
JOIN_PID=$!
pending() { $WS mesh pending 2>/dev/null | grep -q '^laptop  code'; }
check "the join request waits for approval" wait_for pending
LAP_CODE=$(grep -o 'code [0-9]\{6\}' "$T/join.out" | head -1)
WS_CODE=$($WS mesh pending | grep -o 'code [0-9]\{6\}')
check "both sides show the same 6-digit code" test -n "$LAP_CODE" -a "$LAP_CODE" = "$WS_CODE"
$WS mesh approve laptop --key "$T/owner" --yes >/dev/null 2>&1
wait $JOIN_PID
check "laptop joins once approved" grep -q "joined; mesh version 3" "$T/join.out"
check "a member machine can't join again" refused "already belongs to a mesh" $LAP join "$TICKET"

# run USER SOCKET MAILBOX tearmesh-args...
run() { local u=$1 s=$2 m=$3; shift 3; sudo -u "$u" env TEARMESH_SOCKET="$s" TEARMESH_MAILBOX="$m" TEARMESH_OFFERS="$T/offers-$u.toml" "$TM" "$@"; }
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
check "vault session can't address a work-only machine" refused "is not in boundary vault" run tme-vault "$T/ws.sock" builder post --to admin@laptop --subject x --body x
check "vault session can't read work mail on the same machine" refused "no letter" run tme-vault "$T/ws.sock" builder read "${ID1:0:12}"
check "work user can't read the vault user's home" refused "Permission denied" sudo -u tme-work ls /home/tme-vault
check "boundary users can't read the daemon's state" refused "Permission denied" sudo -u tme-vault cat "$T/ws/boundaries/vault.db"
check "an unmapped OS user is refused" refused "isn't mapped" sudo -u tme-none env TEARMESH_SOCKET="$T/ws.sock" "$TM" who
check "a boundary user can't run admin commands" refused "admin only" run tme-work "$T/ws.sock" admin status

# Tools: ws's work boundary offers an MCP server; laptop may call one of its two tools.
cat > "$T/echo-server.py" <<'EOF'
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if "id" not in m:
        continue
    if m["method"] == "initialize":
        r = {"protocolVersion": m["params"]["protocolVersion"], "capabilities": {"tools": {}},
             "serverInfo": {"name": "echo", "version": "1"}, "instructions": "Echoes text."}
    elif m["method"] == "tools/list":
        r = {"tools": [{"name": "echo", "description": "Echo text", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
                       {"name": "wipe", "description": "Deletes everything", "inputSchema": {"type": "object"}}]}
    elif m["method"] == "tools/call":
        r = {"content": [{"type": "text", "text": "echo: " + m["params"].get("arguments", {}).get("text", "")}]}
    else:
        print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "error": {"code": -32601, "message": "no"}}), flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}), flush=True)
EOF
cat > "$T/offers-tme-work.toml" <<EOF
[echo]
command = ["python3", "$T/echo-server.py"]
description = "Echoes text"
dir = "$T"
EOF
chmod 0644 "$T/echo-server.py" "$T/offers-tme-work.toml"
publish() { local out; out=$(run tme-work "$T/ws.sock" admin offer publish echo 2>&1); grep -q 'published; pin' <<<"$out" || { echo "  got: $out"; return 1; }; }
check "a boundary user publishes an offer" publish
sudo -u tme-work env TEARMESH_SOCKET="$T/ws.sock" TEARMESH_OFFERS="$T/offers-tme-work.toml" TEARMESH_MAILBOXES=/nonexistent "$TM" steward 2>"$T/steward-ws.log" &
MCP_INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}'
remote_call() {
  printf '%s\n' "$MCP_INIT" '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"over the mesh"}}}' \
    '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"wipe","arguments":{}}}' \
    '{"jsonrpc":"2.0","id":5,"method":"resources/list"}' \
    | (cat; sleep 3) | sudo -u tme-lap env TEARMESH_SOCKET="$T/laptop.sock" "$TM" mcp --remote ws/echo 2>&1
}
check "no tools grant: the call is refused" bash -c "$(declare -f remote_call); MCP_INIT='$MCP_INIT' T=$T TM=$TM remote_call | grep -q 'no tools grant'"
check "no shell grant: shell is refused" refused "no shell grant" run tme-lap "$T/laptop.sock" admin shell-proxy ws
$WS mesh grant laptop ws tools shell --key "$T/owner" --out "$T/v4.toml" >/dev/null
lap_has_grant() { $LAP mesh show 2>/dev/null | grep -q 'from = "laptop"'; }
check "laptop learns the grant" wait_for lap_has_grant
check "an offer needs the owner's approval" bash -c "$(declare -f remote_call); MCP_INIT='$MCP_INIT' T=$T TM=$TM remote_call | grep -q \"hasn't approved\""
$WS mesh approve-offer ws work echo --tools echo --key "$T/owner" --out "$T/v5.toml" >/dev/null
lap_has_approval() { $LAP mesh show 2>/dev/null | grep -q 'server = "echo"'; }
check "laptop learns the approval" wait_for lap_has_approval
OUT=$(remote_call)
check "a tool call reaches the offered server and back" grep -q 'echo: over the mesh' <<<"$OUT"
only_echo() { grep '"id":2' <<<"$OUT" | grep -q '"echo"' && ! grep '"id":2' <<<"$OUT" | grep -q wipe; }
check "the tool list is cut to the approved subset" only_echo
reply_has() { grep "\"id\":$1" <<<"$OUT" | grep -q "$2"; }
check "an unapproved tool is refused" reply_has 4 "isn't approved"
check "other MCP methods are refused" reply_has 5 "isn't allowed"
check "the steward ran the server as the boundary user" grep -q "serving echo" "$T/steward-ws.log"

shell_ok() { local out; out=$(printf '' | timeout 10 sudo -u tme-lap env TEARMESH_SOCKET="$T/laptop.sock" "$TM" shell-proxy ws 2>&1); grep -q "SSH-2.0-fake" <<<"$out" || { echo "  got: $out"; return 1; }; }
check "shell-proxy reaches ws's sshd" shell_ok
check "the shell grant is one way" refused "no shell grant" run tme-work "$T/ws.sock" admin shell-proxy laptop

printf 'role: build box\noffers: [echo]\n' | run tme-work "$T/ws.sock" admin bio set - >/dev/null
lap_sees_bio() { run tme-lap "$T/laptop.sock" admin bio show ws 2>/dev/null | grep -q 'build box'; }
check "a bio set on ws shows on laptop" wait_for lap_sees_bio

MCP_OUT=$(printf '%s\n' "$MCP_INIT" \
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
sudo -u tme-lap env TEARMESH_SOCKET="$T/laptop.sock" TEARMESH_OFFERS=/nonexistent "$TM" steward --mailboxes "$T/lap-mailboxes.toml" 2>"$T/waker.log" &
sleep 1
PING=$(run tme-work "$T/ws.sock" builder post --to helper@laptop --subject ping --body ping)
ws_has_reply() { run tme-work "$T/ws.sock" builder inbox 2>/dev/null | grep -q "re: wake"; }
check "mail to an empty mailbox wakes a session, which replies" wait_for ws_has_reply
REPLY_ID=$(run tme-work "$T/ws.sock" builder inbox | grep "re: wake" | cut -c1-12)
check "the reply is on the same thread" bash -c "sudo -u tme-work env TEARMESH_SOCKET=$T/ws.sock TEARMESH_MAILBOX=builder $TM read $REPLY_ID | grep -q 'thread:  $PING'"
sleep 3
check "one letter wakes once" test "$(grep -c 'waking helper@laptop' "$T/waker.log")" = 1

# The connector: HTTP MCP on a Unix socket only tme-lap can open; its letters are guest.
sudo -u tme-lap mkdir -p /home/tme-lap/notes
sudo -u tme-lap sh -c 'echo "meeting at noon" > /home/tme-lap/notes/today.md'
cat > "$T/connector.toml" <<EOF
listen = "/home/tme-lap/.local/state/tearmesh/connector/mcp.sock"
mailbox = "phone"
roots = ["/home/tme-lap/notes"]
EOF
chmod 0644 "$T/connector.toml"
sudo -u tme-lap env TEARMESH_SOCKET="$T/laptop.sock" "$TM" mcp --http "$T/connector.toml" 2>"$T/connector.log" &
CSOCK=/home/tme-lap/.local/state/tearmesh/connector/mcp.sock
wait_for sudo -u tme-lap test -S "$CSOCK"
# curl as USER: JSON-RPC over the connector's socket, with the session id after initialize.
cpost() { local u=$1 body=$2 sid=${3:-}; sudo -u "$u" curl -s -m 10 --unix-socket "$CSOCK" -D - \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  ${sid:+-H "mcp-session-id: $sid"} -d "$body" http://localhost/mcp; }
cpost tme-lap "$MCP_INIT" >"$T/c-init.out"
SID=$(grep -i '^mcp-session-id:' "$T/c-init.out" | cut -d' ' -f2 | tr -d '\r')
check "the connector answers initialize" grep -q tearmesh-connector "$T/c-init.out"
cpost tme-lap '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$SID" >/dev/null
C_FILE=$(cpost tme-lap '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"today.md"}}}' "$SID")
check "the connector reads a file under its roots" grep -q 'meeting at noon' <<<"$C_FILE"
C_OUT=$(cpost tme-lap '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"../.bashrc"}}}' "$SID")
check "the connector refuses a path outside its roots" grep -q "can't open" <<<"$C_OUT"
cpost tme-lap '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"post","arguments":{"to":["helper@laptop","builder@ws"],"subject":"from the phone","body":"hi","kind":"task"}}}' "$SID" >/dev/null
ws_has_phone() { run tme-work "$T/ws.sock" builder inbox 2>/dev/null | grep -q "from the phone"; }
check "a letter posted through the connector arrives" wait_for ws_has_phone
PHONE_ID=$(run tme-work "$T/ws.sock" builder inbox | grep "from the phone" | cut -c1-12)
check "it carries guest trust and its kind" bash -c "sudo -u tme-work env TEARMESH_SOCKET=$T/ws.sock TEARMESH_MAILBOX=builder $TM read $PHONE_ID | grep -q 'trust:   guest' && sudo -u tme-work env TEARMESH_SOCKET=$T/ws.sock TEARMESH_MAILBOX=builder $TM read $PHONE_ID | grep -q 'kind:    task'"
sleep 3
check "a guest letter doesn't wake a default mailbox" test "$(grep -c 'waking helper@laptop' "$T/waker.log")" = 1
check "another local user can't reach the connector" refused "" cpost tme-work "$MCP_INIT"

# The terminal UI, driven through tmux as the laptop's boundary user.
if command -v tmux >/dev/null; then
  export TMUX_TMPDIR=$T
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

if [ $FAILED = 0 ]; then echo "ALL PASSED"; else
  for f in ws.log laptop.log steward-ws.log waker.log connector.log join.out; do echo "--- $f"; tail -15 "$T/$f"; done
  exit 1
fi
