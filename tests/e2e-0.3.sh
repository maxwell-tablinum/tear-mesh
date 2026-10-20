#!/bin/bash
# End to end for 0.3 on one Linux box, trying to break things: the setup wizard (bad input,
# running twice, stopping halfway), the MCP hub (connect-or-start, one service per user, auth,
# all three channels both ways, harness chats), a stolen machine key and a leaked owner key, a
# node dropping mid-session, the owner offline, a flapping peer, and the menu, including a mesh
# created, joined and approved without leaving it. Three daemons
# stand in for three machines: "own" (the owner node), "mem" and "far", on the default network.
# Needs passwordless sudo, python3, curl, tmux, and a local sshd on port 22 that takes keys.
# Creates and removes the users tme3-own, tme3-mem, tme3-far, tme3-x and tme3-lab.
# Usage: cargo build --release && tests/e2e-0.3.sh
set -uo pipefail
BIN=${TEARMESH_BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/release/tearmesh}
[ -x "$BIN" ] || { echo "build first: cargo build --release" >&2; exit 2; }
cd /
T=$(mktemp -d /tmp/tm-e3.XXXX)
chmod 0755 "$T"
USERS="tme3-own tme3-mem tme3-far tme3-x tme3-lab"
FAILED=0
cleanup() {
  kill $(jobs -p) 2>/dev/null
  for u in $USERS; do sudo pkill -u "$u" 2>/dev/null; done
  pkill -f "$T/tearmesh" 2>/dev/null
  tmux -S "$T/tmux" kill-server 2>/dev/null
  sleep 0.5
  for u in $USERS; do sudo userdel -r "$u" 2>/dev/null; done
  rm -rf "$T"
}
trap cleanup EXIT
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAILED=1; }
check() { local what=$1; shift; if "$@"; then pass "$what"; else fail "$what"; fi; }
wait_for() { for _ in $(seq 1 80); do "$@" && return 0; sleep 0.5; done; return 1; }
has() { grep -q -- "$1" <<<"$2" || { echo "  got: ${2:0:800}"; return 1; }; }
lacks() { ! grep -q -- "$1" <<<"$2" || { echo "  got: ${2:0:800}"; return 1; }; }
refused() { local want=$1; shift; local out; out=$("$@" 2>&1) && return 1; grep -q -- "$want" <<<"$out" || { echo "  got: $out"; return 1; }; }
my_setup_dirs() { find /tmp -maxdepth 1 -name 'tearmesh-setup-*' -user "$(id -un)" 2>/dev/null | wc -l; }

for u in $USERS; do sudo useradd --create-home --shell /bin/bash "$u" && sudo chmod 0700 "/home/$u"; done
cp "$BIN" "$T/tearmesh" && chmod 0755 "$T/tearmesh"
TM=$T/tearmesh
# ssh-keygen (the CLI's signer) reads the passphrase from here; the recovery key has its own.
echo e2e-passphrase >"$T/pass"
printf '#!/bin/sh\ncat %s/pass\n' "$T" >"$T/askpass" && chmod 0755 "$T/askpass"
export SSH_ASKPASS=$T/askpass SSH_ASKPASS_REQUIRE=force DISPLAY=none

for n in own mem far; do
  cat >"$T/$n.toml" <<EOF
machine = "$n"
state_dir = "$T/$n"
socket = "$T/$n.sock"
sync_interval_secs = 2
[users]
tme3-$n = "work"
EOF
done
start() { "$TM" daemon --config "$T/$1.toml" 2>>"$T/$1.log" & echo $! >"$T/$1.pid"; wait_for test -S "$T/$1.sock"; }
stop() { kill "$(cat "$T/$1.pid")" 2>/dev/null; wait "$(cat "$T/$1.pid")" 2>/dev/null; rm -f "$T/$1.sock"; }
for n in own mem far; do start $n; done
on() { local n=$1; shift; env TEARMESH_SOCKET="$T/$n.sock" "$TM" "$@"; }
# setup N HOME: the wizard for daemon N with keys under HOME/.ssh, answers on stdin.
setup() { env HOME="$2" TEARMESH_SOCKET="$T/$1.sock" "$TM" setup --config "$T/$1.toml"; }
version() { on "$1" status | python3 -c 'import json,sys;print(json.load(sys.stdin)["mesh"]["version"])'; }
mkdir -p "$T/h-own" "$T/h-mem" "$T/h-far"

echo "== setup"
OUT=$(printf 'x\n3\n1\nBad Name\n-home\nhome\nshort\nshort\ne2e-passphrase\nother-one\ne2e-passphrase\ne2e-passphrase\nnope\nsaved\ny\n' | setup own "$T/h-own" 2>&1)
check "setup re-asks on a bad choice" has "isn't one of the choices" "$OUT"
check "setup re-asks on a bad mesh name" has 'use 1–32 characters' "$OUT"
check "setup refuses a short passphrase" has '8 characters' "$OUT"
check "setup refuses passphrases that differ" has 'passphrases differ' "$OUT"
check "setup waits for the word saved" has 'type the word saved' "$OUT"
check "only the recovery key is shown, once" test "$(grep -c 'BEGIN OPENSSH PRIVATE KEY' <<<"$OUT")" = 1
check "  with the instruction" has 'Save both somewhere off this machine' "$OUT"
check "setup creates the mesh" has 'Mesh home is created' "$OUT"
OWNER=$T/h-own/.ssh/tearmesh-owner-home
check "the everyday key is in ~/.ssh, private" test "$(stat -c %a "$OWNER" 2>/dev/null)" = 600
check "the everyday key has a passphrase" refused "" ssh-keygen -y -P '' -f "$OWNER"
check "  the one given at setup" bash -c "ssh-keygen -y -P e2e-passphrase -f $OWNER >/dev/null"
check "only one private key is left on the machine" test "$(ls "$T/h-own/.ssh" | grep -vc '\.pub$')" = 1
check "no setup leftovers in the temp directory" test "$(my_setup_dirs)" = 0
awk '/^──── Recovery key/{f=1;next} f&&/^────/{exit} f' <<<"$OUT" >"$T/recovery"
chmod 600 "$T/recovery"
RECPASS=$(awk '/^──── Its passphrase/{getline; print; exit}' <<<"$OUT")
check "the recovery passphrase is six words" bash -c "[[ '$RECPASS' =~ ^[a-z]+(-[a-z]+){5}\$ ]]"
check "the shown recovery key opens with its own passphrase" bash -c "ssh-keygen -y -P '$RECPASS' -f $T/recovery >/dev/null"
check "  and not with the everyday one" refused "" ssh-keygen -y -P e2e-passphrase -f "$T/recovery"
V1=$(version own)
OUT=$(printf '\n' | setup own "$T/h-own" 2>&1)
check "setup again: says it's set up" has 'is already set up: mesh home' "$OUT"
check "setup again: knows it's the owner node" has 'It is an owner node' "$OUT"
check "setup again: changes nothing" test "$(version own)" = "$V1"
check "setup on closed input quits cleanly" bash -c "env HOME=$T/h-own TEARMESH_SOCKET=$T/own.sock $TM setup --config $T/own.toml </dev/null >/dev/null 2>&1"
head -c 4000 /dev/urandom | tr -d '\000' >"$T/junk"
check "setup survives binary junk on its input" bash -c "env HOME=$T/h-mem TEARMESH_SOCKET=$T/mem.sock $TM setup --config $T/mem.toml <$T/junk >/dev/null 2>&1"
check "  and the junk created no mesh" has '"mesh": null' "$(on mem status)"

# Stop halfway: Ctrl-C at the passphrase, then a hard kill.
mkfifo "$T/in"
exec 7<>"$T/in"
env HOME="$T/h-mem" TEARMESH_SOCKET="$T/mem.sock" "$TM" setup --config "$T/mem.toml" <"$T/in" >"$T/half.out" 2>&1 &
HALF=$!
printf '1\nhalfway\n' >&7
wait_for grep -q 'Passphrase:' "$T/half.out"
kill -INT $HALF; wait $HALF
check "Ctrl-C mid-setup says nothing changed" grep -q 'Setup stopped. Nothing was changed' "$T/half.out"
check "Ctrl-C mid-setup leaves no key" test ! -e "$T/h-mem/.ssh/tearmesh-owner-halfway"
check "Ctrl-C mid-setup leaves no temp keys" test "$(my_setup_dirs)" = 0
check "Ctrl-C mid-setup leaves no mesh" has '"mesh": null' "$(on mem status)"
env HOME="$T/h-mem" TEARMESH_SOCKET="$T/mem.sock" "$TM" setup --config "$T/mem.toml" <"$T/in" >"$T/half2.out" 2>&1 &
HALF=$!
printf '1\nhalfway\ne2e-passphrase\ne2e-passphrase\n' >&7
wait_for grep -q 'Type `saved`' "$T/half2.out"
kill -KILL $HALF; wait $HALF 2>/dev/null
check "a killed setup leaves nothing behind (keys live in memory until the end)" \
  bash -c "test ! -e $T/h-mem/.ssh/tearmesh-owner-halfway && test \$(find /tmp -maxdepth 1 -name 'tearmesh-setup-*' -user $(id -un) | wc -l) = 0"
# Rerun and join this time, giving a bad and a cut ticket first. The ticket names no machine.
TICKET=$(on own mesh invite 2>"$T/invite.err")
check "invite's hint points at the menu and setup" grep -q 'tearmesh menu' "$T/invite.err"
env HOME="$T/h-mem" TEARMESH_SOCKET="$T/mem.sock" "$TM" setup --config "$T/mem.toml" <"$T/in" >"$T/join.out" 2>&1 &
JOIN=$!
printf '2\nhello\ntm2-cut\n%s\n' "$TICKET" >&7
pending() { on own mesh pending 2>/dev/null | grep -q "^$1  code"; }
check "the rerun's join request reaches the owner" wait_for pending mem
check "a bad ticket is re-asked" grep -q 'a ticket starts with tm2-' "$T/join.out"
check "a cut ticket is re-asked" grep -q 'too short' "$T/join.out"
CODE=$(on own mesh pending | grep -o 'code [0-9]\{6\}' | cut -d' ' -f2)
check "approve finds the owner key itself" has 'applied mesh version' "$(env HOME=$T/h-own TEARMESH_SOCKET=$T/own.sock $TM mesh approve mem --yes 2>&1)"
wait $JOIN
exec 7>&-
check "mem joins through the wizard" grep -q 'Joined. Mesh version' "$T/join.out"
check "the code shown matches the owner's" grep -q "Code $CODE" "$T/join.out"
TICKET=$(on own mesh invite far --boundary work 2>/dev/null)
on far join "$TICKET" >/dev/null 2>&1 &
FARJ=$!
wait_for pending far
on own mesh approve far --key "$OWNER" --yes >/dev/null 2>&1
wait $FARJ
check "a home with no owner key is refused with the fingerprints" refused "no owner key for mesh home" \
  env HOME=$T/h-far TEARMESH_SOCKET=$T/own.sock $TM mesh boundary add lab --out "$T/b0.toml"
check "setup on a member says member" has 'It is a member' "$(printf '\n' | setup mem "$T/h-mem" 2>&1)"

echo "== ping and the map"
cat >"$T/ping.py" <<'EOF'
import json, socket, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(b'{"op":"ping"}\n')
r = json.loads(s.makefile().readline())
up = {p["name"]: p["rtt_ms"] is not None for p in r.get("data") or []}
want = dict(x.split("=") for x in sys.argv[2].split(","))
sys.exit(0 if all(up.get(k, False) == (v == "up") for k, v in want.items()) else 1)
EOF
# ping_is NODE machine=up|down,...: what NODE's ping round says.
ping_is() { python3 "$T/ping.py" "$T/$1.sock" "$2"; }
check "the owner pings both members" wait_for ping_is own mem=up,far=up
OUT=$(echo '{"op":"ping"}' | sudo -u tme3-mem python3 -c "import socket,sys;s=socket.socket(socket.AF_UNIX);s.connect('$T/mem.sock');s.sendall(sys.stdin.buffer.read());print(s.makefile().readline())")
check "a boundary user can't ping (admin only)" has 'admin only' "$OUT"

echo "== grants, and an offer on two machines"
g=0
grant() { g=$((g + 1)); on own mesh grant "$@" --key "$OWNER" --out "$T/g$g.toml" >/dev/null 2>&1; }
grant mem own converse tools shell; grant own mem converse tools shell
grant far own converse; grant own far converse; grant mem far converse; grant far mem converse
cat >"$T/echo.py" <<'EOF'
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if "id" not in m: continue
    if m["method"] == "initialize":
        r = {"protocolVersion": m["params"]["protocolVersion"], "capabilities": {"tools": {}}, "serverInfo": {"name": "echo", "version": "1"}}
    elif m["method"] == "tools/list":
        r = {"tools": [{"name": "echo", "description": "Echo", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}]}
    else:
        r = {"content": [{"type": "text", "text": "echo from " + sys.argv[1] + ": " + m["params"]["arguments"].get("text", "")}]}
    print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}), flush=True)
EOF
chmod 0644 "$T/echo.py"
for n in own mem; do
  printf '[echo]\ncommand = ["python3", "%s", "%s"]\ndir = "%s"\n' "$T/echo.py" "$n" "$T" >"$T/offers-$n.toml"
  chmod 0644 "$T/offers-$n.toml"
  sudo -u tme3-$n env TEARMESH_SOCKET="$T/$n.sock" TEARMESH_OFFERS="$T/offers-$n.toml" "$TM" offer publish echo >/dev/null 2>&1
  sudo -u tme3-$n env TEARMESH_SOCKET="$T/$n.sock" TEARMESH_OFFERS="$T/offers-$n.toml" TEARMESH_MAILBOXES=/nonexistent "$TM" steward 2>"$T/steward-$n.log" &
done
seen_offer() { on own offers --boundary work 2>/dev/null | grep -q "\"machine\": \"$1\""; }
wait_for seen_offer mem
on own mesh approve-offer own work echo --key "$OWNER" --out "$T/a1.toml" >/dev/null 2>&1
on own mesh approve-offer mem work echo --key "$OWNER" --out "$T/a2.toml" >/dev/null 2>&1
has_approvals() { [ "$(on mem mesh show 2>/dev/null | grep -c 'server = "echo"')" = 2 ]; }
check "the members learn the grants and approvals" wait_for has_approvals

echo "== MCP hub: one service per user"
for n in own mem far x; do
  sudo -u tme3-$n mkdir -p /home/tme3-$n/.config/tearmesh
  printf 'port = %s\n[harness.say]\ncommand = ["/bin/echo", "chat:", "{prompt}"]\n' $((17000 + RANDOM % 2000)) \
    | sudo -u tme3-$n tee /home/tme3-$n/.config/tearmesh/hub.toml >/dev/null
done
port_of() { sudo cat /home/tme3-$1/.config/tearmesh/hub.toml | grep -o '[0-9]*' | head -1; }
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}'
INITED='{"jsonrpc":"2.0","method":"notifications/initialized"}'
LIST='{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
call() { printf '{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"%s","arguments":%s}}' "$1" "$2" "$3"; }
# stdio NODE SECONDS LINES...: an MCP session through `tearmesh mcp connect`, kept open SECONDS.
stdio() { local n=$1 secs=$2; shift 2; printf '%s\n' "$INIT" "$INITED" "$@" | (cat; sleep "$secs") | timeout $((secs + 30)) sudo -u tme3-$n env TEARMESH_SOCKET="$T/$n.sock" "$TM" mcp connect 2>&1; }
hubs() { pgrep -u tme3-$1 -f "tearmesh mcp serve" | wc -l; }
check "no hub runs before a client asks" test "$(hubs mem)" = 0
# Another user sits on far's hub port before far's hub ever starts.
FPORT=$(sudo cat /home/tme3-far/.config/tearmesh/hub.toml | grep -o '[0-9]*' | head -1)
sudo -u tme3-x python3 -c "import socket,time;s=socket.socket();s.bind(('127.0.0.1',$FPORT));s.listen();time.sleep(25)" &
SQUAT=$!
sleep 1
check "with its port taken by another user, a hub still starts and answers over its socket" has 'shell_exec' "$(stdio far 2 "$LIST")"
check "  and says HTTP is off" bash -c "sudo grep -q 'HTTP is off' /home/tme3-far/.local/state/tearmesh/hub/hub.log"
kill $SQUAT 2>/dev/null
OUT=$(stdio mem 2 "$LIST")
check "connect starts the hub and lists the shell tools" has 'shell_exec' "$OUT"
check "  the tools-channel tools" has 'call_tool' "$OUT"
check "  and the conversation tools" has 'wait_for_mail' "$OUT"
sleep 1
check "the hub keeps running after the client exits" test "$(hubs mem)" = 1
check "a second hub exits and says one is running" has 'already running' "$(sudo -u tme3-mem env TEARMESH_SOCKET=$T/mem.sock $TM mcp serve 2>&1)"
check "still exactly one hub" test "$(hubs mem)" = 1
sudo pkill -u tme3-mem -f "tearmesh mcp serve"; sleep 0.5
PIDS=""
for i in 1 2 3 4 5 6; do stdio mem 2 "$LIST" >"$T/race$i.out" & PIDS="$PIDS $!"; done
wait $PIDS
sleep 1
check "six clients starting it at once leave one hub" test "$(hubs mem)" = 1
check "  and all six got answers" test "$(grep -l shell_exec "$T"/race*.out | wc -l)" = 6
OUT=$(printf '%s\n' "$INIT" "$INITED" "$LIST" | (cat; sleep 2) | sudo -u tme3-mem env TEARMESH_SOCKET=$T/mem.sock $TM mcp 2>&1)
check "a harness's own stdio copy runs beside the hub" has '"name":"post"' "$OUT"
check "  and the hub is untouched" test "$(hubs mem)" = 1
check "the hub's directory is private" test "$(sudo stat -c %a /home/tme3-mem/.local/state/tearmesh/hub)" = 700
check "the token file is private" test "$(sudo stat -c %a /home/tme3-mem/.local/state/tearmesh/hub/token)" = 600
check "another user can't open the hub socket" refused "" sudo -u tme3-x python3 -c "import socket;s=socket.socket(socket.AF_UNIX);s.connect('/home/tme3-mem/.local/state/tearmesh/hub/hub.sock')"

PORT=$(port_of mem)
TOKEN=$(sudo cat /home/tme3-mem/.local/state/tearmesh/hub/token)
hpost() { curl -s -m 15 -D - -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' "$@" "http://127.0.0.1:$PORT/mcp"; }
check "HTTP without a token is 401" has '^HTTP/1.1 401' "$(hpost -d "$INIT")"
WRONG=$(printf '%s' "$TOKEN" | tr '0-9a-f' '1-9a-f0')
check "HTTP with a wrong token is 401" has '^HTTP/1.1 401' "$(hpost -H "Authorization: Bearer $WRONG" -d "$INIT")"
check "HTTP with a token prefix is 401" has '^HTTP/1.1 401' "$(hpost -H "Authorization: Bearer ${TOKEN:0:10}" -d "$INIT")"
check "HTTP from a foreign Host (DNS rebinding) is refused" lacks '^HTTP/1.1 200' "$(hpost -H "Authorization: Bearer $TOKEN" -H 'Host: evil.example' -d "$INIT")"
hpost -H "Authorization: Bearer $TOKEN" -d "$INIT" >"$T/h-init.out"
SID=$(grep -i '^mcp-session-id:' "$T/h-init.out" | cut -d' ' -f2 | tr -d '\r')
check "HTTP with the token initializes" grep -q tearmesh-hub "$T/h-init.out"
hpost -H "Authorization: Bearer $TOKEN" -H "mcp-session-id: $SID" -d "$INITED" >/dev/null
hcall() { hpost -H "Authorization: Bearer $TOKEN" -H "mcp-session-id: $SID" -d "$(call "$@")"; }

echo "== conversation, both ways"
check "the hub posts a letter over HTTP" has '\\"id\\"' "$(hcall 2 post '{"to":["agent@own"],"subject":"from mem hub","body":"hi"}')"
inbox_has() { sudo -u tme3-$1 env TEARMESH_SOCKET="$T/$1.sock" TEARMESH_MAILBOX=agent "$TM" inbox --all 2>/dev/null | grep -c -- "$2"; }
once_in() { [ "$(inbox_has "$1" "$2")" = 1 ]; }
check "it arrives on the owner node" wait_for once_in own "from mem hub"
# A session that stays open, to see the reply both pushed and returned by wait_for_mail.
(printf '%s\n' "$INIT" "$INITED"; sleep 1; call 3 wait_for_mail '{"timeout_secs":40}'; echo; sleep 14) \
  | sudo -u tme3-mem env TEARMESH_SOCKET="$T/mem.sock" "$TM" mcp connect >"$T/push.out" 2>&1 &
PUSH=$!
sleep 3
sudo -u tme3-own env TEARMESH_SOCKET="$T/own.sock" TEARMESH_MAILBOX=agent "$TM" post --to agent@mem --subject "back to mem" --body "reply" >/dev/null
wait $PUSH
check "wait_for_mail returns the reply" grep -q 'back to mem' "$T/push.out"
check "new mail is pushed to the open session" grep -q 'notifications/message.*new_mail' "$T/push.out"

echo "== tools, both ways"
check "mem's hub calls own's offered tool" has 'echo from own: ping' "$(stdio mem 6 "$(call 2 call_tool '{"machine":"own","server":"echo","tool":"echo","arguments":{"text":"ping"}}')")"
check "own's hub calls mem's offered tool" has 'echo from mem: pong' "$(stdio own 6 "$(call 2 call_tool '{"machine":"mem","server":"echo","tool":"echo","arguments":{"text":"pong"}}')")"
check "far has no tools grant: refused with the reason" has 'no tools grant' "$(stdio far 6 "$(call 2 call_tool '{"machine":"own","server":"echo","tool":"echo","arguments":{}}')")"
check "remote_tools shows the input schema" has 'inputSchema' "$(stdio mem 4 "$(call 2 remote_tools '{"machine":"own","server":"echo"}')")"

echo "== shell, both ways"
for a in own mem far; do sudo -u tme3-$a sh -c 'mkdir -p ~/.ssh && ssh-keygen -q -t ed25519 -N "" -f ~/.ssh/id_ed25519' </dev/null; done
for pair in "mem own" "own mem" "far own"; do
  set -- $pair
  sudo cat /home/tme3-$1/.ssh/id_ed25519.pub | sudo -u tme3-$2 sh -c 'cat >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys'
done
check "mem runs a command on own over the mesh" has 'tme3-own.*ran-on-own' "$(stdio mem 15 "$(call 2 shell_exec '{"machine":"own","user":"tme3-own","command":"id -un; echo ran-on-own"}')" | tr '\n' ' ')"
check "own runs a command on mem over the mesh" has 'tme3-mem' "$(stdio own 15 "$(call 2 shell_exec '{"machine":"mem","user":"tme3-mem","command":"id -un"}')")"
OUT=$(stdio far 15 "$(call 2 shell_exec '{"machine":"own","user":"tme3-own","command":"touch /tmp/far-was-here"}')")
check "far has no shell grant: refused with the reason" has 'no shell grant' "$OUT"
check "  and the command didn't run" test ! -e /tmp/far-was-here
check "an option smuggled in as a machine name is refused" has 'bad machine name' "$(stdio mem 4 "$(call 2 shell_exec '{"machine":"-oProxyCommand=touch /tmp/pwned","command":"x"}')")"
check "  and nothing ran" test ! -e /tmp/pwned
check "an option smuggled in as a user name is refused" has 'bad user name' "$(stdio mem 4 "$(call 2 shell_exec '{"machine":"own","user":"-oProxyCommand=x","command":"x"}')")"
shell_id() { grep -o '\\"id\\":\\"[0-9a-f]\{16\}' "$1" | grep -o '[0-9a-f]\{16\}' | head -1; }
(printf '%s\n' "$INIT" "$INITED"; call 2 shell_open '{"machine":"own","user":"tme3-own"}'; echo; sleep 6) \
  | sudo -u tme3-mem env TEARMESH_SOCKET="$T/mem.sock" "$TM" mcp connect >"$T/sh1.out" 2>&1
SHID=$(shell_id "$T/sh1.out")
OUT=$(stdio mem 12 "$(call 2 shell_read "{\"id\":\"$SHID\",\"wait_ms\":3000}")" "$(call 3 shell_send "{\"id\":\"$SHID\",\"input\":\"echo interactive-\$((6*7))\\n\"}")" "$(call 4 shell_read "{\"id\":\"$SHID\",\"wait_ms\":5000}")")
check "an open shell keeps going across client sessions" has 'interactive-42' "$OUT"

echo "== harness chats"
OUT=$(stdio mem 3 "$(call 2 harnesses '{}')" "$(call 3 start_chat '{"harness":"say","prompt":"hello; rm -rf /tmp/x $(id)"}')")
CHAT=$(grep -o '\\"id\\":\\"[0-9a-f]\{16\}' <<<"$OUT" | grep -o '[0-9a-f]\{16\}' | head -1)
check "harnesses lists the configured one" has 'say' "$OUT"
sleep 1
check "a chat runs, its prompt one argument, not shell" has 'chat: hello; rm -rf /tmp/x $(id)' "$(stdio mem 3 "$(call 2 chat_status "{\"id\":\"$CHAT\"}")")"
OUT=$(stdio mem 3 "$(call 2 chat_status '{"id":"../../token"}')" "$(call 3 start_chat '{"harness":"bash","prompt":"x"}')")
check "chat ids can't walk the filesystem" has 'no such chat' "$OUT"
check "only configured harnesses start" has 'no harness' "$OUT"
check "a prompt that looks like an option is refused" has "can't start with -" "$(stdio mem 3 "$(call 2 start_chat '{"harness":"say","prompt":"--dangerously-skip-permissions"}')")"

echo "== bad input to the daemon and the hub"
OUT=$(timeout 10 python3 -c "
import socket
s = socket.socket(socket.AF_UNIX); s.connect('$T/own.sock')
try: s.sendall(b'x' * 3000000 + b'\\n')
except (BrokenPipeError, ConnectionResetError): pass
print(s.makefile().readline())")
check "a 3 MB request line is refused" has 'too long' "$OUT"
check "  and the daemon lives" bash -c "env TEARMESH_SOCKET=$T/own.sock $TM status >/dev/null"
head -c 2000 /dev/urandom | timeout 5 sudo -u tme3-mem env TEARMESH_SOCKET=$T/mem.sock $TM mcp connect >/dev/null 2>&1
sleep 0.5
check "junk on the hub socket leaves the hub running" test "$(hubs mem)" = 1
head -c 5000 /dev/urandom | curl -s -m 5 -H "Authorization: Bearer $TOKEN" --data-binary @- "http://127.0.0.1:$PORT/mcp" >/dev/null
check "HTTP junk leaves the hub running" test "$(hubs mem)" = 1
# Another local user opens 400 connections at once and holds them.
sudo -u tme3-x python3 -c "
import socket, time
c = []
for _ in range(400):
    try:
        s = socket.socket(); s.connect(('127.0.0.1', $PORT)); c.append(s)
    except OSError: break
time.sleep(12)" &
FLOOD=$!
sleep 4
check "a connection flood from another user doesn't kill the hub" test "$(hubs mem)" = 1
wait $FLOOD
check "  and once it's over, the hub answers with the token again" has 'tearmesh-hub' "$(hpost -H "Authorization: Bearer $TOKEN" -d "$INIT")"
OUT=$(stdio mem 20 "$(call 2 shell_exec '{"machine":"own","user":"tme3-own","command":"head -c 3000000 /dev/zero | tr \\\\0 x"}')")
check "a command's output is capped at 256 KiB" has 'truncated\\": true' "$OUT"

echo "== resilience"
(printf '%s\n' "$INIT" "$INITED"; call 2 shell_open '{"machine":"own","user":"tme3-own"}'; echo; sleep 4) \
  | sudo -u tme3-mem env TEARMESH_SOCKET="$T/mem.sock" "$TM" mcp connect >"$T/sh2.out" 2>&1
SHID=$(shell_id "$T/sh2.out")
NUT=$(on own mesh invite nu --boundary work 2>/dev/null)
printf 'machine = "nu"\nstate_dir = "%s/nu"\nsocket = "%s/nu.sock"\n' "$T" "$T" >"$T/nu.toml"
start nu
stop own
START=$SECONDS
ended() { stdio mem 6 "$(call 2 shell_read "{\"id\":\"$SHID\",\"wait_ms\":4000}")" | grep -q 'running\\": false'; }
check "a shell to a node that dies mid-session reports it ended" wait_for ended
check "  without hanging" test $((SECONDS - START)) -lt 60
check "a tool call to a node that's down fails with a reason" has 'isError\|error' "$(stdio mem 50 "$(call 2 call_tool '{"machine":"own","server":"echo","tool":"echo","arguments":{}}')")"
sudo -u tme3-mem env TEARMESH_SOCKET="$T/mem.sock" TEARMESH_MAILBOX=agent "$TM" post --to agent@far --subject "owner is away" --body x >/dev/null
check "with the owner offline, mail still flows between members" wait_for once_in far "owner is away"
check "the map shows the owner down and far up" wait_for ping_is mem own=down,far=up
check "a join to an offline owner fails with a reason" refused "not reachable" timeout 90 env TEARMESH_SOCKET="$T/nu.sock" "$TM" join "$NUT"
stop nu
start own
for i in $(seq 1 10); do
  stop far
  sudo -u tme3-mem env TEARMESH_SOCKET="$T/mem.sock" TEARMESH_MAILBOX=agent "$TM" post --to agent@far --subject "flap $i." --body x >/dev/null
  sleep 0.7; start far; sleep 0.8
done
all_flaps() { for i in $(seq 1 10); do once_in far "flap $i\." || return 1; done; }
check "after ten restarts, every letter arrived exactly once" wait_for all_flaps
check "all three daemons still run" bash -c "for n in own mem far; do kill -0 \$(cat $T/\$n.pid) || exit 1; done"

echo "== a stolen machine key"
# Someone copies mem's node key and runs it as their own daemon. The owner revokes mem.
mkdir -p "$T/evil" && cp -r "$T/mem/." "$T/evil/"
sed -e "s#$T/mem#$T/evil#g" -e "s#tme3-mem#tme3-x#" "$T/mem.toml" >"$T/evil.toml"
stop mem
start evil
check "before revocation, the stolen key gets in (the threat)" wait_for ping_is evil own=up
on own mesh remove mem --key "$OWNER" --out "$T/r1.toml" >/dev/null 2>&1
far_revoked() { ! on far mesh show 2>/dev/null | grep -q 'name = "mem"'; }
check "far learns the revocation" wait_for far_revoked
check "the stolen key no longer reaches the owner or far" wait_for ping_is evil own=down,far=down
sudo -u tme3-x env TEARMESH_SOCKET="$T/evil.sock" TEARMESH_MAILBOX=agent "$TM" post --to agent@far --subject "from the thief" --body x >/dev/null 2>&1
sleep 6
check "letters from the stolen key never arrive" test "$(inbox_has far 'from the thief')" = 0
stop evil

echo "== a leaked owner key"
ssh-keygen -q -t ed25519 -N '' -f "$T/new-owner"
on own mesh owner-add "$T/new-owner.pub" --key "$OWNER" --out "$T/o1.toml" 2>&1 | sed "s/^/  /"
LEAKED_FP=$(ssh-keygen -lf "$OWNER.pub" | cut -d' ' -f2)
on own mesh owner-remove "$LEAKED_FP" --key "$T/new-owner" --out "$T/o2.toml" 2>&1 | sed "s/^/  /"
check "the leaked key is gone from the owners" lacks "$LEAKED_FP" "$(on own status)"
check "a change signed with the leaked key is refused" refused "owner" on own mesh grant far own tools --key "$OWNER" --out "$T/o3.toml"
far_has_v() { [ "$(version far)" = "$(version own)" ]; }
wait_for far_has_v
on far mesh show >"$T/far-cur.toml" 2>/dev/null
check "a member refuses it too" refused "owner" on far mesh grant far own shell --file "$T/far-cur.toml" --out "$T/o4.toml" --key "$OWNER"
ssh-keygen -q -t ed25519 -N '' -f "$T/rando"
check "a random key can't sign changes" refused "owner" on own mesh grant far own shell --key "$T/rando" --out "$T/o5.toml"
echo "$RECPASS" >"$T/pass"
check "the recovery key from setup still signs" has 'applied mesh version' "$(on own mesh set tools-sharing approval --key "$T/recovery" --out "$T/o6.toml" 2>&1)"
check "a boundary can be added, hosted by a machine, in one version" has 'applied mesh version' "$(on own mesh boundary add lab --host far --key "$T/recovery" --out "$T/o7.toml" 2>&1)"
hosts_of() { env TEARMESH_SOCKET="$T/$1.sock" "$TM" mesh show | python3 -c "import sys,tomllib;print(','.join(next(m['boundaries'] for m in tomllib.load(sys.stdin.buffer)['machine'] if m['name']=='$2')))"; }
check "  and far hosts it" test "$(hosts_of own far)" = "work,lab"
check "hosts sets a machine's boundaries back" has 'applied mesh version' "$(on own mesh hosts far work --key "$T/recovery" --out "$T/o8.toml" 2>&1)"
echo e2e-passphrase >"$T/pass"

echo "== the menu"
TMX="tmux -S $T/tmux"
$TMX new-session -d -s m -x 140 -y 40 "env HOME=$T/h-own TEARMESH_SOCKET=$T/own.sock $TM menu"
pane_has() { $TMX capture-pane -p -t m 2>/dev/null | grep -q -- "$1"; }
check "with its owner key removed from the mesh, the machine shows as a member" wait_for pane_has "MEMBER"
# The menu finds the owner key by fingerprint; give it the replacement key.
$TMX kill-session -t m
cp "$T/new-owner" "$T/h-own/.ssh/" && cp "$T/new-owner.pub" "$T/h-own/.ssh/"
$TMX new-session -d -s m -x 140 -y 40 "env HOME=$T/h-own TEARMESH_SOCKET=$T/own.sock $TM menu"
check "with the new key in ~/.ssh it's the owner node again" wait_for pane_has "OWNER NODE"
check "menu has the Owner tab" wait_for pane_has "│ Owner │"
$TMX send-keys -t m Right
check "the map draws far with its ping" wait_for pane_has "far [0-9]*ms"
$TMX send-keys -t m Right
check "nodes lists the machines" wait_for pane_has "this machine"
check "the shortcut bar changed with the screen" pane_has "Disconnect"
$TMX send-keys -t m c
check "C opens the invite form" wait_for pane_has "Invite a machine"
$TMX send-keys -t m Enter
check "an empty form makes a ticket, shown in the menu" wait_for pane_has "Ticket for a new machine"
check "  with the ticket itself" pane_has "^tm2-"
$TMX send-keys -t m Enter Escape
# Ctrl-C in a program the menu runs stops that program, not the menu.
$TMX send-keys -t m S
check "S runs status in the plain terminal" wait_for pane_has "Press Enter to return"
$TMX send-keys -t m C-c
sleep 1
check "Ctrl-C there leaves the menu running" $TMX has-session -t m
$TMX send-keys -t m Enter
check "  and Enter comes back to it" wait_for pane_has "OWNER NODE"
$TMX send-keys -t m q
sleep 1
$TMX new-session -d -s f -x 140 -y 40 "env HOME=$T/h-far TEARMESH_SOCKET=$T/far.sock $TM menu"
pane_f() { $TMX capture-pane -p -t f 2>/dev/null | grep -q -- "$1"; }
check "on a machine without an owner key, menu says member" wait_for pane_f "MEMBER"
check "  and has no Owner tab" bash -c "! $TMX capture-pane -p -t f | grep -q '│ Owner │'"
$TMX send-keys -t f q

echo "== a mesh made, joined and approved without leaving the menu"
printf 'machine = "nw"\nstate_dir = "%s/nw"\nsocket = "%s/nw.sock"\n[users]\ntme3-x = "work"\n' "$T" "$T" >"$T/nw.toml"
printf 'machine = "jn"\nstate_dir = "%s/jn"\nsocket = "%s/jn.sock"\n[users]\ntme3-x = "work"\ntme3-lab = "lab"\n' "$T" "$T" >"$T/jn.toml"
start nw; start jn
mkdir -p "$T/h-nw/.ssh" "$T/h-jn"
menu() { $TMX new-session -d -s "$1" -x 140 -y 40 "env HOME=$T/h-$1 TEARMESH_SOCKET=$T/$1.sock TEARMESH_CONFIG=$T/$1.toml $TM menu"; }
in_pane() { $TMX capture-pane -p -t "$1" 2>/dev/null | grep -q -- "$2"; }
menu nw
wait_for in_pane nw "NOT SET UP"
make_mesh() { $TMX send-keys -t nw c; wait_for in_pane nw "Create a mesh"; $TMX send-keys -t nw -l menumesh; $TMX send-keys -t nw Tab; $TMX send-keys -t nw -l menu-passphrase; $TMX send-keys -t nw Tab; $TMX send-keys -t nw -l menu-passphrase; $TMX send-keys -t nw Enter; }
make_mesh
check "the menu shows the recovery key on a plain screen" wait_for in_pane nw "^-----BEGIN OPENSSH PRIVATE KEY-----"
check "  with its generated passphrase" in_pane nw "Passphrase: [a-z]*-"
check "  and no passphrase typed shows on screen" bash -c "! $TMX capture-pane -p -t nw | grep -q menu-passphrase"
$TMX send-keys -t nw Escape
sleep 1
check "Esc there leaves no key and no mesh" bash -c "test -z \"\$(ls $T/h-nw/.ssh)\" && env TEARMESH_SOCKET=$T/nw.sock $TM status | grep -q '\"mesh\": null'"
make_mesh
wait_for in_pane nw "^-----BEGIN OPENSSH PRIVATE KEY-----"
MPASS=$($TMX capture-pane -p -t nw | grep -o 'Passphrase: [a-z-]*' | cut -d' ' -f2)
$TMX send-keys -t nw w Enter
check "W saves the recovery key" wait_for in_pane nw "Saved to"
check "  to a file only this user can read" test "$(stat -c %a "$T/h-nw/tearmesh-recovery-menumesh.key" 2>/dev/null)" = 600
check "  that opens with the generated passphrase" bash -c "ssh-keygen -y -P '$MPASS' -f $T/h-nw/tearmesh-recovery-menumesh.key >/dev/null"
$TMX send-keys -t nw y; $TMX send-keys -t nw -l wrong; $TMX send-keys -t nw Enter
check "a wrong word 3 is caught" wait_for in_pane nw "isn't word 3"
$TMX send-keys -t nw -l "$(cut -d- -f3 <<<"$MPASS")"; $TMX send-keys -t nw Enter
wait_for in_pane nw "Create mesh menumesh now"
$TMX send-keys -t nw y
check "the mesh is created in the menu" wait_for in_pane nw "is ready"
check "  the everyday key is in ~/.ssh, private" test "$(stat -c %a "$T/h-nw/.ssh/tearmesh-owner-menumesh" 2>/dev/null)" = 600
check "  locked with the passphrase typed" bash -c "ssh-keygen -y -P menu-passphrase -f $T/h-nw/.ssh/tearmesh-owner-menumesh >/dev/null"
$TMX send-keys -t nw Enter
check "  and the menu is the owner node's" wait_for in_pane nw "OWNER NODE"
$TMX send-keys -t nw Right Right c
wait_for in_pane nw "Invite a machine"
$TMX send-keys -t nw Enter
wait_for in_pane nw "Ticket for a new machine"
$TMX send-keys -t nw w Enter
check "the ticket saves to a file" wait_for test -s "$T/h-nw/tearmesh-ticket.txt"
$TMX send-keys -t nw Enter
menu jn
wait_for in_pane jn "NOT SET UP"
$TMX send-keys -t jn j
check "the join form shows this machine's boundaries" wait_for in_pane jn "boundaries lab, work"
# A ticket pasted in one go (bracketed paste), as a terminal does it.
$TMX load-buffer -b t "$T/h-nw/tearmesh-ticket.txt"
$TMX paste-buffer -p -b t -t jn
$TMX send-keys -t jn Enter
check "the joining menu shows a code" wait_for in_pane jn "Code  [0-9]\{3\} [0-9]\{3\}"
check "the owner's menu pops up the request" wait_for in_pane nw "jn wants to join with boundaries lab, work"
JCODE=$($TMX capture-pane -p -t jn | grep -o 'Code  [0-9]\{3\} [0-9]\{3\}' | cut -c7-)
check "  with the same code" in_pane nw "Code $JCODE"
V0=$(version nw)
# Tick "Add boundary lab" and "jn may use nw's tools", then the passphrase (past the note).
$TMX send-keys -t nw Space Tab Space Tab Tab Tab Tab
$TMX send-keys -t nw -l not-the-passphrase; $TMX send-keys -t nw Enter
check "a wrong passphrase is refused in the form" wait_for in_pane nw "doesn't open"
$TMX send-keys -t nw -l menu-passphrase; $TMX send-keys -t nw Enter
check "approving signs and applies" wait_for in_pane nw "Signed and applied mesh version"
check "jn joins" wait_for in_pane jn "Joined"
check "  one new version for the machine, its boundary and the grant" test "$(version nw)" = $((V0 + 1))
SHOW=$(env TEARMESH_SOCKET=$T/nw.sock $TM mesh show)
check "  jn hosts lab and work" test "$(hosts_of nw jn)" = "lab,work"
check "  and may use nw's tools" has 'from = "jn"' "$SHOW"
check "jn has the same version" wait_for bash -c "test \"\$(env TEARMESH_SOCKET=$T/jn.sock $TM status | python3 -c 'import json,sys;print(json.load(sys.stdin)[\"mesh\"][\"version\"])')\" = $((V0 + 1))"
$TMX send-keys -t nw Enter
# A grant from the Nodes screen, signed in the menu.
$TMX send-keys -t nw Down g
wait_for in_pane nw "To machine"
$TMX send-keys -t nw Enter
wait_for in_pane nw "Passphrase for"
$TMX send-keys -t nw -l menu-passphrase; $TMX send-keys -t nw Enter
check "a grant signed in the menu" wait_for in_pane nw "Signed and applied mesh version $((V0 + 2))"
$TMX send-keys -t nw Enter q
$TMX send-keys -t jn Enter q

echo
if [ "$FAILED" = 0 ]; then echo "ALL PASSED"; else echo "SOME FAILED"; exit 1; fi
