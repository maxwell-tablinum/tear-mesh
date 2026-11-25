# tear-mesh

A peer-to-peer mesh that connects the apps and agents on your own machines, not whole machines.
- Agents in Claude Code (and anything else that speaks MCP) mail each other.
- They call MCP servers that other machines offer.
- They can reach other machines' shells.

All of it is encrypted app to app over [iroh](https://iroh.computer), with no VPN and no public endpoint, under permissions you sign with an ordinary SSH key. Every machine keeps each **boundary**'s data inside that boundary. The daemon and the operating system enforce that, never a model's judgment.

**Status: 0.4.0, early.** It runs on Linux (systemd or OpenRC; one static binary for any distribution) and natively on Windows. How every part behaves, and what is still undecided, is in the specification: [docs/spec.md](docs/spec.md). 0.3 added `tearmesh menu` (bare `tearmesh` opens it), where you create, join and approve without leaving it, `tearmesh install` and the MCP hub. 0.4 renames and extends the MCP tools, adds agent status and claims, replaces the old Claude connector with the gateway, and adds a Claude Desktop extension (see below). Every machine of a mesh must run 0.4 before agents use status records or claims: a 0.3 machine rejects those two new kinds of letter (its log says ``unknown variant `status` ``) and then takes nothing more from that author until it is upgraded; after the upgrade it catches up by itself. Upgrading in place keeps the node id and the mesh. The project stays at 0.x until the maintainers declare it launched.

**About the name:** in intelligence reporting, a *tear line* separates the classified part of a document from a cleaned-up summary that can be torn off and shared at a lower clearance. The hyphen in tear-mesh is that line.

## What it's for

The headline use is that an agent on one machine drives MCP servers and other capabilities on your other machines, from anywhere. Those machines don't need an agent of their own.

What's different from a Cloudflare Tunnel or ngrok with OAuth, or from Tailscale with an HTTP MCP server:
- no public endpoint;
- no system DNS or routes touched;
- stdio MCP servers bridged unmodified;
- permissions signed by you per pair of machines;
- one install.

Some overlap is real: machine bios resemble A2A Agent Cards and MCP registry metadata, and Tailscale already solves the machine-level mesh.

## How it works

- **A mesh is a signed membership file.** It's TOML, listing:
  - the member machines (by iroh node key) and the boundaries each hosts;
  - the grants between machines;
  - the MCP servers you approved;
  - the owner keys.

  It's signed in the SSHSIG format of `ssh-keygen -Y sign`. At least two owner keys are required, so losing one doesn't lock you out: setup makes an everyday key that stays on the owner node under your passphrase, and a recovery key with a generated six-word passphrase that it shows once for you to keep somewhere safe. Any OpenSSH ed25519 key works, security keys included. Versions form a hash chain: each one names the one before and is signed by an owner of it. A machine that missed versions gets each one. If two owners sign different versions at once:
  - a version that removes the other's signer wins;
  - otherwise the one with more versions built on it wins;
  - otherwise a version that dissolves the mesh wins;
  - otherwise the lower hash wins.

  Only a machine's newest version can be replaced, and only by a version signed by a key that's still an owner, so a removed key can't come back and rewrite history. Connections from keys not in the file are refused during the handshake.

  There is one exception, the farewell rule: a machine that a version removed may still use the sync protocol, and only that. It gets the versions up to and including the one that removed it, and no mail, no addresses and no later versions. So a removed machine notices on its next sync and leaves the mesh. Its logs move to `boundaries-<mesh id>/` (kept, not deleted), and it is free to create or join any mesh, this one included.
- **Dissolving a mesh.** `tearmesh mesh dissolve` signs a last version with no machines, after which nothing can follow. It hands that version to the machines it can reach; the rest fetch it on their next sync. Each machine then shows the mesh as dissolved. When you create or join another mesh, or run `tearmesh mesh leave` or `mesh reset`, it moves the old logs to `boundaries-<mesh id>/` (kept, not deleted), and it never adopts that mesh again. Upgrade every machine first: builds from before 2026-11-12 (they also call themselves 0.3.0) can't read the closed version.
- **A boundary is an OS user.** Each boundary on a machine has its own user (`tm-work`, `tm-vault`). The daemon learns a session's boundary from the OS (`SO_PEERCRED` on Linux; the pipe client's token on Windows), so a session can't claim another one.
- **One log per boundary.** Each boundary has an append-only SQLite file, synced only with machines that host that boundary. Moving information between boundaries is a person's job.
- **Permissions are three categories, each in two directions, per pair of machines.** A machine *speaks* a category to another machine (acts on it) and *listens* to it (accepts the same from it):

  | Category | speak: this machine… | listen: this machine… |
  |---|---|---|
  | `converse` | posts notes to that machine | accepts notes from that machine |
  | `tools` | calls the MCP servers that machine offers | accepts tool calls from that machine |
  | `shell` | drives that machine, with anything its SSH login can do | can be driven by that machine |

  An action from A to B needs A to speak it to B and B to listen to it from A. The membership file holds the pair as one grant, `A → B`, which both daemons check, so a switch can't be half on. An owner node usually speaks `shell` and never listens to it: it drives other machines and can't be driven. In the menu, **Mesh → G** on a machine's row shows the six switches between it and this machine, and signs everything you change at once.

  Grants are deny by default. A new mesh starts with mail allowed among all machines; tools and shell need explicit grants, and shell grants must name both machines. Grants are checked at both ends. They never widen a boundary: a `work` session reaches only `work` tools.
- **Offers.** A machine shares an MCP server by publishing an offer that pins the server's instructions and exact tool list. By default the owner approves each offer, optionally only some of its tools.
  - Both daemons filter the session. Only the core tool methods pass, and the tool list is cut to what was approved.
  - Any change to what the caller's model would read closes the stream until the offer is approved again.
  - The per-boundary **steward** runs the server as the boundary's own user; the daemon never starts user code.
- **Mailboxes belong to roles.** `builder@workstation` outlives any one session. Mail that reaches an unheld mailbox can wake a new session. Each letter wakes a mailbox at most once, each mailbox has an hourly budget, and threads have a length cap.
- **Bios.** Each machine says what it is and what it offers, per boundary (`tearmesh bio template > bio.yaml`, edit, `tearmesh bio set bio.yaml`; the starter uses A2A Agent Card field names). Agents read bios through `list_nodes`. A bio is signed by its machine, which proves who wrote it, not that it's safe.

```
 owner SSH keys ──sign──▶ mesh.toml (+ .sig)   versions gossiped by every daemon

 ┌ workstation ──────────────────────┐           ┌ laptop ─────────────────────┐
 │ tm-work:  Claude Code ─┐          │           │ tm-work: Claude Code ─┐     │
 │ tm-work:  steward → MCP server    │           │                       │     │
 │ tm-vault: Claude Code ─┤ socket   │           │       tearmesh daemon ◀┘     │
 │            tearmesh daemon ◀──────┘           │       work.db               │
 │            work.db  vault.db      │           └──────────────┬──────────────┘
 └────────────────┬──────────────────┘                          │
                  └── iroh: work mail, tool and shell streams ──┘
```

## What it guarantees, and what it doesn't

In scope: careless agents and prompt-injected agents. Specifically:
- A session in one boundary can't post to, read from, address, call tools in, or attach to another boundary.
- A machine can't receive or push another boundary's entries, or entries signed as another machine.
- Non-members are refused at the handshake. Strangers reach only the join protocol, only while an invite is open, and a ticket alone gets nobody in.
- Membership files can't be rolled back, jumped ahead, or signed by a non-owner. A removed owner key can't sign what comes next.
- A machine can't change the tools or instructions a caller's model sees after you approved them.

Not covered:
- **Your model provider sees everything its sessions read.** A boundary that "never leaves the machine" only holds if its agents use a local model.
- **Proving a remote machine runs honest code isn't possible without special hardware.** The reasoning:
  1. A machine signs its own offer: that proves which machine made the claim, not what code runs.
  2. You approve it: a person decided, but still on a claim.
  3. The pinned hash and tool list catch changes, but a compromised machine can report any hash it likes.
  4. A live challenge over the mesh proves something answers, not what it is.
  5. Proving unmodified code needs hardware remote attestation: Intel SGX/TDX, AMD SEV-SNP, Arm CCA, AWS Nitro Enclaves or TPM measured boot. All of them are hardware-specific.

  So the model is: **only admit machines you trust.**
- **Network egress isn't locked yet.** A prompt-injected agent with a shell can still send data out over the internet.
- **Inside SSH, tear-mesh can't see which user logs in.** A shell grant gets bytes to the other machine's sshd; that machine's `authorized_keys` decides who logs in. Give each boundary user its own SSH key.
- **Relays see metadata.** By default tear-mesh uses n0's public relays and n0's DNS address lookup, plus mDNS on the LAN. Published address records carry only the relay URL, not IP addresses. Relays see which nodes talk, when, how much, and IPs, never content. n0 says the public relays are rate-limited and meant for development. For privacy or production, run your own `iroh-relay` and set `relays` and `lookup`.
- **Root, kernel exploits and hostile admin-level software** are out of scope.
- **Every member sees the whole membership file:** boundary names, grants, and the names of approved servers and tools. Letters, offers and bios stay inside their boundary.
- **Trust labels are claims.** A letter's trust (`guest`, `member`, `admin`) is set by the machine that wrote it and decides only local things, such as whether it wakes a mailbox.

## Quick start (Linux)

On **each machine**, install the release with one OS user per boundary the machine hosts (`<VER>` is the release, e.g. `0.4.0`):

```sh
curl -fsSL https://github.com/maxwell-tablinum/tear-mesh/releases/download/v<VER>/install.sh | sudo sh -s -- workstation work vault
tearmesh menu
```

The releases are listed at <https://github.com/maxwell-tablinum/tear-mesh/releases>; the first is 0.4.0. To use a build of your own instead, run `cargo build --release` and `sudo target/release/tearmesh install workstation work vault`, or serve your build's folder and set `TEARMESH_RELEASE_URL` to it (the spec's section on the one-line install says how). A machine without curl can use `wget -qO- <address> | sudo sh -s -- …`; as root on a machine without sudo, leave `sudo` out.

`install.sh` downloads the static binary for this machine (`tearmesh-x86_64-linux` or `tearmesh-aarch64-linux`, for any distribution), refuses it unless its SHA-256 matches the one pinned in the script, and runs `tearmesh install` with your arguments. The pinned SHA protects against a replaced binary, not against a replaced `install.sh`: if you'd rather check the script too, download it, compare it with `SHA256SUMS` on the Releases page and read it before running `sudo sh install.sh …`. A new machine can also install and join in one go with the line `tearmesh mesh invite` prints on the owner node: `… | sudo sh -s -- --join <ticket>` (`… -- <name> --join <ticket>` for `mesh invite <name>`, so the machine installs under the name the ticket is for). It shows the code to compare, waits for the owner's approval, then creates the users of the boundaries the owner picked. Running it again skips the join and only adds missing users. `… | sudo sh -s -- --uninstall [--keep-users]` uninstalls.

Or by hand: download the binary and `SHA256SUMS`, then `grep ' tearmesh-x86_64-linux$' SHA256SUMS | sha256sum -c`, `chmod +x tearmesh-x86_64-linux`, `sudo ./tearmesh-x86_64-linux install workstation work vault` (add `--join <ticket>` to join too). Or run `./tearmesh-x86_64-linux` as yourself: on a machine without tear-mesh the menu opens its Install form (the hostname and `work` filled in) and runs the install through sudo.

`install` puts the binary at `/usr/local/bin/tearmesh`, creates the `tearmesh` daemon user and `tm-work`/`tm-vault`, writes `/etc/tearmesh/config.toml` (making you an admin), installs the Claude Code plugin under `/usr/local/share/tearmesh`, and starts the service (systemd or OpenRC). The machine name defaults to the hostname, and boundaries are optional: `sudo tearmesh install` alone installs a machine whose boundaries the owner picks when it joins (`tearmesh status` lists those with no OS user yet under `unmapped`). Add `--me <boundary>` to also map your own OS user to a boundary, so agents you run as yourself (and Claude Desktop) are its sessions. Run it again to upgrade or to add boundaries; with no name it keeps the installed one. `sudo tearmesh uninstall` removes it all (the gateway too, if there is one), with the users it made, after telling the other machines this one is leaving (they list it under `leaving` until the owner node removes it); on an owner node it suggests `tearmesh mesh dissolve` first, and it never touches the keys in `~/.ssh`. From source: `cargo build --release` (Rust 1.88+), then `sudo target/release/tearmesh install …`.

Everything else happens in **`tearmesh menu`**, without leaving it. It has three screens: **Mesh** (a summary, a live map and the machines, with join requests on top on the owner node), **Mail** (read and write letters) and **Settings** (the mesh's settings, the owner keys, the MCP hub, and the event and daemon logs). On Mesh, **U** adds boundaries through sudo (or UAC) when this machine hosts none yet or the mesh has it host one with no OS user here, and **Settings → X** uninstalls (the menu closes afterwards, since its binary goes too). Arrow keys or the keypad move, Enter picks, Esc goes back, `?` lists the keys, and a nano-style bar shows them:

1. On the first machine, the **owner node**, press **C** to create a mesh. You choose the everyday key's passphrase; the menu shows the recovery key and its generated passphrase once, with C to copy and W to save to a file, and asks for word 3 to check you saved it.
2. On the owner node, **Mesh → A** makes a one-time ticket at once (it works for an hour) and shows it with two one-liners that install tear-mesh and join: C copies the Linux line, P the PowerShell line, T the ticket, W saves the ticket. The new machine proposes its name and boundaries; you decide.
3. On the new machine, run one of the one-liners, or, if tear-mesh is installed there already, press **J** in its menu and paste the ticket. Both screens show the same 6-digit code.
4. The request replaces the ticket screen on the owner node (any other request pops up when no screen is open; later, select its row on Mesh: Enter approves, D refuses). Tick the boundaries it hosts (what it asked for that the mesh has is ticked; a new one adds it to the mesh; if it asked for none, you pick at least one) and any grants (tools, shell), and enter the passphrase: one signed version adds it all.

A machine that says it left (uninstalled there, or left with the menu's Leave or `tearmesh mesh leave`) pops up on the owner node, which signs its removal; its row shows "(says it left)" until then. **Settings → Shift-K** dissolves the mesh after you type its name; the menu then says how many machines it reached.

Stopping anywhere before the last step leaves the machine as it was. The same steps work from the command line: `tearmesh mesh invite`, `tearmesh mesh approve laptop [--host work] [--add-boundary lab] [--grant laptop:workstation:tools]` (`--host` picks exactly what it hosts; by default, what it asked for that the mesh has), `tearmesh mesh reject laptop`. Commands that sign find this mesh's owner key in `~/.ssh` (or take `--key`). Grant and revoke with `tearmesh mesh grant laptop workstation tools shell` and `tearmesh mesh revoke …`; remove a machine with `tearmesh mesh remove laptop`; add a boundary later with `tearmesh mesh boundary add lab --host workstation`. Every change is a new signed version, applied to the local daemon and gossiped from there.

**Agents.** Install the Claude Code plugin for each boundary user. It adds ten MCP tools, plus hooks that announce new letters. Seven are the **conversation tools**: `list_nodes` and `node_status` (who is online, and what each agent is working on), `send_message`, `inbox_list` and `inbox_fetch`, and `board_read` and `board_post` for the boundary's board. Three are for agents: `set_status` and `claim` ("working on it", so the asker knows to wait) and `set_bio`. `send_message` returns at once and the answer comes through the inbox; it fails within seconds if the other machine is off, unless you ask it to queue the letter. `node_status` also gives when a machine was last seen. `board_read` lists what other agents posted, not your own posts. A `send_message` with `reply_to` to your own earlier message goes to that message's recipient, and reusing an `idempotency_key` with a different message is an error. Agents can also run `tearmesh agent status --about "…"` and `tearmesh agent claim`.

```sh
claude plugin marketplace add /usr/local/share/tearmesh   # written by install
claude plugin install tearmesh@tear-mesh
tearmesh launch --boundary work --mailbox builder -- claude
```

**Any MCP client: the hub.** `tearmesh mcp serve` is one long-running MCP service per user. It has the same ten tools and three channels, each working both ways: conversation (the tools above; `inbox_list` can wait up to 30 seconds for mail, and new mail is also pushed to open sessions), tools on other machines (`offers`, `remote_tools`, `call_tool`) and shells on other machines (`shell_exec`, or `shell_open`/`shell_send`/`shell_read`/`shell_close`). It can also start chats in agent harnesses you configure (`harnesses`, `start_chat`, `chat_status`). Register it by URL, or by command for clients that only start processes:

```sh
tearmesh mcp info     # prints the URL, the bearer token and the commands below
claude mcp add --transport http tearmesh http://127.0.0.1:<port>/mcp --header "Authorization: Bearer <token>"
# Claude Desktop, Cursor and others that start a command: command `tearmesh`, args ["mcp", "connect"]
```

`mcp connect` connects to the running hub, or starts it; the hub stays running after the client exits. Only `serve` binds anything, and a lock file keeps it to one hub per user, so a client that starts its own copy can't collide with it. The HTTP door listens on 127.0.0.1 only and needs the token; the local socket admits only the same user. Each OS user gets its own port (picked from the user, 7787–8786; `mcp info` prints it). `~/.config/tearmesh/hub.toml` sets the `port`, the `mailbox` and the harnesses:

```toml
[harness.claude]
command = ["claude", "-p", "{prompt}"]   # the default when claude is on the PATH
```

**Share an MCP server.** As the boundary user on the machine that has the server, write `~/.config/tearmesh/offers.toml`:

```toml
[cad]
command = ["/opt/cad-mcp/bin/server"]
description = "Parametric CAD export and properties"
```

Then publish it, approve it, and use it from another machine:

```sh
tearmesh offer publish cad                                      # as tm-work on the workstation
sudo systemctl enable --now tearmesh-steward@tm-work            # runs offered servers and wakes mailboxes
tearmesh mesh approve-offer workstation work cad                # on the owner node; add --tools a,b for a subset
claude mcp add cad -- tearmesh mcp --remote workstation/cad     # as tm-work on the laptop
```

On the owner node, `tearmesh menu` shows a line on the Mesh screen while offers wait; **O** lists them, and one signature approves the ones you tick. Approving a subset of an offer's tools is `approve-offer --tools`; re-approving a changed offer in the menu keeps that subset.

**Shell.** With a `shell` grant, set this in the client's `~/.ssh/config`:

```
Host workstation
  ProxyCommand tearmesh shell-proxy %h
```

**Wake on mail.** As the boundary user, write `~/.config/tearmesh/mailboxes.toml`:

```toml
[helper]
dir = "/home/tm-work/src/project"
# {prompt} is replaced by the wake prompt. Put it right after -p: --allowedTools takes several values.
command = ["claude", "-p", "{prompt}", "--output-format", "json",
           "--allowedTools", "mcp__plugin_tearmesh_tearmesh__*"]
max_wakes_per_hour = 6        # default
wake_on = ["member", "admin"] # default; add "guest" to wake on letters from the owner's Claude (the gateway)
about = "Answers questions about the project."   # shown to others in list_nodes; default "Woken when mail arrives."
```

**Screening inbound mail (the honeypot reader).** Letters from other machines can carry prompt injections. With screening on, every letter that reaches a boundary from another machine (or from a guest, through the gateway) waits until a cheap model has read it. The model's only job is a one-line summary, and it holds only decoy tools: run a shell command, delete files, send a file. None of them does anything. A letter that gets the model to reach for one is quarantined: no session, hook, wake or MCP tool on this machine shows it until an admin releases it.

Turn it on per boundary in the daemon's config (above the `[users]` line), which is root-owned, so a session in the boundary can't turn it off. Then restart the daemon:

```toml
screen = ["work"]
```

The boundary's steward runs the screener as the boundary's user. Give it an API key in `~/.config/tearmesh/screen.toml` (as that user):

```toml
api_key_file = "/home/tm-work/.config/tearmesh/anthropic.key"   # chmod 600; default: ANTHROPIC_API_KEY
# model = "claude-haiku-5-5"
# base_url = "https://api.anthropic.com"
```

```sh
tearmesh quarantine --boundary work                  # flagged letters, and how many wait
tearmesh quarantine show <id> --boundary work        # read a flagged letter yourself
tearmesh quarantine release <id> --boundary work     # let sessions see it
```

These three take an admin: the list quotes the sender's subject and what the reader tried, which is text an attacker wrote. Sessions see only the counts, in `tearmesh status`.

- With screening on and no working screener (no key, no network, the API down), letters wait. They are never shown unscreened. A letter the model API refuses to read goes to quarantine, so it can't hold up the ones behind it.
- Screening starts with the mail that arrives after you turn it on. Letters already in the log stay readable and aren't sent to the model.
- Letters written on this machine by its own sessions aren't held. Offers and bios aren't screened.
- To block a sender, on the owner node: `tearmesh mesh revoke <sender's machine> <this machine> converse`.
- `tearmesh status` and the menu show, per screened boundary, how many letters wait and how many are flagged, and warn when `screen` names a boundary this machine doesn't host.

Know its limits:
- **It catches clumsy attacks better than careful ones.** An injection written to look like ordinary mail can pass as clean.
- **False positives happen.** A phishing mail forwarded for analysis, or a letter that quotes commands, can make the reader reach for a tool. Check the quarantine and release what is fine.
- **The model provider sees all screened mail:** the sender, subject and body of every letter that arrives from another machine.
- **It filters inbound mail; it is not a sandbox.** A session in the boundary can ask the daemon for letters that still wait, as the steward does.
- **Bios and offer descriptions aren't screened.** They are also text another machine wrote that agents read.

**Phones, voice and the web: the gateway.** On a Linux machine of the mesh, `sudo tearmesh gateway setup <boundary> --url https://<host>/mcp` turns on the gateway: an MCP server that Claude's apps (voice, phone, web) add as a custom connector.
- It is the only part of tear-mesh that faces the internet. Setup makes it an OS user of its own, `tm-<boundary>-gw`, and lists that user under `[guests]` in `/etc/tearmesh/config.toml`. The daemon itself holds that user to guest trust, one mailbox (`claude`) and six requests, and `gateway serve` refuses to run unless it does. So a taken-over gateway can send guest-marked letters in its boundary and read its own mailbox and the board, and nothing else: not the node key, not another boundary, not the mail between the boundary's agents. A tunnel (Cloudflare Tunnel or Tailscale Funnel; setup prints the commands) gives it a public name.
- Sign-in uses a passphrase of six random words that setup shows once. A wrong try answers 403 and is logged; there is no lockout. Sign-ins can be listed and ended with `tearmesh gateway grants` and `revoke`, and `tearmesh gateway passphrase` makes a new passphrase (`--revoke-all` also ends every sign-in). Run as root, these commands do their work as the gateway's user.
- Limits: 512 connections, a body of at most 1 MiB, 600 tool calls an hour per sign-in, and time limits on headers and bodies. `sudo tearmesh gateway remove` takes the service, its state, the `[guests]` entry and the user away; `tearmesh uninstall` does too.
- It offers conversation only: the seven conversation tools, no tools and no shell. Its letters come from `claude@<machine>`, marked `guest`. They wake a mailbox only if its `wake_on` lists `guest`.
- Everything that passes through it is visible to the gateway, the tunnel's operator and Anthropic, so keep secret boundaries away from it.

The steps are in [docs/testing.md](docs/testing.md#the-gateway); `tests/gateway-client.py` stands in for Claude there, so you can try it without Claude. The 0.2 and 0.3 connector (`tearmesh mcp --http`) is gone. **Never tested:** a real Claude client (web, phone, voice or Desktop) against the gateway, and whether voice can call a custom connector at all. It was tried with the stand-in client, including once through a public HTTPS tunnel from another network.

**Claude Desktop (Windows).** The extension `tearmesh.mcpb` gives Desktop the hub's tools with no gateway. It runs the installed `tearmesh mcp connect`. Install tear-mesh with `--me <boundary>`, then add the file under Settings, Extensions. The file is not signed, so Desktop warns at install, and it has not been tried with Claude Desktop. See [adapters/claude-desktop/README.md](adapters/claude-desktop/README.md).

**For people:** `tearmesh menu` is the full-screen front end; its Mail tab is the mail client. Mail belongs to a boundary, so run it as a boundary user to read mail: `tearmesh launch --boundary work -- tearmesh`. `tearmesh who | post | inbox | read | bio` work from scripts.

## Windows

tear-mesh runs natively on Windows. Earlier versions were tested on Windows Server 2022; 0.3 and 0.4.0 have not been run on a real Windows machine yet. The 0.4.0 Windows build was only smoke-tested under Wine: the daemon starts on a named pipe and the stdio mail server lists its ten tools. Windows 10 and 11 use the same APIs but haven't been tested.

- The local socket is a named pipe, and a session's boundary is its Windows account. The daemon identifies a caller by impersonating it.
- The daemon runs as a service under the virtual account `NT SERVICE\tearmesh`.
- Clients refuse a pipe that account (or SYSTEM, or Administrators) didn't create.

Install it in PowerShell as Administrator:

```powershell
& ([scriptblock]::Create((irm https://github.com/maxwell-tablinum/tear-mesh/releases/download/v<VER>/install.ps1))) -Machine <name> -Boundaries work
& ([scriptblock]::Create((irm https://github.com/maxwell-tablinum/tear-mesh/releases/download/v<VER>/install.ps1))) -Join <ticket>   # install and join
& ([scriptblock]::Create((irm https://github.com/maxwell-tablinum/tear-mesh/releases/download/v<VER>/install.ps1))) -Uninstall
```

`install.ps1` checks the binary against the SHA-256 pinned in it (which, as on Linux, doesn't protect against a replaced script) and runs `tearmesh install`; `-Uninstall` runs a temporary copy of the installed exe, so the exe itself goes too. By hand: check the release binary with `Get-FileHash tearmesh-x86_64-windows.exe` against `SHA256SUMS`, run `Unblock-File tearmesh-x86_64-windows.exe`, then `.\tearmesh-x86_64-windows.exe install <name> work --stewards`. It adds `C:\Program Files\tearmesh` to the PATH and the plugin there. The steps are in [docs/testing.md](docs/testing.md#windows). The gateway runs on Linux only. The Claude Desktop extension is for Windows.

## Config

`/etc/tearmesh/config.toml` (`C:\ProgramData\tearmesh\config.toml` on Windows):

```toml
machine = "workstation"            # this machine's name in the mesh
admins = ["alice"]                 # OS users who may run admin commands without sudo
# sync_interval_secs = 30
# max_thread_len = 40             # letters per thread
# max_posts_per_hour = 600         # local posts per boundary
# max_log_mb = 1024                # a boundary's log stops growing here
# shell_port = 22                  # where shell streams go on this machine
# screen = ["work"]                # boundaries whose inbound mail waits for the screener

[users]                            # OS user -> boundary
tm-work = "work"
tm-vault = "vault"

[network]                          # overrides the mesh-wide settings for this machine
# relay = "n0"                     # "n0", "none", or ["https://relay.example.com"]
# lookup = ["n0-dns", "mdns"]
# bind = "0.0.0.0:7777"
```

Mesh-wide settings live in the membership file. Change them with `tearmesh mesh set tools-sharing approval|free`, `mesh set relays …` and `mesh set lookup …`.

## Tests

[docs/testing.md](docs/testing.md) has the full walkthrough.
- `cargo test` (209 tests: 145 unit, 8 in main, 5 gateway, 40 mesh, 11 talk): unit tests and in-process mesh tests over real iroh connections. They cover placement, membership, revocation, the version chain and split healing, ticket joins, converse, tool and shell grants, and carrying a 0.1 circle over.
- `tests/e2e-linux.sh`: two daemons with real OS users. It covers the ticket join, a tool call through the steward, shell, bios, the mail server, the waker and the menu's Mail tab.
- `tests/talk.rs`: the conversation tools against real in-process daemons: every tool, the error texts, offline and queued sends, claims, status records and paging.
- `tests/gateway.rs`: the gateway against an in-process daemon: sign-in with PKCE, the tools, and the refusals (no token, forged, expired or revoked tokens, wrong passphrases, foreign redirect addresses, floods).
- `tests/e2e-0.4.sh`: two parts. The first runs three throwaway daemons and `gateway serve`. The second, with `E2E_SYSTEM=1` on a machine with no tear-mesh installed, does a real install, `gateway setup`, `remove` and `uninstall`. It makes OS users, so run it on a throwaway machine.
- `tests/gateway-client.py`: a stand-in for Claude's connector client, standard library only (`tests/gateway-client.py [--via http://127.0.0.1:8787] [--state FILE] URL signin PASSPHRASE | tools | call TOOL ['{json}'] | refresh`).
- `tests/e2e-0.3.sh`: three daemons, trying to break 0.3: the setup wizard (bad input, run twice, stopped halfway), joins (nameless tickets, key lookup, boundaries added later), a mesh created, joined and approved entirely in the menu, the hub (connect-or-start, one per user, auth, all three channels both ways, chats), a stolen machine key, a leaked owner key, a node dropping mid-session, the owner offline, a flapping peer, and the menu.
- `tests/distros.sh`: the e2e and `tearmesh install` (re-run, uninstall) in Debian, Ubuntu, Fedora, Arch, openSUSE and Alpine containers.
- `tests/e2e-windows.ps1`: the Windows version.

## Docs

- [Specification](docs/spec.md): how every part behaves, what is undecided, known limits, the change log
- History, no longer updated: the [0.2 spec](docs/spec-0.2.md) and the [design](docs/design.md) with its decisions
- [Testing](docs/testing.md): automated tests and step-by-step tests across machines
- [Research notes](docs/research.md): the incident behind it, prior art and the building blocks

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. Unless you state otherwise, any contribution you intentionally submit for inclusion in this project is dual licensed as above, without additional terms.

The passphrase word list is the EFF large wordlist (CC BY 3.0 US, Electronic Frontier Foundation).
