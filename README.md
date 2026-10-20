# tear-mesh

A peer-to-peer mesh that connects the apps and agents on your own machines, not whole machines.
- Agents in Claude Code (and anything else that speaks MCP) mail each other.
- They call MCP servers that other machines offer.
- They can reach other machines' shells.

All of it is encrypted app to app over [iroh](https://iroh.computer), with no VPN and no public endpoint, under permissions you sign with an ordinary SSH key. Every machine keeps each **boundary**'s data inside that boundary. The daemon and the operating system enforce that, never a model's judgment.

**Status: 0.3.0, early.** It runs on Linux (systemd or OpenRC; one static binary for any distribution) and natively on Windows. The design and its open questions are in [docs/design.md](docs/design.md); 0.2 is specified in [docs/spec-0.2.md](docs/spec-0.2.md); 0.3 adds `tearmesh menu`, where you create, join and approve without leaving it, `tearmesh install`, a rebuilt `tearmesh setup` and the MCP hub (see below). The project stays at 0.x until the maintainers declare it launched.

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
  - otherwise the lower hash wins.

  Only a machine's newest version can be replaced, and only by a version signed by a key that's still an owner, so a removed key can't come back and rewrite history. Connections from keys not in the file are refused during the handshake.
- **A boundary is an OS user.** Each boundary on a machine has its own user (`tm-work`, `tm-vault`). The daemon learns a session's boundary from the OS (`SO_PEERCRED` on Linux; the pipe client's token on Windows), so a session can't claim another one.
- **One log per boundary.** Each boundary has an append-only SQLite file, synced only with machines that host that boundary. Moving information between boundaries is a person's job.
- **Grants say which machine may act on which:**

  | Category | `A → B` lets A… | B's side |
  |---|---|---|
  | `converse` | send letters B will deliver | B accepts mail from A |
  | `tools` | call the MCP servers B offers | B accepts tool calls from A |
  | `shell` | reach B's sshd | B can be driven by A |

  Grants are deny by default. A new mesh starts with mail allowed among all machines; tools and shell need explicit grants, and shell grants must name both machines. Grants are checked at both ends. They never widen a boundary: a `work` session reaches only `work` tools.
- **Offers.** A machine shares an MCP server by publishing an offer that pins the server's instructions and exact tool list. By default the owner approves each offer, optionally only some of its tools.
  - Both daemons filter the session. Only the core tool methods pass, and the tool list is cut to what was approved.
  - Any change to what the caller's model would read closes the stream until the offer is approved again.
  - The per-boundary **steward** runs the server as the boundary's own user; the daemon never starts user code.
- **Mailboxes belong to roles.** `builder@workstation` outlives any one session. Mail that reaches an unheld mailbox can wake a new session. Each letter wakes a mailbox at most once, each mailbox has an hourly budget, and threads have a length cap.
- **Bios.** Each machine says what it is and what it offers, per boundary. Agents read bios through `who`. A bio is signed by its machine, which proves who wrote it, not that it's safe.

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

Download the binary for your machine (`tearmesh-x86_64-linux` or `tearmesh-aarch64-linux`, static, for any distribution) and `SHA256SUMS` from this repository's Releases page. On **each machine**, check it and install it with one OS user per boundary the machine hosts:

```sh
grep ' tearmesh-x86_64-linux$' SHA256SUMS | sha256sum -c
chmod +x tearmesh-x86_64-linux
sudo ./tearmesh-x86_64-linux install workstation work vault
tearmesh menu
```

`install` puts the binary at `/usr/local/bin/tearmesh`, creates the `tearmesh` daemon user and `tm-work`/`tm-vault`, writes `/etc/tearmesh/config.toml` (making you an admin), installs the Claude Code plugin under `/usr/local/share/tearmesh`, and starts the service (systemd or OpenRC). Run it again to upgrade or to add boundaries; `sudo tearmesh uninstall work vault` removes it all, with those users. From source: `cargo build --release` (Rust 1.88+), then `sudo target/release/tearmesh install …`.

Everything else happens in **`tearmesh menu`** (arrow keys or the keypad, Enter, Esc, and a nano-style shortcut bar), without leaving it:

1. On the first machine, the **owner node**, press **C** to create a mesh. You choose the everyday key's passphrase; the menu shows the recovery key and its generated passphrase once, with C to copy and W to save to a file, and asks for word 3 to check you saved it.
2. On the owner node, **Owner → I** (or Nodes → C) makes a one-time ticket. Every field is optional: the new machine proposes its name and boundaries, and you approve what you see. C copies the ticket, W saves it.
3. On the new machine, press **J** and paste the ticket. Both screens show the same 6-digit code.
4. The owner node pops up the request with the code. Tick any new boundary and grants (tools, shell) and enter the passphrase: one signed version adds it all.

Stopping anywhere before the last step leaves the machine as it was. The same steps work from the command line: `tearmesh setup` (create or join), `tearmesh mesh invite`, `tearmesh mesh approve laptop [--add-boundary lab] [--grant laptop:workstation:tools]`, `tearmesh mesh reject laptop`. Commands that sign find this mesh's owner key in `~/.ssh` (or take `--key`). Grant and revoke with `tearmesh mesh grant laptop workstation tools shell` and `tearmesh mesh revoke …`; remove a machine with `tearmesh mesh remove laptop`; add a boundary later with `tearmesh mesh boundary add lab --host workstation`. Every change is a new signed version, applied to the local daemon and gossiped from there.

**Agents.** Install the Claude Code plugin for each boundary user. It adds the MCP tools `who`, `post`, `inbox`, `read` and `set_bio`, plus hooks that announce new letters:

```sh
claude plugin marketplace add /usr/local/share/tearmesh   # written by install
claude plugin install tearmesh@tear-mesh
tearmesh launch --boundary work --mailbox builder -- claude
```

**Any MCP client: the hub.** `tearmesh mcp serve` is one long-running MCP service per user. It has three channels, each working both ways: conversation (`post`, `inbox`, `read`, `wait_for_mail`, with new mail pushed to open sessions), tools on other machines (`offers`, `remote_tools`, `call_tool`) and shells on other machines (`shell_exec`, or `shell_open`/`shell_send`/`shell_read`/`shell_close`). It can also start chats in agent harnesses you configure (`harnesses`, `start_chat`, `chat_status`). Register it by URL, or by command for clients that only start processes:

```sh
tearmesh mcp info     # prints the URL, the bearer token and the commands below
claude mcp add --transport http tearmesh http://127.0.0.1:<port>/mcp --header "Authorization: Bearer <token>"
# Claude Desktop, Cursor and others that start a command: command `tearmesh`, args ["mcp", "connect"]
```

`mcp connect` connects to the running hub, or starts it; the hub stays running after the client exits. Only `serve` binds anything (the port doubles as its lock), so a client that starts its own copy can't collide with it. The HTTP door listens on 127.0.0.1 only and needs the token; the local socket admits only the same user. Each OS user gets its own port (picked from the user, 7787–8786; `mcp info` prints it). `~/.config/tearmesh/hub.toml` sets the `port`, the `mailbox` and the harnesses:

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
wake_on = ["member", "admin"] # default; add "guest" to wake on letters from the connector
```

**Phones and chat: the Claude connector.** `tearmesh mcp --http` serves the mail tools plus read-only `repo_status` and `read_file` to Claude's custom connectors (phone, web, desktop):
- It listens on a Unix socket only that boundary's user can open.
- Put a tunnel such as cloudflared, running as the same user, and an OAuth layer in front.
- Letters posted through it are marked `guest`.

The setup is in [docs/testing.md](docs/testing.md#the-claude-connector).

**For people:** `tearmesh menu` is the full-screen front end (arrow keys or the keypad, Enter, Esc, and a nano-style shortcut bar). `tearmesh tui` is a terminal mail client. `tearmesh who | post | inbox | read | bio | offers` work from scripts.

## Windows

tear-mesh runs natively on Windows. It is tested on Windows Server 2022; Windows 10 and 11 use the same APIs but haven't been tested yet.

- The local socket is a named pipe, and a session's boundary is its Windows account. The daemon identifies a caller by impersonating it.
- The daemon runs as a service under the virtual account `NT SERVICE\tearmesh`.
- Clients refuse a pipe that account (or SYSTEM, or Administrators) didn't create.

Install it from an elevated prompt with the release binary: check it with `Get-FileHash tearmesh-x86_64-windows.exe` against `SHA256SUMS`, run `Unblock-File tearmesh-x86_64-windows.exe`, then `.\tearmesh-x86_64-windows.exe install <name> work --stewards`. It adds `C:\Program Files\tearmesh` to the PATH and the plugin there. The steps are in [docs/testing.md](docs/testing.md#windows). The connector runs on Linux.

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
- `cargo test`: unit tests and in-process mesh tests over real iroh connections. They cover placement, membership, revocation, the version chain and split healing, ticket joins, converse, tool and shell grants, and carrying a 0.1 circle over.
- `tests/e2e-linux.sh`: two daemons with real OS users. It covers the ticket join, a tool call through the steward, shell, bios, the connector, the waker and the TUI.
- `tests/e2e-0.3.sh`: three daemons, trying to break 0.3: the setup wizard (bad input, run twice, stopped halfway), joins (nameless tickets, key lookup, boundaries added later), a mesh created, joined and approved entirely in the menu, the hub (connect-or-start, one per user, auth, all three channels both ways, chats), a stolen machine key, a leaked owner key, a node dropping mid-session, the owner offline, a flapping peer, and the menu.
- `tests/distros.sh`: the e2e and `tearmesh install` (re-run, uninstall) in Debian, Ubuntu, Fedora, Arch, openSUSE and Alpine containers.
- `tests/e2e-windows.ps1`: the Windows version.

## Docs

- [Spec for 0.2](docs/spec-0.2.md): what this release does and why
- [Design](docs/design.md): decisions, history, what comes next
- [Testing](docs/testing.md): automated tests and step-by-step tests across machines
- [Research notes](docs/research.md): the incident behind it, prior art and the building blocks

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. Unless you state otherwise, any contribution you intentionally submit for inclusion in this project is dual licensed as above, without additional terms.

The passphrase word list is the EFF large wordlist (CC BY 3.0 US, Electronic Frontier Foundation).
