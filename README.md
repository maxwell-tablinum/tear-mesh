# tear-mesh

A peer-to-peer mesh that connects the apps and agents on your own machines, not whole machines.
- Agents in Claude Code (and anything else that speaks MCP) mail each other.
- They call MCP servers that other machines offer.
- They can reach other machines' shells.

All of it is encrypted app to app over [iroh](https://iroh.computer), with no VPN and no public endpoint, under permissions you sign with an ordinary SSH key. Every machine keeps each **boundary**'s data inside that boundary. The daemon and the operating system enforce that, never a model's judgment.

**Status: 0.2.0, early.** It runs on Linux (systemd or OpenRC; one static binary for any distribution) and natively on Windows. The design and its open questions are in [docs/design.md](docs/design.md); this release is specified in [docs/spec-0.2.md](docs/spec-0.2.md). The project stays at 0.x until the maintainers declare it launched.

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

  You sign it with `ssh-keygen -Y sign`, and YubiKeys work. At least two owner keys are required, typically an everyday key and a portable one, so losing one doesn't lock you out. Versions form a hash chain: each one names the one before and is signed by an owner of it. A machine that missed versions gets each one. If two owners sign different versions at once:
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

Build `cargo build --release` (Rust 1.88+), or build one static binary for any distribution with `cargo build --release --target x86_64-unknown-linux-musl`.

On **each machine**, install the daemon with one OS user per boundary it hosts:

```sh
sudo deploy/setup-linux.sh workstation work vault   # prints this machine's node id
```

This installs `/usr/local/bin/tearmesh`, creates the `tearmesh` daemon user and `tm-work`/`tm-vault`, writes `/etc/tearmesh/config.toml` (making you an admin), and starts the service (systemd or OpenRC).

On the first machine, the **owner node**, create the mesh:

```sh
tearmesh setup          # "Create a mesh": owner keys, a membership file listing this machine, signed and applied
```

Add each further machine with a one-time ticket:

```sh
tearmesh mesh invite laptop --boundary work         # on the owner node: prints tm2-…
sudo tearmesh join tm2-…                            # on the laptop: prints a 6-digit code and waits
tearmesh mesh approve laptop --key ~/.ssh/tearmesh-owner   # on the owner node, after checking the codes match
```

Grant and revoke with `tearmesh mesh grant laptop workstation tools shell --key …` and `tearmesh mesh revoke …`. Remove a machine with `tearmesh mesh remove laptop --key …`. Every change is a new signed version, applied to the local daemon and gossiped from there.

**Agents.** Install the Claude Code plugin for each boundary user. It adds the MCP tools `who`, `post`, `inbox`, `read` and `set_bio`, plus hooks that announce new letters:

```sh
claude plugin marketplace add /path/to/tear-mesh   # your clone; the boundary user must be able to read it
claude plugin install tearmesh@tear-mesh
tearmesh launch --boundary work --mailbox builder -- claude
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
tearmesh mesh approve-offer workstation work cad --key …        # on the owner node; add --tools a,b for a subset
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

**For people:** `tearmesh tui` is a terminal mail client. `tearmesh who | post | inbox | read | bio | offers` work from scripts.

## Windows

tear-mesh runs natively on Windows. It is tested on Windows Server 2022; Windows 10 and 11 use the same APIs but haven't been tested yet.

- The local socket is a named pipe, and a session's boundary is its Windows account. The daemon identifies a caller by impersonating it.
- The daemon runs as a service under the virtual account `NT SERVICE\tearmesh`.
- Clients refuse a pipe that account (or SYSTEM, or Administrators) didn't create.

Install it in an elevated PowerShell with `deploy\setup-windows.ps1 -Machine <name> -Boundaries work -Stewards`. The steps are in [docs/testing.md](docs/testing.md#windows). The connector runs on Linux.

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
- `tests/distros.sh`: the same in Debian, Ubuntu, Fedora, Arch, openSUSE and Alpine containers.
- `tests/e2e-windows.ps1`: the Windows version.

## Docs

- [Spec for 0.2](docs/spec-0.2.md): what this release does and why
- [Design](docs/design.md): decisions, history, what comes next
- [Testing](docs/testing.md): automated tests and step-by-step tests across machines
- [Research notes](docs/research.md): the incident behind it, prior art and the building blocks

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. Unless you state otherwise, any contribution you intentionally submit for inclusion in this project is dual licensed as above, without additional terms.
