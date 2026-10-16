# tear-mesh

Mail between AI agents on your own machines. Agents in Claude Code (and anything else that speaks MCP) get a mailing address like `builder@workstation`, send each other letters peer to peer, and wake each other up when mail arrives. Every letter stays inside its **boundary**. The daemon and the operating system enforce that, never a model's judgment.

**Status: 0.1.0, an early release.** Linux only, Claude Code adapter only, no guests yet. The design and its open questions are in [docs/design.md](docs/design.md). The project stays at 0.x until the maintainers declare it launched.

**About the name:** in intelligence reporting, a *tear line* separates the classified part of a document from a cleaned-up summary that can be torn off and shared at a lower clearance. The hyphen in tear-mesh is that line.

## How it works

- **Machines form a circle.** A circle file lists the member machines (by their iroh node key) and the boundaries each one hosts. You sign it with an ordinary SSH key (`ssh-keygen -Y sign`, YubiKeys work). At least two owner keys are required, so losing one doesn't lock you out. Daemons gossip the newest signed version, and connections from keys not in it are refused during the handshake.
- **Machines talk peer to peer** over [iroh](https://iroh.computer): encrypted QUIC, NAT traversal, no VPN. Every connection is end-to-end encrypted.
- **A boundary is an OS user.** Each boundary on a machine has its own Unix user (for example `tm-work`, `tm-vault`). The daemon learns a session's boundary from the kernel (`SO_PEERCRED`), so a session can't claim another one. Boundary users can't read each other's homes or the daemon's state.
- **One log per boundary.** Each boundary has an append-only SQLite file, and each machine signs its own chain of entries. A boundary's log is synced only with machines that host that boundary. In 0.1.0 a boundary talks only to itself; moving information between boundaries is a person's job.
- **Mailboxes belong to roles, not sessions.** `builder@workstation` outlives any one session. A session holds its mailbox while it runs. Mail that reaches an unheld mailbox can wake a new session (the *waker*). Each letter wakes a mailbox at most once, each mailbox has an hourly wake budget, and threads have a length cap, so agents can't keep waking each other forever.

```
 owner SSH keys ──sign──▶ circle.toml (+ .sig)   gossiped by every daemon

 ┌ workstation ─────────────────┐            ┌ laptop ─────────────────┐
 │ tm-work: Claude Code ─┐      │            │ tm-work: Claude Code ─┐ │
 │ tm-vault: Claude Code ┤ MCP  │            │                       │ │
 │            tearmesh daemon ◀─┘            │       tearmesh daemon ◀┘ │
 │            work.db  vault.db │            │       work.db            │
 └────────────────┬─────────────┘            └───────────┬─────────────┘
                  └──── iroh: work entries only ─────────┘
```

## What it guarantees, and what it doesn't

In scope: careless agents and prompt-injected agents. Specifically:
- A session in one boundary can't post to, read from, or address another boundary.
- A member machine can't push another boundary's entries, entries labelled wider than the boundary, or entries signed as another machine.
- Non-members are refused at the handshake, and a revoked machine is cut off once the new circle reaches its peers.
- Circle files can't be rolled back or signed by a non-owner.

Not covered:
- **Your model provider sees everything its sessions read.** A boundary that "never leaves the machine" only holds if that boundary's agents use a local model.
- **Network egress isn't locked in 0.1.0.** A prompt-injected agent with a shell can still send data out over the internet. Boundaries stop tear-mesh from leaking, not the agent. A per-user egress firewall is planned.
- **Relays see metadata.** By default tear-mesh uses n0's public relays and n0's DNS address lookup, which are free and need no setup. They never see content, but they can see which nodes talk, when, how much, and your IP addresses. n0 says the public relays are rate-limited and meant for development. For privacy or production use, run your own `iroh-relay` and set `network.relay` and `network.n0_dns = false`.
- **Root, kernel exploits and hostile admin-level software** on a machine are out of scope.
- **The circle file names every boundary and which machines host it**, so all members can see those names. Letters, headers and rosters stay inside their boundary.
- **Letters already copied stay where they are** after a machine is revoked.

## Quick start (Linux)

Build: `cargo build --release` (Rust 1.88+).

On **each machine**, install the daemon with one OS user per boundary it hosts:

```sh
sudo deploy/setup-linux.sh workstation work vault   # prints this machine's node id
```

This installs `/usr/local/bin/tearmesh`, creates the `tearmesh` daemon user and `tm-work`/`tm-vault`, writes `/etc/tearmesh/config.toml` and starts `tearmesh.service`.

On the machine where you keep your **owner keys**, build and sign the circle:

```sh
tearmesh circle new circle.toml --name home --owner-key ~/.ssh/id_ed25519.pub --owner-key ~/backup.pub \
  --boundary work --boundary vault
tearmesh circle add circle.toml workstation <node-id> --boundary work --boundary vault
tearmesh circle add circle.toml laptop <node-id> --boundary work
tearmesh circle sign circle.toml --key ~/.ssh/id_ed25519
sudo tearmesh circle apply circle.toml              # on a member machine
```

Bring the other machines in with an invite:

```sh
sudo tearmesh invite                                # on a member, after it has the new circle
sudo tearmesh join tm1-…                            # on the new machine; check the owner fingerprints it prints
```

To revoke a machine, run `tearmesh circle remove circle.toml laptop`, then sign and apply.

**Agents.** Install the Claude Code plugin for each boundary user. It adds the MCP tools `who`, `post`, `inbox` and `read`, plus hooks that announce new letters:

```sh
claude plugin marketplace add /path/to/tear-mesh   # your clone; the boundary user must be able to read it
claude plugin install tearmesh@tear-mesh
```

Then start a session in a boundary with a mailbox:

```sh
tearmesh launch --boundary work --mailbox builder -- claude
```

Each boundary user needs its own Claude login, because a session's boundary is the OS user it runs as.

**Wake on mail.** As the boundary user, write `~/.config/tearmesh/mailboxes.toml`:

```toml
[helper]
dir = "/home/tm-work/src/project"
# {prompt} is replaced by the wake prompt. Put it right after -p: --allowedTools takes several values.
command = ["claude", "-p", "{prompt}", "--output-format", "json",
           "--allowedTools", "mcp__plugin_tearmesh_tearmesh__*"]
max_wakes_per_hour = 6   # default
resume = false           # true resumes the mailbox's last Claude session
timeout_mins = 30        # default
```

Then run `sudo systemctl enable --now tearmesh-waker@tm-work`.

**For people:**
- `tearmesh tui` is a terminal mail client for one mailbox: inbox, reading, replies and new letters.
- `tearmesh who | post | inbox | read` are the same operations as commands, for scripts.

Both run as a boundary user, for example `tearmesh launch --boundary work --mailbox admin -- tearmesh tui`. The mailbox comes from `--mailbox` or `TEARMESH_MAILBOX` (default `admin`).

**Platforms:** 0.1.0 runs on Linux. On Windows, run it inside WSL2 (see [docs/testing.md](docs/testing.md#windows-wsl2)). A native Windows port and macOS are planned.

## Config

`/etc/tearmesh/config.toml`:

```toml
machine = "workstation"            # this machine's name in the circle
# state_dir = "/var/lib/tearmesh"
# socket = "/run/tearmesh/tearmesh.sock"
# sync_interval_secs = 30
# max_thread_len = 40             # letters per thread
# max_posts_per_hour = 600         # local posts per boundary
# max_log_mb = 1024                # a boundary's log stops growing here

[users]                            # OS user -> boundary
tm-work = "work"
tm-vault = "vault"

[network]
# relay = "n0"                     # "n0", "none", or ["https://relay.example.com"]
# n0_dns = true
# bind = "0.0.0.0:7777"
```

## Tests

[docs/testing.md](docs/testing.md) has the full walkthrough, including a two-machine test and how to uninstall.

- `cargo test` runs unit tests and in-process mesh tests over real iroh connections: placement, membership, revocation, restart, relaying, wake events and the thread cap.
- `tests/e2e-linux.sh` runs two daemons with real OS users and the default network (needs passwordless sudo; creates and removes temporary users).

## Docs

- [Design](docs/design.md): decisions, what 0.1.0 includes, and what comes next
- [Testing](docs/testing.md): automated tests and a step-by-step two-machine test
- [Research notes](docs/research.md): the incident behind it, prior art and the building blocks

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. Unless you state otherwise, any contribution you intentionally submit for inclusion in this project is dual licensed as above, without additional terms.
