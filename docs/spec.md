# tear-mesh specification

This is the one specification of tear-mesh: what it is, how every part behaves, and what is still undecided. It describes version 0.5.0 (tag `v0.5.0`, 2026-11-26). 0.4.0 (tag `v0.4.0`, 2026-11-25) was the first release with binaries. 0.5.0 names three channels (mail, tools, shell) and leaves what each causes to configuration, adds mailbox rules, the Permissions box, versions in a ping and `tearmesh update` with a release the owner names for the whole mesh. All of it is built; what has not been tried yet (Windows, Claude on the web, a real Windows machine) is listed in section 26.

Older documents are history and are no longer updated: `docs/spec-0.2.md` (the 0.2 specification), `docs/design.md` (the 0.1 design and its questions) and the notes under `docs/research/`. Where they disagree with this file, this file is right. `README.md` is the short introduction and `docs/testing.md` is the hands-on test guide; both follow this file.

## 0. How this spec is kept

1. **The spec comes first.** Anything a person, another machine, an agent or a test can observe is changed here before it is changed in code: commands and their output, files and their formats, wire protocols, limits, permissions, security rules. Then the code is changed. Then this file is corrected to what was really built, and the change is noted in the change log at the end.
2. **Every statement has a status.** A statement with no mark is built and was checked against the code. The marks are:
   - **PLANNED**: agreed, not built.
   - **BEING BUILT** (`name`): the spec already says the new behaviour and the code is being changed to match. No finished piece of work leaves this mark behind.
   - **PROPOSED**: suggested by someone, not agreed, not built.
   - **OPEN**: undecided. Maxwell decides; nobody builds on a guess.
   - **LIMIT**: a known shortcoming of what is built, kept because fixing it was not worth it yet. Each says when it would matter.
3. **Rulings are folded in as they are given.** A ruling marked DECIDED goes into the body. One marked PROPOSED is written as proposed. One marked OPEN stays undecided and is listed in "Open questions". When two rulings or a ruling and the code disagree, the conflict is written down and asked, never settled silently.
4. **Names, not numbers.** Open questions, proposals and changes carry short names (for example `open/converse-category`) so they can be discussed without section numbers, which move.
5. **Checked against the code.** After a pass over this file, every claim that something is absent or refused ("there is no …", "… is never …") is checked against the code by a reader that changes nothing.
6. **Builders get this rule.** Every brief to someone building tear-mesh says: the spec was updated before you start; build what it says; if it is wrong or cannot be built as written, stop and report; afterwards report what the spec must say.
7. **Versions.** tear-mesh stays at 0.x until Maxwell declares it launched. Protocol names stay `tear-mesh/…` (and `shell/1` inside them); they change only with a wire-format change.

## 1. What tear-mesh is

tear-mesh is a peer-to-peer mesh that connects the apps and agents on one person's own machines. It does not join whole machines to a network.

- Agents (in Claude Code, or anything else that speaks MCP) send each other letters.
- They call MCP servers that other machines share.
- They can open shells on other machines.

All of it runs encrypted from app to app over [iroh](https://iroh.computer) (QUIC, with relays and hole punching). No VPN, no public endpoint, no system DNS or route is touched. What may happen between two machines is decided by permissions the owner signs with an ordinary SSH key. Each machine keeps the data of each **boundary** inside that boundary; the daemon and the operating system enforce that, never a model's judgment.

The headline use: an agent on one machine drives MCP servers and other capabilities on the person's other machines, from anywhere. Machines with no agent of their own are full members (DECIDED 2026-11-12).

**The name.** In intelligence reporting, a tear line separates the classified part of a document from a summary that can be torn off and shared at a lower clearance. The hyphen in tear-mesh is that line.

**The trust rule (DECIDED 2026-11-12): only admit machines you trust.** A member machine signs its own claims; nothing proves from afar what code it runs. tear-mesh limits what a careless or prompt-injected agent can do. It does not defend against a member machine that is itself hostile at the admin level.

The binary is `tearmesh`. One Rust crate, about 19,000 lines. It runs on Linux (systemd or OpenRC; one static binary for any distribution) and on Windows (a service). macOS is not supported: install refuses it.

## 2. Terms

| Term | Meaning |
|---|---|
| mesh | One person's set of machines, defined by a signed membership file. |
| membership file | The TOML file that lists owner keys, boundaries, machines, grants, approved MCP servers and settings. Each change is a new signed **version**. |
| owner key | An SSH key (ed25519, or an ed25519 security key) allowed to sign the next version. A mesh has at least two. |
| owner node | A machine whose user holds an owner key for the mesh in `~/.ssh`. Only a name for where signing happens; the file does not mark it. |
| machine | One installed daemon, known by its name and its iroh node id (its public key). |
| boundary | A named compartment of data (`work`, `vault`). On a machine, each boundary is one OS user (`tm-work`). |
| boundary user | The OS user of a boundary. Agents run as it. |
| admin | Someone the daemon lets manage the machine: root or an Administrator, the daemon's own user, or a user listed in `admins` in the config. |
| session | One connection to the daemon's local socket, by an agent, the menu or a command. Its boundary is that of its OS user. |
| letter | A piece of mail: `info`, `task` or `question`. |
| mailbox | A named recipient on a machine, written `mailbox@machine` (`builder@workstation`). Mailboxes belong to roles, not to sessions. |
| entry | One signed record in a boundary's log: a letter, an offer or a bio. |
| grant | Permission from one machine to another for a category: `converse`, `tools` or `shell`. |
| offer | A machine's signed description of an MCP server it shares: its instructions and exact tool list, and their hash (the **pin**). |
| approval | The owner's signed acceptance of one offer at one pin, for all or some of its tools. |
| steward | A process run as a boundary user. It starts shared MCP servers, wakes agents when mail arrives, and runs the mail screener. |
| hub | One long-running MCP server per OS user that gives an agent harness mail, remote tools, remote shells and chats. |
| ticket | A one-time text (`tm2-…`) that lets one new machine ask to join. |
| trust | A label on a letter set by the machine that wrote it: `guest`, `member` or `admin`. |
| agent | Whoever answers a mailbox: a session, a woken harness, or Claude through the gateway. Addressed as `mailbox@machine`. |
| status record | An agent's own short record: what it is, what it is doing, how many questions wait for the owner. |
| claim | A header-only letter in a thread: "working on it, expect an answer in N seconds". |
| gateway | A member machine that also serves the conversation tools to Claude's apps over public HTTPS with OAuth. |
| grant (gateway) | One completed sign-in of a Claude app at the gateway. Not the membership file's grant. |

## 3. Architecture

### 3.1 Processes

| Process | Runs as | What it does |
|---|---|---|
| daemon (`tearmesh daemon`) | the `tearmesh` service user (Windows: `NT SERVICE\tearmesh`) | Holds the node key, the membership file and its history, one log per hosted boundary and the iroh endpoint. Serves the local socket. Never runs user code. |
| steward (`tearmesh steward`) | each boundary user | Starts shared MCP servers for peers, wakes agent sessions on mail, screens mail. Optional. |
| hub (`tearmesh mcp serve`) | each OS user that uses it | MCP server for agent harnesses: HTTP on 127.0.0.1 and a private socket. Optional. |
| stdio mail server (`tearmesh mcp`) | the agent's OS user | MCP server with the mail tools, started by the agent harness (the Claude Code plugin). |
| gateway (`tearmesh gateway serve`) | a boundary user, Linux only | MCP server with OAuth on `127.0.0.1`, behind a tunnel, for Claude's custom connectors (voice, phone, web, Desktop). Optional; one per machine. |
| menu, commands | the person | Talk to the daemon over the local socket. Commands that sign do the signing themselves. |

### 3.2 Files on Linux

| Path | Owner, mode | Contents |
|---|---|---|
| `/usr/local/bin/tearmesh` | root, 0755 | the binary |
| `/etc/tearmesh/config.toml` | root, 0644 | the daemon's config (no secrets) |
| `/etc/tearmesh/created-users` | root, 0644 | the boundary users install created, one per line |
| `/var/lib/tearmesh/` | tearmesh, 0700 | the state directory, below |
| `/run/tearmesh/tearmesh.sock` | tearmesh, 0666 | the local socket |
| `/usr/local/share/tearmesh/` | root | the Claude Code plugin |
| `/etc/systemd/system/tearmesh.service`, `tearmesh-steward@.service` | root | systemd units |
| `/etc/systemd/system/tearmesh-update.service`, `tearmesh-update.timer` | root | the updater and its timer (section 22.3) |
| `/usr/local/bin/.tearmesh-update/`, `/run/tearmesh-update.lock` | root, 0700 and 0600 | only while an update runs: the folder the download is checked in and run from, and the lock that keeps two updates apart (section 22.3) |
| `/etc/tearmesh/gateway.toml` | root, 0644 | the gateway's config (no secrets). Its presence makes this machine a gateway. |
| `/var/lib/tearmesh-gateway/` | the gateway's boundary user, 0700 | `gateway.db` (clients, sign-ins, token hashes, the passphrase hash), `audit.log` |
| `/etc/systemd/system/tearmesh-gateway.service` | root | the gateway's unit, written by `gateway setup` |
| `/etc/init.d/tearmesh`, `/var/log/tearmesh.log` | | OpenRC script and its log |
| `~/.ssh/tearmesh-owner-<mesh>` (+ `.pub`) | the person, 0600 | the everyday owner key |
| `~/.config/tearmesh/` | each user | `mailboxes.toml`, `offers.toml`, `screen.toml`, `hub.toml` |
| `~/.local/state/tearmesh/` | each user | `sessions.json` (steward), `hub/` (hub) |

The state directory holds:

| File | Contents |
|---|---|
| `node.key` | the machine's secret key (hex of 32 bytes). Made on first use. |
| `mesh/<version>.json` | every adopted version as `{toml, sig}` |
| `mesh-id` | the id of the mesh this machine's logs belong to |
| `boundaries/<boundary>.db` | the log of each hosted boundary (SQLite) |
| `boundaries-<mesh id>/` (or `.1`, `.2` …) | the logs of a mesh this machine left. Kept, never deleted. |
| `dissolved` | ids of dissolved meshes, one per line (tombstones) |
| `leaving` | present while a leave is half done; finished at the next start |
| `peers.json` | last known addresses of member machines |
| `invites.json` | open invites (owner node) |

### 3.3 Files on Windows

Program: `%ProgramFiles%\tearmesh\tearmesh.exe` plus the plugin files. Data: `%ProgramData%\tearmesh\` with `config.toml`, `passwords.txt` (the generated passwords of the boundary users; SYSTEM and Administrators only) and `state\` (as above, plus `daemon.log`). The local socket is the named pipe `\\.\pipe\tearmesh`. Service `tearmesh` runs as `NT SERVICE\tearmesh`. Firewall rule `tearmesh-udp` (inbound UDP for the program, Private and Domain profiles). Stewards are scheduled tasks `tearmesh-steward-<boundary>`. The updater is the scheduled task `tearmesh-update` (section 22.3); while it works it uses the folder `%ProgramFiles%\tearmesh\.update` and the lock file `%ProgramData%\tearmesh\update.lock`.

**LIMIT** (`limit/windows-log-rotation`): `daemon.log` is never rotated. It matters on a node that runs for months.

### 3.4 Environment variables

| Variable | Read by | Meaning |
|---|---|---|
| `TEARMESH_CONFIG` | daemon, menu, `launch`, `id` | config file path |
| `TEARMESH_SOCKET` | every client | local socket path; set by `launch` |
| `TEARMESH_MAILBOX` | sessions | the session's mailbox (default `admin`); set by `launch --mailbox`, by wakes and by hub chats |
| `TEARMESH_WAKE_IDS` | a woken command | ids of the letters that caused the wake |
| `TEARMESH_MAILBOXES`, `TEARMESH_OFFERS`, `TEARMESH_SCREEN` | steward, `offer publish` | paths of the steward's files |
| `TEARMESH_HUB_CONFIG`, `TEARMESH_HUB_DIR` | hub | `hub.toml` path, hub state directory |
| `TEARMESH_GATEWAY_CONFIG`, `TEARMESH_GATEWAY_DIR` | gateway | `gateway.toml` path, gateway state directory |
| `TEARMESH_RELEASE_URL` | `install.sh`, `install.ps1`; `mesh invite` and the menu | folder to download the release from, in place of the GitHub release |
| `TEARMESH_BIN` | `setup-linux.sh` | the binary to install |
| `ANTHROPIC_API_KEY` | steward | the screener's key when `screen.toml` names no key file |
| `RUST_LOG` | all | log filter; default `info,iroh=warn,noq=warn` |

## 4. Transport

Machines talk over iroh 1.3. A machine's identity is its node key; its public half is the **node id** listed in the membership file. The endpoint offers five protocols (ALPN names):

| ALPN | Purpose | Who is admitted at the handshake |
|---|---|---|
| `tear-mesh/sync/2` | membership versions and log entries | members; also machines a stored version removed (the farewell rule) |
| `tear-mesh/join/1` | a new machine asks to join | anyone, but only while this machine has an open invite; always when this machine is the one dialing |
| `tear-mesh/mcp/1` | tool streams | members |
| `tear-mesh/shell/1` | shell streams | members |
| `tear-mesh/ping/1` | reachability, and "I am leaving" | members |

1. **The handshake check.** After every handshake, inbound and outbound, the daemon looks the other side's node id up in its current membership file. Anything not allowed by the table is closed with QUIC error code 403 and the reason `not a mesh member`. Because the check also runs on outbound connections, a machine cannot dial a non-member except to join.
2. The handshake checks membership only. Grants for tools and shell are checked when a stream is opened, at both ends. Ping needs no grant.
3. A connection is checked once. When a new version is adopted, open tool and shell streams are checked again and closed if the mesh no longer allows them (`closed: the mesh no longer allows it`).
4. **Finding each other.** Lookup methods come from the config (`network.lookup`) or else the mesh setting `lookup`, default `["n0-dns", "mdns"]`: `n0-dns` publishes and resolves address records through n0's DNS service (records carry only a relay URL, not IP addresses); `mdns` finds machines on the local network (service name `tearmesh`). Addresses learned from members are kept in `peers.json`; an address with more than 16 entries is ignored.
5. **Relays.** From the config (`network.relay`) or else the mesh setting `relays`, default `n0` (n0's public relays). `none` turns relays off. A list of URLs uses the person's own relays. Relays see which nodes talk, when, how much and from which IP addresses, never content.
6. `network.bind` in the config fixes the local UDP address; otherwise any free port.
7. **LIMIT** (`limit/settings-need-restart`): the daemon reads the mesh settings `relays` and `lookup` once, when it starts. A machine that joins a mesh with other than default settings, and every machine after a change to them, uses the new settings only after its daemon restarts. Matters only for meshes with their own relays.
8. Frames on sync, join and the stream headers are a 4-byte big-endian length followed by JSON, at most 4 MiB; the join request a stranger sends first is at most 4096 bytes.

## 5. The membership file

### 5.1 Format

A TOML document, format 2. Unknown keys anywhere make the file unreadable.

```toml
format = 2
id = "5f0c…"            # 32 hex characters, random, fixed when the mesh is created
name = "home"
version = 3
prev = "9a41…"          # blake3 hash of the previous version's exact text; absent in version 1
# closed = true         # present only in the last version of a dissolved mesh
owners = ["ssh-ed25519 AAAA… tearmesh owner home", "ssh-ed25519 AAAA… tearmesh recovery home"]
boundaries = ["vault", "work"]

[settings]
relays = "n0"           # "n0", "none" or a list of relay URLs
lookup = ["n0-dns", "mdns"]
tools_sharing = "approval"   # or "free"
# release = "0.5.1"         # the version every machine should run (section 22.3); absent when none is named

[[machine]]
name = "alpha"
id = "<iroh node id>"
boundaries = ["vault", "work"]

[[grant]]
from = "*"
to = "*"
allow = ["converse"]

[[approved]]
machine = "beta"
boundary = "work"
server = "files"
pin = "<64 hex>"
tools = ["read", "list"]     # absent: every tool in the offer
```

1. A version's **hash** is the blake3 hash of its exact TOML text, as 64 lowercase hex characters.
2. Size limits, checked when a file is verified: the file at most 64 KiB, its signature at most 8 KiB (`membership file too large`). **LIMIT** (`limit/file-size-late`): nothing stops an owner from signing a larger file; the daemon then refuses it. Matters past a few hundred machines and grants.
3. **Names** (mesh, machine, boundary, mailbox, server): 1 to 32 characters of `a-z`, `0-9` and `-`, not starting with `-`.

### 5.2 What a valid file needs

Checked in this order whenever a file is read or a new version is made:

1. `id` is 1 to 64 ASCII letters and digits; `name` is a valid name; `version` is 1 or more; `prev`, if present, is 64 lowercase hex characters.
2. Every owner key parses as an OpenSSH public key of type `ssh-ed25519` or `sk-ssh-ed25519`. No other key type is accepted.
3. At least two distinct owner keys (compared by key, not by comment): `a mesh needs at least two distinct owner keys, so losing one doesn't lock it`.
4. At least one boundary; boundaries are valid names, none twice.
5. `settings.relays`, when a single word, is `n0` or `none`; `settings.lookup` entries are `n0-dns` or `mdns`.
6. A closed file has no machines, grants or approvals. Owners and boundaries stay.
7. Each machine has a valid, unique name, a unique node id, and hosts at least one boundary, each of which exists in the mesh.
8. Each grant's ends are a listed machine or `*`; it allows at least one category; a grant that includes `shell` names both machines (no `*`).
9. Each approval names a machine that hosts that boundary, a valid server name, a 64-hex pin, and is unique per machine, boundary and server. Tool names are 1 to 128 characters of letters, digits, `_`, `-` and `.`.

### 5.3 A new mesh

Version 1 has the two owner keys, the boundaries, no machines until the creating machine is added, default settings, and one grant: `* → *` for `converse` (mail allowed among all machines). Tools and shell start with no grant.

### 5.4 Changes

An owner changes the mesh by signing a new version. Any number of changes go under one signature. The changes are:

| Change | Effect |
|---|---|
| add machine | Adds a machine with its node id and boundaries. An existing name is refused unless it is a replacement, which gives the name a new node id, keeps its grants and drops its approvals. |
| remove machine | Removes the machine and every grant and approval that names it. |
| grant | Adds categories to the grant `from → to`, creating it if needed. A grant from a machine to itself is refused (`a machine needs no grant to itself`). Only the change is refused: a file that already holds such a grant (0.4.0 signed them) still loads, and the grant can be revoked. |
| revoke | Removes categories from the exact grant `from → to` (`no grant A -> B` if there is none). If a `*` grant still allows a category for the pair, a note says so. |
| approve | Approves an offer at a pin, for all its tools or a named subset, replacing an earlier approval of the same server. |
| unapprove | Removes an approval (`no such approval`). |
| add boundary | Adds a boundary to the mesh. |
| set hosts | Replaces the list of boundaries a machine hosts. Approvals in boundaries it no longer hosts are dropped, with a note. |
| add owner key, remove owner key | By public key line and by SHA256 fingerprint. Two distinct keys must remain. |
| set | `tools-sharing` = `approval` or `free`; `relays` = `n0`, `none` or a comma list of http(s) URLs (anything else is refused when the version is made: `relays is n0, none or http(s) URLs separated by commas; "<part>" isn't one`); `lookup` = a comma list of `n0-dns`, `mdns`. **LIMIT** (`limit/stored-relay-url`): the relay check is made when a version is made. A version an owner key signed some other way with a relay URL that does not parse stops every daemon that adopts it from starting. |
| set `release` | `release` = a version of three numbers (`0.5.1`), or `none` to name none. It is the version every machine of the mesh should run; each machine's updater installs it (section 22.3). The change carries a note: `machines that run 0.4 can't read a membership file that names a release: update them by hand first`. |
| dissolve | Removes every machine, grant and approval and marks the file closed. |

The first change that fails stops the whole version. A grant is written `from:to:categories` on the command line, for example `laptop:ws:tools,shell`.

### 5.5 Signatures and the chain

1. A version is signed over its exact TOML text, in OpenSSH's SSHSIG format (what `ssh-keygen -Y sign` writes), namespace `tear-mesh-membership`. tear-mesh signs with SHA-512; the check accepts the hash the signature names.
2. **A first file** (version 1, or the first file a machine ever adopts) must be signed by one of the owner keys listed inside it. Whether to believe it comes from how the machine got it: its own admin applied it, or a ticket named its owner keys.
3. **A next file** is accepted only if, in this order: the current version is not closed; the signature is by an owner key of the *current* version; the file is valid, format 2, has the same mesh id, has version = current + 1, and its `prev` is the current version's hash. So a file cannot be replayed, rolled back, jumped ahead, or signed by a key that was removed.
4. **Security keys.** A signature by an `sk-ssh-ed25519` key must carry both the user-presence and the user-verification flags (touch and PIN). A key made without `-O verify-required` cannot sign: `security-key signature lacks user presence or user verification (create the key with -O verify-required)`. **LIMIT** (`limit/sk-key-unusable`): such a key can still be *added* as an owner, because a public key does not show how it was made, and then counts toward the two-key minimum without being able to sign.
5. Every adopted version is stored. At start the daemon reads them back and re-verifies the chain; a link that does not verify is ignored together with everything after it.
6. A stored 0.1.0 "circle" (a file with no `format` key, signed under the namespace `tear-mesh-circle`) is read as a format-1 file that keeps its own version number, with the `* → *` converse grant; its next version is format 2.

### 5.6 Two owners sign at once

Two owners can sign different files with the same version number. A machine holds one of them as its newest version. When a peer shows it the other, the machine checks the other against the version before (it needs that version stored) and applies these rules in order. Only the newest version can be replaced, and only by a file whose signer is still an owner in the machine's own newest version.

1. A file that removes the other's signer from the owners wins.
2. Otherwise the file with more versions already built on it wins, even against a dissolve.
3. Otherwise a closed (dissolving) file wins.
4. Otherwise the lower hash wins.

The machine that drops its own file warns: `two owners signed different version Ns; this machine dropped its own (…) for the other (…). Re-apply the dropped changes on top of the current version`.

**LIMIT, OPEN** (`open/mutual-owner-removal`): if two owners each sign a version that removes the *other's* key, every machine keeps the one it saw first and the mesh stays split until a person re-applies one side by hand. Making the rule symmetric (fall through to rules 2 to 4) would let a thief with one stolen owner key win the race by making many candidate files and picking a low hash. Which is worse is Maxwell's call.

### 5.7 How versions travel

Every sync session exchanges versions both ways, at most 32 per session; adopting a version starts another sync round at once, so a machine far behind catches up 32 versions per round. A machine that is ahead sends what the other lacks; one that sees a different file at the same number sends its own so the split can be settled.

`tearmesh mesh apply FILE` hands a signed file to the local daemon. Applying a next version this machine did not adopt (an older fork, or the losing one of two versions with the same number) fails with `version N (<first 12 characters of its hash>) wasn't adopted: this machine keeps its own version M`; applying one it already holds succeeds.

**LIMIT** (`limit/warnings-stay`): warnings about splits stay in `tearmesh status` until the daemon restarts, even after the split is settled.

## 6. Owners and keys

1. **Two keys from the start.** Creating a mesh makes two ed25519 keys in memory:
   - the **everyday key**, encrypted with the person's passphrase (8 characters or more), saved as `~/.ssh/tearmesh-owner-<mesh>` (mode 0600) with its `.pub`. An existing file of that name is first renamed to `<name>.old-<time>`.
   - the **recovery key**, encrypted with a generated passphrase of six words from the EFF large wordlist joined by `-` (about 77 bits). The key and its passphrase are shown once, for the person to keep away from the machine. tear-mesh never writes them to disk unless the person presses the key that saves the key file.
   Both are OpenSSH private key files (AES-256-CTR, bcrypt with 100 rounds).
2. **Where signing happens.** In the process the person runs (the menu or a `mesh` command), never in the daemon. A passphrase-protected key file signs in that process. A security key signs through `ssh-keygen` with the PIN passed on its standard input, never in arguments, environment or a file; a security key whose file also has a passphrase, and any security key on Windows, signs in the plain terminal (**LIMIT** `limit/sk-windows-terminal`: untested in-process on Windows).
3. **Which key.** Commands that sign look in `~/.ssh` for private key files whose `.pub` is an owner key of the mesh. The command line needs exactly one (else `--key PATH`); the menu takes the first by file name. A machine is called an owner node, and its menu offers the keys that sign, when one is found.
4. **A lost or leaked key.** Add a new owner key, then remove the old one; both need a signature by a key that is still an owner. The recovery key exists for this. With every owner key lost, the mesh cannot change any more: create a new one.
5. **LIMIT** (`limit/passphrase-128`): the menu and the old wizard take at most 128 characters of a passphrase or PIN and drop the rest without saying so.
6. **LIMIT** (`limit/owner-key-home`): the everyday key is saved in the home directory of the user that runs the menu. Created as root, it lands in root's `~/.ssh` and another user's commands will not find it.

## 7. Boundaries and who is who

1. **A boundary is an OS user.** The config maps OS users to boundaries (`[users]`: `tm-work = "work"`). Install creates one user `tm-<boundary>` per boundary, with a home only it can read (mode 0700) and no password (Linux) or a generated one (Windows). Two OS users may map to the same boundary.
2. **The daemon asks the operating system who is calling.** On Linux the kernel reports the caller's uid on the socket (`SO_PEERCRED`). On Windows the daemon impersonates the pipe client after its first line and reads its SID. Nothing a session says can change its boundary.
3. **Admin** is: uid 0 or the daemon's own user (Linux); SYSTEM, the daemon's user, or an elevated member of Administrators (Windows; a UAC-filtered token is not admin); or a user listed in `admins` in the config. Install lists the person who ran it through sudo (Windows: the account that ran it).
4. A user can be both mapped and admin. An admin with no boundary can manage the machine and the mesh but has no mail: mail commands answer ``this OS user isn't mapped to a boundary: mail belongs to a boundary user; run the command through `tearmesh launch --boundary <b> -- …` ``. A user who is neither gets `OS user <id> isn't mapped to a boundary on this machine` and is disconnected.
5. **Where a boundary's data goes.** A boundary's log is synced only with machines that host that boundary in the membership file. A session can only address mailboxes on machines that host its boundary, only reads its own boundary's log, and only calls tools and opens shells within it. Grants never widen a boundary. Moving information between boundaries is a person's job.
6. The mesh lists which boundaries each machine hosts. A machine may host a boundary for which it has no OS user yet (the owner assigned it at join): `tearmesh status` lists these under `unmapped`, and the menu offers to add the users.
7. **Running something as a boundary user.** `tearmesh launch --boundary B [--mailbox M] -- command…` finds the OS user for B in the config and runs the command as it with `TEARMESH_SOCKET` (and `TEARMESH_MAILBOX`) set. Linux: through `sudo -u <user> -i`, so the command starts in that user's home directory (relative paths in its arguments are read from there); as root on a machine with no sudo, through `su -l` (the same home directory rule); with neither, `launch needs sudo, or run it as root`. Windows: through `runas`, which asks for that user's password and opens a new window.

## 8. Logs and entries

### 8.1 One log per boundary

Each hosted boundary has one SQLite file, `boundaries/<boundary>.db`. Its `entries` table is append-only (the database itself refuses updates and deletes). Every machine writes its own numbered chain of entries: sequence numbers from 1, each entry naming the id of that machine's previous entry. Four more tables are local and never synced: `rcpt` (who each entry is addressed to), `seen` (which mailbox has read or been told of which letter), `screen` (screening verdicts) and `idem` (the keys of posts sent with one, for a day; section 13).

### 8.2 An entry

An entry is `{envelope, sig, body}`. The envelope is the exact JSON text that was signed; it is never re-encoded before it is checked. Its fields, in order:

| Field | Meaning |
|---|---|
| `v` | envelope version, 2. Version-1 envelopes from 0.1.0 (letters of kind `info`, which name the mesh `circle`) are still accepted. |
| `mesh` | the mesh id |
| `boundary` | the boundary |
| `author` | node id of the machine that wrote and signed it |
| `seq`, `prev` | position in the author's chain; `prev` is null (or missing) exactly when `seq` is 1 |
| `ts` | the author's clock in milliseconds; for display only |
| `from` | `mailbox@machine` |
| `to` | 1 to 32 addresses, or `*` for everyone in the boundary |
| `thread` | id of the thread's first letter, if any |
| `subject` | one line, at most 200 characters, no control characters |
| `body_hash`, `body_len` | blake3 hash and byte length of the body |
| `label` | `{boundaries, trust}` |
| `kind` | `info`, `task`, `question`, `claim` (letters), `offer`, `bio`, `status` |

1. The signature is Ed25519 by the author's node key over the envelope text, as 128 hex characters (anything else is refused as bad input). The entry's **id** is the blake3 hash of the envelope text, 64 hex characters.
2. Limits: envelope 16 KiB, body 256 KiB, subject 200 characters, 32 recipients, bio 16 KiB, offer 192 KiB, status record 4 KiB, a claim's body 8 characters.
3. Other unknown envelope fields are refused. **LIMIT** (`limit/envelope-frozen`): a later release that adds a field must also raise `v`, or older machines will refuse its entries.
4. **Trust** is set by the machine that writes the entry and is only that machine's claim: `guest` (from outside the mesh: the connector), `member` (a session on a member machine; the default), `admin` (the machine's admin). A session may lower its trust, never raise it. The old names `circle` and `owner` are still read as `member` and `admin`.

### 8.3 The one gate

Every entry, written here or received from a peer, passes the same checks before it is stored: the envelope checks above; the mesh id and boundary match; the author is a machine in the current membership file and hosts the boundary; the label names this boundary only; offers, bios and status records are addressed to `*`; a claim names a thread and its body is empty or 1 to 8 digits; `from` is an address on the author's own machine; every recipient is `*` or a mailbox on a machine that hosts the boundary. Then the chain: an entry already held is ignored; a different entry at a sequence number already held is a **fork** and is refused with a warning; a gap or a wrong `prev` is refused.

**LIMIT** (`limit/chain-stall`): entries are checked against the membership file as it is now. If one entry of a machine is refused (say it is addressed to a machine that has since stopped hosting the boundary), every later entry of that machine in that boundary is refused too, as a gap: the first refusal logs a warning, the later ones only a debug line. Matters when machines are removed from a boundary while old mail is still spreading.

### 8.4 Limits on the daemon (config)

| Key | Default | Effect |
|---|---|---|
| `max_log_mb` | 1024 | a boundary log this big accepts no more entries. Local posts get the error `boundary log is full (<size> bytes)`. A value too large to count in bytes is treated as the largest that can be. Synced mail that is refused for this reason raises a warning in `tearmesh status`, which stays until the daemon restarts: `boundary <b>'s log is full (<max_log_mb> MB): mail for it is not being stored; raise max_log_mb`. |
| `max_posts_per_hour` | 600 | posts per boundary per hour written on this machine (letters, claims, offers, bios and status records). Kept in memory; a restart resets it. Only posts that pass every check count; one that then cannot be stored (a full log) still counts. |
| `max_thread_len` | 40 | letters in one thread before this machine refuses to add to it |

Each must be 1 or more, or the daemon does not start (`max_thread_len must be at least 1`, and the same for the other two). **LIMIT** (`limit/limits-local-only`): the thread and hourly limits apply to posts written on this machine, not to entries received from peers.

## 9. Sync

1. **Who.** A machine syncs with every machine that shares at least one boundary with it in the membership file.
2. **When.** Every `sync_interval_secs` (default 30, at least 1), and at once when something changes: a local post, an adopted version. Also right when the daemon starts. `SyncNow` (used by dissolve) runs a round on request.
3. **A session** is one QUIC stream. Both sides send `hello` (mesh id, version, hash, own address, and for each shared boundary the highest sequence number held per author), then the membership versions the other lacks (section 5.7), then, for each shared boundary, the entries after the other's heads in batches of at most 256 entries or about 1 MiB, then `end`. A peer in another mesh is refused (`peer is in another mesh`).
4. A received entry goes through the one gate. A peer that sends a boundary it does not share ends the session (`peer … may not send boundary …`).
5. Timeouts: the serving side gives a session 60 s; the dialing side 30 s per machine.
6. Mail is relayed: a machine passes on entries of every author in a shared boundary, so two machines that never meet still exchange mail through a third that hosts the boundary.
7. **LIMIT** (`limit/sync-frame-escape`): a batch is cut at 1 MiB of raw bytes but a frame at 4 MiB of JSON. Several maximum-size letters made mostly of control characters could grow past the frame limit when encoded and then fail to sync every round. Not seen in practice.

### 9.1 Ping

`tearmesh status --ping` and the menu send one byte to every other machine and time the echo (6 s limit for each step). A machine that is about to leave sends the byte `L` instead; a member that receives it notes "says it left" for that machine and answers `l`. The note changes nothing in the mesh: an owner must still sign the removal. It is kept in memory (an owner node that restarts forgets it) and cleared by the next completed sync with that machine.

The ping of `status --ping` and the menu sends the byte `V`. A daemon from 0.5.0 on answers `v` followed by its version as text; an older daemon echoes the byte, and its version is unknown. The asker keeps the text only if it is 1 to 32 characters of digits, letters, `.`, `-` and `+` (a longer or other answer counts as no version), so nothing a peer sends reaches a terminal unchecked. `status --ping` and the menu show each machine's version, so the owner sees which machines still run an older one. The 4-second reachability check that `send_message` makes (section 18.6) still sends the byte `7`, which every version echoes.

## 10. Joining

Joining needs two things: a ticket from the owner node, and the owner's signature on a version that adds the machine. A ticket alone admits nobody.

### 10.1 The ticket

1. `tearmesh mesh invite [NAME] [--boundary B]… [--replace] [--expires DUR]` on the owner node, or **A** in the menu, prints a ticket. Without NAME the new machine proposes its own name and boundaries. NAME and `--boundary` pin them: a machine that proposes another name, or another non-empty set of boundaries, is refused (one that proposes no boundaries gets the pinned ones). `--replace` (needs NAME) lets the new machine take over the name of an existing one with a new node id. `--expires` takes a number with `s`, `m`, `h` or `d` (a bare number is minutes); default one hour, at least one second (`a ticket must last at least a second`), at most 7 days. The menu always makes a one-hour ticket with nothing pinned.
2. A ticket is `tm2-` followed by base64 (URL-safe, no padding) of: version byte 2, the mesh id, a 16-byte hash of the owner key set, a 16-byte random secret, the expiry time, the owner node's id and up to 8 of its addresses (relay URLs and IP addresses). Under 250 characters in the usual case.
3. The owner node keeps open invites in `invites.json`, so a daemon restart does not void them. An invite is dropped when it expires; once a machine has claimed it, it lives at least one more hour.
4. With the ticket, `mesh invite` and the menu also print one-line install commands for Linux and PowerShell that download the release, install and join (section 22.5).

### 10.2 The exchange

1. On the new machine, an admin runs `tearmesh join TICKET`, or **J** in the menu, or the one-line install command. The daemon does the joining, so the command can be closed; `tearmesh join --cancel` stops it.
2. Before dialing, the new machine refuses: a ticket for a mesh that was dissolved here; a machine that is already in a mesh (the error says to run `tearmesh mesh leave` first); a ticket expired by more than an hour.
3. It dials the owner node on the join protocol (30 s to connect: `owner node … not reachable`) and sends its request: mesh id, its configured machine name, the boundaries its config maps users to, and a proof. The proof is a keyed blake3 hash, with a key derived from the ticket's secret, over both node ids, so it is good only for this machine talking to this owner node. The request is at most 4096 bytes.
4. The owner node looks for an open invite whose secret matches. If none: `no open invite matches this ticket (used, expired, or wrong)`. Failed attempts are limited to 30 an hour for all invites together (`too many failed join attempts this hour`); the first machine to match a ticket never counts, so a stranger cannot lock the real machine out; a second machine that matches an already claimed ticket (a leaked ticket) does count.
5. **A leaked ticket.** If another node already claimed this invite, the newcomer is refused (`this ticket was already used by another machine …`), the first claim is marked **contested**, and the owner sees a warning when approving.
6. The owner node checks the proposal: a valid name, at most 16 valid boundaries, matching any pins, no machine of that name in the mesh (unless the invite replaces it), no other waiting request with that name. A refusal here does not use up the ticket.
7. It answers `pending` with a **6-digit code**, derived from the ticket's secret and both node ids. The new machine computes the code itself and refuses to go on if the owner's differs. Both screens show the code. The person compares them: that is the check that the machine asking is the machine in front of them.

### 10.3 Approval

1. The owner node lists waiting requests (`tearmesh mesh pending`; the menu shows them on top of the Mesh screen and opens the approval form by itself). Each shows name, node id, boundaries asked for, the code, whether the machine is still waiting or away, and the contested warning.
2. The owner approves with `tearmesh mesh approve NAME [--host B]… [--add-boundary B]… [--grant FROM:TO:CATEGORIES]…` or by ticking boxes in the menu. One signed version then: adds any new boundary the machine asked for and the owner accepted; adds the machine hosting the boundaries the owner picked (by default those it asked for that the mesh has; the owner may pick any boundary of the mesh, or fewer); adds the grants. The owner cannot change the machine's name or node id.
3. `--yes` skips the question "Does the new machine show the same code?" and is refused for a contested request.
4. When the owner node adopts a version that lists a waiting machine, it sends that machine the file. The invite is deleted only once the file was written to that machine's connection; if the write fails it stays approved, and the machine gets the file when it joins again with the same ticket. **LIMIT** (`limit/approved-frame-written`): written means handed to the connection, not confirmed by the new machine. A connection that dies in that instant can still lose the file; the machine is then listed without holding the file, and an owner removes and invites it again, or the current file is applied on it by hand. A machine that was away gets the file when it joins again with the same ticket (`NAME is away; it gets the file when it runs join again with the same ticket`).
5. The new machine adopts the file only if it is signed by an owner key listed in it, is for the ticket's mesh, its owner key set hashes to what the ticket named (if not: `the file's owner keys aren't the ones the ticket named: the mesh's owner keys changed after this ticket was made; ask the owner node for a new ticket`), and it lists this machine with this name and node id. It then prints `joined; mesh version N`.
6. `tearmesh mesh reject NAME` refuses one waiting request; `mesh reject --all` voids every invite.
7. After joining through `install --join`, install creates the OS users for boundaries the owner had this machine host that have no user yet.
8. A dissolved mesh voids all its invites.

**LIMITS.**
- `limit/unused-tickets`: an unused ticket cannot be listed, and one cannot be voided by itself; `reject --all` voids all, including approved ones whose machine has not come back for its file.
- `limit/code-formats`: the code is printed as `123 456` by the menu and by `install --join`, and as `code 123456` by `tearmesh join`.
- `limit/ticket-grace`: the new machine accepts a ticket up to an hour past its expiry, but the owner node has dropped an unclaimed invite by then, so the person sees "no open invite matches" instead of "expired".

## 11. Leaving, removal, dissolving

| What happens | Who starts it | Result on the machine |
|---|---|---|
| **Removed** | an owner signs "remove machine" | The machine is refused on every protocol but sync. On its next sync it receives the versions up to the one that removed it (the **farewell rule**), nothing else, and leaves: its logs move to `boundaries-<mesh id>/`, `mesh-id` goes, and it is free to create or join any mesh, this one included (through a new invite). |
| **Leaves by itself** | `tearmesh mesh leave`, the menu's Leave, `tearmesh uninstall` | The machine first tells every machine it can reach that it is leaving (they show "says it left"; the owner node's menu offers to sign its removal). Then it leaves exactly as a removed machine does, and can create or join a mesh. A machine that only holds the `mesh-id` an earlier `mesh reset` left behind is freed the same way. With neither a mesh nor that file: `this machine isn't in a mesh`. It stays listed in the membership file until an owner removes it. |
| **Dissolved** | an owner signs "dissolve" | A last, closed version with no machines; nothing can follow it. The owner node (`mesh dissolve`, or the menu's dissolve) hands it to every machine it reaches and says how many; the rest fetch it on their next sync (sync stays open to every machine of the last open version for this). Each machine shows the mesh as dissolved. When it next creates, joins or leaves, the logs move aside and the mesh id is added to `dissolved`: that mesh is never adopted again. |
| **Reset** | `tearmesh mesh reset` | The machine forgets its membership file but keeps its logs bound to the mesh id: only a file for the same mesh can be applied next. This is the way back after every owner key was lost and the mesh was re-founded with the same id (`mesh new --id`). It is not a way to leave, except on a dissolved mesh, where it forgets the mesh as leave does. |

1. The farewell rule gives a removed machine no mail, no addresses and no later versions. **LIMIT** (`limit/farewell-history`): a machine can hand out only versions it has stored, so one that joined after the removal cannot tell the removed machine; any older member can.
2. A removal that this machine's own admin applies by hand (`mesh apply`) never makes it leave; only versions received by sync from a member do.
3. Logs are never deleted by any of these. A second leave of the same mesh makes `boundaries-<mesh id>.1`, and so on.
4. A leave that is interrupted is finished when the daemon next starts.
5. An owner node can leave only from the command line, and uninstalling one (when an owner key of the mesh is found in the home directory of the user who runs it) prints what that means: afterwards only the other owner keys can sign.
6. While a machine leaves, nothing can open one of its boundary logs: a sync or a post under way finishes before the logs are moved aside, or is refused because the machine is no longer in the mesh.
7. When a machine stops being in a mesh in any way (it leaves, it is removed, the mesh is dissolved), every ticket it made and every join request waiting on it is dropped.
8. A machine that left by itself stays listed until an owner removes it. While it is listed, the owner node refuses its attempt to join with a new ticket (making the ticket works) and says what to do: ``this node is already in the mesh as NAME: if it left, on the owner node run `tearmesh mesh remove NAME` and join again, or apply the current membership file on it with `tearmesh mesh apply` ``. **LIMIT** (`limit/rejoin-needs-removal`): there is no one-step way back in for a machine that left and is still listed.
9. If the `mesh-id` file a reset left behind does not hold a mesh id, `mesh leave` fails with `<state dir>/mesh-id doesn't hold a mesh id ("<contents>"); delete that file and leave again`.
10. **LIMIT** (`limit/leave-rename-fails`): if moving the logs aside fails (a file another program holds open, mostly on Windows), the leave fails but its mark that a leave is under way stays. The daemon carries on in the mesh until it restarts; it then finishes the leave, or refuses to start if the move fails again.

## 12. Permissions

**DECIDED 2026-11-12:** permissions are three categories, each in two directions, per pair of machines, and they are enforced in code, never by a model.

**DECIDED 2026-11-26** (Maxwell: the fewest channels, with configuration doing the rest, and no feature made for one kind of request). Everything one machine does on another goes through one of three **channels**. Each channel is one category of grant. What a channel can cause on the other machine is decided there, by that machine's configuration. The menu and this section say **mail** for the first channel; the membership file keeps the word `converse`, and the commands accept both.

| Channel | Word in the file | Carries | What it can cause there is decided by |
|---|---|---|---|
| **mail** | `converse` | letters to mailboxes: notes, questions, tasks, alerts, progress, answers | the mailbox's table in that machine's `mailboxes.toml` (section 18.5): what answers, for which senders, within which limits; or the live session that holds the mailbox |
| **tools** | `tools` | calls to the MCP servers that machine shares | the server, and the owner's approval of its tool list (section 15) |
| **shell** | `shell` | an SSH connection | the SSH login on that machine (section 17) |

A fourth thing travels to every machine and is no channel between two of them: the **membership file**, which only an owner key can change. It holds the grants, the approvals, the settings and the release the mesh should run.

1. An action from A to B needs the grant `A → B` for its channel. Both daemons check the same grant, so it cannot be half on. The menu shows, for this machine and another, what each may do on the other (**G** on its row, section 19.3) and signs everything changed at once.
2. **Deny by default.** No grant, no action. A machine's mail to itself is always allowed, so a grant from a machine to itself is refused (`a machine needs no grant to itself`); one signed by 0.4.0 is harmless and can be revoked.
3. `*` stands for any machine on either side of a grant, except in a grant that includes `shell`. `* → *` is a grant for **all machines**, also those that join later; the menu has a row for it (section 19.3).
4. A new mesh starts with `* → *` mail. To keep a pair from mailing each other, revoke that grant and grant the pairs that should. Revoking a pair alone does not help while the `*` grant stands; the revoke says so. There are no deny entries.
5. Grants never cross boundaries: an action also needs both machines to host the session's boundary.
6. What each channel gates:
   - **mail** decides **delivery**, not storage. A letter from a machine with no mail grant to this one is still stored and synced, but not shown, not announced and not screened. Revoking a grant hides that machine's earlier letters; granting again shows them.
   - **tools** lets the caller open tool streams to the target's shared servers. Unless the mesh setting `tools_sharing` is `free`, each server also needs the owner's approval (section 15).
   - **shell** lets the caller reach the target's sshd (section 17).
7. An owner node usually has shell on other machines and gives none on itself. In the Permissions box of an owner node's menu, turning on shell for another machine on this one gets a warning (`Careful: X will be able to drive this machine, which holds an owner key.`).

### 12.1 What each use goes through

No use has a channel or a feature of its own. A use is a channel plus configuration on the machine it reaches.

| Use | Channel | Configuration that makes it work |
|---|---|---|
| see which machines and agents exist and what each is doing | mail | bios and status records, read without waking anyone (`list_nodes`, `node_status`) |
| leave a note; one session writes to another | mail | none |
| ask everyone | mail to `*` (the board) | none; a post wakes no one, agents read the board when they look |
| an agent asks the person; an alert | mail | the person's mailbox: `admin` on a machine, or the gateway's mailbox for their Claude apps. A mailbox whose command sends a push message turns a letter into a notification. A script sends with `tearmesh post`. |
| ask about a machine or a project | mail | a mailbox whose command starts an agent that can only read |
| give a task | mail | a mailbox whose command starts an agent that may act, opened only to the senders that may give tasks (`wake_on`, `from`) |
| reach a session that is working | mail | the session holds a mailbox (the plugin), or a mailbox whose command hands the letter to the running session |
| long work with progress | mail | claims (section 13) |
| fetch a file, use a device or a database | tools | an MCP server shared from that machine and approved by the owner |
| drive a machine: run anything, copy files, install, restart | shell | an SSH login there |
| update tear-mesh everywhere | the membership file | the release the owner names (section 22.3) |
| run the mesh: invite, approve, grant, remove | the membership file | an owner key |
| context from the person's Claude apps to a machine | mail | agents write to the gateway's mailbox; a Claude session reads it when the person next opens one. Claude cannot be woken. |

Claude's apps reach the mesh through the gateway, which carries mail only (`open/gateway-channels`). What they can cause is therefore what the mailboxes they may write to are configured to do.

**PROPOSED** (2026-11-12, not agreed, not built):
- `proposed/deny-all-default`: a new mesh starts with no grants at all (no `* → *` converse), and shell listen is off for every new machine until switched on.
- `proposed/taint`: data that came from a less trusted source keeps a mark that limits where it may flow.
- `proposed/human-approval`: some actions wait for a person to approve each time.

**OPEN** questions about this model are listed in section 27.

## 13. Mail

1. **Addresses.** `mailbox@machine`: the machine (node) and the agent on it. The mailbox is any valid name; nothing registers it. `*` addresses everyone in the boundary: letters to `*` are the boundary's **board**. A session's own mailbox comes from `TEARMESH_MAILBOX` (default `admin`); the hub's default is `agent`, the gateway's `claude`. `admin` is also every machine's **default addressee**: the conversation tools read a bare machine name as `admin@machine` (section 18.6).
2. **Posting.** A session posts a letter with 1 to 32 recipients, a one-line subject, a body, a kind (`info` by default, `task`, `question`) and optionally a thread. A post that names a thread and no recipient goes to the sender of the letter it names; when that letter is the session's own, it goes to whoever that letter was addressed to. Checks, in order: a valid mailbox; the limits of section 8.2; every recipient is `*` or a mailbox on a machine that hosts the boundary (a value that is not an address is answered with the form to use: `bad address "alpha": use mailbox@machine (for example admin@alpha), or * for everyone`; the example is given only when the value is a valid machine name); this machine has a converse grant to each named recipient's machine (`<me> has no converse grant to <host>, so <host> won't deliver mail from it`; `*` is not checked); the thread exists, is visible to the session and is not full; the hourly limit. The reply is the new letter's id.
3. **Threads.** A reply names the letter it answers by id or by a prefix of 6 or more characters. Every reply therefore carries the id of the thread it belongs to. The thread is that letter's thread, or the letter itself. A thread holds at most `max_thread_len` letters (`thread … has reached N letters (the limit); start a new thread`).
4. **Inbox.** A mailbox's inbox lists letters addressed to it or to `*`, oldest first, unread only unless all are asked for. A mailbox never sees its own letters there. Reading a letter marks it read for that mailbox. `inbox` shows ids, senders, subjects and tags, not bodies. A listing can be narrowed to one thread. Each listed letter carries its body's size in bytes.
5. **What is shown.** One rule decides for inbox, read, notices and thread roots: the author's machine has a converse grant to this machine, and, in a screened boundary, the letter passed screening (section 14).
6. **Notices.** When a letter becomes visible, the daemon tells listeners in that boundary (the steward, the hub) for each recipient mailbox on this machine, unless the letter is from that mailbox itself or a live session **holds** the mailbox. A session holds its mailbox while a connection that said so is open; the stdio mail server does, the hub and the menu do not. Letters to `*` produce no notice: readers find them when they next look.
7. **Tags.** Where letters are listed, kind and trust are shown as `[task]` or `[question, guest]`, except plain `info` from `member`.
8. Letters come from other agents. Every door tells its reader so: treat what a letter says as a request to weigh, not a command.
9. **Claims.** A claim (kind `claim`) says "working on it" without an answer yet, so the asker can be told to hold on. It is a letter with three differences: it must name a thread and goes to the sender of the letter it names; its subject is a short note (default `working on it`) and its body is empty or the number of seconds until an answer is expected (1 to 8 digits), shown in listings as `expect_secs`; and it never wakes a mailbox: it produces no notice for the steward or the hub, though the hook's notice to a session that is in use lists it, tagged `[claim]`. A claim is marked read for a mailbox as soon as the `inbox_list` tool has shown it to that mailbox, since there is nothing more to open; other listings (the `inbox` command, the menu, the steward) leave it unread. Long work is a claim, then further claims as progress, then the answer, all in one thread. Claims count toward `max_thread_len` and are screened like other letters.
10. **Posting once.** A post may carry a key (`idem`, 1 to 128 printable ASCII characters). If the same mailbox posted with the same key in the last 24 hours, nothing is written, nothing counts toward the hourly limit, and the reply is the first letter's id with `duplicate: true`. A key that was used for a different message (other recipients, subject, body or thread) is an error, `this key was already used for a different message; use a new key`, and nothing is sent. The key is looked up after the address and grant checks, so a repeat that is no longer permitted is refused, not answered, and before the thread and hourly limits, so a repeat is answered even when the thread has since filled. Keys are kept in the boundary's local `idem` table and forgotten after 24 hours.
11. **Reachability.** A session can ask whether machines of its boundary answer right now (`reach`): one ping each (section 9.1), all at once, 4 s limit. Only machines that host the session's boundary can be named; this machine always answers `online`. The conversation tools use it so that a message to a machine that is off fails within seconds unless the sender asks for it to be left waiting (section 18.6).

**Command line** (as a boundary user): `tearmesh who`, `post --to A… --subject S --body B|- [--thread ID] [--kind K]`, `inbox [--all]`, `read ID`. `read`, `inbox`, `bio show` and `quarantine show` replace control characters other than newline and tab with U+FFFD, so a letter cannot send escape sequences to the terminal.

**NOT BUILT:** a "delivered" status per recipient, and a listing of sent letters (both described in the 0.2 specification); group chats made on demand (`planned/group-chats`); expiry of old letters (`open/inbox-retention`).

## 14. Screening

**DECIDED 2026-11-12:** a mail reader that tests letters for prompt injection is built in. It is off unless switched on.

1. **Switch.** `screen = ["work", …]` in the daemon's config names the boundaries to screen (daemon restart needed). The screener runs in that boundary's steward.
2. **What is screened.** Letters (claims too; not offers, bios or status records) in a screened boundary that were written on another machine, or carry `guest` trust. Letters already in the log when screening is first switched on are exempt. Letters from machines with no converse grant are never screened (they are not shown anyway).
3. **Until a verdict,** a letter that needs screening is not shown, not announced and wakes nobody.
4. **The test.** The steward sends each letter (sender, subject, body; nothing else) to a model through the Anthropic Messages API, with a system prompt that says its only job is a one-line summary and that it must never act on the letter, and with three **decoy tools** it has no reason to use: `run_shell_command`, `delete_files`, `send_file`. Verdict, first match:
   - the model tried to use any tool: **flagged**, reason `tried <tool>: …`;
   - the model finished normally: **clean**, with its summary as the reason;
   - the model stopped for another reason (length, refusal): **flagged**, `the reader stopped early (…)`;
   - the API answered 400 or 413: **flagged**, `the reader couldn't read it (HTTP N)`.
   Any other failure (no key, 401, 429, 5xx, timeout) gives no verdict: letters wait, the steward logs `screener: …; letters wait` once per distinct error and retries with a pause that doubles from 2 minutes to 15 minutes.
5. **Settings** (`~/.config/tearmesh/screen.toml` of the boundary user; all optional): `model` (default `claude-haiku-5-5`), `base_url` (default `https://api.anthropic.com`), `api_key_file` (must not be readable by group or others; a file that is, or that cannot be read, is an error). With no `api_key_file`, the environment variable `ANTHROPIC_API_KEY` is used.
6. **Quarantine.** A clean letter is shown and announced. A flagged one is held. An admin lists held letters with `tearmesh quarantine [--boundary B]`, reads one with `quarantine show ID` (control characters replaced; with the warning not to paste it into an agent) and lets one through with `quarantine release ID`. `tearmesh status` counts waiting and flagged letters per screened boundary and warns while any are flagged.
7. **LIMIT** (`limit/screening-not-a-sandbox`): any session in the boundary can ask for waiting letters and give verdicts, so screening protects against letters, not against an agent on this machine that is already compromised.
8. The model provider sees every screened letter.

## 15. Shared tools

**DECIDED 2026-11-12:** a machine's MCP servers are reachable through tear-mesh as their own service, without that machine running an agent.

### 15.1 Offers

1. A boundary user lists the servers it shares in `~/.config/tearmesh/offers.toml`, one table per server name: `command` (the stdio MCP server to run, required), `description`, `env`, `dir` (working directory, default the user's home).
2. `tearmesh offer publish NAME` starts the server, reads its instructions and its tool list (30 s limit per answer; paged tool lists are refused), and posts a signed **offer** entry to the boundary: server name, description, the server's own info, instructions, the tools sorted by name, the pin, and, when the command is a file, the blake3 hash of that file (the machine's own claim). It prints the pin and what the owner runs next.
3. **The pin** is the blake3 hash of the instructions and the exact tool objects (key order and tool order do not matter). The daemon always computes it itself. Description, server info and executable hash are not part of it.
4. `tearmesh offer withdraw NAME` posts a withdrawal; nothing is callable under a withdrawn name. The newest offer per machine and server name counts.

### 15.2 Approval

1. With the mesh setting `tools_sharing = "approval"` (default), a server is callable only after the owner approves it: `tearmesh mesh approve-offer MACHINE BOUNDARY SERVER [--tools a,b]`, or **O** in the owner's menu. The approval stores the pin, computed over the approved tools only when a subset is given.
2. With `tools_sharing = "free"`, any published offer is callable by machines with a tools grant. An approval that exists still applies its pin and subset.
3. An offer is in one of four states: `approved`, `changed since approval`, `free`, `pending approval`.

### 15.3 Calling

1. A caller's session opens a tool stream to `machine/server` (`tearmesh mcp --remote machine/server`, or the hub's `call_tool`). Both daemons check, in order: both machines host the boundary; the caller is not the target; the caller has a `tools` grant to the target; the approval exists (unless sharing is free); the offer exists and is not withdrawn; the approval's pin still matches the offer (`… changed since the owner approved it; it needs approving again`).
2. The target's daemon asks that boundary's steward to start the server (`no steward is serving boundary … on …` after 15 s without one). The steward runs one server process per stream, as the boundary user; the daemon never runs user code.
3. **The filter.** Both daemons sit between the caller's session and the server and pass only:
   - from the caller: `initialize`, `tools/list`, `tools/call`, `ping` and the notifications `initialized` and `cancelled`. Any other request is answered with an error (`… isn't allowed over tear-mesh`); any other notification, and any response, is dropped. A call to a tool outside the approved set is answered `tool "x" isn't approved for use over tear-mesh`. Batches, odd request ids and reused ids close the stream.
   - from the server: answers to requests still outstanding; the notifications `progress`, `cancelled` and `tools/list_changed`, rebuilt without free text. Requests from the server to the client (sampling, elicitation, roots) are refused.
   - The `initialize` answer must carry exactly the offer's instructions, and its capabilities are replaced by "tools only". The `tools/list` answer must match the pin; the list shown to the caller is cut to the approved tools. A mismatch closes the stream (`the server's instructions differ from its offer`, `the server's tools differ from its offer`).
4. Limits: 4 MiB per line; a stream idle for 30 minutes is closed; at most 8 open streams per peer, tools and shells together.
5. Tool results are the server's own text and pass unchanged. **LIMIT** (`limit/server-info-unpinned`): the server's name and version in the `initialize` answer are not pinned.

## 16. Bios

Each machine can publish one bio per boundary: free text saying what it is and what it offers, at most 16 KiB. `tearmesh bio template` prints a starter in YAML with A2A Agent Card field names; `tearmesh bio set FILE` publishes it (as a boundary user; an admin adds `--boundary B` and the bio carries `admin` trust); `tearmesh bio show [MACHINE]` prints bios. Agents read bios through `who`. A bio is signed by its machine, which proves who wrote it, not that it is true. `who` shows a machine's bio only if that machine may mail this one (converse grant), and its offers only if this machine has a tools grant to it.

### 16.1 Status records

A bio describes a machine. A **status record** describes one agent (one mailbox) and is what `list_nodes` and `node_status` read, without waking any model.

1. A record is an entry of kind `status`, addressed to `*`, sent from the agent's own address. Its subject is the agent's current task in one line (may be empty). Its body is a JSON object, at most 4 KiB, with the optional keys `about` (what the agent is, which project or repository it sits on, what it can answer; a few lines) and `pending_questions` (how many questions wait for the owner; a whole number). Other keys are refused when the record is written.
2. The newest record per address counts. Setting some fields keeps the others: the daemon merges the change into the mailbox's own newest record and writes the whole record again. An empty `about` or task clears that field. Status records are not screened (like bios).
3. An agent sets it with the `set_status` tool (section 18.6), a script or an orchestrator with `tearmesh agent status [--about TEXT] [--task TEXT] [--pending N]` (as a boundary user; the mailbox is `TEARMESH_MAILBOX`).
4. Like a bio, a record is the writing machine's claim, is shown only where that machine may mail this one, and is information, not instruction.
5. **Known agents.** The agents known on a machine are the addresses there that have a status record, have sent a letter, or (on this machine) are held by a live session, plus `admin`. The conversation tools refuse to send to an agent that is not known (section 18.6). Each time it connects to the daemon, the steward writes a status record for each mailbox in its `mailboxes.toml` that has none, so that agents it can wake are known before they have ever spoken (section 18.5).

## 17. Shell

1. A shell stream is a plain byte pipe from the caller to the target machine's own sshd on `127.0.0.1:<shell_port>` (config, default 22). Both daemons require both machines to host the boundary and a `shell` grant from caller to target.
2. tear-mesh does not see inside SSH. Who logs in is decided by the target's sshd and `authorized_keys`. A shell grant means "this machine may reach that machine's sshd", nothing finer. Give each boundary user its own SSH key.
3. Use: `ssh -o ProxyCommand='tearmesh shell-proxy %h' user@machine`; the menu's Shell key and the hub's shell tools do the same. A session uses its own boundary; an admin with no boundary names one (`shell-proxy MACHINE --boundary B`; the menu does this by itself).
4. A shell stream ends when the mesh stops allowing it. **LIMIT** (`limit/shell-streams`): shell streams have no idle timeout and share the 8-per-peer limit with tool streams, so many long ssh sessions from one machine can block its tool calls.

## 18. Doors for agents

An agent reaches the mesh through one of five doors. All of them are plain clients of the daemon's local socket, so the daemon applies the same boundary and permission checks whichever door is used. The mail server, the hub and the gateway serve the same **conversation tools** (section 18.6), with the same names and behaviour.

| Door | Command | For | Mailbox |
|---|---|---|---|
| mail server | `tearmesh mcp` | one agent session (the Claude Code plugin starts it) | `TEARMESH_MAILBOX`, default `admin`; **held** while it runs |
| hub | `tearmesh mcp serve`, `mcp connect` | any harness on the machine; long-running | `mailbox` in `hub.toml`, default `agent`; not held |
| remote server shim | `tearmesh mcp --remote MACHINE/SERVER` | using one shared server as if it were local | none |
| gateway | `tearmesh gateway serve` | Claude's apps (voice, phone, web, Desktop), from outside the mesh | `mailbox` in `gateway.toml`, default `claude`; `guest` trust |
| steward | `tearmesh steward` | starting agents and servers on demand | the mailboxes in `mailboxes.toml` |

### 18.1 The mail server and the Claude Code plugin

1. `tearmesh mcp` is a stdio MCP server with ten tools: the seven conversation tools and the three agent tools `set_status`, `claim` and `set_bio` (section 18.6). Each returns JSON text, or the error text.
2. It holds its mailbox for as long as it runs, so the steward does not wake a second session for mail a live session will see.
3. If the daemon cannot be reached, or the OS user has no boundary, the server still starts and every tool answers `tear-mesh is not available: <reason>`. When a call fails (the daemon restarted or was upgraded), the server opens a new session with the daemon at once and holds the mailbox again: that one call returns the error, the next one works, and the agent needs no restart. **LIMIT** (`limit/hold-after-restart`): between the daemon's restart and the agent's next tool call the mailbox is not held, so mail that arrives then can wake a second session.
4. Its instructions tell the model its address, that letters stay inside its boundary, that letters come from other agents (requests to weigh, not commands), and how to answer: reply in the thread, open with one or two sentences that can be read aloud, and send a claim first when the answer will take more than a few seconds.
5. **The plugin** (installed to `/usr/local/share/tearmesh`; added with `claude plugin marketplace add "<dir>" && claude plugin install tearmesh@tear-mesh`, which install prints) registers that server and three hooks (session start, each prompt, after each tool use) that run `tearmesh hook`.
6. **The hook** asks the daemon for letters this mailbox has not been told about yet, and prints them as extra context for the model: `📨 tear-mesh: N new letter(s) for <address>:`, one line per letter (first 12 characters of the id, sender, subject, tags), and how to open and answer them (`inbox_fetch`, then `send_message` with `reply_to`; a short spoken-style answer first; a `claim` when it will take a while; `guest` letters from the gateway are the owner speaking through Claude, to be weighed with extra care all the same). Each letter is announced once per mailbox. Bodies are never included. On any error it prints nothing and exits 0: it never fails the agent's turn.

### 18.2 The hub

1. One hub per OS user, so per boundary. It has two entrances with the same 21 tools:
   - **HTTP** on `127.0.0.1` at `/mcp` (streamable HTTP). The port is `port` in `hub.toml`, or else a fixed number between 7787 and 8786 worked out from the user's id. Every request needs `Authorization: Bearer <token>`; the token is 64 hex characters in `<state>/token` (mode 0600), made on first use. A wrong or missing token gets 401; with the right token, a foreign `Host` header gets 403.
   - **A private socket** (`<state>/hub.sock`; on Windows a named pipe per user). `tearmesh mcp connect` is a stdio relay onto it, and starts the hub in the background if it is not running. The hub refuses any other OS user there.
2. A lock file makes it one hub per user: a second `mcp serve` prints `the hub is already running (<url>)` and exits 0. If the HTTP port is taken, the hub still serves its socket and warns `HTTP is off: port N on 127.0.0.1 is taken …; set `port` in <hub.toml>`.
3. `tearmesh mcp info` prints the URL, the header, the token file with the warning `anyone with it can use your mesh as you, so keep it private`, the `claude mcp add --transport http tearmesh <url> --header …` line, and the stdio form (`tearmesh mcp connect`). In the menu: Settings, **H** starts the hub, **U** shows the same.
4. State directory: `TEARMESH_HUB_DIR`, else `~/.local/state/tearmesh/hub` (Windows `%LOCALAPPDATA%\tearmesh\hub`); mode 0700. It holds `hub.lock`, `token`, `hub.sock`, `hub.log`, `known_hosts` and `chats/<id>.log`.
5. `hub.toml` (`TEARMESH_HUB_CONFIG`, else `~/.config/tearmesh/hub.toml`; optional; unknown keys refused): `port`, `mailbox` (default `agent`), and `[harness.<name>]` tables with `command` (required) and `dir` (default the home directory). With no harness configured and `claude` on the hub's PATH, there is one harness `claude` = `["claude", "-p", "{prompt}"]`.
6. **Tools.**

   | Tool | Does |
   |---|---|
   | the seven conversation tools | section 18.6 |
   | `set_status`, `claim`, `set_bio` | the agent tools, section 18.6 |
   | `offers()` | shared servers in the boundary with their approval state |
   | `remote_tools(machine, server)` | the tool list of a shared server |
   | `call_tool(machine, server, tool, arguments?)` | calls a tool of a shared server; 120 s limit for the whole exchange |
   | `shell_exec(machine, command, user?, timeout_secs?)` | runs one command over ssh (default 60 s, at most 3600); returns `{exit_code, stdout, stderr, truncated}` with at most 256 KiB of each stream. A command that reaches the cap on either stream is stopped at once, and what was read is returned with `truncated: true` and `exit_code` null. At the timeout the error is `stopped after N s`. |
   | `shell_open(machine, user?, shell?)` | opens an interactive shell; returns `{id}`. At most 16 open. |
   | `shell_send(id, input)`, `shell_read(id, wait_ms?)`, `shell_close(id)` | write to it; take its output so far (the newest 256 KiB are kept); end it |
   | `harnesses()` | the configured harness names |
   | `start_chat(harness, prompt)` | starts a harness with the prompt (at most 64 KiB, not starting with `-`) as the hub's mailbox; returns `{id, harness}`. At most 16 running. |
   | `chat_status(id)` | `running`, `{exited: code}` or `finished earlier`, with the last 256 KiB of its output |

7. Shell tools run the system `ssh` through `tearmesh shell-proxy` with batch mode on, host keys accepted on first use into the hub's own `known_hosts`, and the OS user's own SSH keys. Open shells live in the hub, so they survive the client that opened them.
8. **New mail is pushed.** For each client session the hub sends an MCP logging notification `{"new_mail": {id, from, subject}}` when a letter arrives for the hub's mailbox. Letters to `*` give no push; `board_read` finds them. Nothing depends on the push: `inbox_list` with `wait_secs` works without it.
9. Limits: 128 connections over both entrances; a line from another machine's server is at most 4 MiB; the first line on the private socket is at most 1 MiB and must arrive within 30 s.
10. **LIMITS.** `limit/hub-token-once`: the hub reads its token once, so a replaced token file takes effect at the next hub start. `limit/hub-info-url`: `mcp info` prints the URL even when HTTP is off. `limit/hub-chats-outlive`: chats keep running when the hub stops. `limit/hub-bearer-is-everything`: whoever holds the token can use every tool, shells included.

### 18.3 The remote server shim

`tearmesh mcp --remote MACHINE/SERVER` connects standard input and output to a tool stream (section 15.3). An MCP client configured with that command sees the shared server as a local stdio server. A refusal (no grant, not approved, changed since approval, no steward) ends the process with the reason.

### 18.4 The gateway

It replaces the connector of 0.2 and 0.3 (`tearmesh mcp --http`, an unauthenticated MCP server on a Unix socket with the extra tools `repo_status` and `read_file`), which is removed: a question about a repository is now a message to the agent that sits on it.

A **gateway** is an ordinary member machine on which one more process runs: `tearmesh gateway serve`, an MCP server for Claude's custom connectors. Claude's apps (voice, phone, web, Desktop) reach it from Anthropic's servers over public HTTPS; it serves the seven conversation tools of section 18.6 and nothing else. Linux only. The same binary and the same daemon as everywhere; the role is switched on by the file `/etc/tearmesh/gateway.toml`.

1. **A process of its own, as a guest user.** The gateway is not part of the daemon. It runs as an OS user of its own, `tm-<boundary>-gw`, which `gateway setup` creates and lists under `[guests]` in the daemon's config with its boundary and its mailbox (section 21.1). It is a client of the local socket, and for a guest user the daemon itself, not the gateway, sets the limits: the session's mailbox is the configured one, its trust is `guest`, and it is answered six requests only: `hello`, `who`, `reach`, `post` (a letter), `inbox` and `read`. `read` and a thread listing give it only letters addressed to its mailbox or to the board, or sent by it as a guest (a member's letter from a mailbox of the same name is not its own), and it can post into a thread only when the letter that thread names is one of those. So the part that faces the internet cannot read the node key, the membership file's history, another boundary's log or the mail between the boundary's agents, and a gateway that is taken over can do what a signed-in Claude can do and nothing more. It is not the boundary's user: the boundary's agents cannot read or change the gateway's state, and the gateway cannot read theirs. `gateway serve` refuses to start unless the daemon says its session is a guest. The user name must fit the system's limit (32 characters on Linux), so a gateway's boundary name is at most 26 characters. It reaches exactly one boundary: the one named in its config. Which boundaries the gateway machine hosts at all is the owner's signed decision, like for any machine.
2. **Identity.** Its letters come from `claude@<gateway machine>` (the mailbox is `mailbox` in the config) and carry `guest` trust: receiving agents see that the message came from outside the mesh, from the owner speaking through Claude. Guest letters wake a mailbox only if its `wake_on` lists `guest`, and are always screened in a screened boundary. Every sign-in shares this one mailbox.
3. **What the gateway identity may do** is what the membership file grants its machine. It needs `converse` and nothing else; it holds no owner key and should be given no `tools` or `shell` grant. Whatever the machine is granted, the daemon's limits of point 1 hold for the gateway's user: a `tools` or `shell` grant reaches the boundary's own user on that machine, never the gateway. An owner cuts it off at once by revoking its machine's converse grants or removing the machine.
4. **Config** `/etc/tearmesh/gateway.toml` (`TEARMESH_GATEWAY_CONFIG`; root-owned, no secrets; unknown keys refused):

   | Key | Default | Meaning |
   |---|---|---|
   | `boundary` | required | the boundary the gateway serves; the gateway's own user `tm-<boundary>-gw` runs the service |
   | `url` | required | the connector URL exactly as it is entered in Claude, path included, for example `https://mesh.example.com/mcp`. Must be `https`, except for `http://127.0.0.1` and `http://localhost` (tests). |
   | `port` | 8787 | the gateway listens on `127.0.0.1:<port>`, plain HTTP; the tunnel adds TLS |
   | `mailbox` | `claude` | the mailbox its letters come from |
   | `calls_per_hour` | 600 | tool calls per sign-in per hour |

5. **State** `/var/lib/tearmesh-gateway/` (`TEARMESH_GATEWAY_DIR`; mode 0700, owned by the gateway's user): `gateway.db` (SQLite: the key that seals client ids, sign-ins, hashes of tokens and of the passphrase; no token or passphrase in clear) and `audit.log`.
6. **Endpoints.** Everything else is answered 404.

   | Path | Purpose |
   |---|---|
   | the path of `url` (`/mcp`) | MCP over Streamable HTTP (not the older HTTP+SSE transport). Needs a bearer token. |
   | `/.well-known/oauth-protected-resource` and the same with the path of `url` appended | protected resource metadata (RFC 9728): `resource` is `url` exactly; `authorization_servers` is the origin of `url` |
   | `/.well-known/oauth-authorization-server` | authorization server metadata (RFC 8414) |
   | `/register` | dynamic client registration (RFC 7591) |
   | `/authorize` | the sign-in page (GET) and its form (POST) |
   | `/token` | codes and refresh tokens for access tokens; form-encoded bodies |
   | `/health` | `{"ok": true, "version": …, "mesh": true or false}`: `mesh` says whether the local daemon answers. No authentication, no other detail. |

7. **Sign-in (OAuth 2.1).**
   - An MCP request with no valid token is answered `401` with `WWW-Authenticate: Bearer resource_metadata="<origin>/.well-known/oauth-protected-resource<path>"`. Tokens are read from the `Authorization` header only, never from the URL.
   - **Registration is open**, as Claude needs, so it gives nothing by itself. A client may register only redirect URIs that are `https://claude.ai/api/mcp/auth_callback`, `https://claude.com/api/mcp/auth_callback`, or `http://localhost` or `http://127.0.0.1` on any port (Claude Code, the MCP Inspector). Anything else is refused. Nothing is stored for a registration: the client id it returns carries the client's name (at most 64 printable characters) and its redirect URIs (at most 5, each at most 255 bytes), sealed with a key only the gateway holds; a registration whose client id would be longer than 1,500 bytes is refused. A client id the gateway did not seal is refused at the sign-in page and, with `401 invalid_client`, at `/token`. So registering costs the gateway nothing, has no limit, and cannot be used to keep others from registering; a client id stays good for as long as the gateway's state exists.
   - **The lock is the passphrase.** The sign-in page names the client and the place the browser returns to, and asks for the gateway passphrase: six random words made by the gateway (`gateway setup`, `gateway passphrase`), never chosen by a person, shown once, of which the gateway keeps only a salted hash. Six words are about 77 bits, far beyond what guessing over the network can reach, so there is **no lockout**: one would let anyone who knows the URL keep the owner out. Every wrong try is written to the audit log. The page says, above the field, that anyone can send a link to this page and that the passphrase is to be typed only by someone who has just added the connector in Claude themselves; it shows the client's name as the client's own claim, and the host the browser returns to. Capitals and the spacing or punctuation between the words do not matter. The page cannot be framed.
   - Every authorization request must use PKCE with `S256`; the redirect URI must be one the client registered, compared exactly (for the loopback hosts the port is ignored). A code lasts 60 seconds and works once. If the request names a `resource`, it must be `url`, compared in canonical form (lower-case scheme and host, no default port, no trailing slash). A code is used up by any attempt to redeem it; a code presented twice ends the sign-in it produced.
   - An access token lasts 1 hour. A refresh token lasts 60 days and is replaced on every use; an access token issued earlier stays good until its own hour is up. Using a refresh token again within 60 seconds of its replacement is only refused (two of Claude's servers may refresh at the same moment); later than that, it ends the sign-in. The server metadata lists the scope `offline_access`, which is what makes Claude ask for a refresh token; scopes mean nothing else here. At most 20 sign-ins are kept: a new one beyond that ends the one unused for longest.
8. **Sign-ins** (called *grants* by the commands; not the membership file's grants). Each completed sign-in is one record: an id, the client's name, when it was made and last used, how many calls. `tearmesh gateway grants` lists them, `tearmesh gateway revoke ID` (or `--all`) deletes one with its tokens, `tearmesh gateway passphrase` replaces the passphrase (`--revoke-all` also ends every sign-in). Ending all sign-ins also ends those under way: codes not yet redeemed. All take effect at the next request: the gateway reads its database on every request.
9. **Limits.** A request body is at most 1 MiB (`413`), 64 KiB on the sign-in paths; request headers must arrive within 10 s, a sign-in body within 5 s and an MCP body within 30 s (`408`), and on the MCP path the token is checked before the body is read; at most 512 connections at once, and at most 32 daemon sessions at a time (further calls wait); `calls_per_hour` tool calls per sign-in (`429` with `Retry-After`): only `tools/call` messages count, not listings. A POST body that is not JSON, or in which a JSON object has a key twice, is answered `400`. On the MCP path, a `Host` header that is neither the host of `url` nor loopback gets `403`. The gateway's letters count toward its machine's hourly posting limit for the boundary (`max_posts_per_hour`), like any session's. Every tool answers within the limits of section 18.6, far below the 240 s and about 150,000 characters Claude allows.
10. **Audit log.** One JSON line per tool call (time, sign-in id, client name, tool, the address it was sent to if any, `ok` or the error's first 200 characters, milliseconds) and per sign-in event (registration, a right or wrong passphrase, tokens issued or refused, a revoked sign-in used, a replaced refresh token used again), and per call refused for the hourly budget. Never bodies, tokens or the passphrase. Lines caused by requests without a valid token are limited to 60 a minute in each of two groups: `security` (wrong passphrases, a revoked sign-in used, a replaced refresh token used again) and `register` (everything else); when more come, one line per group (`{"event": "left_out", "of": "security" or "register", "lines": N}`) gives the number left out, so a flood cannot push the record of real calls out. At 8 MiB the file is renamed to `audit.log.1`, replacing the previous one.
11. **MCP sessions keep no state in the gateway's memory**, and the inbox is the boundary's log, which every machine of the boundary holds. A second gateway behind the same host name could therefore share the work later, given the same `gateway.db`; none is built (`open/second-gateway`).
12. **Commands** (section 20.5): `gateway setup`, `serve`, `status`, `grants`, `revoke`, `passphrase`, `remove`.
13. **The service.** `gateway setup` writes `tearmesh-gateway.service`: it runs `tearmesh gateway serve` as the gateway's user, restarts on failure, starts at boot, and runs with a read-only system, no home directories, no new privileges, a private `/tmp`, IP and Unix sockets only, and write access to `/var/lib/tearmesh-gateway` alone. It needs systemd; elsewhere setup writes the config and the passphrase and says to run `tearmesh gateway serve` as that user. `serve` refuses to run as root, or with a state directory that others can read. Root never opens the files in the state directory itself: `setup` and the commands below, when root starts them, run that part as the gateway's user, in a session of its own with no terminal, and root prints what it wrote with control characters removed: so a taken-over gateway can neither type into root's terminal nor send it escape sequences through its own files.
14. **The tunnel is not part of tear-mesh.** The gateway listens on loopback; a tunnel gives it a public host name with a valid certificate and no open router port. `gateway setup` prints the commands for two that work: a Cloudflare Tunnel (`cloudflared`) and Tailscale Funnel. Both the MCP path and the OAuth paths must be reachable from Anthropic's servers. Optional hardening, done at the tunnel or a firewall, not in tear-mesh: allow only Anthropic's published ranges, `160.79.104.0/21` and `153.61.208.0/20`. Claude needs a public IPv4 address with a valid certificate for the host name; an address inside a tailnet does not work.
15. **What the gateway and the cloud see.** The gateway ends the MCP connection, so it, the tunnel's operator and Anthropic see every message that passes through it in clear, and the tunnel's operator sees the passphrase when it is typed. Anything that must not leave the mesh stays out of the gateway's boundary.
16. **LIMITS.** `limit/gateway-one-boundary`: one gateway per machine, one boundary per gateway. `limit/gateway-grants-local`: sign-ins are listed and revoked on the gateway machine by its admin, not from an owner node; an owner node can only cut the whole gateway off (point 3). `limit/gateway-shared-inbox`: every sign-in reads and writes the same mailbox. `limit/gateway-port-local`: the gateway listens on a loopback TCP port, which any OS user of the gateway machine could take while the gateway is not running, and so receive the sign-in page with the passphrase typed into it; run the gateway on a machine where nobody else has a login. `limit/gateway-slow-connections`: someone who keeps several hundred slow connections open can keep the gateway unreachable for as long as they keep it up (nothing is read or changed); the tunnel in front is the defence. `limit/gateway-no-cimd`: client ID metadata documents are not supported; clients register dynamically.

### 18.5 The steward

One per boundary user: `tearmesh steward [--mailboxes F] [--offers F] [--screen F]`, as the systemd unit `tearmesh-steward@<user>` (Windows: a scheduled task). It is meant for the boundary users only: install starts it for no one else, and the unit file says not to run it as root or as the daemon's user, but the code does not refuse that. It follows the daemon's events for its boundary and reconnects every 5 s when the daemon is away. It does three jobs:

1. **Serves shared servers** (section 15): for each tool stream it starts the server's command from `offers.toml` as its own user and connects it to the stream. One process per stream.
2. **Wakes agents on mail.** `mailboxes.toml` has one table per mailbox:

   | Key | Default | Meaning |
   |---|---|---|
   | `dir` | required | working directory of the woken command |
   | `command` | required | the command; an argument `{prompt}` is replaced by the wake prompt, else the prompt is added last |
   | `max_wakes_per_hour` | 6 | hourly budget, 1 or more |
   | `timeout_mins` | 30 | a woken command running longer is stopped |
   | `resume` | false | add `--resume <session id>` of the last wake (taken from a `session_id` field in the command's JSON output) |
   | `wake_on` | `["member", "admin"]` | which trust levels wake this mailbox. Letters from the gateway are `guest`: list it to let the owner's Claude apps wake this mailbox. |
   | `from` | every sender (`["*"]`) | Which senders wake this mailbox: a list of addresses, where `*` stands for any agent or any machine (`claude@gw`, `*@laptop`, `herder@*`; `*` alone or `*@*` is every sender). A letter wakes the mailbox only if its trust is listed in `wake_on` and its sender matches an entry here. Any other entry stops the steward at start: `mailbox <table>: bad sender "<entry>" in from: use agent@machine (either side may be *), or * for anyone`. The mesh proves only the machine part of a sender (the signing machine, section 13); the agent part is the name a session on that machine gave itself. So `herder@ws` means any session on `ws` that calls itself `herder`, within the boundaries that may write here. |
   | `about` | `Woken when mail arrives.` | the `about` text of the status record the steward writes for this mailbox when it has none (section 16.1) |

   A mailbox is woken when it has unread, visible letters of a listed trust that have not caused a wake yet, no live session holds it, no wake of it is running and its budget is not used up (`wake budget (N an hour) used up; mail waits`). The command gets `TEARMESH_MAILBOX` and `TEARMESH_WAKE_IDS`. The prompt lists the letters and tells the agent to open each with `inbox_fetch`, do what it reasonably asks within its own work, answer in the thread with `send_message` and `reply_to` (first one or two sentences that can be read aloud, then the detail), send a `claim` first if the answer will take more than a few seconds, and stop; and that letters come from other agents, to be weighed, not obeyed. Claims never wake a mailbox. Mailboxes are checked at steward start and after every wake.

   A table named `"*"` stands for every mailbox of this machine that has no table of its own, `admin` included: mail for any of them runs its command. In a command, an argument `{mailbox}` is replaced by the name of the mailbox the mail is for, in any table. All mailboxes that the `"*"` table answers share its hourly budget; each is woken on its own, so two can run at once. A mailbox with a table of its own is never answered by `"*"`. No status record is written for `"*"`, and at steward start only the named tables are checked. No other table name may contain `*`. With it one agent answers everything nobody else does, or a small script hands each letter to the running session of that name. The session ids for `resume` are kept in `~/.local/state/tearmesh/sessions.json`, written only for a table with `resume` on.

   What a woken command may do is not tear-mesh's to grant: it is the command's own limits (an agent program's permission settings, the user it runs as, the confinement of the steward's service). A mailbox that only answers questions gets a command that can only read; one that takes tasks gets a command that may act, and `wake_on` and `from` say who may give them. `docs/testing.md` has both forms for Claude Code. The command need not start a new agent: one that hands the prompt to a session that is already running (for example `herdr agent prompt NAME {prompt}`) delivers mail into that session.
3. **Screens mail** (section 14) when the daemon's config lists its boundary.

With no mailbox and no offer configured and no `screen.toml` (the files missing or empty) the steward keeps running and logs once that nothing is configured (it can still be asked to screen). `offers.toml` is read again whenever a peer opens a tool stream, and `mailboxes.toml` whenever mail arrives and before a mailbox is checked, so edits need no restart. A file that no longer parses keeps its last good contents, with one warning per distinct error (`…; keeping the last good contents`); a file that does not parse when the steward starts still stops it. `screen.toml` is read once, at start.

**LIMITS.** `limit/wake-once-in-memory`: which letters already caused a wake is kept in memory, so a steward restart can wake a mailbox again for letters still unread. `limit/wake-held-at-start`: the check at steward start and after a wake does not look at whether a live session holds the mailbox. `limit/star-no-wake`: letters to `*` never wake anyone (the steward's own checks do not keep to this yet: `fix/board-wake-at-check`).

### 18.6 The conversation tools

The mail server, the hub and the gateway serve these seven tools with the same names, arguments and behaviour, from one piece of code. They are general: asking an agent for its open questions, or how a repository works, is a message; the agent that answers does the thinking next to the code.

| Tool | Read-only | Does |
|---|---|---|
| `list_nodes()` | yes | this agent's own address; every machine (node) of the boundary with `online`, its bio, and its known agents (section 16.1), each with `about`, `task`, `pending_questions` and `updated` from its status record |
| `node_status(node, agent?)` | yes | one node: `online`, when it was last seen (`last_seen`), and the status records of its agents, or of one. Reads what this machine already holds plus one ping; wakes no model. |
| `send_message(to?, body, subject?, reply_to?, kind?, if_offline?, idempotency_key?)` | no | sends a letter and returns `{id, state}` at once; the answer comes through the inbox |
| `inbox_list(unread_only?, thread?, since_minutes?, limit?, wait_secs?)` | yes | headers of the letters addressed to this agent |
| `inbox_fetch(id, detail?, offset?)` | yes | one letter's text; marks it read |
| `board_read(unread_only?, since_minutes?, limit?)` | yes | headers of the letters on the board (addressed to `*`) |
| `board_post(body, subject?, kind?, idempotency_key?)` | no | posts to the board. Its description says that a post wakes no agent, and that a message meant for one agent goes through `send_message`. |

1. **Annotations.** Each tool has a title. The five read tools carry `readOnlyHint: true`; the two that send carry `readOnlyHint: false` and `destructiveHint: false`. So a client can let the read tools run without asking and keep its own setting for sending.
2. **Nothing blocks on an agent.** `send_message` returns as soon as the letter is written. Nothing depends on the server pushing to the client: answers are fetched.
3. **Addressing.** `to` is `agent@node`, or a bare node name, which means that node's default addressee `admin`. With `reply_to` (the id of the letter being answered, or a prefix of 6 or more characters) `to` may be left out: the reply goes to that letter's sender, in its thread. `subject` defaults to the body's first line that has text, cut to 80 characters. `send_message` refuses `*`: the board is `board_post`. `kind` is `info` (default), `task` or `question`.
4. **Plain errors, within seconds.** Each is a tool result marked as an error, with text a model can act on:
   - an unknown node: `no node "x" in this boundary; nodes: a, b`;
   - a node that is off: `node x is offline (no answer in 4 s); nothing was sent. Pass if_offline="queue" to leave the message waiting for it`; when the call carried an `idempotency_key` the text says `nothing was sent now` and adds `If an earlier call with this idempotency_key returned an id, that message was already sent.`;
   - an unknown agent: `no agent "y" is known on x; agents there: admin, herder`;
   - not permitted: the daemon's own text (section 13);
   - no daemon: `tear-mesh is not available: <reason>`.
5. **Offline targets.** `if_offline` is `fail` (default) or `queue`. Before sending, each target node is pinged (4 s limit; section 13). With `fail`, a node that does not answer stops the send. With `queue` the letter is written anyway and reaches the node when it is back. `state` in the reply is `sent`, `queued` or `duplicate`.
6. **Sending once.** With `idempotency_key`, a repeated call returns the first letter's id with `state: "duplicate"` and sends nothing (section 13).
7. **Headers.** `inbox_list` and `board_read` return `{letters: […], more: N}`. Per letter: `id`, `from`, `kind`, `subject`, `thread` (a first letter shows its own id, so the value can always be passed back as `thread` or `reply_to`), `time` (UTC), `age_secs`, `size` (bytes of the body), `unread`, `trust` when it is not `member`, and `expect_secs` on a claim. `inbox_list` shows the letters addressed to this agent by name, `board_read` those that others addressed to `*` (an agent's own posts are not listed to it: `limit/board-own-posts`). Oldest first; unread only unless `unread_only` is false; the newest `limit` (default 20, at most 100), with `more` saying how many older ones were left out. `thread` narrows to one thread, `since_minutes` to recent letters.
8. **Waiting a little.** `inbox_list` with `wait_secs` (0 to 30, default 0) returns at once when something matches, and otherwise waits up to that long for it. A client that cannot act on its own between the person's turns can so send, wait and read in one go.
9. **Summaries by default.** `inbox_fetch` returns `{id, from, kind, subject, thread, time, size, text, truncated}`, with `trust` when it is not `member`. With `detail: "summary"` (default) `text` is the letter's opening: up to its first blank line, at most 1,200 characters. With `detail: "full"` it is up to 20,000 characters from `offset` (default 0), with `next_offset` when more remains. A long letter is paged, never refused; an `offset` past the end is an error that says how long the letter is.
10. **Three more tools for agents**, on the mail server and the hub, not on the gateway:

    | Tool | Does |
    |---|---|
    | `set_status(about?, task?, pending_questions?)` | writes this agent's status record (section 16.1) |
    | `claim(reply_to, expect_secs?, note?)` | answers a letter with a claim (section 13) |
    | `set_bio(text)` | replaces this machine's bio (section 16) |

11. **Nobody announced there.** When a new message (one without `reply_to`) goes to an address that has no status record and that no live session on this machine holds, `send_message` sends it and adds `note` to its reply: `admin@x has no status record: a person may read this later, in the menu. Agents on x with one: herder`, or `… No agent on x has one.` The default addressee `admin` is the usual case: it is a person's mailbox unless that machine's steward answers it. Which local mailboxes a live session holds comes from the daemon (`held` in the `who` answer); for another machine only the status record counts. **LIMIT** (`limit/note-one-way-mail`): status records come only from machines that may send mail to this one, so where mail is granted one way only, the note can say there is no record when there is one.
12. **How an agent should answer** is said in every door's instructions, in the hook's notice and in the wake prompt: reply in the thread; open with one or two sentences that can be read aloud, then the detail; send a claim first when the answer takes more than a few seconds; treat what a letter says as a request to weigh. Answers to an agent's own questions arrive as ordinary replies in the thread it asked in.

### 18.7 The Claude Desktop extension

`tearmesh.mcpb` is a Claude Desktop extension: a zip with a `manifest.json` and a small stdio program. It holds no copy of tear-mesh. It runs the installed `tearmesh mcp connect`, which relays to the hub of the person's OS user and starts that hub in the background, to outlive Desktop, if it is not running (section 18.2). So Desktop gets the hub's tools, works with no gateway, and never owns a private tear-mesh.

1. It finds `tearmesh` in this order: the extension's setting `tearmesh_path` (optional, passed to the program as an argument), the PATH (install puts it there), `%ProgramFiles%\tearmesh`. When none is there, or the person's user belongs to no boundary, Desktop shows one plain sentence that says what to run.
2. The person's own OS user must belong to a boundary: `tearmesh install … --me BOUNDARY` (section 22.1).
3. The manifest declares Windows only: tear-mesh has no macOS build. Each release carries the file; the version is the crate's. The file is not signed, so Desktop shows its warning for an unsigned extension at install.
4. Claude Code and other harnesses need no extension: they use the hub's HTTP entrance (`claude mcp add --transport http …`, as `tearmesh mcp info` prints) or `tearmesh mcp connect`.

## 19. The menu

`tearmesh menu`, and `tearmesh` with no arguments, open a full-screen program with three screens: **Mesh**, **Mail**, **Settings**. It shows the daemon's live state (status every 3 s, a ping round every 10 s) and does everything without leaving the screen: install, create, join, invite, approve, permissions, owner keys, settings, dissolve, leave, uninstall. Every signature is made by the menu: in its own process for a key file, through `ssh-keygen` started by the menu for a security key.

### 19.1 Who you are

The header reads `o─o tear-mesh  <machine>  ROLE` (the role is a coloured tag). The role is worked out at every refresh:

| Role | When | Offered |
|---|---|---|
| `NOT SET UP` | not installed, the daemon is not answering, or the machine is in no mesh | install; create; join; add boundaries |
| `MEMBER` | in a mesh; no owner key for it in `~/.ssh` | look, ping, shell, leave |
| `OWNER NODE` | in a mesh; an owner key for it is in `~/.ssh` | also everything that signs |
| `BOUNDARY USER` | run as a boundary user who is not an admin | mail; that user's MCP hub |

1. "Not installed" means: no config file and nothing listening on the socket. Then the install form opens by itself, once.
2. For a boundary user the menu opens on Mail. Its Mesh screen says who they are (address, boundary, machine), that mail is on the Mail screen, and that the mesh is managed by an admin of this machine. Settings shows and starts that user's hub, and reads `(managed by an admin of this machine)` where the mesh's settings would be. No key that needs an admin is offered.
3. A refresh that fails to fetch the membership file keeps showing the last one, as long as the daemon still names the same mesh id and a version no older than the one shown. When the daemon no longer names a mesh (the machine left, or the mesh was dissolved), the Mail screen is emptied.

### 19.2 Keys everywhere

`←` `→` `Tab` (also `h` `l` `4` `6`) change screen. `↑` `↓` (also `k` `j` `8` `2`) move the selection. `Esc` goes to Mesh. `?` help. `R` refresh. `Q` or `Ctrl-C` quit. Letters work in either case, except that plain `h`, `k`, `l` move; the three commands on those letters need Shift and the key bar writes them `Shift-H`, `Shift-K`, `Shift-L`. The bottom key bar lists what the current screen offers to the current role; its key column is as wide as the widest key on it.

### 19.3 Mesh screen

**Not in a mesh:** the machine's name and node id, and what can be done: `C` create a mesh, `J` join one, `U` add boundaries (when the machine has none, or hosts one with no OS user), `I` install (when not installed). While joining: `Joining: reaching the owner node…` or `Waiting for approval: code 123 456`, with `X` to cancel. A dissolved mesh is named as such.

**In a mesh:** a summary line (mesh, version, how many machines answer, boundaries), yellow lines for things that wait (join requests, offers to approve, status warnings, boundaries with no OS user), a map of the machines, and a table: machine, version, ping, boundaries, "may do there" (what this machine may do on that one), "may do here" (what that machine may do on this one), last sync. Channels read `mail`, `tools`, `shell`. This machine's version is always shown; another machine's is what it answered to the last ping, and `?` when it has not said (an older daemon, or not pinged yet). Join requests are listed on top with their code. The next row is **All machines**: in both columns it shows what the grant `* → *` allows every machine on every other; `Enter`, `X` and `D` do nothing on it, and the selection starts there when no request waits. A machine that announced it is leaving shows `(says it left)`.

| Key | Who | Does |
|---|---|---|
| `Enter` | all | details of the selected machine; on a join request: the approval form |
| `X` | all | opens a shell on the selected machine (ssh over the mesh). An admin with no boundary gets a boundary both machines host; with none shared the menu says `no boundary in common with NAME: a shell goes through a boundary both machines host`. If the menu cannot find out which boundary the user has, it opens nothing and says `can't tell which boundary this user has: <error>`. |
| `P`, `S` | all | ping now; the daemon's status as JSON |
| `U` | all, when offered | add boundaries (runs install with admin rights) |
| `A` | owner | add a machine: makes a one-hour ticket and shows it |
| `D` | owner | on a machine: disconnect it (signs its removal); on a join request: refuse it |
| `G` | owner | On a machine: the Permissions box for this machine and that one (point 7). On **All machines**: the box for all machines. On this machine's own row: `a machine needs no grant to itself`. The box is always between this machine and the selected one; a pair of two other machines is signed with `mesh grant` and `mesh revoke`. There is no separate revoke form: removing a tick revokes. |
| `O` | owner, when offers wait | approve offered MCP servers |
| `Shift-L` | member | leave the mesh. It asks first: `Leave mesh NAME? This machine tells the others it is leaving, then forgets the mesh (its logs are kept, moved aside). The owner node then removes it.` An owner node leaves from the command line. |

1. **Create** (`C`): mesh name, passphrase twice. The menu makes both owner keys, then shows the **recovery key and its passphrase** on a screen of their own: `C` copies the key, `P` the passphrase, `W` saves the key to a file (new, mode 0600, never overwriting), `Y` says "I've saved them" and asks for the third word of the passphrase as proof. While it asks, the key and passphrase are not on the screen (`The key and passphrase are hidden. Esc brings them back.`); a wrong word shows them again with a note, and `Y` asks once more and clears the note. Then one confirmation, and the mesh exists with this machine in it. `Esc` before that changes nothing.
2. **Join** (`J`): paste the ticket. The menu shows the code and waits; `Esc` hides the box while the daemon keeps waiting.
3. **The ticket screen** (`A`): the one-line commands for Linux and PowerShell and the bare ticket, without borders so a mouse selection copies them whole. `C`, `P`, `T` copy each (through the terminal's OSC 52 clipboard; tmux needs `set -g set-clipboard on`), `W` saves the ticket.
4. **Approval** opens by itself when a machine asks. It shows the name, the boundaries asked for, the code with the question whether the new machine's own screen shows the same, and a red warning if another machine also tried the ticket. Boxes: which boundaries the machine hosts (those it asked for are ticked; a boundary new to the mesh is offered unticked), and grants in both directions for mail, tools and shell, all unticked, in the words of the Permissions box (point 7): `What NEW may do on THIS`, then `What THIS may do on NEW`. A channel the mesh already allows in both directions between the two is not offered (for mail the form then says `Everyone may already mail everyone.`). The last line takes the key's passphrase or PIN. `Esc` leaves the request waiting.
5. A form the menu opened by itself ignores `Enter` for its first 700 ms, so an Enter meant for the screen before cannot approve anything.
6. **Machine left:** when a machine says it left, the owner's menu offers once to sign its removal (`NAME says it left the mesh (it left there, or tear-mesh was uninstalled).`).
7. **The Permissions box** (`G`). It says who may do what where, one line per switch:

   ```
   Permissions: alpha and beta

   What alpha may do on beta
    [x] mail    send letters to its agents             on for all machines
    [ ] tools   use the MCP servers it shares
    [ ] shell   log in over SSH and run anything

   What beta may do on alpha
    [x] mail    send letters to this machine's agents  on for all machines
    [ ] tools   use the MCP servers shared here
    [ ] shell   log in here over SSH and run anything
   ```

   A switch that a grant with `*` already turns on is shown ticked with `on for all machines` and cannot be changed here; Space on it says where (`on for all machines: change it on the All machines row (a grant that names one machine and *: tearmesh mesh revoke)`). A pair's own grant under such a switch is not shown and is not changed by the box. Ticking a switch grants, removing a tick revokes that pair's grant, and everything changed is listed on one signing screen (`Allow shell: what beta may do on alpha`, `Stop mail: what every machine may do on every other`) and signed at once with the key's passphrase or PIN; with nothing changed, Enter closes the box. Shell for the other machine on an owner node shows the warning of section 12 on the signing screen. The box for **All machines** (`Permissions: all machines`) has two switches, `mail   every machine may send letters to every other` and `tools  every machine may use the MCP servers every other shares`, the line `shell is always set for one pair of machines`, and says that machines that join later are covered. Grants with `*` on one side only (`alpha → *`) are signed with `mesh grant` and removed with `mesh revoke`; the boxes show their effect and do not change them (`limit/menu-one-sided-grants`).

### 19.4 Mail screen

A mail client for the OS user's boundary and the mailbox `TEARMESH_MAILBOX` (default `admin`): inbox on the left, the open letter or the letter being written on the right, and how long ago each other machine synced. It does not hold the mailbox, so agents are still woken.

Keys in the list: `↑` `↓` move, `Enter` open, `Esc` close the letter, `Space` `PgDn` `PgUp` scroll, `n` new letter, `r` reply (in the thread), `a` all or unread only, `g` refresh. While writing: `Tab` next field, `Enter` new line in the body, `Ctrl-S` send, `Esc` discard. An admin with no boundary is told to run the menu as a boundary user (`tearmesh launch --boundary <b> -- tearmesh`).

**LIMIT** (`limit/mail-editor`): the letter editor has no cursor movement; Backspace deletes the last character. `limit/mail-esc`: on this screen `Esc` belongs to the mail client and does not go to Mesh.

### 19.5 Settings screen

Shows the mesh's signed settings, the MCP hub (running or not, its URL, the stdio command), this machine (owner key, config, socket), the owner keys by fingerprint (here or elsewhere), the menu's own event log and the daemon's log.

| Key | Who | Does |
|---|---|---|
| `Shift-H` | all | starts the MCP hub in the background |
| `U` | all | how to register the hub with a harness; `C` copies the `claude mcp add` line |
| `E` | all | clears the event log |
| `V` | all | Leaves the full screen, runs `tearmesh update --check` (section 22.3) and returns on Enter; a run that fails is noted in the event log. The screen itself shows this machine's version and, among the signed settings, the mesh's release (`none` when no release is named). |
| `X` | admin | uninstall: lists what goes and what stays, then runs with admin rights |
| `T` | owner | tools sharing: approval or free |
| `Y` | owner | relays |
| `N`, `Z` | owner | add an owner key (a `.pub` file); remove the selected one |
| `Shift-K` | owner | dissolve the mesh: type its name, then sign. Afterwards it says how many machines it reached. |

### 19.6 Forms and boxes

`Tab` `↓` next field, `Shift-Tab` `↑` previous, `Space` ticks, `Ctrl-U` clears a field, `Enter` submits, `Esc` cancels. Pasting works. A failed check keeps the form open with the reason in red; it names the field and puts the cursor on it. When the job behind a form fails, the form comes back with the error and its secret fields empty. A running job is stopped with `Esc`, except the last step of creating a mesh.

Commands that need admin rights (install, add boundaries, uninstall) leave the full screen, run through `sudo` (Windows: a UAC prompt), and return on Enter.

**LIMITS.** `limit/menu-size`: there is no minimum terminal size; below about 80x24 parts are cut off. `limit/menu-first-key`: with several owner keys of the mesh in `~/.ssh` the menu uses the first by file name. `limit/settle-enter-only`: the 700 ms guard covers Enter only, not Space or typed characters. `limit/menu-ticket-grace`: the Join form accepts a ticket up to an hour past its expiry (see `limit/ticket-grace`).

The older mail-only program `tearmesh tui [MAILBOX]` still exists and is deprecated.

## 20. Command line

`tearmesh` with no arguments opens the menu. An error prints `Error: <reason>` and exits 1; a usage error exits 2. Commands marked *hidden* work but are left out of `--help`. "Admin" and "boundary user" are as in section 7.

### 20.1 Machine

| Command | Who | Does |
|---|---|---|
| `tearmesh menu [--config F]` | anyone | the menu (section 19) |
| `tearmesh install [MACHINE] [BOUNDARIES…] [--stewards] [--me BOUNDARY] [--join TICKET]` | admin rights | installs or adds boundaries (section 22) |
| `tearmesh uninstall [BOUNDARIES…] [--keep-users] [--yes]` | admin rights | removes tear-mesh (section 22.4) |
| `tearmesh update [--to VERSION] [--mesh]`, `tearmesh update --check` | admin rights; `--check`: anyone | Installs a newer release in place; `--check` only looks (section 22.3). `--to` and `--mesh` cannot be combined, and `--check` takes neither. |
| `tearmesh status [--ping]` | admin | the daemon's status as JSON; `--ping` adds reachability of every machine |
| `tearmesh join TICKET`, `tearmesh join --cancel` | admin | joins a mesh; stops a join that is waiting |
| `tearmesh launch --boundary B [--mailbox M] [--config F] -- CMD…` | sudo rights (or root) | runs CMD as the boundary's user (section 7) |
| `tearmesh id` (hidden) | reads the state directory | prints this machine's node id |
| `tearmesh daemon [--config F]` (hidden) | the service | runs the daemon |
| `tearmesh shell-proxy MACHINE [--boundary B]` (hidden) | boundary user or admin | carries an ssh connection (section 17) |
| `tearmesh setup`, `tearmesh tui`, `tearmesh offers` (hidden) | | deprecated: the old wizard, the old mail screen, offers as JSON |

`status` shows: this machine's tear-mesh version (`version`) and, with `--ping`, each machine's (`version` in its `ping` entry, absent when it has not said), machine, node id, mesh (name, id, version, hash, the release it names (`release`, null when none), owner keys, hosted boundaries; null when the machine is in no mesh, with `dissolved` naming a mesh that was dissolved), the boundaries hosted and those hosted with no OS user (`unmapped`), per machine the last sync and any "says it left", join state, screening counts and `warnings`.

### 20.2 Mail and bios (as a boundary user)

| Command | Does |
|---|---|
| `tearmesh who` | own address; the machines of the boundary with bios and offers; as JSON |
| `tearmesh post --to A… --subject S --body TEXT [--thread ID] [--kind info/task/question]` | sends a letter and prints its id. `--body -` reads the body from standard input. (`--help` describes every flag.) |
| `tearmesh inbox [--all]` | one line per letter: 12 characters of id, `*` if unread, sender, subject, tags |
| `tearmesh read ID` | prints a letter and marks it read |
| `tearmesh bio show [MACHINE]`, `bio template`, `bio set FILE [--boundary B]` | section 16 |
| `tearmesh agent status [--about TEXT] [--task TEXT] [--pending N]` | writes this mailbox's status record (section 16.1); with no flag, prints it |
| `tearmesh agent claim LETTER [--secs N] [--note TEXT]` | answers a letter with a claim (section 13) |
| `tearmesh offer publish NAME [--offers F]`, `offer withdraw NAME` | section 15.1 |
| `tearmesh quarantine [--boundary B]`, `quarantine show ID`, `quarantine release ID` | admin; section 14 |

The mailbox is `TEARMESH_MAILBOX` (default `admin`).

### 20.3 The mesh (admin; signing commands need an owner key)

| Command | Does |
|---|---|
| `tearmesh mesh show [--file F]` | prints the current membership file |
| `mesh invite [NAME] [--boundary B]… [--replace] [--expires DUR]` | prints a ticket on standard output, and the one-line install commands on standard error |
| `mesh pending` | lists join requests |
| `mesh approve NAME [--host B]… [--add-boundary B]… [--grant FROM:TO:CATS]… [--key F] [--yes]` | approves a join request with one signature |
| `mesh reject NAME`, `mesh reject --all` | refuses one request; voids every invite |
| `mesh remove NAME` | removes a machine |
| `mesh grant FROM TO CATEGORIES…`, `mesh revoke FROM TO CATEGORIES…` | permissions; `*` for any machine (not with shell). The categories are `converse` (also written `mail`), `tools`, `shell`. |
| `mesh approve-offer MACHINE BOUNDARY SERVER [--tools a,b]`, `mesh unapprove MACHINE BOUNDARY SERVER` | shared servers |
| `mesh boundary add B [--host M]…`, `mesh hosts MACHINE BOUNDARIES…` | boundaries of the mesh; which a machine hosts |
| `mesh owner-add PUBKEY`, `mesh owner-remove FINGERPRINT` | owner keys |
| `mesh set SETTING VALUE` | `tools-sharing`, `relays`, `lookup`, `release` (section 5.4) |
| `mesh dissolve [--yes] [--uninstall]` | ends the mesh for good: type its name to confirm; says how many machines it reached. `--uninstall` uninstalls only when the dissolve was signed and applied here; otherwise `not uninstalling: the dissolve wasn't applied`. |
| `mesh leave [--yes]` | asks first (unless `--yes`), tells the others, then leaves (section 11). Prints `left the mesh; this machine can create or join a mesh now`. |
| `mesh reset [--yes]` | forgets the membership file, keeping the logs bound to this mesh (section 11) |
| `mesh new FILE --name N --owner-key PUB… --boundary B… [--id ID]`, `mesh add NAME NODE_ID --boundary B… [--replace]`, `mesh sign FILE [--key F]`, `mesh apply FILE` (hidden) | by-hand work on a membership file |

Every command that edits the membership file (`grant`, `revoke`, `remove`, `hosts`, `boundary add`, `set`, `owner-add`, `owner-remove`, `approve-offer`, `unapprove`, `add`, `dissolve`) takes: `--key F` (which owner key signs), `--no-sign` (write the file only), `--no-apply` (sign but do not hand it to the daemon), `--file F` (start from this file, not the daemon's; the result then goes to the daemon only if one is running), `--out F` (where to write; default `./mesh-v<N>.toml`, or the `--file` file itself when `--file` is given; `dissolve` writes to a private temporary folder). `mesh approve` takes only `--key` and `--yes` and also writes to a private temporary folder. `invite`, `reject`, `leave` and `reset` take none of these. It reads the current version, makes the next one, writes it, signs it (`<file>.sig`), hands it to the daemon and prints `applied mesh version N`.

### 20.4 Agents

| Command | Does |
|---|---|
| `tearmesh mcp` | stdio mail server (section 18.1) |
| `tearmesh mcp serve`, `mcp connect`, `mcp info` | the hub (section 18.2) |
| `tearmesh mcp --remote MACHINE/SERVER` | one shared server as a stdio server (section 18.3) |
| `tearmesh steward [--mailboxes F] [--offers F] [--screen F]` (hidden) | section 18.5 |
| `tearmesh hook` (hidden) | the Claude Code hook (section 18.1) |
| `tearmesh env-run [--set K=V]… -- CMD…` (hidden) | helper for `launch` on Windows |

### 20.5 The gateway (Linux)

| Command | Who | Does |
|---|---|---|
| `tearmesh gateway setup BOUNDARY --url URL [--port N] [--mailbox M] [--new-passphrase]` | root | makes this machine a gateway (section 18.4): creates the gateway's user `tm-<boundary>-gw` and lists it under `[guests]` in the daemon's config (the daemon is restarted when that changed), writes `/etc/tearmesh/gateway.toml`, creates the state directory, makes the passphrase and prints it once, writes and starts the service, waits for `/health`, then prints the tunnel commands and the URL to enter in Claude (Customize, Connectors, Add custom connector). With another boundary, URL or mailbox than the config it finds, it stops and says to run `tearmesh gateway remove` first. It refuses when a user named `tm-<boundary>-gw` is already a boundary's user or an admin on this machine (`the user NAME is already the user of a boundary on this machine (or an admin); the gateway needs a user of its own`), refuses `admin` as the mailbox, and checks the new daemon config before writing it. An existing state directory must belong to the gateway's user (or be root's and empty, left by a setup that stopped); otherwise setup stops the same way. Where no daemon service is installed, it says to restart the daemon by hand. Safe to run again, and after a run that stopped halfway: it keeps the passphrase and the sign-ins it finds (`--new-passphrase` replaces the passphrase) and rewrites the rest. The boundary must have an OS user on this machine. |
| `tearmesh gateway serve` (hidden) | the service | runs the gateway |
| `tearmesh gateway status` | root or the gateway's user | the config, whether the service answers `/health`, whether the daemon answers it, the sign-ins and the last call |
| `tearmesh gateway grants` | root or the gateway's user | lists the sign-ins: id, client, made, last used, calls |
| `tearmesh gateway revoke ID`, `gateway revoke --all` | root or the gateway's user | ends a sign-in, or all |
| `tearmesh gateway passphrase [--revoke-all]` | root or the gateway's user | makes a new passphrase and prints it once |
| `tearmesh gateway remove [--yes]` | root | stops and removes the service, the config, the state directory, the `[guests]` entry, and the gateway's user if setup created it (it is listed in `/etc/tearmesh/created-users`). Uninstall does this too. |

## 21. Config files

All are TOML. Unknown keys are refused in every one of them.

### 21.1 The daemon: `/etc/tearmesh/config.toml`

Written by install; read when the daemon starts (a change needs a daemon restart). It holds no secrets.

| Key | Default | Meaning |
|---|---|---|
| `machine` | required | this machine's name in the mesh |
| `state_dir` | `/var/lib/tearmesh` | the state directory |
| `socket` | `/run/tearmesh/tearmesh.sock` | the local socket (under 108 bytes; on Windows a named pipe `\\.\pipe\<name>`) |
| `[users]` | empty | OS user name = boundary. A user that does not exist stops the daemon at start (`config maps unknown OS user X`). |
| `[guests]` | empty | OS user name = `{ boundary = "…", mailbox = "…" }`: a user whose sessions the daemon holds to a guest's requests, with that mailbox (section 18.4, point 1). Written by `gateway setup`. A name cannot also be under `[users]` or `admins`, and cannot be root or the daemon's user. The mailbox cannot be `admin`. A user that does not exist stops the daemon at start, as for `[users]`. |
| `admins` | empty | OS users who are admins besides root and the daemon's user |
| `[network]` `relay`, `lookup`, `bind` | from the mesh settings | overrides for this machine (section 4) |
| `sync_interval_secs` | 30 | 1 or more |
| `max_thread_len`, `max_posts_per_hour`, `max_log_mb` | 40, 600, 1024 | section 8.4 |
| `shell_port` | 22 | where this machine's sshd listens on 127.0.0.1 |
| `screen` | empty | boundaries whose mail is screened (section 14) |

### 21.2 Per-user files (`~/.config/tearmesh/`)

| File | Read by | Section |
|---|---|---|
| `offers.toml` | steward, `offer publish` | 15.1 |
| `mailboxes.toml` | steward | 18.5 |
| `screen.toml` | steward | 14 |
| `hub.toml` | hub | 18.2 |
| `/etc/tearmesh/gateway.toml` (not per user) | gateway | 18.4 |

## 22. Install, upgrade, uninstall, release

### 22.1 Install

`sudo tearmesh install [MACHINE] [BOUNDARIES…] [--stewards] [--me BOUNDARY] [--join TICKET]`. Linux and Windows only (`install runs on Linux and Windows`). It needs root (Windows: an elevated Administrator). The same command installs, upgrades and adds boundaries.

1. MACHINE defaults to the installed name, else the host name made into a valid name. A machine is never renamed (`… install doesn't rename machines`).
2. A boundary whose OS user name `tm-<boundary>` would be longer than the system allows (32 characters on Linux, 20 on Windows) is refused before anything is changed.
3. On Linux, in order:
   - copies the binary to `/usr/local/bin/tearmesh` (replacing a running one safely);
   - creates the system user `tearmesh`;
   - creates a user `tm-<boundary>` for each boundary that has none, records the ones it created in `/etc/tearmesh/created-users`, and sets every boundary user's home to mode 0700; no password is set;
   - writes the config if there is none (machine, `admins` = the user who ran sudo, `[users]`). An existing config is kept; new boundaries are added under `[users]` as a text edit that keeps comments. If the install script then fails, that edit is undone; a failure after the script (the plugin files, the steward step) leaves it.
   - creates the state directory and the node key;
   - installs and (re)starts the service: systemd units (with the updater's timer, section 22.3, enabled on every run, and the gateway restarted if it runs, so it uses the new program), or an OpenRC script; with neither it says how to start the daemon by hand. Where it started a service it then waits up to 10 s for the daemon to answer. If it does not, install ends, after its closing lines, with `the daemon didn't answer within 10 s; its log: …` (the `journalctl -u tearmesh -n 20` command on systemd, `/var/log/tearmesh.log` on OpenRC). With `--join` the wait is the join's own 30 s.
   - writes the Claude Code plugin files to `/usr/local/share/tearmesh` and prints the command that adds the plugin;
   - prints the machine's node id and what to do next: `Next: tearmesh menu` when run by root directly, `Next, as yourself (not root): tearmesh menu` when run through sudo.
4. `--stewards` also enables `tearmesh-steward@tm-<boundary>` for the boundaries named on this run. It needs systemd; without systemd the install is finished first and the error comes last.
5. `--me BOUNDARY` also maps the person's own OS user (the one who ran sudo; on Windows the one who ran the elevated command) to BOUNDARY under `[users]`, so that agents the person runs as themselves, and Claude Desktop, are sessions of that boundary. BOUNDARY must be one this machine has an OS user for after this run. It is refused for root and SYSTEM and for users named `tm-…`. A user is in one boundary: mapping one that is already mapped elsewhere is refused. The mapping is written after the rest of the install and the service is restarted; on Windows the user is written as `DOMAIN\user`. The boundary's own work (`tearmesh launch`, the steward, the gateway) still runs as `tm-<boundary>`. Uninstall never deletes the person's user.
6. `--join TICKET` then joins (section 10): waits up to 30 s for the daemon, prints the code, waits for approval, and afterwards creates users for boundaries the owner had this machine host.
7. With no boundaries given and none in the config: `No boundaries yet: an owner picks them when this machine joins, or add one later …`. A re-install of a machine that already has boundary users (an upgrade) does not print it. Boundaries added to an installed machine are local until an owner lets the machine host them in the mesh (`tearmesh mesh hosts`).
8. **The service** (systemd): runs as `tearmesh` with a read-only system, no access to home directories, no capabilities, only IP, Unix and netlink sockets, and limits of 1 GB memory and 512 tasks. The steward unit runs as the boundary user with no new privileges and a private `/tmp`. Under OpenRC the daemon runs without this hardening and there is no steward service (**LIMIT** `limit/openrc-plain`).

### 22.2 Windows

Install copies the program to `%ProgramFiles%\tearmesh`, adds it to the machine PATH, creates the service `tearmesh` (automatic start, account `NT SERVICE\tearmesh`, restarts on failure), locks the data directory to SYSTEM, Administrators and the service, creates local users `tm-<boundary>` with generated passwords kept in `passwords.txt` (SYSTEM and Administrators only; **in plain text**, so stewards can be scheduled), writes the config, makes the node key, adds the firewall rule and starts the service. `--stewards` registers a scheduled task per boundary user. Install also registers the updater's task `tearmesh-update` (section 22.3) when it is missing, and never changes it afterwards, since the task may be what runs the install. On an upgrade the old program is renamed aside (`tearmesh.exe.old-<pid>`; a running program can be renamed, not replaced) and deleted by a later install once nothing runs from it, and steward tasks that run are stopped and started so they use the new program.

The pipe `\\.\pipe\tearmesh` lets any authenticated local user connect and refuses remote clients; clients check that the pipe belongs to the service before they speak.

### 22.3 Upgrade

**DECIDED 2026-11-26** (Maxwell asked how the whole network is updated): the owner names the release in the membership file, and every machine installs it by itself.

1. **One machine.** `sudo tearmesh update` (Windows: from an elevated prompt) finds the newest published release, and when it is newer than the installed version, downloads this machine's binary, checks it, and installs it in place. `--to VERSION` names the release instead. The machine keeps its node id, config, state, users and its place in the mesh; the service, the stewards and the gateway restart with the new program. `tearmesh update --check` needs no rights and changes nothing: it prints the installed version, the newest release, the release the mesh names when it can learn it (from the daemon for an admin, else from the stored file for root), and what to run. To someone who holds an owner key of the mesh it also prints `To update every machine of the mesh: tearmesh mesh set release X`, when the newest release is not older than this machine's and newer than the one the mesh names.
2. **The whole mesh.** On the owner node: `tearmesh mesh set release 0.5.1`. That is one signature. Every machine then installs that release by itself, within about 15 minutes of receiving the file; a machine that is off does it after it is back. `tearmesh status --ping` and the menu show each machine's version (section 9.1). `mesh set release none` names no release. Update the owner node first (point 1), so the release is known to work before every machine follows.
3. **The updater.** **DECIDED 2026-11-26** (Maxwell): it is on from install on every machine, and a machine opts out by switching its own timer or task off. Install registers it: on systemd the timer `tearmesh-update.timer`, which runs `tearmesh update --mesh` as root 5 minutes after boot and every 15 minutes; on Windows the scheduled task `tearmesh-update`, which runs the same as SYSTEM every 15 minutes. `update --mesh` reads the highest-numbered membership file in the state directory (never through a link, at most 256 KiB) and takes one thing from it, the release. If that is newer than the installed version, it does what `update --to` does; otherwise it prints nothing, makes no connection and ends with success. A stored file it cannot read is an error, repeated at every run. To keep a machine from following the mesh: `systemctl disable --now tearmesh-update.timer` (Windows: `Disable-ScheduledTask tearmesh-update`). **LIMIT** (`limit/openrc-no-updater`): under OpenRC there is no updater; run `tearmesh update` there yourself.
4. **What is downloaded and checked.** From `https://github.com/maxwell-tablinum/tear-mesh/releases/download/v<version>/`: `SHA256SUMS` and the binary for this system (`tearmesh-x86_64-linux`, `tearmesh-aarch64-linux` or `tearmesh-x86_64-windows.exe`). The binary's SHA-256 must be the one `SHA256SUMS` lists (`checksum mismatch: not installing`; `SHA256SUMS lists no <binary>: not installing`), and the binary, asked for `--version`, must report the expected version. It is then run as `install` for this machine (section 22.1). Only the three numbers of a version ever reach a URL or a path. The newest release is the one `https://github.com/maxwell-tablinum/tear-mesh/releases/latest` leads to. A download that starts on HTTPS is not followed to plain HTTP, and it may take 10 minutes at most. `TEARMESH_RELEASE_URL` replaces the download folder (section 22.5); the version on offer there is the one its binary reports, and `--check` then downloads nothing. The updater's service and task start without that variable, and `sudo` drops it.
5. **Where it works, and one at a time.** The download is put in a folder beside the installed program, made new for each run with access for root only (`/usr/local/bin/.tearmesh-update`; Windows: `%ProgramFiles%\tearmesh\.update`), not in the temp directory, which hardened machines mount without the right to run programs. A lock (`/run/tearmesh-update.lock`, mode 0600; Windows: `%ProgramData%\tearmesh\update.lock`) is held for the whole run: a second update started meanwhile ends at once, silently when it is the updater's and with `another update is running on this machine` otherwise. Nothing in the folder is run that this run did not write and check. **LIMIT** (`limit/windows-update-folder`): on Windows ordinary users can read that folder; one who keeps the downloaded file open makes later updates fail until it is let go. Nothing can be put there or changed by them. **LIMIT** (`limit/update-lock-holders`): on Windows the daemon's service account can open the lock as well and so hold updates off (it could already keep the stored file from the updater); and when the updating process alone is killed, the install it started runs on without the lock.
6. **Never backwards.** A release that is not newer than the installed version is not installed (`already at 0.5.1`), whoever asks.
7. **Trust.** The daemon runs without rights and cannot replace the program; the updater runs with full rights. It takes one thing from the stored membership file, a version number, and fetches that version from the project's releases over HTTPS, the same trust as the one-line installer. The updater does not check the file's signatures again: the daemon checked them before it stored the file, and the daemon's own OS user can write that folder anyway. So an owner key, and on one machine that machine's daemon user, can make it install a newer published release and nothing else: not an older one, not a program from elsewhere. A release is not signed by a key of its own (`proposed/signed-releases`): whoever can publish a release in the project's repository decides what the machines run once an owner names it. **LIMIT** (`limit/update-no-rollback`): if a new program's daemon does not start, nothing goes back by itself; install the older release by hand (point 9).
8. **From 0.4.0.** 0.4.0 has no `update` and no updater, and cannot read a membership file that names a release: it refuses that file (`unknown field release` in its log), stays at the version before, and goes on exchanging mail. Update each 0.4.0 machine once by hand with the install line of the new release (section 22.5, with the machine's name and no ticket), then name the release.
9. **By hand, from a binary.** Run `install` again with the new binary: it replaces the binary and restarts the service, keeping config, state and users. The one-line installer always installs the version it was released with.

### 22.4 Uninstall

`sudo tearmesh uninstall [BOUNDARIES…] [--keep-users] [--yes]`, the menu's Settings → **X**, or `install.sh --uninstall`.

1. It prints what goes: the service and its user, the gateway when there is one (its service, its user and `/var/lib/tearmesh-gateway`), the binary, the plugin, `/etc/tearmesh`, **the state with every mail log**, and the boundary users install created with their homes. Users install did not create are kept and listed. `--keep-users` keeps all users; naming boundaries removes exactly those users.
2. On an owner node it warns that afterwards only the other owner keys can sign, and points to dissolve.
3. It asks `Remove tear-mesh from this machine? [y/N]` unless `--yes`.
4. If the machine is in a mesh it tells the others it is leaving and prints who heard; the owner still removes it.
5. It stops running hubs, stewards and menus (not the menu that started it). Before it deletes the service user or a boundary user, it ends every process of that user (asks them to stop, kills what is left after 5 s) and waits up to 10 s for them to go, so an account still in use (a login that ended seconds ago, an agent still running) does not stop the uninstall halfway. Users it keeps are left running. Owner keys in `~/.ssh` always stay. Without `--yes` it offers to remove the invoking user's own `~/.config/tearmesh` and `~/.local/state/tearmesh`.

**LIMITS.** `limit/windows-uninstall-users`: on Windows the record of created users is in the data directory, which uninstall deletes, so a failed uninstall cannot be repeated with the same result. `limit/windows-leave-before-fail`: a non-elevated uninstall on Windows tells the mesh the machine is leaving before it fails for lack of rights.

### 22.5 One-line install

Each release carries `install.sh` and `install.ps1` with the version and the binaries' SHA-256 hashes filled in.

- Linux: `curl -fsSL <release>/install.sh | sudo sh -s -- [MACHINE [BOUNDARIES…]] [--me BOUNDARY] [--join TICKET]` (the arguments of `tearmesh install`). It picks the binary for the CPU (x86_64 or aarch64), downloads it with curl or wget, checks the hash (`checksum mismatch: not installing`) and runs its `install`. `--uninstall [--keep-users] [--yes]` runs the installed binary's uninstall.
- Windows (PowerShell as Administrator): `& ([scriptblock]::Create((irm <release>/install.ps1))) [-Machine M] [-Boundaries a,b] [-Me BOUNDARY] [-Join TICKET]`; `-Uninstall` removes.
- The hash protects against a replaced binary, not a replaced script.
- `TEARMESH_RELEASE_URL` makes the scripts download from another folder (a mirror, a local test server). Set in the environment of `tearmesh menu` or `tearmesh mesh invite` (an http or https URL made of letters, digits and `._:/~%+-`; anything else is ignored), it also changes the commands they print, which then pass the variable on to the script.
- `<release>` is `https://github.com/maxwell-tablinum/tear-mesh/releases/download/v<version>`. The first release is 0.4.0 (2026-11-25); for a version with no published release the printed commands fail with 404 unless `TEARMESH_RELEASE_URL` points elsewhere.

### 22.6 Release

A tag `v*` starts the one workflow: it builds three static binaries (`tearmesh-x86_64-linux`, `tearmesh-aarch64-linux`, `tearmesh-x86_64-windows.exe`) and the Claude Desktop extension `tearmesh.mcpb` (section 18.7), runs a smoke test (Linux, on both CPU types: a refused corrupted download, install and uninstall through `install.sh`, and a re-install with `tearmesh install`; Windows: a refused corrupted download, install through `install.ps1`, uninstall with the binary, no re-install), checks the tag against the crate version, fills the install scripts, writes `SHA256SUMS` and creates a **draft** release. A person publishes it. Release binaries are stripped of debug symbols.

**LIMIT** (`limit/release-no-tests`): the workflow does not run `cargo test`; run it before tagging.

## 23. The local socket

Everything local talks to the daemon over one socket: JSON, one request per line, one reply per line.

1. Reply: `{"ok": true, "data": …}` or `{"ok": false, "error": "…"}`. `join` sends lines with `"more": true` (the code) before its last reply. `subscribe` is followed by one event per line. `remote`, `attach` and `shell` turn the connection into a pipe after their reply.
2. Limits: 2 MiB per request line (`request too long`); 256 open connections; 10 s to send the first line, no idle limit after it.
3. On the first line the daemon reads who the caller is (section 7). A caller who is neither a boundary user nor an admin is answered `OS user <id> isn't mapped to a boundary on this machine` and disconnected. A line that does not parse is answered `bad request: …` and the connection stays open.
4. A session has a mailbox (default `admin`) and a trust (default `member`), set by `hello`. Trust may only be lowered.

| Request (`"op"`) | Fields | Who | Reply |
|---|---|---|---|
| `hello` | `mailbox?`, `hold?`, `trust?` | boundary user, guest user | `{address, boundary}`, with `guest: true` for a guest user. A guest user's mailbox and trust are fixed: another `mailbox`, a `trust` other than guest, or `hold` is refused. A guest user is answered `hello`, `who`, `reach`, `post`, `inbox` and `read` only (`a guest session can't do that`). For every session whose trust is guest, `read`, `inbox` with a thread, and `post` with a thread accept only letters to its mailbox or the board, or from it as a guest, and `set_status`, `claim` and `bio` are refused. |
| `who` | | boundary user | machines, bios, offers, mailboxes, status records |
| `post` | `to[]`, `subject`, `body`, `thread?`, `kind?`, `idem?` | boundary user | `{id}`, with `duplicate: true` when the key was used before. `to` may be empty when `thread` is given. |
| `inbox` | `all?`, `thread?` | boundary user | letters |
| `claim` | `thread`, `expect_secs?`, `note?` | boundary user | `{id}` |
| `set_status` | `about?`, `task?`, `pending_questions?` | boundary user | `{id}`; with no field, the mailbox's current record |
| `reach` | `machines?` | boundary user | `[{name, online, rtt_ms?}]` for the named machines of the boundary, or all; no `rtt_ms` for this machine |
| `read` | `id` | boundary user | the letter; marks it read |
| `notify` | | boundary user | letters not yet announced to this mailbox; marks them announced |
| `subscribe` | | boundary user | `{subscribed}`, then events (new mail; a tool stream to serve; a letter to screen) |
| `bio` | `text` | boundary user | `{id}` |
| `publish_offer` | `offer` | boundary user | `{id, pin}` |
| `offers` | `boundary?` | boundary user (own), or admin naming one | offers with their state |
| `screen_next`, `screen_verdict` | `boundary?`; `id`, `verdict`, `reason` | boundary user, or admin naming one | letters waiting for a verdict; the verdict stored |
| `quarantine`, `release` | `boundary?`; `id` (optional for `quarantine`) | admin | held letters; a letter let through |
| `remote` | `machine`, `server` | boundary user | `{connected}`, then MCP lines |
| `attach` | `stream` | boundary user (the steward) | `{attached}`, then MCP lines |
| `shell` | `machine`, `boundary?` | boundary user, or admin naming one | `{connected}`, then bytes |
| `status`, `ping` | | admin | status; reachability |
| `mesh_current`, `apply_mesh` | `toml`, `sig` | admin | `{toml, sig}`; `{version}` |
| `invite`, `pending`, `reject` | `name?`, `boundaries[]`, `replace`, `ttl_secs?` | admin | `{ticket}`; requests; `{rejected}` |
| `join`, `join_cancel` | `ticket` | admin | code lines, then `{version}`; `{cancelled}` |
| `leave` | | admin | `{heard: [names]}`: tells the others; changes nothing here |
| `leave_mesh` | | admin | `{left: true}` |
| `reset` | | admin | `{reset: true}` |
| `sync_now` | | admin | `{synced: [names]}` |
| `admin_bio` | `boundary`, `text` | admin | `{id}` |

A request that needs an admin answers others with `admin only (root or an Administrator, the daemon's user, or a configured admin)`. A boundary user who names another boundary gets `a session can't pick another boundary`.

**LIMIT** (`limit/socket-slots`): the socket is open to every local user (mode 0666) and has 256 slots, so local users who hold connections open can keep others out. Matters on shared machines.

## 24. Security model

### 24.1 What tear-mesh defends against

Careless agents and prompt-injected agents on member machines, and strangers on the network.

1. A session in one boundary cannot post to, read from, address, call tools in, or open a shell through another boundary. The operating system says who the session is; the daemon holds the logs; boundary users cannot read the daemon's state or each other's homes.
2. A machine cannot receive or push another boundary's entries, or entries signed as another machine.
3. Non-members are refused at the handshake. Strangers reach only the join protocol, only while an invite is open, and a ticket alone admits nobody: the owner compares a code and signs.
4. Membership files cannot be rolled back, jumped ahead, or signed by a non-owner. A removed owner key cannot sign what comes next.
5. Permissions are checked by code at both ends, never by a model. An agent cannot change the permission table: only an owner's signature can.
6. A machine cannot change the tools or instructions a caller's model sees after the owner approved them.
7. A removed machine is cut off as soon as the others have the version that removes it: it gets no mail, no tool or shell streams, no addresses.
8. A shell needs two locks: the mesh's shell grant and the target's own SSH login. A stolen node key alone gives no shell.

9. **The gateway** is the only part that faces the internet. Its lock is the sign-in: the passphrase, PKCE, and redirect URIs limited to Claude's and to loopback. Behind the lock it is an OS user of its own that the daemon holds to a guest's requests (section 18.4, point 1): a gateway that is taken over completely can send mail as `claude@<gateway>` with `guest` trust and read that mailbox and the board, in one boundary, and nothing else: no owner key, no node key, no mail between agents, no tools, no shell. Agents are told that its letters are data to weigh. An owner cuts it off by revoking its converse grants or removing the machine.

### 24.2 What it does not defend against

1. **A hostile member machine.** Proving from afar that a machine runs honest code is not possible without special hardware. The reasoning (DECIDED 2026-11-12 that it be written down):
   1. A machine signs its own offer: that proves which machine made the claim, not what code runs.
   2. The owner approves it: a person decided, but still on a claim.
   3. The pin and the tool list catch changes, but a compromised machine can report any hash it likes.
   4. A live challenge over the mesh proves something answers, not what it is.
   5. Proving unmodified code needs hardware remote attestation (Intel SGX/TDX, AMD SEV-SNP, Arm CCA, AWS Nitro Enclaves, TPM measured boot), all hardware-specific. Left as a possible later add-on.
   
   So: only admit machines you trust.
2. **The model provider sees everything its sessions read**, and everything the screener is shown. A boundary that "never leaves the machine" holds only if its agents use a local model.
3. **Network egress is not locked.** A prompt-injected agent with a shell or network access can still send data out over the internet.
4. **Prompt injection can still be read.** Screening catches clumsy attacks better than careful ones and raises some false alarms. What code bounds is what an injected agent can reach: its boundary, its grants.
5. **Inside SSH tear-mesh sees nothing.** The target's `authorized_keys` decides who logs in.
6. **Relays see metadata** (who talks to whom, when, how much, from which IP addresses), never content. n0's public relays are rate-limited and meant for development; for privacy or production run your own relay and set `relays` and `lookup`.
7. **Root, kernel exploits and hostile software with admin rights** on a member machine.
8. **Trust labels and bios are claims** of the machine that wrote them.
9. **A stolen owner key** can sign anything until another owner key removes it; see also `open/mutual-owner-removal`.
10. **What passes through the gateway is seen** by the gateway, the tunnel's operator and Anthropic; the tunnel's operator also sees the gateway passphrase when it is typed (section 18.4).
11. **A letter from the gateway can still mislead an agent** that reads it, like any letter. Code bounds what that agent can reach, not what it believes.

### 24.3 Secrets and where they live

| Secret | Where | Protected by |
|---|---|---|
| node key | `node.key` in the state directory | file mode 0600 in a 0700 directory of the daemon's user (Windows: ACL). Not encrypted. |
| everyday owner key | `~/.ssh/tearmesh-owner-<mesh>` | the person's passphrase |
| recovery owner key | wherever the person put it | its generated passphrase |
| ticket secret | in the ticket; `invites.json` on the owner node | one use, expiry, the code comparison |
| hub token | `<hub state>/token` | file mode 0600 |
| gateway passphrase | with the person; a salted hash in `gateway.db` | six random words, shown once; five wrong tries per 15 minutes |
| gateway tokens | with Claude; hashes in `gateway.db` | directory mode 0700 of the gateway's user; 1 hour (access), 60 days and single use (refresh) |
| Windows boundary user passwords | `passwords.txt` | ACL: SYSTEM and Administrators. Plain text. |
| screener API key | `api_key_file` or the steward's environment | file mode (refused if readable by others) |

## 25. Versions and compatibility

1. This specification describes **0.5.0**, tagged `v0.5.0` on 2026-11-26. 0.4.0, tagged `v0.4.0` on 2026-11-25, was the first tag and the first release with published binaries. 0.5.0 changes no wire or file version. A 0.4.0 machine and a 0.5.0 machine share a mesh and exchange mail; once the membership file names a release (the key `release`), a 0.4.0 machine refuses that file and every later one and stays at the version before, still exchanging mail, until it is updated by hand (section 22.3). A 0.4.0 machine answers a ping without its version. Building from source needs Rust 1.89 (0.4.0: 1.88). Earlier versions exist as commits only: 0.1.0 (2026-10-16), 0.2.0 (2026-10-18) and 0.3.0, which was never released on its own (0.4.0 builds on it).
2. The crate version and the plugin's version are the same; a test checks it.
3. Wire and file versions in 0.5.0, the same as in 0.4.0:

   | Thing | Version | Where it shows |
   |---|---|---|
   | sync protocol | 2 | ALPN `tear-mesh/sync/2` |
   | join, tools, shell, ping protocols | 1 | ALPNs `tear-mesh/join/1`, `mcp/1`, `shell/1`, `ping/1` |
   | membership file | 2 | `format = 2` |
   | entry envelope | 2 | `"v": 2` |
   | ticket | 2 | prefix `tm2-` |

4. Machines of one mesh must run builds that agree on all of these. Because unknown keys are refused in membership files and envelopes, a build that adds a key cannot share a mesh with one that lacks it: for example builds from before `closed` existed refuse a dissolve. **Upgrade every machine before using something new.** 0.4.0 adds the entry kinds `claim` and `status` without raising the envelope version: a 0.3 build refuses such an entry, and with it every later entry of that machine in that boundary (`limit/chain-stall`), so a mesh runs 0.4 on every machine or on none.
5. Carried over from older versions: a stored 0.1.0 circle is read as version 1 of a mesh (section 5.5); the trust names `circle` and `owner` are read as `member` and `admin`; the command `tearmesh waker` is an alias of `steward`.
6. Deprecated, still present: `tearmesh setup` (the wizard), `tearmesh tui`, `tearmesh offers`.
7. The project stays at 0.x until Maxwell declares it launched (DECIDED).

## 26. Tests

| Suite | What it covers | Needs |
|---|---|---|
| `cargo test` | unit tests in every module, and `tests/mesh.rs`: in-process daemons over real iroh (boundaries, handshake, removal, leaving, dissolve, splits, sync, relaying, joins, grants, tools, shell, screening), a ping's version, the release setting, and `update` against a local web server (a refused checksum, a missing entry, a wrong version, never backwards, the stored file) | nothing |
| `tests/e2e-linux.sh` | two daemons and real OS users: boundaries on disk and on the wire, join with a code, offers, approvals, tool calls, shell proxy, bios, the mail server, the hook, wakes, the menu's Mail screen | sudo without a password, python3, curl; tmux for the menu checks (skipped without it); a release build |
| `tests/talk.rs` | the conversation tools against real in-process daemons: every tool, the error texts, offline and queued sends, claims, status records, paging, a guest door, the steward's registration, the note when nobody has announced themselves | nothing |
| `tests/e2e-0.3.sh` | three daemons: the old wizard, ping, the hub (both entrances, token, limits), mail, tools and shell both ways, chats, bad input, restarts, a stolen machine key, a leaked owner key, the menu (create, join, approve, permissions, leave), dissolve | the same, and sshd on port 22 |
| `tests/distros.sh` | `e2e-linux.sh` plus install, add boundaries and uninstall in containers of Debian, Ubuntu, Fedora, Arch, openSUSE and Alpine | podman or docker; a static build |
| `tests/gateway.rs` | the gateway against an in-process daemon: discovery, registration, sign-in with PKCE, the tools, and the refusals (no token, forged, expired, revoked, a reused refresh token, a client that never signed in, wrong passphrases, foreign redirect URIs, oversized bodies, a body that is not JSON, a flood, a user the daemon does not hold as a guest) | nothing |
| `tests/e2e-0.4.sh` | three daemons and a gateway as real OS users, the gateway as a guest user: the seven tools end to end, an offline node, claims, status records, a paged reply, the reply waiting after the client is gone; what the gateway's user is refused (on the raw socket, owner actions, tools, shell, other agents' letters); sign-in with no lockout, a tampered client id, a revoked gateway locked out. With `E2E_SYSTEM=1`, on a machine with no tear-mesh installed: install, `gateway setup` (twice, stopped halfway, with another URL), the service and its user, `gateway remove`, uninstall | sudo without a password, python3, curl; a release build; systemd for the second part |
| `tests/e2e-windows.ps1` | Windows: identity over the pipe, boundaries, join, mail, the mail server, the hook | an elevated prompt on Windows |
| release workflow | Linux: a refused corrupted download, install and uninstall through `install.sh`, a re-install with `tearmesh install`. Windows: a refused corrupted download, install through `install.ps1`, uninstall with the binary | runs on a tag |

1. The end-to-end scripts create OS users and throwaway daemons with their own config, state and socket. They never touch an installed tear-mesh.
2. Not covered by any automated test: install and uninstall on a machine with systemd or OpenRC running (the release workflow covers the GitHub runners only); the Windows install script outside the release workflow; security keys; the screener against the real API (tests use a stand-in server); relays other than the defaults.
3. Tried by hand, not by a test. On 2026-11-25, on the owner's mesh with 0.4.0: Claude Desktop added the gateway as a custom connector (automatic registration) and signed in, and a voice call used it (`list_nodes`, `board_read`, `inbox_list`, `inbox_fetch`, `send_message`). On 2026-11-26, on three throwaway containers with systemd that started from the published 0.4.0: the upgrade to 0.5.0 with the install line; mail between a 0.4.0 and a 0.5.0 machine; versions in a ping; `update` (the newest release looked up on GitHub; from a test folder a refused checksum, never backwards, a caller without root, two at once, the lock's mode); the mailbox rules `from`, `"*"` and `{mailbox}` with the shared budget; `mesh set release`, followed by the 0.5 machines through their updater and refused by a 0.4.0 machine, which kept exchanging mail. At the tag, the release workflow built the three programs and ran its install tests (on the Windows runner: 0.5.0 installed, the updater's task there, uninstalled), and the draft's own install line upgraded a fresh 0.4.0 container. After the release, the published install line upgraded the owner's two Linux machines from 0.4.0 in place: the same node id and mesh, the gateway's sign-ins kept, the updater's timer on and its first run clean. A task mailbox there (`proposed/task-agent`) answered a question, started a session in a new worktree, and passed a follow-up to a running session for a letter that came over the mesh from the gateway machine; a sender outside `from` did not wake it. `docs/testing.md` lists these.
4. Never tried: Claude on the web against the gateway; whether Claude prompts before the reading tools; Claude Desktop with `tearmesh.mcpb`; anything of 0.5.0 on Windows (`check/windows-update`); a real Windows machine with a person at it (the release workflow installs the build on a Windows Server runner through `install.ps1`, sees the service running and the updater's task, and uninstalls; a GNU cross-build was also run under Wine, where the daemon starts on a named pipe and the mail server lists its ten tools); aarch64 beyond the release workflow's install test; `update` from GitHub to a release newer than the installed one (none is published); `tests/distros.sh` since its 0.5.0 changes; a task given to a task mailbox from a Claude app (the trial letters were written by hand); the menu's new screens with a person at a terminal (`check/menu-by-eye`).
5. `docs/testing.md` is the hands-on guide: how to run each suite and how to try tear-mesh on two machines.

## 27. Open questions, proposals, plans, conflicts and limits

Nothing in this section is built on a guess. **OPEN** items wait for Maxwell.

### 27.1 Open questions

From the design sessions of October 2026 (collected 2026-11-12 in `docs/research/capability-synopsis-2026-11-12.md`), with what the code does today so the question can be judged:

| Name | Question | Today |
|---|---|---|
| `open/converse-category` | Does converse stay its own category, or become a built-in messaging toolset under tools? | its own category, with its own grant. 0.5.0 calls it the **mail** channel and keeps the word `converse` in the file (section 12). |
| `open/converse-only-nodes` | Is a machine with converse and no tools a supported setup? | works: a new mesh starts that way |
| `open/doorbell-levels` | Do "ring the doorbell" and "view only" survive as levels of their own, or fold into converse? | neither exists |
| `open/per-tool-scoping` | Per-tool permissions, or only the broad tools switch per pair of machines? | one tools switch per pair; the owner's approval can limit a server to some of its tools, for every caller alike |
| `open/boundaries-and-grants` | How do boundaries and the per-machine switches interact, and in what order? | boundary first, then the pair's grant, both in code (section 12) |
| `open/reader-gatekeeper-worker` | Is reader / gatekeeper / worker the locked architecture against prompt injection? | not built. Only the screening reader of section 14 exists. |
| `open/owner-model` | One owner node with a portable recovery key, or two or more owner keys? Both were stated; the later statement preferred the first. | both at once: the file needs two keys; setup makes an everyday key on the owner node and a portable recovery key |
| `open/converse-wire` | Name and wire format of a converse protocol | none: letters travel as log entries over `tear-mesh/sync/2` |
| `open/new-node-defaults` | Defaults for a new machine (see `proposed/deny-all-default`) | a new mesh allows mail among all machines; tools and shell need grants |
| `open/early-comm-design` | The October 12 and 13 design (broadcast queries, group chats, headers synced first with bodies fetched on demand, settling rounds with claims) was called "still in force unless it conflicts" and never revisited. Is it still wanted? | none of it is built: letters are whole entries, addressed to mailboxes or to everyone |
| `open/gateway-login` | How does the owner prove it is them at the gateway's sign-in: a passkey, approval on an owner node, or a passphrase? | a generated passphrase, shown once (section 18.4) |
| `open/gateway-channels` | Conversation only through the gateway, or tools and shell as well? | conversation only: the seven tools of section 18.6 |
| `open/gateway-tier` | Does the earlier rule hold that the public endpoint reaches the lowest classification tier only? | the gateway reaches one boundary, the one its config names; which boundaries its machine hosts is the owner's signed choice |
| `open/gateway-tunnel` | Which tunnel, and which host name? | none is built in: the gateway listens on loopback and `gateway setup` prints the commands for a Cloudflare Tunnel and for Tailscale Funnel |
| `open/herder-status` | Does Herder keep a running status record, or must it be asked each time? | the record exists (section 16.1); an agent or orchestrator has to write it (`set_status`, `tearmesh agent status`) |
| `open/no-session-policy` | When the target agent has no running session: start a harness to answer, or wait until one exists? | wait, unless that mailbox is in the steward's `mailboxes.toml` with `guest` in `wake_on` |
| `open/launch-agents` | Which agents are addressable at launch besides Herder? | any agent known on a node (section 16.1); none is configured by install |
| `open/inbox-retention` | How long are letters in the gateway's inbox kept, and how many? | nothing expires: the log is append-only and capped by `max_log_mb`; listings show unread letters by default |
| `open/second-gateway` | A second gateway on the cloud node for failover: now or later? | later; nothing built (section 18.4, point 11) |
| `open/other-users-relay` | For other users later: a hosted relay, or setup that automates a tunnel on their own node? | nothing built |
| `open/voice-polling` | Can Claude call a connector's tools on its own during a voice call, or only when the person speaks? Not said in Anthropic's documentation; to be tried with the gateway. | built for either: `inbox_list` can wait up to 30 s (section 18.6) |
| `open/sync-version` | 0.4.0 adds entry kinds without a new version of the sync protocol, so a 0.3 machine in a 0.4 mesh stops taking a 0.4 machine's mail from that machine's first status record or claim on (its log warns `rejected an entry … unknown variant`), and catches up by itself once it is upgraded (seen on the test mesh, 2026-11-25; section 25). Should the sync protocol's version be raised, so that mixed versions fail to connect and say so? That changes a protocol name, which the rulings freeze. | not raised: every machine is upgraded together, and the refusing side logs a warning |
| `open/mutual-owner-removal` | Two owners each sign a version removing the other's key (section 5.6): keep "first seen wins", which can split the mesh until a person steps in, or settle by the tie-break rules, which lets a thief with one owner key grind for a win? | first seen wins |

### 27.2 Where a ruling and the code disagree

Written down, not settled. Each needs a word from Maxwell: change the code, or change the ruling.

| Name | The ruling (2026-11-12 synopsis) | The code |
|---|---|---|
| `conflict/mesh-wide-grants` | "Every switch is granted per target machine, never mesh-wide." (DECIDED) | A grant may use `*` for any machine (not for shell), and every new mesh starts with `* → *` converse. |
| `conflict/harness-child-copy` | The tear-mesh MCP server is one independent service; "harnesses must not spawn their own child-process copy." (DECIDED) | The hub is that service, and Claude Desktop reaches it through the extension. But the Claude Code plugin still starts `tearmesh mcp` as a child of each session (the same conversation tools; it is what gives each session its own mailbox and holds it so wakes are not doubled). |
| `conflict/listen-off-drops` | With listen off for a peer, "that peer's notes are dropped by code at the network layer." (stated, not tagged) | Such letters are still stored and synced; they are not shown, announced or screened (section 12). Granting later shows them. |
| `conflict/protocol-names` | Protocol ids `tearmesh/mcp/1` and `tearmesh/ssh/1`. | `tear-mesh/mcp/1` and `tear-mesh/shell/1`. Settled since by Maxwell's standing rule that the names in the code are frozen; listed for the record. |

### 27.3 Proposed (suggested, not agreed, not built)

| Name | Proposal |
|---|---|
| `proposed/deny-all-default` | A new mesh starts with no grants; shell listen is off for every machine until switched on. |
| `proposed/taint` | After a session reads an untrusted letter, code lowers what it may do (no shell, read-only tools). |
| `proposed/human-approval` | A person approves risky actions one by one, shell above all. |
| `proposed/restricted-shell-user` | Agents log in over shell as a restricted OS user on the target, never as the person's own account. Today the target's `authorized_keys` decides. |
| `proposed/inventor-milestone` | First real-world milestone: drive the Inventor MCP server on the Windows VM from the laptop. |

Built as proposed, never confirmed: the membership version counter; the screener's decoy tools, switch, default model and quarantine; the pin over instructions and tool list, with approval dropping to "changed" when either changes; the executable hash in offers.

### 27.4 Decided, not built

| Name | What | State |
|---|---|---|
| `planned/menu-connect-claude` | In the menu: a "Connect Claude" flow (designate the gateway, bring up the tunnel, show the URL, offer the Desktop extension), a gateway panel (health, last call, sign-ins, revoke) and gateway status in the machine list. | Not built: the menu is briefed separately. The commands exist (`tearmesh gateway …`, section 20.5). |
| `planned/gateway-grants-from-owner` | List and revoke single gateway sign-ins from an owner node. | Not built (`limit/gateway-grants-local`). |
| `planned/group-chats` | Group chats made on demand, after peer-to-peer and the board. | Not built. |
| `planned/adversarial-windows-test` | A real mesh with the Windows VM, tested adversarially, then wiped for a fresh setup by Maxwell. | The scripted tests cover the adversarial cases on Linux. The Windows VM run has not been done. |
| `planned/cross-boundary` | Boundaries with a configurable adjacency map. | Parked until after launch; today only same-boundary traffic exists. |
| `planned/delivery-status` | "Delivered" per recipient and a list of sent letters (0.2 specification). | Not built. |

### 27.5 Limits

Every **LIMIT** in this file, by name:

| Name | Where |
|---|---|
| `limit/approved-frame-written` | 10.3 Approval |
| `limit/board-own-posts` | 18.6 The conversation tools |
| `limit/chain-stall` | 8.3 The one gate |
| `limit/code-formats` | 10.3 Approval |
| `limit/envelope-frozen` | 8.2 An entry |
| `limit/farewell-history` | 11. Leaving, removal, dissolving |
| `limit/file-size-late` | 5.1 Format |
| `limit/gateway-grants-local` | 18.4 The gateway |
| `limit/gateway-no-cimd` | 18.4 The gateway |
| `limit/gateway-one-boundary` | 18.4 The gateway |
| `limit/gateway-port-local` | 18.4 The gateway |
| `limit/gateway-shared-inbox` | 18.4 The gateway |
| `limit/gateway-slow-connections` | 18.4 The gateway |
| `limit/hold-after-restart` | 18.1 The mail server and the Claude Code plugin |
| `limit/hub-bearer-is-everything` | 18.2 The hub |
| `limit/hub-chats-outlive` | 18.2 The hub |
| `limit/hub-info-url` | 18.2 The hub |
| `limit/hub-token-once` | 18.2 The hub |
| `limit/leave-rename-fails` | 11. Leaving, removal, dissolving |
| `limit/limits-local-only` | 8.4 Limits on the daemon (config) |
| `limit/mail-editor` | 19.4 Mail screen |
| `limit/mail-esc` | 19.4 Mail screen |
| `limit/menu-first-key` | 19.6 Forms and boxes |
| `limit/menu-one-sided-grants` | 19.3 Mesh screen |
| `limit/menu-size` | 19.6 Forms and boxes |
| `limit/menu-ticket-grace` | 19.6 Forms and boxes |
| `limit/note-one-way-mail` | 18.6 The conversation tools |
| `limit/openrc-no-updater` | 22.3 Upgrade |
| `limit/openrc-plain` | 22.1 Install |
| `limit/owner-key-home` | 6. Owners and keys |
| `limit/passphrase-128` | 6. Owners and keys |
| `limit/rejoin-needs-removal` | 11. Leaving, removal, dissolving |
| `limit/release-no-tests` | 22.6 Release |
| `limit/screening-not-a-sandbox` | 14. Screening |
| `limit/server-info-unpinned` | 15.3 Calling |
| `limit/settings-need-restart` | 4. Transport |
| `limit/settle-enter-only` | 19.6 Forms and boxes |
| `limit/shell-streams` | 17. Shell |
| `limit/sk-key-unusable` | 5.5 Signatures and the chain |
| `limit/sk-windows-terminal` | 6. Owners and keys |
| `limit/socket-slots` | 23. The local socket |
| `limit/star-no-wake` | 18.5 The steward |
| `limit/stored-relay-url` | 5.4 Changes |
| `limit/sync-frame-escape` | 9. Sync |
| `limit/ticket-grace` | 10.3 Approval |
| `limit/unused-tickets` | 10.3 Approval |
| `limit/wake-held-at-start` | 18.5 The steward |
| `limit/update-lock-holders` | 22.3 Upgrade |
| `limit/update-no-rollback` | 22.3 Upgrade |
| `limit/wake-once-in-memory` | 18.5 The steward |
| `limit/warnings-stay` | 5.7 How versions travel |
| `limit/windows-leave-before-fail` | 22.4 Uninstall |
| `limit/windows-log-rotation` | 3.3 Files on Windows |
| `limit/windows-update-folder` | 22.3 Upgrade |
| `limit/windows-uninstall-users` | 22.4 Uninstall |

### 27.6 Left from the 0.5.0 list

The list was collected on 2026-11-25, after the first day of real use (the mesh `mw`: an owner node, a gateway, a third machine, Claude Desktop and a voice call through the gateway). What was built from it is in the change log under 0.5.0. This is what is left. Nothing here is built.

**Waiting for Maxwell's ruling.** Each is a suggestion; none is built on a guess.

| Name | Suggestion | To rule |
|---|---|---|
| `proposed/task-agent` | An agent that takes tasks from Claude's apps, so that a voice call can change what is running and start new work (his stated aim for the voice path, 2026-11-25). Since 0.5.0 this is configuration, not a feature: a mailbox whose command may act, with `wake_on` and `from` naming who may give it tasks (section 18.5; `docs/testing.md` has the form). The owner's workstation has had one since 2026-11-26 (Maxwell: set one up): a mailbox `tasks` that only the gateway's `claude` mailbox wakes. Its agent edits nothing; it types a task into a session that is running, or starts a session in a new worktree through one fixed script, and the settings of a session started that way refuse push, merge and delete. Nothing in tear-mesh was added for it. | Whether those limits are the right ones. A session that was already running keeps its own permissions: a task passed to it is held back only by the wording and by what that session refuses. |
| `proposed/node-version-in-tools` | `list_nodes` and `node_status` say nothing about a machine's version; `status --ping` and the menu do. In a voice call on 2026-11-26 the question "which version is running" could not be answered through the gateway. | Whether the two tools should carry the version a ping already brings. |
| `proposed/session-mailboxes` | Mail into agent sessions that are already running. Since 0.5.0 the steward can do the delivery: a table `"*"` whose command hands the letter to the session named by `{mailbox}` (section 18.5). What is missing is that command for his session manager, and a rule for how sessions are named. No machine has one. | How mailboxes are named (by project, by pane), and whether mail may be typed into a running session at all. |
| `proposed/node-agent-setup` | A node agent out of the box: one command sets up what was done by hand on 2026-11-25 (an agent woken by mail, read-only, with an allowlist, its service confined to a read-only home directory), and decides whether guest mail to `admin` goes to it. `docs/testing.md` now has the recipe. | Whether install offers it, and what it may read. Touches `open/no-session-policy` and `open/launch-agents`. |
| `proposed/context-notes` | Context from Claude to a node: agents leave questions in the gateway's mailbox for the next session he opens, or Claude writes notes into the mesh during a call, kept on the node. | Undecided by him in the call. |
| `proposed/per-boundary-wildcard` | A grant for "every machine that hosts boundary B". Needs a change to the membership file's format. | Suggested: not before a mesh has a second boundary. |
| `proposed/signed-releases` | Releases signed with a key whose public half is built into the binary, checked by `update` and the install scripts. Adds a signing step to every release. With the updater of 0.5.0 this matters more: whoever can publish a release decides what every machine runs once an owner names it (section 22.3). | Whether to do it before the updater is relied on. |
| `proposed/gateway-cimd` | The gateway accepts client ID metadata documents (`limit/gateway-no-cimd`), so the choice Claude's connector dialog recommends works too. | Whether it is worth it: registering automatically works. |
| `proposed/list-invites` | `mesh pending` also lists the open invites and when each ends. Today nothing shows whether a ticket is still good. | — |

**Fixes and checks.**

| Name | What |
|---|---|
| `fix/research-references` | Committed files point to files under `docs/research/` that are not in the repository (this spec, the test guide, the design note, a comment in `src/gateway.rs`). Commit those files or drop the references: Maxwell's choice. |
| `check/release-notes` | Checked at the 0.5.0 tag: the draft's notes are the tag's message. The draft had no title, and the message's first line opened the notes; both were put right by hand before publishing. Left: give the workflow's `gh release create` a title, or keep the hand step in `docs/testing.md`. |
| `check/windows-update` | Nothing of 0.5.0 has run on Windows: the updater's task, the renamed old program, the restarted steward tasks, the lock and the download folder. The code compiles for Windows, and the release workflow ran install and uninstall on a Windows runner at the tag, where the updater's task was there after the one and gone after the other. An update on a real Windows machine has to be tried by hand. |
| `check/windows-person` | A person installs and joins on a real Windows machine, with `-Me` and `-Join` together, and adds the Claude Desktop extension. |
| `check/menu-by-eye` | The new Permissions box, the All machines row and the Settings key `V` are covered by tests that read the drawn screen; no person has used them in a terminal yet. Before the tag they were drawn once in a terminal against the owner's mesh and showed what the tests expect. |
| `check/flaky-leave-test` | `a_leaving_machine_tells_the_others` in `tests/mesh.rs` failed once on 2026-11-26 (the mark `old` was gone from another machine's status) and passed in the nine runs after it; the disk was busy during the failed run. Neither the test nor the code it covers changed in 0.5.0. Likely cause, not confirmed: a sync with that machine that begins after the mark clears it, as designed (section 9.1), and the test looks without waiting for syncs to settle. Not fixed. |
| `fix/board-wake-at-check` | Found on 2026-11-26 on the owner's mesh: a new mailbox table woke its agent for an old board post. A notice is never sent for a letter to `*`, but the steward's checks at its start and after a wake take every unread letter of the mailbox, and the inbox holds board posts: one whose sender and trust pass `from` and `wake_on` wakes the mailbox then, against `limit/star-no-wake`. The sender still has to pass the table's rules. The fix is one condition in the steward (the letter names the mailbox) and a test. |
| `check/review-owed` | 0.5.0 had two review rounds; the fixes made after the second (the lock file's mode and place, the work folder removed by uninstall, three menu texts) were tested and not reviewed again. The second fix round of 0.4.0 and the two Windows install fixes of 2026-11-25 have had no independent review either. A further round needs Maxwell's go-ahead. |

## 28. Changes being built

Nothing is being built.

When work starts, the body of this spec is changed first and each changed place is marked **BEING BUILT** with a name that is listed here. When the work is built and tested, the marks go, the body is corrected to what was really built, and the entry moves to the change log.

## 29. Change log

Newest first. Dates are when the change was built. 0.4.0 is the first tagged release; 0.3.0 was never released on its own.

### 0.5.0 (2026-11-26, tag `v0.5.0`)

- **2026-11-26: three channels, configuration, and updating the whole mesh** (Maxwell: "the fewest channels work well with powerful and sensible configurations; no specialized features for a unique task"; and "how the entire network will get updated"). Built:
  - `build/channels`: section 12 names three channels, mail, tools and shell, and section 12.1 shows which channel and which configuration each use goes through; no use has a feature of its own. Commands accept `mail` for `converse`, which stays the word in the file; what people read before signing says `mail`. A new grant from a machine to itself is refused; one that 0.4.0 signed still loads and can be revoked.
  - `build/mailbox-rules`: `mailboxes.toml` gains `from` (which senders wake a mailbox), the table `"*"` (every mailbox without a table of its own, on one shared hourly budget) and the command argument `{mailbox}`. `sessions.json` is read and written only with `resume`.
  - `build/answer-note`: `send_message` adds a note when the address has no status record and no live session holds it here, naming the agents on that machine that have one; `board_post` says a post wakes no agent.
  - `build/permissions-box`: the Mesh screen's table shows "may do there" and "may do here" and has an **All machines** row; the Permissions box says "What A may do on B" for mail, tools and shell, shows what a grant for all machines already turns on, grants on a tick and revokes on its removal, all in one signature. The revoke form and the any-pair grant form are gone (`mesh grant`, `mesh revoke`). The approval form uses the same words.
  - `build/versions`: a ping carries the machine's version; `status` has `version`, `mesh.release` and a version per pinged machine; the menu shows them.
  - `build/update`: `tearmesh update [--to V]`, `update --check`, `update --mesh`; the setting `release` in the membership file (`mesh set release`); the updater (a systemd timer, a Windows scheduled task); install enables it and restarts the gateway. Section 22.3.
- **Found by two review rounds and fixed:** the download is checked and run beside the installed program, not in the temp directory; a lock keeps two updates apart, and only root can hold it; a ping answer longer than a version is refused, not cut; on Windows the old program gets a name of its own at each swap; uninstall removes what an interrupted update left; small menu fixes. Recorded as limits or text, not changed: the updater trusts the stored file without checking signatures again; `from` proves only the machine part of a sender.
- **Tried on three throwaway containers** (section 26). **Not built, on purpose:** more levels of mail permission; board posts that wake agents; an OS sandbox per mailbox; tools and shell through the gateway (`open/gateway-channels`); signed releases (`proposed/signed-releases`); an updater under OpenRC; signing the release or one-sided `*` grants from the menu.
- Building from source now needs Rust 1.89.
- **Agreed by Maxwell on 2026-11-26, after the build:** the updater on by default; Rust 1.89; the All machines row as the first row of the Mesh screen's table, where the selection starts.
- **Published on 2026-11-26.** The release workflow ran at the tag; the owner's two Linux machines were upgraded with the published install line; a task mailbox was set up on his workstation by configuration alone (`proposed/task-agent`). Found on that day and not fixed: `fix/board-wake-at-check`. Asked for in a voice call: `proposed/node-version-in-tools`. The owner's mesh names 0.5.0 since the same day (`mesh set release`, membership version 5), signed once its third machine also answered a ping with that version; the two Linux machines hold the file and report that they are up to date.

### 0.4.0 (2026-11-25, tag `v0.4.0`)

- **2026-11-24 and 25: the Claude connector** (Maxwell's build list of 2026-11-24, "gateway, tool surface, inbox"). Built:
  - `build/talk-tools`: the seven conversation tools (`list_nodes`, `node_status`, `send_message`, `inbox_list`, `inbox_fetch`, `board_read`, `board_post`) and three agent tools (`set_status`, `claim`, `set_bio`), one implementation for the mail server, the hub and the gateway. The old `who`, `post`, `inbox`, `read` and `wait_for_mail` tools are gone.
  - `build/status-records`, `build/claims`, `build/daemon-requests`: status records and known agents; claims ("working on it"); the daemon requests `reach`, `claim`, `set_status`; `post` with an idempotency key; `inbox` narrowed to a thread. The steward registers its mailboxes and wakes on `guest` only where `wake_on` lists it.
  - `build/gateway`: `tearmesh gateway` (setup, serve, status, grants, revoke, passphrase, remove): an MCP server for Claude's apps behind a tunnel, with OAuth sign-in (dynamic registration, PKCE, rotating refresh tokens), limits and an audit log, running as a guest OS user of its own. The connector of 0.2 and 0.3 (`tearmesh mcp --http`, `repo_status`, `read_file`) is removed.
  - `build/desktop-extension`: `tearmesh.mcpb` for Claude Desktop, packed by the release workflow. `build/install-me`: `install --me BOUNDARY`.
- **Two security reviews, a fix round after each.** The first found that the gateway, running as the boundary's OS user, was a full member once taken over; that anyone could lock the owner out of sign-in or stop registration; and that slow requests could hold every connection. Since then: the gateway has an OS user of its own that the daemon holds to guest trust, one mailbox and six requests (`[guests]`); there is no lockout and registration stores nothing; bodies have time limits. The second found that root's `tearmesh gateway …` commands shared root's terminal with the gateway's user, that "sent by it" was matched by address alone, and that `gateway setup` could take a boundary's user as its own: all fixed. Left as limits: `limit/gateway-port-local`, `limit/gateway-slow-connections`.
- **Checked on 2026-11-25** with `cargo test` (209 tests), `tests/e2e-linux.sh` (43 checks), `tests/e2e-0.3.sh` (162 checks) and `tests/e2e-0.4.sh` with its system part (295 checks) in a Debian container; and by hand on three Debian containers: an upgrade in place from 0.3.0 (node id and mesh kept; a machine still on 0.3 stops at the first status record and catches up after its upgrade), a new machine joining, `gateway setup` and `remove` as root, sign-in and every tool through `tests/gateway-client.py`, a question from the gateway waking a scripted agent on another machine that claimed and answered, an agent's question answered back in its thread, a revoked sign-in, an offline node, the owner removing the gateway machine, and the same sign-in and calls once through a public HTTPS tunnel from another network. The Windows build was run under Wine only. Not run: what point 3 of section 26 lists, `tests/distros.sh`, `tests/e2e-windows.ps1`, the release workflow.
- **Where the build differs from the build list** (each the conservative choice; Maxwell decides): sign-in is a generated six-word passphrase, not an identity provider; the gateway is a process and OS user of its own, not a part of the daemon; it serves the conversation tools only, never shared tools or shell; one boundary per gateway; sign-ins are listed and ended on the gateway machine only; registration is dynamic only (no client ID metadata documents); the tunnel is not set up by tear-mesh; nothing in the inbox expires; the menu has no gateway screens yet.

- **2026-11-25: the first release.** The release workflow ran for the first time. Both Linux builds passed their install test. The Windows install test failed: `install.ps1` kept its Administrator check in a variable named `$me`, which PowerShell reads as the `-Me` parameter, so the script stopped before it downloaded anything. The Windows one-line install had never worked since `-Me` was added. The variable was renamed. The next run found a second one: started from PowerShell 7, `tearmesh install` ran its script in Windows PowerShell 5.1 with PowerShell 7's module path, where `ConvertTo-SecureString` cannot load, so no boundary user could be made. tear-mesh now starts Windows PowerShell without the caller's `PSModulePath`. The tag was moved to these fixes before anything was published; the third run passed on all three targets and the release was published the same day. Its notes came out as the last commit's message, because the workflow's checkout leaves the tag without its own message; they were set by hand, and the workflow now fetches the tag first (not run yet).

### 0.3.0 (never released on its own; part of 0.4.0)

- **2026-11-19 and 20: product review.** This specification replaces `docs/spec-0.2.md` and `docs/design.md` as the source of truth. A review of the product (two fresh machines, from install to mail to shared tools, plus a read of every source file) and two independent code reviews led to the changes listed under "Changes from the product review" below. Checked on 2026-11-20 with `cargo test` (147 tests), `tests/e2e-linux.sh` (50 checks) and `tests/e2e-0.3.sh` (162 checks), and by hand on Debian containers through the one-line installer (two machines in a mesh; a third for the upgrade from the 2026-10-19 build, install and uninstall); `tests/distros.sh`, `tests/e2e-windows.ps1` and the release workflow were not run.
- **2026-11-12 to 18:** leaving and dissolving (the farewell rule, tombstones, `mesh dissolve`, `mesh reset`, "says it left"); permissions shown as speak and listen with the six switches in the menu; mail screening with quarantine; the one-line installers and the release workflow's smoke tests; install with no boundaries, add boundaries later; the owner picks boundaries at approval.
- **2026-10-20 (commits `e776da7` to `e900a09`):** `tearmesh menu`; owner keys made and used in memory, one recovery key with a generated passphrase; the new machine proposes its name and boundaries, one signature for many changes; the MCP hub; `tearmesh install` and `uninstall`; release binaries.

#### Changes from the product review (2026-11-19 and 20)

**Daemon**

- `fix/leave-frees-machine`. A machine that leaves a mesh on its own is free afterwards. New admin request `leave_mesh`: the daemon leaves the way a removed machine does (logs moved to `boundaries-<mesh id>/`, `mesh-id` removed, no tombstone), or forgets a dissolved mesh. The menu's Leave, the old wizard's "leave and set up again" and the new command `tearmesh mesh leave` use it. `mesh reset` keeps its meaning (forget the file but keep the logs bound to the same mesh, for re-pinning after every owner key was lost). Before: Leave used reset, which keeps `mesh-id`, so the machine could neither create a mesh nor join a different one ("this machine was reset from mesh X; a file for mesh Y would strand its logs").
- `fix/unhex-no-panic`. A signature or hash field that is not plain hexadecimal is refused as bad input. Before: a peer could send a signature with a multi-byte character that made the receiving task panic.
- `fix/sync-at-start`. The daemon runs its first sync round when it starts, not one interval (30 s) later.
- `fix/full-log-warning`. When a boundary log is full and synced mail is being refused, `tearmesh status` carries the warning `boundary <b>'s log is full (<n> MB): mail for it is not being stored; raise max_log_mb`. Before: only a debug log line.
- `fix/budget-after-checks`. A post that is refused (bad recipient, long subject, no grant) no longer uses one of the boundary's posts for the hour.
- `fix/limits-at-least-one`. `max_thread_len`, `max_posts_per_hour` and `max_log_mb` must be 1 or more; the daemon refuses to start on 0 and names the key.
- `fix/relay-urls-checked`. A change that sets `relays` must be `n0`, `none` or http(s) URLs; anything else is refused when the version is made. Stored versions are not re-checked.
- `fix/ticket-min-life`. A ticket must last at least one second (`--expires 0` is refused: "a ticket must last at least a second").
- `fix/approved-frame-kept`. When the owner node approves a waiting machine, the invite is deleted only after the approved file was written to that machine. If the write fails the invite is kept as approved-while-away, so the machine gets the file when it joins again with the same ticket. Before: a lost last frame left the machine in the mesh file but unable to fetch it.
- `fix/owner-change-message`. A joiner that is handed a file signed by other owner keys than its ticket named says so in words a person can act on: "… the mesh's owner keys changed after this ticket was made; ask the owner node for a new ticket".
- `fix/unmapped-hint`. An admin with no boundary who runs a mail command is told what to do: the error "this OS user isn't mapped to a boundary" continues with ": mail belongs to a boundary user; run the command through `tearmesh launch --boundary <b> -- …`".
- `fix/address-hint`. A recipient that is not an address is refused with the form to use: `bad address "alpha": use mailbox@machine (for example admin@alpha), or * for everyone`.
- `fix/apply-says-not-adopted`. `mesh apply` of a file this machine did not adopt (an older fork, or the losing one of two versions with the same number) fails with "version N (<hash>) wasn't adopted: this machine keeps its own version M" in place of printing "applied".

**Doors for agents**

- `fix/steward-stays-up`. A steward with no `mailboxes.toml`, `offers.toml` or `screen.toml` keeps running (it still screens when the daemon asks) and logs once that nothing is configured. Before: it exited with an error, which under the shipped service is a restart loop.
- `fix/steward-rereads`. The steward reads `offers.toml` again when a peer opens a tool stream and `mailboxes.toml` again before it checks a mailbox, so an edit works without a restart. A file that no longer parses keeps the last good contents and logs a warning.
- `fix/mcp-reconnects`. The mail server for agents (`tearmesh mcp`) opens a new session with the daemon when the old one is gone, so mail tools work again after a daemon restart or upgrade without restarting the agent.
- `fix/wait-for-mail-no-spin`. The hub's `wait_for_mail` falls back to asking every 3 s when its event subscription ends. Before: it asked in a tight loop until its deadline.
- `fix/shell-exec-cap`. The hub's `shell_exec` stops the command as soon as its output reaches 256 KiB on either stream and returns what it has with `truncated: true`. Before: it waited for the command to end, usually into the timeout, and returned nothing.

**Menu**

- `fix/menu-shell-boundary`. The menu's Shell key works for an admin who has no boundary: it names a boundary both machines host. With none shared it says so.
- `fix/menu-boundary-user`. Run as a boundary user, the menu says who you are and opens on Mail. Its header reads BOUNDARY USER; the Mesh screen says the mesh is managed by an admin of this machine; Settings still shows and starts that user's MCP hub. Before: it showed NOT SET UP and "The daemon isn't answering".
- `fix/menu-keeps-mesh`. A refresh that fails to fetch the membership file keeps showing the last one. Before: one failed fetch showed "This machine isn't in a mesh yet" with Create and Join offered.
- `fix/menu-shift-keys`. The key bar writes the three keys that need Shift as `Shift-H`, `Shift-K`, `Shift-L`.
- `fix/menu-form-field`. A form that fails a check names the field and puts the cursor on it.
- `fix/menu-recovery-hidden`. While the menu asks for word 3 of the recovery passphrase, the passphrase is not on the screen.

**Command line and install**

- `fix/launch-without-sudo`. `tearmesh launch` run as root on a machine with no `sudo` uses `su`. Not root and no sudo: "launch needs sudo, or run it as root".
- `fix/install-next-line`. Install ends with "Next: tearmesh menu" when it was run by root directly, and "Next, as yourself (not root): tearmesh menu" when run through sudo.
- `fix/install-checks-daemon`. After starting the service, install waits up to 10 s for the daemon to answer. If it does not, install ends with an error that says where the daemon's log is. Skipped where install started no service.
- `fix/install-stewards-last`. `install --stewards` on a machine without systemd finishes the install (plugin files, the closing lines) before it reports that stewards need systemd.
- `fix/install-no-boundaries-line`. An upgrade (`tearmesh install` with no boundaries on a machine whose config already maps boundary users) no longer ends with "No boundaries yet".
- `fix/uninstall-busy-user`. Uninstall on Linux failed halfway (service removed, everything else left, `the install script stopped (exit status: 8)`) when the service user or a boundary user still had a process: for about 10 s after any install, because install's own login as the service user leaves a user manager behind, and whenever a boundary user's session or agent was still ending. Uninstall now ends those processes and waits for them before it deletes the user. Found and checked by hand in a systemd container; `tests/distros.sh` runs without systemd and does not cover it.
- `fix/install-name-length`. Install refuses a boundary whose OS user name would be too long for the system (`tm-<boundary>` over 32 characters on Linux, over 20 on Windows) before it changes anything.
- `fix/install-config-restored`. If the install script fails after install added users to an existing config, the config is put back as it was.
- `fix/dissolve-uninstall-safe`. `mesh dissolve --uninstall` uninstalls only when the dissolve was signed and applied to this machine's daemon. Otherwise it stops with "not uninstalling: the dissolve wasn't applied".
- `fix/letters-printed-clean`. `tearmesh read`, `inbox` and `bio show` replace control characters (other than newline and tab) in what other machines wrote with U+FFFD, as `quarantine show` already does.
- `fix/post-help`. `tearmesh post --help` describes every flag; `mesh invite --help` says a bare number of `--expires` is minutes.
- `fix/mesh-leave-command`. New: `tearmesh mesh leave [--yes]` tells the other machines, then leaves (see `fix/leave-frees-machine`). `mesh reset`'s prompt says what it keeps and points to `mesh leave`. The errors that sent people to `mesh reset` to get out of a mesh name `mesh leave` instead: "this machine already belongs to a mesh (run `tearmesh mesh leave` first to leave it)", and the two "this machine was reset from mesh …" errors end with "(to leave that mesh for good: tearmesh mesh leave)".
- `fix/release-url-override`. With `TEARMESH_RELEASE_URL` set in the environment of `tearmesh menu` or `tearmesh mesh invite`, the one-line install commands they print fetch from that folder and pass it on to the install script. For mirrors and for trying a build before it is released.
- `fix/stripped-binary`. Release builds are stripped of debug symbols.

**From the reviews of 2026-11-20**

Two independent reviews of the changes above (the daemon and the menu) found these. None changes a file format or a protocol.

- `fix/leave-holds-logs`. While a machine leaves a mesh, nothing can open one of its boundary logs: a sync or a post under way either finishes before the logs are moved aside or is refused because the machine is no longer in the mesh. Before: a sync that ran during a leave could reopen a log, and on Linux the next mesh's mail then went into the old mesh's moved log until the daemon restarted.
- `fix/leave-closes-tickets`. When a machine stops being in a mesh in any way (it leaves, it is removed, the mesh is dissolved) every ticket it made and every join request waiting on it is dropped. Before: they lived on, and after the machine created another mesh an old ticket's machine showed up as a join request for the new mesh.
- `fix/rejoin-while-listed`. A machine that left on its own but is still listed in the membership file is refused when it comes with a new ticket, and the refusal says what to do: remove it first, or apply the current membership file on it. Before: only "already in the mesh as NAME".
- `fix/bad-mesh-id-named`. If the `mesh-id` file a reset left behind does not hold a mesh id, `mesh leave` fails with an error that names the file to delete.
- `fix/log-limit-no-wrap`. A very large `max_log_mb` no longer wraps around into a tiny limit.
- `fix/menu-leave-text`. The Leave question (in the menu and in the old wizard) says the logs are kept and moved aside, not that they stay.
- `fix/menu-boundary-settings`. For a boundary user, Settings says the mesh is managed by an admin of this machine, in place of "(no mesh)" and "owner key none here".
- `fix/menu-key-bar-width`. The key bar sizes its key column from the widest key on it, so `Shift-L` does not push the items after it out of line or off an 80-column screen.
- `fix/menu-keeps-mesh`, addition: the last membership file is kept only while the daemon still names the same mesh id.
- `fix/menu-shell-boundary`, addition: only the answer "isn't mapped to a boundary" counts as having no boundary; any other failure is shown as it is.
- `fix/menu-recovery-hidden`, addition: asking for the word again clears the note about the wrong word.
- `fix/menu-mail-after-leave`. After Leave the Mail screen shows no letters of the mesh that was left.

### 0.2.0 (2026-10-18)

The membership file as a signed hash chain with owner keys; grants; tickets with approval; offers, approvals and the tool bridge; shell streams; the connector; bios; portable Linux install (systemd, OpenRC); the native Windows port. Specified in `docs/spec-0.2.md`.

### 0.1.0 (2026-10-16)

Boundaries as OS users, one log per boundary, signed entries, sync over iroh, mail, the stdio mail server, the hook and the wake-on-mail steward, a single signed "circle" file. Designed in `docs/design.md`.
