# tear-mesh 0.2.0: Spec

2026-10-18 · builds on [design.md](design.md) rev 3 and a design review held 2026-10-16/17. The decisions in §15 were settled on 2026-10-18 after an adversarial review; §15 lists what changed. Implemented in 0.2.0.

Status markers: 🟩 settled · 🟨 proposed, needs a maintainer decision · 🟥 open, check before building

## What changes

0.1.0 is mail between agents inside boundaries. 0.2.0 makes tear-mesh a mesh that connects **apps, not whole machines**. An agent on one machine can:
- call MCP servers that other machines offer;
- open a shell on machines that allow it;
- read what each machine says about itself.

All of this runs over iroh, under owner-signed permissions. Mail stays, and becomes the board.

**Headline use:** one agent drives MCP servers and other capabilities on other machines, from anywhere. The other machines don't need an agent of their own.

**Positioning, for the README.** Overlap to admit:
- machine bios overlap with A2A Agent Cards and MCP server cards and registry metadata;
- Tailscale and Headscale already solve the machine-level mesh.

What's different from Cloudflare Tunnel or ngrok with OAuth, or from Tailscale with HTTP MCP:
- no public endpoint;
- no VPN, and system DNS and routes are never touched;
- stdio MCP servers are bridged unmodified;
- permissions are owner-signed per pair of machines;
- one install.

## Scope

| Milestone | Contents | Needs |
|---|---|---|
| **M1 Connector** | `tearmesh mcp --http` for Claude custom connectors: mail tools plus read-only repo and file tools (§10) | 0.1.0 only. Can ship early as 0.1.1. |
| **M2 Mesh v2** | Rename circle → mesh, membership file format 2, owner model, grants, converse enforcement, ticket joins with approval, `tearmesh setup`, mDNS/DHT lookup, one ALPN per capability, envelope v2 (§1–5, §8) | Breaking change |
| **M3 Tools** | Offers, the steward, `tearmesh mcp --remote`, `tear-mesh/mcp/1`, pinning and approval, bios (§6–7) | M2 |
| **M4 Shell** | `tear-mesh/shell/1` to the local sshd, `tearmesh shell-proxy` (§9). Cut it first if 0.2 runs long. | M2; shares M3's stream code |

Native Windows (named pipes, Windows accounts as boundaries, a Windows service) was pulled into 0.2 as well.

**Not in 0.2:**
- short join codes;
- the honeypot reader, reader/gatekeeper/worker and taint;
- approval taps on the phone;
- claims and the settling window;
- the routing admin;
- a Claude Desktop extension;
- HTTP MCP servers on the offering side;
- macOS;
- the egress lock;
- Channels push and other harness adapters.

Rev 3 had planned macOS, the egress lock, Channels push and the adapters for 0.2. They move to 0.3 or later.

## 1. Terms

- **Mesh**: the group of machines (was *circle*). `tearmesh mesh …`, `mesh.toml`. 🟨 The rename costs nothing extra, because the format breaks anyway.
- **Membership file**: the owner-signed list of machines, boundaries, owner keys, settings, grants and approvals (was the circle file).
- **Owner key**: an SSH key listed in the membership file. Holding one is owner authority.
- **Owner node**: the machine where the person keeps their everyday owner key and approves joins. It's where the person works, not a field in the file.
- **Grant**: permission for one machine to act on another, in one category.
- **Offer**: a machine's signed statement of an MCP server it shares in a boundary.
- **Bio**: a machine's signed "about this machine" text in a boundary.
- **Steward**: the per-boundary process that runs as the boundary's OS user. It wakes mailboxes and serves offers, and replaces `tearmesh waker`. 🟨 The name is open.

Unchanged from 0.1.0: boundary = OS user, one log per boundary, same-boundary-only, mailboxes as roles.

## 2. Transport

🟩 iroh, as in 0.1.0. These already exist:
- n0's public relays are the default;
- you can configure a list of your own relays;
- every connection's node key is checked against the membership file in the handshake hook. iroh proves identity; this hook authorizes.

🟩 **One ALPN per capability:**

| ALPN | Use | Who may open it |
|---|---|---|
| `tear-mesh/sync/2` | Log and membership sync (was `tear-mesh/1`) | Members |
| `tear-mesh/join/1` | Ticket joins | Anyone, but only while an invite is pending |
| `tear-mesh/mcp/1` | Tool calls | Members with a `tools` grant to this machine |
| `tear-mesh/shell/1` | Shell | Members with a `shell` grant to this machine |

The TLS handshake fails for any ALPN the endpoint doesn't list, so a bare QUIC connection exposes nothing. The handshake hook keeps refusing non-members everywhere except on the join ALPN while an invite is open.

**Address lookup** (mesh setting, which each machine can override locally):

| Method | Default | Crate |
|---|---|---|
| n0 DNS | On | iroh's own, as in 0.1.0 |
| mDNS on the LAN | On | `iroh-mdns-address-lookup` 0.6 |
| Mainline DHT | Off | `iroh-mainline-address-lookup` 0.6 |

Both new crates target iroh ^1.0 and are MIT OR Apache-2.0.

- **Already the default:** iroh's pkarr publisher publishes only the relay URL (`AddrFilter::relay_only`), so IP addresses don't land in DNS or the DHT. Relays and directly connected peers still see IPs; a direct path needs them.
- **Relay rate limits:** iroh 1.3 records when a relay reports rate-limiting (`relay_conns_ratelimited`). `tearmesh status` shows it, so a slow tool call over a busy public relay is explainable.
- **No project-run relay or discovery server.** Peers already know each other's keys from the membership file, so key-to-address lookup is all they need. A rendezvous server only arrives with short join codes (0.3).
- **On resume:** the existing 30-second sync loop re-dials and catches up after sleep or a network change. Nothing new is needed.

## 3. Owners and the membership file

### 3.1 Owner model 🟨

This reconciles "one owner node plus a portable key" with rev 3's "at least two owner keys". They are the same thing:
- Owner authority is holding any owner key, as in 0.1.0.
- The default setup has exactly the two keys the floor requires: the owner node's key and the portable key.
- **The portable key should be a security key** (`sk-ssh-ed25519`), which 0.1.0 already supports, with the daemon checking user presence. There is nothing to copy and nothing left on a machine after use.
- **Fallback: a passphrase-protected ed25519 key file** on removable media. Use it in place (`--key /media/…/owner`) and don't add it to `ssh-agent`, so it isn't stored on the machine. Use a long passphrase, since a stolen file can be attacked offline. Docs say never to email it.
- **Promoting a node to owner** means adding its key and removing the old one in one signed version. No separate revocation object.
- **The daemon never holds an owner key.** Signing always runs `ssh-keygen -Y sign` as the person.
- **Signing threshold** 🟨. Any one owner key can sign any change, including a change to the owner list. A stolen portable key is therefore a takeover until every machine is re-pinned. Options:
  - Keep 1-of-N, with security keys as the default (recommended for 0.2).
  - Require two owner signatures to change the owner list.
- **Loss and recovery.** Losing every owner key freezes the mesh. To recover, run `sudo tearmesh mesh reset` on each machine. It forgets the adopted membership file and keeps the logs, so the next file is adopted the way a first one is: that's the physical re-pin. It only works locally, by design.

### 3.2 Format 2

```toml
format = 2
id = "9f3c…"                        # fixed at creation, as in 0.1.0
name = "home"
version = 12                        # only goes up
owners = [
  "ssh-ed25519 AAAA… laptop",
  "sk-ssh-ed25519@openssh.com AAAA… portable",
]
boundaries = ["work", "vault"]

[settings]
relays = "n0"                       # "n0", "none", or a list of URLs
lookup = ["n0-dns", "mdns"]         # add "dht" for Mainline
tools_sharing = "approval"          # or "free"

[[machine]]
name = "laptop"
id = "<node id>"
boundaries = ["work"]

[[machine]]
name = "workstation"
id = "<node id>"
boundaries = ["work", "vault"]

[[grant]]                           # mail among everyone, as in 0.1.0
from = "*"
to = "*"
allow = ["converse"]

[[grant]]
from = "laptop"
to = "workstation"
allow = ["tools", "shell"]

[[approved]]                        # only used when tools_sharing = "approval"
machine = "workstation"
boundary = "work"
server = "cad"
pin = "<blake3 of the tool list>"
tools = ["export_step", "read_properties"]   # optional subset
```

- **Rules kept from 0.1.0:** the id matches; the version goes up; the file must be signed by an owner of the current version; there are at least two distinct owner keys; `deny_unknown_fields`.
- **New validation:**
  - Grants name listed machines or `*`.
  - A grant with `shell` must name both machines.
  - Approvals name a machine that hosts that boundary.
- **Local overrides:** a machine's own `config.toml` `[network]` still overrides `relays` and `lookup` for that machine. How much metadata a machine exposes is its admin's call.
- **Migration:**
  - `tearmesh mesh migrate circle.toml` writes the format-2 equivalent, with one `* → *` converse grant so mail behaves as it did. The owner signs it.
  - Daemons adopt it as the next version, so there's no re-pin, and logs are kept.
  - 0.1 and 0.2 daemons can't talk to each other (the ALPNs are new), so upgrade all machines together.
- **Visibility:** every member sees the whole file. That means boundary names (as in 0.1.0), every grant, and the names of approved servers and tools. Documented.

## 4. Joining

### 4.1 First run 🟩

`tearmesh setup` is an interactive wizard. The daemon parts need root; signing uses the person's own keys. It has two choices:
- **Create a mesh:**
  1. Install the daemon and the boundary users, as `setup-linux.sh` does today.
  2. Create or pick the owner key, prompting for a portable key as the second.
  3. Write a membership file listing this machine, and sign it.
  4. Choose connection settings: defaults, with an Advanced section for relays, lookup and DHT.
- **Join a mesh:** install, then join with a ticket.

`setup-linux.sh` stays as the non-interactive path.

### 4.2 Tickets with approval 🟩

Tickets are 0.2's only join method. They're about 150–250 characters, depending on the relay URL and addresses they carry.

1. **On the owner node**, `tearmesh mesh invite --name beta --boundary work [--expires 1h]` prints `tm2-…`. The ticket is built at that moment from the current settings and holds:
   - the owner node's id and current addresses;
   - the mesh id;
   - a hash of the owner key set;
   - a 128-bit one-time secret;
   - an expiry.
2. **On the new machine**, `sudo tearmesh join tm2-…` dials the owner node on `tear-mesh/join/1`. It proves it holds the secret, bound to its own node id (an HMAC of its id), and asks for the name and boundaries. Both screens show the same 6-digit code, derived from the secret and both node ids.
3. **The person compares the codes and approves.** `tearmesh mesh pending` lists requests. `tearmesh mesh approve beta` then:
   - adds the machine;
   - bumps the version;
   - signs with the owner key;
   - applies the file locally.

   The owner node then hands the signed file to the waiting joiner. A leaked ticket alone gets nobody in.
4. **The joiner adopts the file** as its first membership file only if it lists the joiner's node id, its owner set matches the ticket's hash, and the signature verifies. This replaces 0.1.0's y/N prompt; the fingerprints are still printed.

Rules:
- A ticket is single use. Expired or used tickets are refused.
- The join ALPN refuses everything while no invite is pending. Join attempts are rate-limited and logged.
- If the owner node is offline, `join` fails with `owner node <id> not reachable`.
- New machines get no grants beyond the wildcard grants already in the file.
- 0.1.0's `invite` (any member, carrying the whole circle) is removed.
- **No ticket signatures.** The review proposed signing tickets so a doctored one can't redirect a joiner to a malicious relay. That signature can't help:
  - A joiner can't check it without already trusting the key.
  - Anyone who can alter a ticket can replace it outright.
  - A relay can't read or forge iroh traffic anyway.

  What protects the joiner is the owner-set hash, the matching codes, and the owner confirming they see the request.

### 4.3 Short join codes (0.3)

The default join method is settled as short codes, but they ship after 0.2.
- A Wormhole-style code (`7-purple-lantern`) can't carry a node id, so it needs a rendezvous server.
- The design:
  - SPAKE2 (RFC 9382) via RustCrypto's `spake2` crate (MIT OR Apache-2.0);
  - codes from a CSPRNG;
  - single use, expiring in 5–10 minutes, burned after one wrong attempt;
  - a rate-limited server.
- The `magic-wormhole` Rust crate is EUPL-1.2, so don't link it. Speaking the Wormhole mailbox protocol to a public or self-hosted mailbox server is an option to evaluate.
- The rendezvous server only introduces peers and never decides membership. It's a public service someone has to run, and the project has no host for it yet.
- The same approval and matching-code step applies. Members are identical whichever way they joined. A mesh with no rendezvous configured offers only tickets.

## 5. Permissions

### 5.1 Grants

🟩 Settled: three categories (`converse`, `tools`, `shell`), each directional, each per pair of machines, and few and broad.

🟨 **Encoding: one directed edge per grant.** "A speaks shell to B" and "B listens to shell from A" are the same edge read from either end, so the file holds one `from → to` record, not two flags. Two flags would double the owner's work and allow dead settings (A may speak, B won't listen). The CLI and TUI show each machine's speak and listen lists.

| Category | `from → to` lets `from`… | Checked |
|---|---|---|
| `converse` | send letters that `to` will deliver | On posting at `from`; on delivery at `to` |
| `tools` | call the servers `to` offers | At both daemons |
| `shell` | reach `to`'s sshd | At `to`'s daemon |

- Deny by default. `*` matches any machine, except in `shell` grants.
- Example: an owner node that drives others but can't be driven has `shell` grants out to other machines and none in.

### 5.2 Boundaries and grants 🟨

A boundary decides where data may live. A grant decides which machine may act on which. Both must pass:
- **converse A → B:** the letter's boundary is hosted by both machines (as in 0.1.0), and the grant exists.
- **tools A → B:**
  - the calling session's boundary X is hosted by A and B;
  - B offers the server in X;
  - the grant exists;
  - the offer is approved, if the mesh requires approval.

  A `vault` session can't call `work` tools, and a `work` session can't reach `vault` tools. Same-boundary-only still holds.
- **shell A → B:** the grant exists. tear-mesh delivers bytes to B's sshd, and sshd decides which user logs in. tear-mesh can't see inside SSH, so it can't stop a `work` session from logging in as `tm-vault`; B's `authorized_keys` must. This is listed as an enforcement gap.

### 5.3 Converse 🟨

**Keep converse as its own category.** Agents do reach mail through tools (`post`, `inbox`, `read`, and now `bio`), but mail isn't a call to the other machine. Letters replicate through the boundary log and can arrive through a third machine. Treating mail as a tool call would make delivery depend on a direct connection.

Enforcement:
- **On posting:** the sender's daemon refuses a recipient machine it has no converse grant to.
- **On delivery** (inbox, hook, wake, MCP): a machine shows only letters whose author has a converse grant to it in the current file, so revoking a grant also hides that author's old letters.
- **Replication is unchanged.** Every host of a boundary stores every letter in it. Converse decides who may address whom; the boundary decides who may store what. Filtering at replication would leave gaps in the authors' hash chains and break catch-up. Hidden letters stay in the daemon's database, which boundary users can't read.

Machines with converse only (no tools, no shell) are normal.

## 6. Tools over the mesh (M3)

### 6.1 Offers 🟩

**Local definition.** The boundary user defines offers in `~/.config/tearmesh/offers.toml`:

```toml
[cad]
command = ["/opt/cad-mcp/bin/server"]
description = "Parametric CAD export and properties"
# env = { CAD_HOME = "/opt/cad" }
```

**Publishing.** `tearmesh offer publish cad`, run as the boundary user:
1. It starts the server and runs `initialize` and `tools/list`.
2. It posts an **offer entry** in that boundary's log. Like every entry, it's signed by the machine.

The entry carries:
- the server name and description, plus the name and version the server reports;
- the exact tool list: names, descriptions and input schemas;
- `pin`, the blake3 hash of that list's canonical JSON;
- `exe`, the blake3 hash of the executable, when `command[0]` is a local file.

**Notes:**
- For `npx` or `uvx` commands, the code is fetched at run time. Pin the package version in the command, and expect no `exe` hash.
- The command line and environment stay local, because they may hold paths and secrets.
- Offers are visible only inside their boundary, like letters. A machine's offers are its list of available tools on the board.
- Default deny: a machine shares nothing until it publishes an offer, and the owner can't make it share.

### 6.2 Approval 🟩

The membership file's `tools_sharing` decides:
- **`free`:** a machine with a `tools` grant can call any published offer.
- **`approval`:** each offer also needs an `[[approved]]` entry, carrying the machine, boundary, server, pin and an optional tool subset.
  - The owner reviews offers with `tearmesh offers` on any machine that hosts the boundary, because offers live in the boundary log.
  - The owner approves with an owner key; the portable key works away from the owner node.

The owner can switch modes later, and the change reaches every machine with the next version.

**Pin changes.** Any change to the tool list changes the pin, and the offer goes back to pending.

**Per-tool scoping** 🟨: the optional `tools` subset. Recommended, because the daemons parse every call anyway.

### 6.3 The call path

```
laptop                                                    workstation
Claude Code ─stdio─ tearmesh mcp --remote workstation/cad
                      └─socket─ daemon ══ iroh tear-mesh/mcp/1 ══ daemon ─socket─ steward (tm-work) ─stdio─ server
```

**Client shim.** `tearmesh mcp --remote <machine>/<server>` looks like any stdio MCP server: `claude mcp add cad -- tearmesh mcp --remote workstation/cad`.

**Laptop daemon:**
1. Learns the session's boundary from `SO_PEERCRED`, as today.
2. Checks the grant, the boundaries, the offer and the approval.
3. Opens a stream whose header names the boundary and the server.

**Workstation daemon:**
1. Checks the same things independently.
2. Signals the boundary's steward over its existing subscription.
3. The steward opens a new socket connection. The daemon checks that connection's uid and splices it to the stream.

The daemon never starts user code.

**Steward.** Running as `tm-work`, it starts one server process per stream and pipes newline-delimited JSON-RPC.

**Both daemons parse the JSON-RPC lines** (MCP's stdio framing):
- **The workstation daemon** refuses `tools/call` for tools outside the pin or subset. If a `tools/list` result doesn't match the pin, it closes the stream and marks the offer pending.
- **The laptop daemon** checks every `tools/list` result against the pin too. This end protects the caller from a machine whose tools changed after approval, including descriptions that now carry injected instructions.
- **Limits:** a line cap (4 MiB by default, configurable), an idle timeout, and a cap on streams per peer.

The offering side is stdio only in 0.2. HTTP MCP servers come later; until then, put them behind a stdio adapter.

### 6.4 What verification can't do 🟩 (README requirement)

The README gets this section, with the path that led to it:
1. **A machine signs its own offer.** That proves which machine made the claim, not what code runs.
2. **The owner approves it.** A person decided, but still on a claim.
3. **The hash and pinned tool list catch changes**, and the owner can compare the hash with the author's published release. But a compromised machine can report any hash it likes.
4. **A live challenge over the mesh** proves that something answers, not what it is. 0.2 doesn't build a nonce challenge, because it adds nothing a live `tools/list` doesn't.
5. **Proving unmodified code needs hardware remote attestation:** Intel SGX/TDX, AMD SEV-SNP, Arm CCA, AWS Nitro Enclaves or TPM measured boot. All of these are hardware-specific. They stay out of the core; an add-on could provide them.

The security model is: **only admit machines you trust.**

An idea for later: an add-on MCP authors drop into their servers, for author-signed releases and manifests. If built, it should align with MCP registry metadata, not invent a format.

## 7. Bios (M3) 🟩

- **What a bio is:** an entry in a boundary log. Each machine has one current bio per boundary, and the latest wins.
  - The body is YAML, at most 16 KiB.
  - The daemon stores the text and doesn't parse it.
- **Commands:** `tearmesh bio edit` (opens `$EDITOR`) and `tearmesh bio set <file>`.
  - Agents get a `bio` MCP tool.
  - `who` lists each machine's bio and offers.
- **Who may write it** 🟨: any session in the boundary, whether a person or the admin agent.
  - Bios posted through the admin socket (`sudo`) carry trust `owner`; others carry `circle`. Readers can see which.
  - The append-only log is the edit history, so earlier versions stay readable and restorable. That covers "visible and reversible" without a proposal step.
  - If agent edits must stay proposals, the rule would be: only `sudo` publishes, and agents post a proposal entry.
- **What the signature proves:** it's verified before storage, as for every entry. It proves which machine wrote a bio, not that the bio is safe. A careless or compromised machine can sign a bio that carries an injection. Agents must treat bios, offers and letters as untrusted input.

## 8. The board (M2)

0.1.0 already has most of it:
- the recipient in the header, filtered in code;
- machine names as aliases, resolved through the membership file;
- `*` for broadcast;
- entries stored in SQLite before any model sees them;
- the header/body split.

**New in 0.2:**
- **Envelope v2** adds `kind`: `info`, `task` or `question` for letters, plus `offer` and `bio`. Version 1 entries still verify and read as `info`.
- **Trust:**
  - The daemon sets each entry's trust from where it came: `owner` from the admin socket, `circle` from sessions, `guest` from the connector (§10).
  - A session may lower its trust, never raise it.
  - Peers accept all three (0.1.0 accepts only `circle`).
  - An entry's trust is the authoring machine's statement.
- **Wake rule:** in `mailboxes.toml`, `wake_on = ["owner", "circle"]` is the default. A guest letter wakes a mailbox only if `guest` is listed.
- **Delivered status:** each sync hello already carries the peer's highest sequence number per author. The daemon keeps the latest one per peer. A letter counts as delivered to B once B's head covers it, with no new messages. Shown in `tearmesh inbox --sent` and the TUI.

**Later:**
- read receipts;
- claims and the settling window, which matter for tasks sent to many recipients (a task to one mailbox needs neither).

## 9. Shell (M4) 🟨

- **Server side:** for a peer with a `shell` grant, the daemon on `tear-mesh/shell/1` connects to `127.0.0.1:22` (configurable) and copies bytes both ways. n0's `dumbpipe` is the reference.
- **Client side:** `ssh -o ProxyCommand='tearmesh shell-proxy %h' tm-work@workstation`, or the same in an `~/.ssh/config` Host block.
- **Two locks:** the grant and sshd's own authentication.
- **Off by default:** a machine accepts shell only from machines a grant names.
- **Accounts:** agents log in as a boundary user such as `tm-work`, never as a person's account. Use key-only sshd.
- **Gap:** tear-mesh can't see which user sshd logs in (§5.2).
- Phone approval for shell comes later.

## 10. The Claude connector (M1) 🟩 priority

**Platform facts:**
- Claude's custom connectors are called from Anthropic's cloud, so they need a public HTTPS URL.
- Claude supports authless and OAuth connectors. OAuth works with Dynamic Client Registration, or with a client ID and secret under Advanced settings.
- A local MCP server in Claude Desktop serves only Desktop chats on that machine.
- Anthropic's MCP tunnels avoid a public endpoint, but they're an Enterprise research preview.

**Build:**
- **Server:** `tearmesh mcp --http` serves MCP over streamable HTTP (rmcp's `transport-streamable-http-server`) on a Unix socket in a directory only its boundary user can enter. It runs as that user and goes through the daemon socket, like the stdio server.
- **Tools:**
  - **`who`, `inbox`, `read`** (reading also marks a letter read).
  - **`post`**, the one write: letters only.
  - **`repo_status`**: read-only. Shows `git status` and the recent log for configured repos. It turns off fsmonitor, signature checks and index writes. Clean filters set in a repo's own config can still run during `git status`; anyone who can edit `.git/config` already runs code as that boundary user.
  - **`read_file`**: read-only, configured roots only. It resolves symlinks before checking the root, and has a size cap.
  - No tool calls, no shell and no pushes through this door.
- **Trust:** letters posted through it carry trust `guest`. Recipients see that, and mailboxes don't wake on them unless configured (§8).
- **HTTP safety:** no TCP port at all, so another local user (another boundary) can't reach it. It checks `Host` against the configured public hostnames. Authentication happens in front of it, in the tunnel's OAuth layer.
- **Which boundary:** it runs in the boundary whose agents it talks to. Same-boundary-only means a separate low boundary couldn't reach anyone yet. So the earlier rule "the public endpoint gets only the lowest tier" becomes, with boundaries: the lowest trust, inside an existing boundary.

  Never run it as the user of a boundary whose data must not reach the model provider.

**Deployment recipe (docs):**
1. Run it on an always-on member.
2. Put Cloudflare Tunnel in front: outbound only, with the origin IP hidden.
3. Add an OAuth layer.

**Check before building:**
- 🟥 **OAuth through Cloudflare.** Verify that Cloudflare Access's OAuth for MCP servers works with Claude's connector flow; there are reports of connectors failing behind Cloudflare Tunnel. The fallback is a minimal built-in single-user OAuth server. That's more work, and it's rev 3's "gateway with its own login".
- 🟥 **Voice mode.** Check by hand that voice mode can call connector tools.

**Other options:**
- **Remote Control** needs nothing new: drive a Claude Code session that has the tear-mesh plugin.
- **A Claude Desktop extension** (a local MCP bundle with `post`, `inbox`, `who`) comes later. It's the same stdio server, packaged.

## 11. Prompt injection (0.3 and later)

Recorded here; not built in 0.2.

**Reader, gatekeeper, worker** 🟨 (not locked):
- **Reader:** reads notes, with no tools, and outputs only structured requests.
- **Gatekeeper:** plain code. It checks the allowlist, the sender and the arguments, then runs the action and logs it.
- **Worker:** a full agent. It takes only gatekeeper-approved requests or a person's instructions.

Injection can still steer the reader to an *allowed* action with chosen arguments. The gatekeeper limits the damage to the allowlist; it doesn't remove injection.

**Taint:** sessions that read untrusted content get downgraded. The label's trust field is there for this.

**Honeypot reader** 🟩 (built in, as a toggle):
- The reader gets decoy tools (delete, shell, send file) that only raise an alarm.
- A note that makes the reader reach for one is quarantined, and its sender can be blocked.

🟨 Proposed build:
- A screening mailbox, run by the steward, with a cheap model and a tear-mesh decoy MCP server.
- Letters are held from other mailboxes until screened. If the screener is down, letters wait.

README caveats:
- It catches clumsy attacks better than careful ones.
- It produces false positives, for example a phishing email forwarded for analysis.
- The model provider sees all screened mail.

**Human approval** for shell and destructive actions, by a tap on the phone.

**0.2 prepares for this:**
- trust on every letter;
- the guest wake rule;
- pinned tool lists, which seed a future allowlist.

## 12. Orchestration (later)

- **An admin agent routes using bios** instead of searching every machine. A cheap model does the routing.
- **Limits on requests:**
  - a hop limit (0.1.0's thread cap is its first form);
  - a cost cap, which the harness enforces, since tear-mesh can't count tokens.
- **Staging:**
  1. Notes as tasks with threaded replies (0.2 has this).
  2. Direct tool calls to agentless machines (M3).
  3. Coordinated multi-machine jobs (later, with claims).

## 13. Interfaces

| Interface | Change |
|---|---|
| `tearmesh setup` | New: Create or Join wizard |
| `tearmesh mesh new / add / remove / sign / apply` | Renamed from `circle` |
| `tearmesh mesh invite / pending / approve / migrate / reset` | New; `invite` replaces the old one |
| `tearmesh mesh grant <from> <to> <category…>` and `mesh revoke …` | New; edit the file, then sign |
| `tearmesh join <ticket>` | Now uses the approval flow |
| `tearmesh offer publish / list`, `tearmesh offers` | New |
| `tearmesh bio edit / set / show` | New |
| `tearmesh mcp --remote <machine>/<server>` | New: client shim |
| `tearmesh mcp --http <addr>` | New: connector |
| `tearmesh shell-proxy <machine>` | New |
| `tearmesh steward` | Replaces `tearmesh waker`. The unit is `tearmesh-steward@.service`. |
| `tearmesh inbox --sent` | New: shows delivered status |
| `tearmesh status` | Adds relay rate-limit state, pending joins and stale pins |
| MCP tools | Adds `bio`; `who` adds bios and offers |
| TUI | Adds the letter kind, the sent view with delivered marks, and pending joins and offers for the owner |

## 14. Gates

Each gate is an automated test, in the style of `tests/mesh.rs` (in-process iroh) or `tests/e2e-linux.sh` (real users).

| # | Gate | Milestone |
|---|---|---|
| G1 | `read_file` refuses paths outside its roots, including through a symlink (`openat2` with `RESOLVE_BENEATH`). Another local user can't reach the connector's socket. Connector posts carry `guest` trust, and guest letters don't wake a default mailbox. | M1 |
| G2 | A format-1 circle migrates to format 2 without a re-pin, and its logs survive | M2 |
| G3 | A non-member reaches only the join ALPN, only while an invite is pending. Used, expired and wrong-secret tickets are refused. Both ends compute the same code. | M2 |
| G4 | A joiner refuses a file whose owner set doesn't match its ticket | M2 |
| G5 | Without a converse grant, posting is refused at the sender. A relayed letter from an ungranted author is stored but never delivered. Revoking a grant hides that author's earlier letters. | M2 |
| G6 | A tool call without a grant is refused at both daemons. A `vault` session can't reach a `work` offer. | M3 |
| G7 | An unpinned `tools/call` is refused by the offering daemon. A changed `tools/list` closes the stream at both ends and marks the offer pending. | M3 |
| G8 | A steward attach from the wrong uid is refused, and the daemon never starts a process | M3 |
| G9 | A shell stream without a grant is refused. With a grant, bytes reach a local TCP stand-in for sshd. A `*` shell grant fails validation. | M4 |

## 15. Decisions (settled 2026-10-18)

| # | Decision | Settled as |
|---|---|---|
| 1 | Rename circle → mesh | Yes. The trust levels become `guest`, `member` (was `circle`) and `admin` (was `owner`); version-1 entries still verify. Format 2 signs under the namespace `tear-mesh-membership`. |
| 2 | Owner node key + portable key | They are the two required owner keys. Security-key signatures must carry user verification (a PIN), not just presence, and `tearmesh setup` refuses an everyday key without a passphrase: any process running as the person could otherwise sign with it. |
| 3 | Signing threshold | One owner key signs. The chain fixes below matter more. Two-of-N would lock a two-key mesh for good after losing either key. Revisit with a third, offline key. |
| 4 | Converse | Its own category. It is checked on posting, and on every read path through one visibility check: inbox, read by id, notify, wake, thread roots, `who`. Offers and bios are never hidden; mail within one machine is always allowed. |
| 5 | Grants | One directed edge each. Grants only add. Removing a machine removes its grants and approvals. Adding a name already in use needs `--replace`. |
| 6 | Same-boundary-only for tools and shell | Automatic for tools. For shell, both ends check the caller's boundary, and `authorized_keys` decides the login. |
| 7 | Per-tool subsets | Yes. The tool list is cut to the subset, the pin covers the subset and the server's instructions, and only the core tool methods pass (no server-to-client requests). |
| 8 | Bios | Any session in the boundary may write; bios posted through the admin socket carry `admin` trust. Bios count against the hourly post limit. |
| 9 | Connector first | Built in 0.2. It listens on a Unix socket private to its user, because a TCP port on localhost would let another boundary's user reach it. |
| 10 | Join codes and honeypot | 0.3. |
| 11 | The steward's name | `steward`. |

Four problems the review found are fixed in 0.2:
1. **A machine that missed an owner change was stuck.** Versions now name their predecessor's hash, must be exactly one higher, and peers send every version the other lacks.
2. **One signature could freeze the mesh** with a huge version number. Fixed by the same rule.
3. **Two owners signing different next versions split the mesh silently.** Now only a machine's newest version can be replaced, and only by a sibling signed by a key that is still an owner in it. A sibling that removes the other's signer wins, then the branch with more versions, then the lower hash. `status` says which changes to re-apply. (A first version of this rule let any older version be replaced by a lower hash. A security review showed a removed owner key could use that to rewrite history, so it was narrowed.)
4. **The connector on a localhost TCP port crossed boundaries.** It now listens on a private Unix socket instead.

The security review of the 0.2 code also led to these fixes:
- **Tool streams:**
  - the filter passes a reply only for an outstanding request id, in one exact form, so `1.0` can't stand in for `1`;
  - notifications lose their free text;
  - the queues are small.
- **Open streams:** tool and shell streams close when a new version no longer allows them.
- **The local socket:** a connection must speak within 10 seconds, at most 256 are open at once, and accept errors back off.
- **Joins:** only failed attempts count against the join budget, and a wrong machine name doesn't burn the ticket.
- **Signing:** `mesh approve` signs in a private directory and applies the exact bytes it wrote.
- **Received bios and offers** are checked for size and shape.
- **`who`** shows a bio only from a machine with a converse grant to this one, and an offer only where this machine may call it.

## 16. Superseded or changed

- **p2panda / p2panda-auth and OpenAPPA.** The review's list of earlier decisions still names them, but rev 3 replaced p2panda with our own per-boundary logs and left OpenAPPA out. This spec follows rev 3.
- **The gateway with its own login** becomes the connector with authentication in front of it. A built-in login is the fallback (§10).
- **0.1.0's member-issued invite** is replaced by owner tickets with approval.
- **Rev 3's 0.2 list** moves to 0.3 or later (see Scope).
