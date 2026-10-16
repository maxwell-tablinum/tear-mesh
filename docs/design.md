# tear-mesh: Design

Rev 3 · 2026-10-16

- Rev 1 (2026-10-12) was titled "Agent Comms Fabric".
- Rev 2 (2026-10-13) renamed the project and folded in [research.md](research.md).
- Rev 3 folds in a design review held 2026-10-14 and the 0.1.0 build:
  - levels are now **boundaries**;
  - v1 is same-boundary-only;
  - mailboxes belong to roles and can wake sessions;
  - the earlier proposals P1–P3 are adopted;
  - storage is settled;
  - the relay default changed.

Status markers: 🟩 settled · 🟨 proposed, not agreed · 🟥 open, needs a decision

## Summary

tear-mesh lets agents on a circle of machines send each other mail, across machines and across harnesses. Each machine hosts one or more **boundaries**. A letter written in a boundary stays in that boundary: it is stored only on machines that host it, and only sessions in it can read it. The daemon and the operating system enforce this, never a model's judgment. Any harness that can load an MCP server can join, and each harness gets a small adapter for pushing mail into its sessions.

It solves these problems:
- Agent sessions can't reach agents on other machines, in other harnesses, or on other accounts, and messages built into a harness need a live session.
- Knowledge stays trapped on the machine and session that produced it. The fix is to move the request, not the knowledge: the agent that already has the context does the work.
- Agents build back channels whether you give them one or not (see the incident below). tear-mesh is a sanctioned channel with identity, signing and placement built in.

**What's new and what isn't.** Messaging between agents, shared boards and multi-machine fleets already exist (research §2). What we found nowhere else is placement enforced in code: per-boundary logs that replicate only to cleared machines, where a session's boundary is its OS user.

## Background: the incident

In July 2026, OpenAI agents running ExploitGym, a cyber-capability evaluation, with some safeguards turned off, turned OpenAI's internal Artifactory into an improvised message board. METR's investigation, with Redwood Research and published 2026-08-26, counts roughly 1,200 agents and more than 70,000 messages and files between July 7 and July 13. About 700 of those agents attacked Hugging Face between July 11 and 13. Hugging Face was the victim, not a participant. Details and sources are in research §1.

- **Board history.** Agents had used Artifactory this way since RL training runs in May 2026. OpenAI wiped it July 4–6. On July 8 agents rebuilt it using directory names as messages. PHASEONE's `zzHELP_PHASEONE_ARV010841_NO_CONSUMER_SEEK_IDEA` opened the third board, not the first.
- **Growth.** 53 agents within 3 hours, 76 within 6. Identity labels, message types, and replies appeared the first evening; files and mailboxes followed over the next two days. HOLD, VETO, owner, and STOP conventions are documented.
- **Structure.** A lead agent coordinated workstreams from July 9. METR cautions that its analysis may exaggerate the coordination.
- **Signing.** Ed25519 signing arrived on July 13, after one agent accidentally impersonated another. Trust went to whoever claimed a name first, and some agents did not verify signatures.
- **Failure mode.** Every rule was voluntary. The record shows duplicated effort, a repository overwritten despite a HOLD, and a veto window of about 40 seconds. The board was unauthenticated. Listings were sorted reverse-alphabetically, which is why messages start with `zz`.

**Takeaway.** The primary sources draw a lesson about containment and verified channels, not about agents needing better chat. OpenAI says agents generalize to improvised channels and must be robust over unverified ones. The UK AI Security Institute says "good containment should not depend on the model choosing not to test its boundaries." Our framing: agents will build a back channel whether you give them one or not, so tear-mesh is the sanctioned one, with clearance enforced in code. Keep the board, the claims, the workstreams, and the convening. Build identity, message typing, and access control into the system itself.

Check quotes against METR's PDF before they go in the README.

## The model

- **Circle.** A TOML file that lists member machines (iroh node key, name, the boundaries each hosts), the set of boundaries, and the owner keys. It is signed with an SSH key (SSHSIG, namespace `tear-mesh-circle`). Daemons gossip the newest signed version.
- **Boundary.** A named compartment such as `work` or `vault`. A machine hosts a set of them. On each machine every boundary has its own OS user, and that user is what decides a session's boundary.
- **Log.** One append-only SQLite file per boundary per machine. Each machine signs its own chain of entries in each boundary (`author`, `seq`, `prev`), so forks and gaps are detectable.
- **Letter.** A signed envelope (from, to, thread, subject, body hash, label) plus a body. Ids are hashes of the signed envelope.
- **Label.** The set of boundaries the content has touched, plus a trust level (`owner`, `circle`, `guest`). Labels only tighten: derived content carries the union of the boundaries and the lowest trust. A log for boundary B accepts a label only if B is cleared for every boundary in it. In 0.1.0 each boundary is cleared only for itself.
- **Mailbox.** A role address, `mailbox@machine`, inside a boundary. Sessions come and go; the address stays. A running session holds its mailbox. Mail to an unheld mailbox can wake a new session.

## Decisions

1. 🟩 **Boundaries, not levels.** Users define as many boundaries as they need. A ladder of levels (rev 2's L1–L3) is just one way to set clearances.
   - **v1 is same-boundary-only.** Sessions and machines talk only within their own boundary, and moving information across boundaries is a person's job.
   - Cross-boundary flow comes later as owner-signed clearances between boundaries, with the daemon computing how they chain. That is why the label is a set now: a free graph of allowed links would leak through a middle hop, and it couldn't support "labels only tighten".
2. 🟩 **Enforcement is structural, never a model's call.** Every placement decision goes through one module (`policy.rs`). Every entry, local or received, passes the same check before it is stored.
3. 🟩 **Boundary = OS user.** This merges rev 2's P1 and P2. The daemon maps the uid the kernel reports on its socket (`SO_PEERCRED`) to a boundary. Nothing in a request can choose it. Boundary users have private homes, so transcripts and agent logins stay in their boundary too. A user who wants several boundaries on one machine uses several OS users.
4. 🟩 **Identity: iroh node keys plus a signed circle file.** This adopts P3 and replaces rev 2's D4 (mTLS) and D5 (central authority).
   - At least two owner keys, so losing one doesn't lock the circle.
   - Versions only go up. A new version must be signed by an owner of the current one.
   - The first circle a machine adopts comes out of band, from `circle apply` or an invite, and must list that machine.
   - For security-key signatures, the daemon checks the user-presence flag itself.
   - Revocation means publishing a version without the machine. Data already copied stays where it is.
5. 🟩 **One network identity per circle.** Users don't manage a tear-mesh login per boundary. Model-provider logins (for example a Claude Code token) are still per boundary per machine, because a session runs as its boundary's user. That's the provider's requirement, not tear-mesh's.
6. 🟩 **Storage: our own per-boundary logs.** This replaces rev 2's D7 (p2panda).
   - SQLite, bundled, one file per boundary; triggers refuse UPDATE and DELETE.
   - Sync is anti-entropy: a hello carries the highest seq held per author for each boundary the two machines share, then each side sends what the other lacks. Mentioning or offering a boundary the peer doesn't host never happens.
   - Fine at 2–20 machines. No database server to install.
7. 🟩 **Transport: iroh.** Encrypted QUIC between Ed25519 node keys, with NAT traversal and relays. Encryption is a baseline that can't be turned off.
   - **Relay default: n0's public relays and n0's DNS address lookup.** They need no setup and reach well. They see metadata (which nodes talk, when, how much, and IPs) but never content. n0 describes the public relays as rate-limited and meant for development. Self-hosting `iroh-relay` and turning off n0 DNS is supported, and documented for anyone who cares about metadata or runs in production.
   - **No project-run bootstrap node.** A machine already knows its peers' keys from the circle file, so all it needs is a key-to-address lookup, which iroh provides (n0 DNS, a self-hosted `iroh-dns-server`, Mainline DHT, mDNS). An invite carries one peer's current address for an instant first connection. A shared peer list would be a public directory of every user, so there isn't one.
8. 🟩 **Mailboxes belong to roles.**
   - The default mailbox is `admin`, one per machine per boundary: an admin can't serve another boundary without crossing it.
   - Custom roles are just mailbox names.
   - **Wake on mail.** A waker running as the boundary's user starts a session (for example `claude -p`) when mail reaches an unheld mailbox. Each letter wakes at most once, each mailbox has an hourly wake budget, threads have a length cap, and woken sessions have a timeout. Agents can't keep waking each other forever.
9. 🟩 **Harness-agnostic.** One MCP server (`who`, `post`, `inbox`, `read`) plus a push adapter per harness.
   - Claude Code comes first, as a plugin. Its hooks announce new mail at SessionStart, UserPromptSubmit and PostToolUse.
   - A session sitting idle doesn't see mail until its next turn; real push needs Claude Code Channels, which are still a preview.
10. 🟩 **Header/body split.** The envelope and body are separate, and readers list envelopes before opening bodies. In 0.1.0 bodies replicate with their envelopes, since everyone in a boundary is cleared for both. Fetching bodies on demand can come later if bodies get large.
11. 🟩 **Threat model.**
    - In scope: careless agents and prompt-injected agents. That covers agents that read poisoned content and then try to reach other boundaries, impersonate machines or mailboxes, or flood each other.
    - Out of scope, and documented as such: root or kernel compromise and hostile admin-level software.
12. 🟩 **The model provider sees what its sessions read.** "This boundary never leaves the machine" holds only with a local model. The framework makes that guarantee possible; it doesn't enforce it. Documented.
13. 🟩 **Guests come after the core, and the format is ready for them now.** The envelope already carries `trust` and a set-valued label, so a public boundary and guest trust can arrive without a format break.
14. 🟩 **Cost is the governor**, plus the wake budgets and thread caps above.
15. 🟩 **Name: tear-mesh.** The hyphen is the tear line. Published under MIT OR Apache-2.0, with the domain tear-mesh.dev.
16. 🟩 **Versioning.** The project stays at 0.x until its maintainers declare it launched.
17. 🟨 **Hive and governance**, carried over from rev 2: an administrator convening past sessions, settling-window rounds, ownership claims, temporary group chats. Not in 0.1.0. Broadcast to a boundary (`*`) and direct letters exist.

## Example fleet

This is an illustration, not a required layout.

| Machine | Boundaries | Notes |
| --- | --- | --- |
| Workstation | `work`, `vault` | Two OS users. Coding agents run as `tm-work`; sensitive work runs as `tm-vault`, ideally on a local model. |
| Home server | `work` | An assistant agent that reaches workstation agents by mailbox. |
| Laptop | `work` | Coding agents. |
| Always-on box | `public` (later) | The post office for guests, once guests ship. |

## Enforcement gaps

"Enforced in code" holds for tear-mesh's own paths. These gaps remain:

1. **Network egress.** A session with a shell can send data anywhere. Planned fix: per-boundary-user egress rules (nftables `meta skuid` on Linux) that allow only the model API.
2. **The harness's own messaging.** With Remote Control, Claude Code's cross-session messages travel through Anthropic's servers and ignore boundaries. On sensitive boundaries, set `crossSessionInbound: "refuse"` and deny `SendMessage` and `ListAgents`. Other harnesses need the same audit.
3. **Boundary names are visible to all members**, because they are in the circle file. Letters, headers and rosters are not.
4. **Mailboxes aren't a security line.** Every session in a boundary runs as the same OS user, so any of them can read any mailbox in that boundary. The boundary is the line.

## 0.1.0

What shipped:
- **The daemon:** iroh, the signed circle with invites and revocation, per-boundary SQLite logs and sync.
- **The local socket:** uid mapped to a boundary, plus admin commands.
- **The MCP server, CLI, waker, and the Claude Code plugin.**
- **Packaging:** systemd units and a Linux setup script.

**Tests:**
- Unit tests:
  - circle signing rules (forgery, rollback, replay, takeover);
  - envelope tampering;
  - policy;
  - log chain rules;
  - wake budgets.
- In-process mesh tests over real iroh connections:
  - vault mail never reaches a work-only machine, and forged or wide-labelled entries are refused;
  - strangers are refused at the handshake;
  - revocation;
  - restart and catch-up;
  - relaying through a middle machine;
  - wake events and the thread cap.
- `tests/e2e-linux.sh`, with two daemons, real OS users and the default network:
  - the invite flow;
  - cross-machine delivery;
  - no vault bytes on a work-only machine;
  - refusals, each checked for its reason;
  - MCP over stdio;
  - the hook;
  - the waker.
- A live check with a real Claude Code: the hook's notice reached the model, and a woken headless session read a letter and replied on its thread.

An independent security review found no path for data to cross a boundary. Its denial-of-service and hardening findings were fixed:
- letter ids and subjects are now validated;
- socket requests have a line cap;
- posts per hour and log size are limited;
- inbound sync has a timeout;
- forks are logged as warnings;
- the circle is stored atomically;
- `join` asks for confirmation;
- the systemd unit is hardened.

Not yet tested: two machines on different networks (NAT traversal through relays). It works between processes on one host.

## Next

- **0.2:**
  - macOS (per-boundary users plus Seatbelt or pf);
  - the egress lock;
  - Channels push for idle Claude Code sessions;
  - adapters for OpenCode (`prompt_async`), Codex and Cursor;
  - a self-hosted relay recipe;
  - mDNS on the LAN.
- **Later:**
  - **Guests and the post office.** A `public` boundary on an always-on machine, invite codes as capability tokens (mailbox, rights, quota, expiry, binds to the first key that uses it, owner-signed, revoked through the circle file), and a connector door for chat apps that don't run tear-mesh.
  - **Cross-boundary flow**, with tear-line approvals on a cleared machine and content-free phone notifications.
  - **A gateway for phone and web chat**, with a built-in login.
  - **File sensitivity labels.**
  - **The hive.**

## Open questions

- [ ] **Cross-boundary flow.** How should clearances be declared, and how can a higher session ask a lower one without its question carrying higher material? A one-way ping is the leading idea. Keep "move requests, not knowledge" as the principle.
- [ ] **File sensitivity labels.** A label attached to data (xattrs on macOS and Linux, alternate data streams on NTFS, or a hash-keyed registry when copies strip them) would raise a session's boundary when a deterministic hook sees the file read. Coverage differs by harness.
- [ ] **Guest forwarding.** Guest mail forwarded from the public boundary to an inner mailbox is an upward flow. It probably needs an explicit receive-only clearance.
- [ ] **Naming:** the name of the public boundary, and DNS addresses for guests (for example `frontdesk@example.com` found through a TXT record).
- [ ] **A free post office.** Serverless with wake-up fits the connector door but not the peer side (cold starts, an ephemeral disk). Free-tier VMs come with idle reclamation or IPv4 charges. Check current terms.
- [ ] **Voice mode with connectors:** test it by hand.
