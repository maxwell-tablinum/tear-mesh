# Testing tear-mesh

There are three levels:
1. **Automated tests** run on one machine. On Linux there's also a container matrix across distributions.
2. **The walkthrough across machines** proves that real machines on different networks find each other, mail each other, call each other's tools and reach each other's shells.
3. **The Claude Code and connector steps** check the agent side.

Commands assume a clone at `/opt/tear-mesh`. Boundary users have private home directories, so put the clone somewhere they can read.

## 1. Automated tests

You need Rust 1.88 or later.

```sh
cargo test                  # about 40 s
cargo build --release
tests/e2e-linux.sh          # Linux; needs passwordless sudo, python3, curl (tmux for the TUI checks)
cargo build --release --target x86_64-unknown-linux-musl
PODMAN="sudo podman" tests/distros.sh      # the same in six distributions' containers
```

**`cargo test`** runs unit tests and in-process mesh tests over real iroh connections on localhost. They check that:
- vault mail never reaches a machine that only hosts `work`, and a machine can't push forged or wide-labelled entries;
- strangers are refused during the handshake, and the join protocol is closed while no invite is open;
- removing a machine cuts it off;
- the membership chain behaves:
  - a machine that missed an owner change catches up in order;
  - a removed owner key can't sign the next version;
  - a jump to a far-off version, or a version that doesn't name its predecessor's hash, is refused;
  - two owners signing different versions settle on the same one everywhere;
- joins work as designed:
  - a ticket join needs the owner's approval;
  - a used ticket is refused;
  - a joiner refuses a file signed by owners its ticket didn't name;
- grants are enforced:
  - converse grants decide delivery, and revoking one hides earlier letters;
  - a tool call needs a grant, a shared boundary and a matching approval;
  - shell streams need a grant in the right direction;
- a restarted machine catches up, mail relays through a middle machine, and a 0.1 circle on disk is carried over;
- the JSON-RPC filter on tool streams refuses unapproved tools and methods and server-to-client requests, and catches changed instructions or tools;
- the connector's `read_file` refuses `..` and symlinks out of its roots.

**`tests/e2e-linux.sh`** runs two daemons on one machine as stand-ins for two machines. It uses real OS users (`tme-work`, `tme-vault`, `tme-lap`, `tme-none`, created and then removed) and the default network. It covers:
- the ticket join: both sides show the same code, and the owner approves;
- delivery between daemons, and that no vault bytes reach the work-only daemon;
- refusals, each checked for its reason;
- an offer published by a boundary user and approved for one of its two tools;
- a tool call from the other machine that reaches the server through the steward: the unapproved tool and other methods are refused, and the tool list is cut to the subset;
- shell-proxy to a stand-in sshd, and that the grant is one way;
- bios;
- the MCP server over stdio;
- the hook;
- the steward waking a mailbox;
- the connector: its socket is private to its user, it reads only under its roots, and its letters carry `guest` trust and don't wake a default mailbox;
- the TUI, through tmux.

It prints `PASS` or `FAIL` for each check and ends with `ALL PASSED`.

**`tests/e2e-0.3.sh`** runs three daemons (`own`, the owner node, `mem` and `far`) with real OS users (`tme3-own`, `tme3-mem`, `tme3-far`, `tme3-x`, `tme3-lab`) and tries to break 0.3. It covers:
- setup: re-asking on bad choices, names, passphrases and tickets; binary junk and closed input; only the recovery key shown, opening with its generated passphrase and not the everyday one; running twice changes nothing; Ctrl-C and `kill -9` halfway leave nothing behind; joining through the wizard with a nameless ticket and the code matching; approving without `--key`; adding a boundary and changing what a machine hosts;
- the ping protocol behind the map, admin only;
- the hub: `mcp connect` starts it, it outlives the client, a second `serve` exits, six clients starting it at once leave one hub, a client's own stdio copy runs beside it; private socket directory and token; HTTP refused without the token, with a wrong one or a prefix, and from a foreign `Host`;
- conversation both ways, with `wait_for_mail` and the push to an open session; tool calls both ways, refused without a grant; shell commands both ways through the real sshd, refused without a grant, with option smuggling refused; an open shell kept across client sessions; harness chats, with the prompt passed as one argument and chat ids that can't name files;
- oversized and junk input to the daemon, the hub socket and the hub's HTTP;
- a node dying mid-shell and mid-call, the owner offline (members still mail each other; joins fail with a reason), a member restarting ten times while letters keep coming (each arrives once);
- a stolen node key, revoked: it reaches nobody afterwards and its letters never arrive; a leaked owner key replaced and removed: its signatures are refused by the owner node and by a member; the recovery key still signs;
- the menu through tmux: role detection, the Owner tab only on an owner node, the map, the nodes table, the shortcut bar, a ticket shown in the menu, Ctrl-C in a program it runs; and a mesh made without leaving it: create (Esc first leaves nothing; the recovery key saved with W; word 3 checked), invite, join by bracketed paste, the same code on both screens, the approval popup with a new boundary and a grant in one version (a wrong passphrase refused), and a grant signed from the Nodes screen.

**`tests/distros.sh`** runs that script and `tearmesh install` (again with an extra boundary, then `uninstall`) in Debian 13, Ubuntu 24.04, Fedora 42, Arch, openSUSE Tumbleweed and Alpine 3.22 containers, on the static musl binary. Name images as arguments to test others.

**`tests/e2e-windows.ps1`** is the Windows version, for an elevated PowerShell on Windows Server or Windows 11. See [Windows](#windows).

## 2. Across machines

Use two machines, ideally on different networks; that is what exercises NAT traversal and relays. We'll call them **alpha**, which hosts `work` and `vault` and is the owner node, and **beta**, which hosts `work`. Beta can be Linux or Windows.

### Install

With a release binary (or `target/release/tearmesh` from `cargo build --release`):

```sh
sudo ./tearmesh install alpha work vault     # on alpha
sudo ./tearmesh install beta work            # on beta (Linux)
```

Each prints its node id. `install` runs the script built into the binary (the same as `deploy/setup-linux.sh`):
- installs `/usr/local/bin/tearmesh`;
- creates the `tearmesh` daemon user and one user per boundary (`tm-work`, `tm-vault`);
- writes `/etc/tearmesh/config.toml`, with you as an admin;
- writes the Claude Code plugin to `/usr/local/share/tearmesh`;
- starts (or restarts) the service (systemd or OpenRC).

Run it again to upgrade, or with more boundaries to add their users to the config. A boundary new to the mesh is then added by an owner: `tearmesh mesh boundary add lab --host beta` (or `tearmesh mesh hosts beta work lab` when the mesh already has it).

For a Windows beta, see [Windows](#windows).

### Create the mesh (alpha)

```sh
tearmesh menu        # press C; or the line-by-line `tearmesh setup`, choosing 1
```

It asks for a mesh name and a passphrase (8 or more characters, twice) for the everyday key, which stays at `~/.ssh/tearmesh-owner-<mesh>`. It then shows the recovery key with a generated six-word passphrase, once: it isn't kept on alpha, and it's your way back in if alpha is lost or its key leaks. In the menu, C copies it (OSC 52; under tmux set `set -g set-clipboard on`), P copies the passphrase, W saves the key to a file, and Y asks for word 3 of the passphrase before creating the mesh. Setup asks you to type `saved`. It then applies a membership file listing alpha, signed with the everyday key. The Overview shows the mesh and alpha's boundaries.

Things to try: a bad answer at any prompt (it asks again), `b` to go back, Esc, `q` or Ctrl-C partway (nothing is written; run it again), and running it a second time (it says alpha is set up and changes nothing).

<details><summary>The same by hand</summary>

```sh
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/tearmesh-owner-test
ssh-keygen -t ed25519 -a 100 -f ./recovery      # copy it somewhere safe, then delete it
tearmesh mesh new mesh.toml --name test \
  --owner-key ~/.ssh/tearmesh-owner-test.pub --owner-key ./recovery.pub \
  --boundary work --boundary vault
tearmesh mesh add alpha <alpha-node-id> --boundary work --boundary vault --file mesh.toml --key ~/.ssh/tearmesh-owner-test
tearmesh mesh apply mesh.toml
```
</details>

### Join beta

In the menu: on alpha, Owner → I and Enter shows a ticket (C copies it, W saves it). On beta, J, paste it, Enter: beta shows "Code 123 456" and waits. Alpha's menu pops up "beta wants to join with boundaries work" with the code; tick any grants, enter the passphrase, Enter. From the command line:

```sh
# alpha
tearmesh mesh invite                            # prints tm2-…, valid for an hour (--expires 1d); NAME pins the name
# beta
tearmesh setup                                  # choose 2 (join), paste the ticket: prints "Code 123456" and waits
# alpha
tearmesh mesh pending                           # shows beta, its code and boundaries (or: the menu's Owner screen)
tearmesh mesh approve beta --grant beta:alpha:tools   # finds the owner key in ~/.ssh; --add-boundary for a new one
```

Approve only if both codes match; `tearmesh mesh reject beta` refuses it. Beta prints `Joined. Mesh version …`. If beta's join is interrupted, running it again with the same ticket gets the same code; another machine with that ticket is refused and the owner sees a warning. Open tickets survive a daemon restart; `tearmesh mesh reject --all` voids them. Within about 30 seconds, `tearmesh status` on either machine shows the other with a `last_sync_ms`.

### Send mail

```sh
# alpha
sudo -u tm-work env TEARMESH_MAILBOX=builder tearmesh post --to admin@beta --subject hello --body "first letter" --kind task
# beta
sudo -u tm-work tearmesh inbox                  # shows "hello [task]"
sudo -u tm-work tearmesh read <id>
sudo -u tm-work tearmesh post --to builder@alpha --subject re --body "got it" --thread <id>
```

### Check the boundaries

Each of these should be refused with the reason shown.

| Where | Command | Expected |
|---|---|---|
| alpha | `sudo -u tm-vault tearmesh post --to admin@beta --subject x --body x` | `beta is not in boundary vault` |
| alpha | `sudo -u tm-vault tearmesh read <id of a work letter>` | `no letter … in this boundary` |
| alpha | `sudo -u nobody tearmesh who` | `isn't mapped to a boundary` |
| alpha | `sudo -u tm-work tearmesh status` | `admin only` |
| alpha | `sudo -u tm-work ls /home/tm-vault` | `Permission denied` |

Then post a vault letter on alpha and confirm it never reaches beta:

```sh
sudo -u tm-vault tearmesh post --to '*' --subject secret --body "vault only"   # alpha
sudo ls /var/lib/tearmesh/boundaries/            # beta, after a minute: only work.db
sudo grep -rc "vault only" /var/lib/tearmesh/    # beta: no matches
```

### Call a tool on another machine

Any stdio MCP server will do. Here beta offers one and alpha calls it.

```sh
# beta, as tm-work: ~/.config/tearmesh/offers.toml
#   [files]
#   command = ["npx", "-y", "@modelcontextprotocol/server-filesystem@<version>", "/home/tm-work/shared"]
sudo -u tm-work tearmesh offer publish files       # prints its tools and the pin
sudo systemctl enable --now tearmesh-steward@tm-work
# alpha
tearmesh mesh grant alpha beta tools
sudo -u tm-work tearmesh offers                    # beta/files: pending approval
tearmesh mesh approve-offer beta work files --tools <tool>,<tool>   # names as `offers` lists them
sudo -iu tm-work claude mcp add files -- tearmesh mcp --remote beta/files
```

In a Claude Code session as `tm-work` on alpha, ask it to list the shared directory. Only the two approved tools appear. To see a refusal:
1. Revoke the grant: `tearmesh mesh revoke alpha beta tools`.
2. Start a new session; the call fails with `no tools grant`.

Pin the package version in `command`. `npx` and `uvx` fetch code at run time, so the offer can't carry an executable hash for them.

### Shell

```sh
tearmesh mesh grant alpha beta shell     # alpha
# alpha, as tm-work, in ~/.ssh/config:
#   Host beta
#     ProxyCommand tearmesh shell-proxy %h
sudo -iu tm-work ssh tm-work@beta
```

Beta needs sshd, with `tm-work`'s key from alpha in beta's `/home/tm-work/.ssh/authorized_keys`. The grant only gets bytes to beta's sshd; sshd decides who logs in. Give each boundary user its own key. `ssh` from beta to alpha is refused (`no shell grant`), because the grant is one way.

### Bios

```sh
printf 'role: build server\noffers: [files]\n' | sudo -u tm-work tearmesh bio set -    # beta
sudo -u tm-work tearmesh bio show beta                                                # alpha
```

### Revoke a machine

```sh
tearmesh mesh remove beta    # alpha
```

Beta's sessions can no longer reach alpha, and its earlier letters are no longer delivered. To bring beta back, run `tearmesh mesh reset` on beta, then invite and join again.

## The terminal UI

```sh
tearmesh launch --boundary work --mailbox admin -- tearmesh tui     # on beta
```

The screen has three parts:
- the inbox, newest first. ● marks unread; `[task]`, `[question]` and `[guest]` mark the kind and trust;
- the open letter;
- a header showing your address and when each machine last synced.

| Key | Does |
|---|---|
| `↑` `↓` or `j` `k` | Move through the inbox |
| `enter` | Open a letter (marks it read) |
| `r` | Reply to the open or selected letter, in its thread |
| `n` | Write a new letter |
| `a` | Switch between all letters and unread only |
| `g` | Refresh (it also refreshes every 3 seconds) |
| `space` / `pgup` | Scroll a long letter |
| `q` | Quit |

While writing a letter:
- `tab` moves between To, Subject and Body;
- `enter` adds a new line in the body;
- `ctrl+s` sends and `esc` discards;
- separate several recipients with commas.

## 3. Claude Code

Each boundary user needs its own Claude Code login, because a session's boundary is the OS user it runs as.

```sh
sudo -iu tm-work
claude                                          # log in once, then /exit
claude plugin marketplace add /usr/local/share/tearmesh
claude plugin install tearmesh@tear-mesh
exit
tearmesh launch --boundary work --mailbox builder -- claude
```

In the session, ask "who's on tear-mesh?" (the `who` tool, which also shows bios and offers). Then ask it to send `admin@beta` a question. On beta, start a session the same way with `--mailbox admin` and type anything. The hook announces the letter, and the agent can `read` it and reply.

### Wake on mail

On beta, as `tm-work`, write `~/.config/tearmesh/mailboxes.toml`:

```toml
[helper]
dir = "/home/tm-work"
command = ["claude", "-p", "{prompt}", "--output-format", "json",
           "--allowedTools", "mcp__plugin_tearmesh_tearmesh__*"]
```

Then run:

```sh
sudo systemctl enable --now tearmesh-steward@tm-work     # beta
sudo -u tm-work env TEARMESH_MAILBOX=builder tearmesh post --to helper@beta --subject question \
  --body "What is 17 times 3? Reply with just the number."   # alpha
sudo -u tm-work env TEARMESH_MAILBOX=builder tearmesh inbox # alpha, within a minute or two
```

`journalctl -u tearmesh-steward@tm-work` shows each wake. If the woken session can't use the tools, check the exact tool names with `/permissions` in an interactive session, and adjust `--allowedTools`.

## The Claude connector

The connector lets Claude on your phone, the web or Claude Desktop reach the mesh. It has:
- the mail tools;
- two read-only tools: `repo_status` for listed git repositories and `read_file` under listed directories.

It runs on a Linux member, as the user of the boundary it serves. Never run it in a boundary whose data must not reach your model provider.

As `tm-work`, write `~/.config/tearmesh/connector.toml`:

```toml
hosts = ["mesh.example.com"]          # the public hostname your tunnel forwards
mailbox = "phone"                     # letters are from phone@<this machine>
roots = ["/home/tm-work/notes"]
repos = ["/home/tm-work/src/project"]
```

Then run it, for example as a user service: `tearmesh mcp --http`. It listens on `~/.local/state/tearmesh/connector/mcp.sock`, which only `tm-work` can open.

Put a tunnel and OAuth in front:
1. Run cloudflared as `tm-work` with an ingress rule `service: unix:/home/tm-work/.local/state/tearmesh/connector/mcp.sock`.
2. Protect the hostname with an OAuth layer.
3. Add `https://mesh.example.com/mcp` as a custom connector in Claude's settings.

Check before relying on it:
- that your OAuth layer works with Claude's connector sign-in, which uses OAuth with dynamic client registration or a client ID and secret;
- that voice mode can use connector tools.

Letters from the connector are marked `guest`, and mailboxes don't wake on them unless `wake_on` lists `guest`.

## Windows

tear-mesh runs natively on Windows. It is tested on Windows Server 2022; Windows 10 and 11 use the same APIs but haven't been tested yet.
- The local socket is the named pipe `\\.\pipe\tearmesh`.
- A session's boundary is the Windows account it runs as. The daemon learns it by briefly impersonating the pipe client.
- Only an elevated Administrator, SYSTEM, the daemon's own account or a listed `admins` user may run admin commands. A non-elevated Administrator is not admin.
- The daemon runs as the service `tearmesh` under the virtual account `NT SERVICE\tearmesh`.
- Clients refuse a pipe that SYSTEM, Administrators or that account didn't create, so another program can't take the name and pose as the daemon.
- The pipe refuses other machines. SSH sessions on the same machine work, as the user they log in as.

### Build

Build on Windows with Rust (`cargo build --release`, MSVC). Or cross-compile on Linux with mingw-w64:

```sh
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu      # target/x86_64-pc-windows-gnu/release/tearmesh.exe
```

### Install

In an elevated PowerShell:

```powershell
Unblock-File .\tearmesh-x86_64-windows.exe     # a downloaded release
.\tearmesh-x86_64-windows.exe install beta work --stewards
```

`install` runs the script built into the binary (the same as `deploy\setup-windows.ps1 -Machine beta -Boundaries work -Exe <exe> -Stewards`). This:
- installs `C:\Program Files\tearmesh\tearmesh.exe` and adds that folder to the machine PATH (new prompts see it);
- writes the Claude Code plugin there too;
- creates the local user `tm-work` with a random password, saved to `C:\ProgramData\tearmesh\passwords.txt`, which only SYSTEM and Administrators can read;
- writes `C:\ProgramData\tearmesh\config.toml`, with you as an admin;
- locks down the state directory;
- creates and starts the service;
- allows inbound UDP for the private and domain profiles;
- with `-Stewards`, starts a steward for each boundary user at boot.

It prints the node id. `tearmesh uninstall work` removes it all again.

Then join as on Linux, from an elevated prompt: `tearmesh join tm2-…`. Run sessions as the boundary user, with `tearmesh launch --boundary work --mailbox admin -- claude` (runas asks for the password) or from a login as `tm-work`. The steward reads `%USERPROFILE%\.config\tearmesh\mailboxes.toml` and `offers.toml`, as on Linux.

### Tests

The Windows tests need an elevated PowerShell on a machine where you can create local users, such as a test VM:

```powershell
tests\e2e-windows.ps1 -Exe C:\path\to\tearmesh.exe
```

It creates `tme-*` users, runs two daemons, and checks:
- the ticket join;
- mail between the daemons, and that no vault bytes reach the work-only daemon;
- the refusals: an unmapped user, a boundary user asking for admin, one boundary reading another's files or the daemon's state;
- that an elevated Administrator is admin;
- that an SSH session is identified as its user;
- that a client refuses a pipe another user created, and that a daemon won't start on a name another program holds;
- MCP over stdio, and the hook.

The test users' commands run as scheduled tasks, because `Start-Process -Credential` fails from SSH. For the unit and mesh tests, cross-compile them with `cargo test --release --target x86_64-pc-windows-gnu --no-run` and run the two `.exe` files from `target/x86_64-pc-windows-gnu/release/deps/` as SYSTEM or an elevated Administrator. The debug build doesn't link with mingw.

WSL2 still works, as for any Linux machine. The connector needs Linux.

## Upgrading from 0.1

0.1 and 0.2 daemons can't talk to each other, so upgrade every machine. Each 0.2 daemon carries its stored 0.1 circle over and keeps its logs. Then turn the circle file into the next version:

```sh
tearmesh mesh migrate --file circle.toml --key ~/.ssh/id_ed25519
```

This applies the new version to the local daemon, and it spreads from there. Mail keeps flowing among all machines (`* → *` converse) until you change the grants. The waker is now the steward: run `systemctl disable --now 'tearmesh-waker@*'` and enable `tearmesh-steward@<user>` instead.

## 4. Uninstall

```sh
sudo tearmesh uninstall work vault      # Windows: tearmesh uninstall work, elevated
```

It stops and removes the service, the binary, the plugin, `/etc/tearmesh` and the state, and deletes the users of the boundaries named (with their homes), then the `tearmesh` user.

## Releases

1. Bump the version in `Cargo.toml` and `adapters/claude-code/.claude-plugin/plugin.json` (a unit test checks they match), and commit.
2. `git tag -a v<version> -m "<notes>"` and push the tag. The `release` workflow builds the Linux (x86_64 and aarch64, musl) and Windows (MSVC) binaries, smoke-tests `install` and `uninstall` on each runner, and creates a **draft** release with `SHA256SUMS`.
3. On the Windows test VM, download the Windows binary from the draft and run `tests\e2e-windows.ps1 -Exe <it>`.
4. Publish the draft.
