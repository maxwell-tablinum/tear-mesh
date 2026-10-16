# Testing tear-mesh

This guide has three levels. Automated tests run on one Linux machine. The two-machine walkthrough proves that real machines on different networks find each other. The Claude Code steps check the agent side. Commands assume a clone at `/opt/tear-mesh`. Boundary users have private home directories, so put the clone somewhere they can read.

## 1. Automated tests

You need Linux and Rust 1.88 or later.

```sh
cargo test                  # about 40 s
cargo build --release
tests/e2e-linux.sh          # needs passwordless sudo
```

**`cargo test`** runs unit tests and in-process mesh tests. The mesh tests make real iroh connections on localhost. They check that:
- vault mail never reaches a machine that only hosts `work`, and a machine can't push forged or wide-labelled entries;
- strangers are refused during the handshake;
- revoking a machine cuts it off;
- a restarted machine catches up on mail it missed;
- mail relays through a middle machine;
- mail to an unheld mailbox raises a wake event, and threads stop at their length cap.

**`tests/e2e-linux.sh`** runs two daemons on one machine as stand-ins for two machines. It uses real OS users (`tme-work`, `tme-vault`, `tme-lap`, created and then removed) and the default network. It covers:
- the invite flow;
- delivery between the two daemons;
- that no vault bytes reach the work-only daemon;
- the refusals, each checked for its reason;
- the MCP server over stdio;
- the hook;
- the waker.

It prints `PASS` or `FAIL` for each check and ends with `ALL PASSED`.

## 2. Two machines

This is the test that exercises NAT traversal and relays. Use two Linux machines, ideally on different networks. We'll call them **alpha**, which hosts `work` and `vault`, and **beta**, which hosts `work`. You need `sudo` on both.

### Install

On each machine:

```sh
cd /opt/tear-mesh && cargo build --release
sudo deploy/setup-linux.sh alpha work vault     # on alpha
sudo deploy/setup-linux.sh beta work            # on beta
```

Each machine prints its node id. Note both. The script installs `/usr/local/bin/tearmesh`, creates the `tearmesh` daemon user and one user per boundary (`tm-work`, `tm-vault`), writes `/etc/tearmesh/config.toml`, and starts `tearmesh.service`.

### Create the circle

Do this on alpha, or wherever your SSH keys live. A circle needs two owner keys, so make a backup key if you don't have one:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/tearmesh-backup
tearmesh circle new circle.toml --name test \
  --owner-key ~/.ssh/id_ed25519.pub --owner-key ~/.ssh/tearmesh-backup.pub \
  --boundary work --boundary vault
tearmesh circle add circle.toml alpha <alpha-node-id> --boundary work --boundary vault
tearmesh circle add circle.toml beta <beta-node-id> --boundary work
tearmesh circle sign circle.toml --key ~/.ssh/id_ed25519
sudo tearmesh circle apply circle.toml
sudo tearmesh invite                             # prints tm1-…
```

On beta, run `sudo tearmesh join tm1-…`. Check that the owner fingerprints it prints match your keys (`ssh-keygen -lf ~/.ssh/id_ed25519.pub`), then answer `y`.

Within about 30 seconds, `sudo tearmesh status` on either machine shows the other machine with a `last_sync_ms`.

### Send mail

```sh
# alpha
sudo -u tm-work env TEARMESH_MAILBOX=builder tearmesh post --to admin@beta --subject hello --body "first letter"
# beta
sudo -u tm-work tearmesh inbox
sudo -u tm-work tearmesh read <id>
sudo -u tm-work tearmesh post --to builder@alpha --subject re --body "got it" --thread <id>
# alpha
sudo -u tm-work env TEARMESH_MAILBOX=builder tearmesh inbox
```

### Check the boundaries

Each of these should be refused with the reason shown.

| Where | Command | Expected |
|---|---|---|
| alpha | `sudo -u tm-vault tearmesh post --to admin@beta --subject x --body x` | `beta is not in boundary vault` |
| alpha | `sudo -u tm-vault tearmesh read <id of a work letter>` | `no letter … in this boundary` |
| alpha | `sudo -u nobody tearmesh who` | `isn't mapped to a boundary` |
| alpha | `sudo -u tm-work ls /home/tm-vault` | `Permission denied` |

Then post a vault letter on alpha and confirm it never reaches beta:

```sh
# alpha
sudo -u tm-vault tearmesh post --to '*' --subject secret --body "vault only"
# beta, after a minute
sudo ls /var/lib/tearmesh/boundaries/            # only work.db
sudo grep -rc "vault only" /var/lib/tearmesh/    # no matches
```

### Revoke a machine

```sh
# alpha
tearmesh circle remove circle.toml beta
tearmesh circle sign circle.toml --key ~/.ssh/id_ed25519
sudo tearmesh circle apply circle.toml
# beta
sudo -u tm-work tearmesh post --to builder@alpha --subject "after revoke" --body x
# alpha, after a minute: "after revoke" never arrives
sudo -u tm-work env TEARMESH_MAILBOX=builder tearmesh inbox
```

To bring beta back, add it again, then sign, apply, invite and join as before.

## 3. Claude Code

Each boundary user needs its own Claude Code login, because a session's boundary is the OS user it runs as.

```sh
sudo -iu tm-work
claude                                          # log in once, then /exit
claude plugin marketplace add /opt/tear-mesh
claude plugin install tearmesh@tear-mesh
exit
tearmesh launch --boundary work --mailbox builder -- claude
```

In the session, ask "who's on tear-mesh?" (the `who` tool). Then ask it to send `admin@beta` a question. On beta, start a session the same way with `--mailbox admin` and type anything: the hook announces the letter, and the agent can `read` it and reply.

### Wake on mail

On beta, as `tm-work`, write `~/.config/tearmesh/mailboxes.toml`:

```toml
[helper]
dir = "/home/tm-work"
command = ["claude", "-p", "{prompt}", "--output-format", "json",
           "--allowedTools", "mcp__plugin_tearmesh_tearmesh__*"]
```

Then:

```sh
sudo systemctl enable --now tearmesh-waker@tm-work
# alpha
sudo -u tm-work env TEARMESH_MAILBOX=builder tearmesh post --to helper@beta --subject question --body "What is 17 times 3? Reply with just the number."
# alpha, within a minute or two
sudo -u tm-work env TEARMESH_MAILBOX=builder tearmesh inbox
```

`journalctl -u tearmesh-waker@tm-work` shows each wake. If the woken session can't use the tools, check the exact tool names with `/permissions` in an interactive session, and adjust `--allowedTools`.

## 4. Uninstall

```sh
sudo systemctl disable --now tearmesh 'tearmesh-waker@*'
sudo rm /etc/systemd/system/tearmesh.service /etc/systemd/system/tearmesh-waker@.service
sudo systemctl daemon-reload
sudo userdel -r tm-work; sudo userdel -r tm-vault; sudo userdel tearmesh
sudo rm -rf /var/lib/tearmesh /etc/tearmesh /usr/local/bin/tearmesh
```
