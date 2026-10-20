use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use serde_json::Value;

use tearmesh::config::{Config, DEFAULT_CONFIG};
use tearmesh::envelope::Kind;
use tearmesh::ipc::{Client, Request, socket_path};
use tearmesh::join::PendingInfo;
use tearmesh::mesh::{Approval, Category, Change, Grant, Machine, Mesh, ssh_sign};
use tearmesh::node::{Letter, Node, Who, load_or_create_key};
use tearmesh::offer::Offer;
use tearmesh::{hook, ipc, mcp, steward, tui};

#[derive(Parser)]
#[command(
    name = "tearmesh",
    version,
    about = "A peer-to-peer mesh for the apps and agents on your own machines, kept inside boundaries."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon (normally as a service).
    Daemon {
        #[arg(long, env = "TEARMESH_CONFIG", default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        /// Run under the Windows service manager.
        #[arg(long, hide = true)]
        service: bool,
    },
    /// Print this machine's node id, creating its key on first use.
    Id {
        #[arg(long, env = "TEARMESH_CONFIG", default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// First run: create a mesh or join one.
    Setup {
        #[arg(long, env = "TEARMESH_CONFIG", default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Install tear-mesh on this machine (root, or an elevated prompt on Windows): the service, a
    /// user per boundary (tm-<boundary>), the config and the Claude Code plugin. Run it again to
    /// upgrade or to add boundaries.
    Install {
        /// This machine's name in the mesh.
        machine: String,
        #[arg(required = true)]
        boundaries: Vec<String>,
        /// Start a steward per boundary user (systemd, or a scheduled task on Windows).
        #[arg(long)]
        stewards: bool,
    },
    /// Remove tear-mesh from this machine, and the users of the boundaries given.
    Uninstall {
        boundaries: Vec<String>,
        #[arg(long)]
        yes: bool,
    },
    /// The membership file: machines, grants, approvals, owners (admin).
    #[command(subcommand)]
    Mesh(MeshCmd),
    /// Join a mesh with a ticket from its owner node (admin, on the new machine). The join runs
    /// in the daemon: Ctrl-C leaves it waiting, `--cancel` stops it.
    Join {
        #[arg(required_unless_present = "cancel")]
        ticket: Option<String>,
        #[arg(long, conflicts_with = "ticket")]
        cancel: bool,
    },
    /// Daemon status (admin).
    Status,
    /// Ping every other machine in the mesh: which answer, and how fast (admin).
    Ping,
    /// Your address, the machines in your boundary with their bios and offers, known addresses.
    Who,
    /// Send a letter. `--body -` reads the body from stdin.
    Post {
        #[arg(long, required = true, num_args = 1..)]
        to: Vec<String>,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        body: String,
        /// Reply in the thread containing this letter id.
        #[arg(long)]
        thread: Option<String>,
        /// info, task or question.
        #[arg(long, default_value = "info")]
        kind: Kind,
    },
    /// List letters for your mailbox (TEARMESH_MAILBOX, default `admin`).
    Inbox {
        #[arg(long)]
        all: bool,
    },
    /// Show a letter and mark it read.
    Read { id: String },
    /// Full-screen menu: status, a live map of the mesh, nodes, setup and owner actions.
    Menu {
        #[arg(long, env = "TEARMESH_CONFIG", default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Terminal mail client for your mailbox (TEARMESH_MAILBOX, default `admin`).
    Tui {
        #[arg(long)]
        mailbox: Option<String>,
    },
    /// This machine's bio in your boundary.
    #[command(subcommand)]
    Bio(BioCmd),
    /// MCP servers your boundary shares (run as the boundary's user).
    #[command(subcommand)]
    Offer(OfferCmd),
    /// Offers in your boundary and whether the owner approved them.
    Offers {
        /// For admins not mapped to a boundary.
        #[arg(long)]
        boundary: Option<String>,
    },
    /// MCP server for agent harnesses: stdio mail tools, a shim for a remote server, or the
    /// HTTP connector.
    Mcp {
        #[command(subcommand)]
        hub: Option<HubCmd>,
        /// Be a shim for `<machine>/<server>`, another machine's offered server.
        #[arg(long, conflicts_with = "http")]
        remote: Option<String>,
        /// Serve the Claude connector over HTTP on a Unix socket, configured by this file
        /// (default ~/.config/tearmesh/connector.toml).
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        http: Option<String>,
    },
    /// Claude Code hook: report new mail to the session.
    Hook,
    /// Wake sessions for unheld mailboxes and run offered servers (run as the boundary's user).
    #[command(alias = "waker")]
    Steward {
        #[arg(long)]
        mailboxes: Option<PathBuf>,
        #[arg(long)]
        offers: Option<PathBuf>,
    },
    /// Carry an SSH connection to another machine: `ssh -o ProxyCommand='tearmesh shell-proxy %h'`.
    ShellProxy {
        machine: String,
        /// For admins not mapped to a boundary.
        #[arg(long)]
        boundary: Option<String>,
    },
    /// Run a command as a boundary's OS user, e.g. `tearmesh launch --boundary work -- claude`.
    Launch {
        #[arg(long)]
        boundary: String,
        #[arg(long)]
        mailbox: Option<String>,
        #[arg(long, env = "TEARMESH_CONFIG", default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// For `launch` on Windows: runas can't pass environment variables, so it runs this.
    #[command(hide = true)]
    EnvRun {
        #[arg(long = "set", value_name = "K=V")]
        set: Vec<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(clap::Args, Clone)]
struct Edit {
    /// Edit this file (the exact bytes of the current version) instead of the daemon's copy.
    #[arg(long)]
    file: Option<PathBuf>,
    /// Where to write the new version when editing the daemon's copy (default ./mesh-v<N>.toml).
    #[arg(long)]
    out: Option<PathBuf>,
    /// Sign with this owner key, then apply to the local daemon (default: this mesh's one owner
    /// key in ~/.ssh).
    #[arg(long, conflicts_with = "no_sign")]
    key: Option<PathBuf>,
    /// Only write the new version; sign it later with `tearmesh mesh sign`.
    #[arg(long)]
    no_sign: bool,
    /// Don't apply after signing.
    #[arg(long)]
    no_apply: bool,
}

#[derive(Subcommand)]
enum MeshCmd {
    /// Start a membership file (version 1).
    New {
        file: PathBuf,
        #[arg(long)]
        name: String,
        /// OpenSSH public key file (.pub). Give at least two.
        #[arg(long = "owner-key", required = true)]
        owner_keys: Vec<PathBuf>,
        #[arg(long = "boundary", required = true)]
        boundaries: Vec<String>,
        /// Keep an existing mesh's id (recovery after losing every owner key).
        #[arg(long)]
        id: Option<String>,
    },
    /// Print the current membership file.
    Show {
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Add a machine.
    Add {
        name: String,
        node_id: String,
        #[arg(long = "boundary", required = true)]
        boundaries: Vec<String>,
        #[arg(long)]
        replace: bool,
        #[command(flatten)]
        edit: Edit,
    },
    /// Remove (revoke) a machine, with its grants and approvals.
    Remove {
        name: String,
        #[command(flatten)]
        edit: Edit,
    },
    /// Let FROM act on TO: converse, tools, shell. `*` matches any machine (not for shell).
    Grant {
        from: String,
        to: String,
        #[arg(required = true)]
        categories: Vec<Category>,
        #[command(flatten)]
        edit: Edit,
    },
    /// Take categories away from the exact FROM → TO grant.
    Revoke {
        from: String,
        to: String,
        #[arg(required = true)]
        categories: Vec<Category>,
        #[command(flatten)]
        edit: Edit,
    },
    /// Approve an offered server, pinned to its current tools (and optionally only some of them).
    ApproveOffer {
        machine: String,
        boundary: String,
        server: String,
        /// Only these tools, comma-separated.
        #[arg(long, value_delimiter = ',')]
        tools: Option<Vec<String>>,
        #[command(flatten)]
        edit: Edit,
    },
    /// Withdraw an approval.
    Unapprove {
        machine: String,
        boundary: String,
        server: String,
        #[command(flatten)]
        edit: Edit,
    },
    /// Change a mesh-wide setting: tools-sharing (approval|free), relays (n0|none|URL,URL),
    /// lookup (n0-dns,mdns).
    Set {
        setting: String,
        value: String,
        #[command(flatten)]
        edit: Edit,
    },
    /// Add an owner key (an OpenSSH .pub file).
    OwnerAdd {
        /// The new key's OpenSSH public key file (.pub).
        #[arg(value_name = "PUBKEY")]
        pubkey: PathBuf,
        #[command(flatten)]
        edit: Edit,
    },
    /// Remove an owner key by its SHA256 fingerprint.
    OwnerRemove {
        fingerprint: String,
        #[command(flatten)]
        edit: Edit,
    },
    /// Turn a 0.1 circle file into the next version in format 2 (needs --file).
    Migrate {
        #[command(flatten)]
        edit: Edit,
    },
    /// Sign a file with an owner key (`ssh-keygen -Y sign`); writes FILE.sig. Needs no daemon.
    Sign {
        file: PathBuf,
        /// Default: the file's one owner key in ~/.ssh.
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Hand a signed file (FILE and FILE.sig) to the local daemon.
    Apply { file: PathBuf },
    /// Print a one-time ticket for a new machine (on the owner node). Without NAME, the new
    /// machine proposes its name and boundaries and you approve what you see.
    Invite {
        /// Only a machine configured with this name may use the ticket.
        name: Option<String>,
        /// Only for a machine hosting exactly these boundaries.
        #[arg(long = "boundary")]
        boundaries: Vec<String>,
        /// Give the existing machine NAME a new node id (a reinstall).
        #[arg(long, requires = "name")]
        replace: bool,
        /// How long the ticket works: e.g. 30m, 2h, 1d.
        #[arg(long, default_value = "1h")]
        expires: String,
    },
    /// Join requests waiting for approval.
    Pending,
    /// Approve a waiting join: compare its code with the new machine's screen, then sign. One
    /// version adds the machine, any new boundaries and grants.
    Approve {
        name: String,
        /// Add this boundary the machine asked for to the mesh (repeat for more).
        #[arg(long = "add-boundary")]
        add_boundaries: Vec<String>,
        /// Also grant FROM:TO:CATEGORIES, e.g. laptop:ws:tools,shell (repeat for more).
        #[arg(long = "grant")]
        grants: Vec<tearmesh::mesh::Grant>,
        /// Default: this mesh's one owner key in ~/.ssh.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Skip the confirmation (for scripts that compared the code).
        #[arg(long)]
        yes: bool,
    },
    /// Refuse a waiting join, or with --all close every open invite (a leaked ticket).
    Reject {
        #[arg(required_unless_present = "all")]
        name: Option<String>,
        #[arg(long, conflicts_with = "name")]
        all: bool,
    },
    /// Add a boundary to the mesh, optionally hosted by machines that already have its user.
    #[command(subcommand)]
    Boundary(BoundaryCmd),
    /// Set which boundaries MACHINE hosts (each must be in the mesh).
    Hosts {
        machine: String,
        #[arg(required = true)]
        boundaries: Vec<String>,
        #[command(flatten)]
        edit: Edit,
    },
    /// Forget the adopted membership file (logs stay), to adopt a new first one.
    Reset {
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum BoundaryCmd {
    /// Add boundary B to the mesh; --host M also makes machine M host it.
    Add {
        boundary: String,
        #[arg(long = "host")]
        hosts: Vec<String>,
        #[command(flatten)]
        edit: Edit,
    },
}

/// The MCP hub: one long-running MCP service per user, for any client.
#[derive(Subcommand)]
enum HubCmd {
    /// Run the hub (HTTP on 127.0.0.1 plus a private socket). Exits if one is already running.
    Serve,
    /// stdio for clients that start a command: connect to the hub, starting it if needed.
    Connect,
    /// The hub's URL, token and how to register it with clients.
    Info,
}

#[derive(Subcommand)]
enum BioCmd {
    /// Show the bios in your boundary.
    Show { machine: Option<String> },
    /// Set this machine's bio from a file (`-` for stdin).
    Set {
        file: PathBuf,
        /// As an admin, for this boundary (the bio then carries admin trust).
        #[arg(long)]
        boundary: Option<String>,
    },
}

#[derive(Subcommand)]
enum OfferCmd {
    /// Start the server from offers.toml, read its tools, and publish the offer.
    Publish {
        name: String,
        #[arg(long)]
        offers: Option<PathBuf>,
    },
    /// Withdraw an offer.
    Withdraw { name: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Cmd::Launch {
        boundary,
        mailbox,
        config,
        command,
    } = &cli.cmd
    {
        return launch(boundary, mailbox.as_deref(), config, command);
    }
    if let Cmd::EnvRun { set, command } = &cli.cmd {
        let mut c = std::process::Command::new(&command[0]);
        c.args(&command[1..]);
        for kv in set {
            let (k, v) = kv.split_once('=').context("--set takes K=V")?;
            c.env(k, v);
        }
        let status = c
            .status()
            .with_context(|| format!("running {}", command[0]))?;
        std::process::exit(status.code().unwrap_or(1));
    }
    // The service logs to a file (its stderr goes nowhere), so it sets up its own logging.
    if let Cmd::Daemon {
        config,
        service: true,
    } = &cli.cmd
    {
        return tearmesh::os::run_service(config.clone());
    }
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,iroh=warn,noq=warn".into()),
        )
        .init();
    tokio::runtime::Runtime::new()?.block_on(run(cli.cmd))
}

async fn run(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Daemon { config, .. } => daemon(config).await?,
        Cmd::Id { config } => {
            let cfg = Config::load(&config)?;
            println!("{}", load_or_create_key(&cfg.state_dir)?.public());
        }
        Cmd::Setup { config } => tearmesh::setup::run(&config).await?,
        Cmd::Mesh(c) => mesh_cmd(c).await?,
        Cmd::Install { machine, boundaries, stewards } => tearmesh::install::install(&machine, &boundaries, stewards)?,
        Cmd::Uninstall { boundaries, yes } => {
            let users: Vec<String> = boundaries.iter().map(|b| format!("tm-{b}")).collect();
            if !yes
                && !confirm(&format!(
                    "Remove tear-mesh from this machine: the service, its config and state, the plugin{}?",
                    if users.is_empty() { String::new() } else { format!(", and users {} with their homes", users.join(", ")) }
                ))?
            {
                bail!("not removed");
            }
            tearmesh::install::uninstall(&boundaries)?
        }
        Cmd::Join { cancel: true, .. } => {
            let v = admin(Request::JoinCancel).await?;
            println!("{}", if v["cancelled"] == true { "cancelled" } else { "no join was running" });
        }
        Cmd::Join { ticket, .. } => {
            let ticket = ticket.unwrap_or_default();
            let mut c = Client::connect(&socket_path()).await?;
            let v = c
                .call_each(&Request::Join { ticket }, |d| {
                    println!(
                        "code {}: check that the owner node shows the same code, then wait for approval.\n(Ctrl-C leaves it waiting in the daemon; `tearmesh join --cancel` stops it.)",
                        d["code"].as_str().unwrap_or_default()
                    );
                })
                .await?;
            println!("joined; mesh version {}", v["version"]);
        }
        Cmd::Status => println!(
            "{}",
            serde_json::to_string_pretty(&admin(Request::Status).await?)?
        ),
        Cmd::Ping => {
            let p: Vec<tearmesh::ping::Ping> = serde_json::from_value(admin(Request::Ping).await?)?;
            for x in p {
                match x.rtt_ms {
                    Some(r) => println!("{:<20} up    {r} ms (dial {} ms)", x.name, x.dial_ms.unwrap_or(0)),
                    None => println!("{:<20} DOWN  {}", x.name, x.error.unwrap_or_default()),
                }
            }
        }
        Cmd::Who => println!(
            "{}",
            serde_json::to_string_pretty(&session(Request::Who).await?)?
        ),
        Cmd::Post {
            to,
            subject,
            body,
            thread,
            kind,
        } => {
            let body = if body == "-" { stdin_all()? } else { body };
            let v = session(Request::Post {
                to,
                subject,
                body,
                thread,
                kind: Some(kind),
            })
            .await?;
            println!("{}", v["id"].as_str().unwrap_or_default());
        }
        Cmd::Inbox { all } => {
            let letters: Vec<Letter> =
                serde_json::from_value(session(Request::Inbox { all }).await?)?;
            for l in letters {
                let tag = match (l.kind, l.trust) {
                    (Kind::Info, tearmesh::envelope::Trust::Member) => String::new(),
                    (k, t) => format!(
                        " [{}{}]",
                        k.as_str(),
                        if t == tearmesh::envelope::Trust::Member {
                            String::new()
                        } else {
                            format!(", {}", t.as_str())
                        }
                    ),
                };
                println!(
                    "{} {} {:<24} {}{tag}",
                    &l.id[..12],
                    if l.read { " " } else { "*" },
                    l.from,
                    l.subject
                );
            }
        }
        Cmd::Read { id } => {
            let l: Letter = serde_json::from_value(session(Request::Read { id }).await?)?;
            println!(
                "id:      {}\nfrom:    {}\nto:      {}\nsubject: {}\nkind:    {}\ntrust:   {}",
                l.id,
                l.from,
                l.to.join(", "),
                l.subject,
                l.kind.as_str(),
                l.trust.as_str()
            );
            if let Some(t) = &l.thread {
                println!("thread:  {t}");
            }
            println!("\n{}", l.body.unwrap_or_default());
        }
        Cmd::Tui { mailbox } => tui::run(mailbox).await?,
        Cmd::Menu { config } => tearmesh::menu::run(&config).await?,
        Cmd::Bio(BioCmd::Show { machine }) => {
            let who: Who = serde_json::from_value(session(Request::Who).await?)?;
            for m in who.machines {
                if machine.as_ref().is_some_and(|x| *x != m.name) {
                    continue;
                }
                println!(
                    "== {}\n{}\n",
                    m.name,
                    m.bio.as_deref().unwrap_or("(no bio)")
                );
            }
        }
        Cmd::Bio(BioCmd::Set { file, boundary }) => {
            let text = if file == Path::new("-") {
                stdin_all()?
            } else {
                std::fs::read_to_string(&file)?
            };
            let v = match boundary {
                Some(boundary) => admin(Request::AdminBio { boundary, text }).await?,
                None => session(Request::Bio { text }).await?,
            };
            println!("{}", v["id"].as_str().unwrap_or_default());
        }
        Cmd::Offer(OfferCmd::Publish { name, offers }) => {
            let path = offers.unwrap_or_else(steward::default_offers);
            let defs = steward::load_offers(&path)?;
            let def = defs
                .get(&name)
                .with_context(|| format!("{} defines no offer {name}", path.display()))?;
            let offer = steward::describe(&name, def).await?;
            println!(
                "{name}: {} tool(s): {}",
                offer.tools.len(),
                offer.tool_names().join(", ")
            );
            let v = session(Request::PublishOffer { offer }).await?;
            println!("published; pin {}", v["pin"].as_str().unwrap_or_default());
        }
        Cmd::Offer(OfferCmd::Withdraw { name }) => {
            session(Request::PublishOffer {
                offer: Offer::withdrawn(&name),
            })
            .await?;
            println!("withdrew {name}");
        }
        Cmd::Offers { boundary } => {
            let req = Request::Offers {
                boundary: boundary.clone(),
            };
            let v = if boundary.is_some() {
                admin(req).await?
            } else {
                session(req).await?
            };
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        Cmd::Mcp {
            hub: Some(h), ..
        } => match h {
            HubCmd::Serve => tearmesh::hub::serve().await?,
            HubCmd::Connect => tearmesh::hub::connect().await?,
            HubCmd::Info => tearmesh::hub::info()?,
        },
        Cmd::Mcp { remote, http, .. } => match (remote, http) {
            (Some(target), _) => mcp::remote(&target).await?,
            (None, Some(path)) => connector(path).await?,
            (None, None) => mcp::run().await?,
        },
        Cmd::Hook => hook::run().await?,
        Cmd::Steward { mailboxes, offers } => {
            steward::run(
                &mailboxes.unwrap_or_else(steward::default_config),
                &offers.unwrap_or_else(steward::default_offers),
            )
            .await?
        }
        Cmd::ShellProxy { machine, boundary } => {
            let mut c = Client::connect(&socket_path()).await?;
            c.call(&Request::Shell { machine, boundary }).await?;
            let (r, w) = c.into_raw();
            tearmesh::shell::splice(tokio::io::stdin(), tokio::io::stdout(), r, w).await?;
        }
        Cmd::Launch { .. } | Cmd::EnvRun { .. } => unreachable!(),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn connector(path: String) -> Result<()> {
    let p = if path.is_empty() {
        tearmesh::connector::default_config()
    } else {
        PathBuf::from(path)
    };
    tearmesh::connector::run(&p).await
}

#[cfg(not(target_os = "linux"))]
async fn connector(_path: String) -> Result<()> {
    bail!("the connector runs on Linux (it listens on a Unix socket); run it on a Linux member")
}

async fn daemon(config: PathBuf) -> Result<()> {
    let node = Node::start(Config::load(&config)?).await?;
    let server = tokio::spawn(ipc::serve(node.clone()));
    tokio::select! {
        r = server => r??,
        r = tearmesh::os::shutdown_signal() => r?,
    }
    node.shutdown().await;
    Ok(())
}

fn stdin_all() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    Ok(s)
}

async fn session(req: Request) -> Result<Value> {
    let (mut c, _) = Client::session(false).await?;
    c.call(&req).await
}

async fn admin(req: Request) -> Result<Value> {
    Client::connect(&socket_path()).await?.call(&req).await
}

fn sig_path(file: &Path) -> PathBuf {
    let mut s = file.as_os_str().to_owned();
    s.push(".sig");
    s.into()
}

fn confirm(q: &str) -> Result<bool> {
    eprint!("{q} [y/N] ");
    std::io::stderr().flush()?;
    let mut a = String::new();
    std::io::stdin().lock().read_line(&mut a)?;
    Ok(a.trim().eq_ignore_ascii_case("y"))
}

fn parse_duration(s: &str) -> Result<Duration> {
    let (n, unit) = s.split_at(s.trim_end_matches(char::is_alphabetic).len());
    let n: u64 = n.parse().with_context(|| format!("bad duration {s:?}"))?;
    Ok(Duration::from_secs(match unit {
        "s" => n,
        "m" | "" => n * 60,
        "h" => n * 3600,
        "d" => n * 86400,
        _ => bail!("bad duration unit in {s:?} (s, m, h, d)"),
    }))
}

/// Applies `change` to the current version (a local file or the daemon's copy), bumps it, writes
/// it, and signs and applies it when a key is given.
async fn edit(e: Edit, change: impl FnOnce(&mut Mesh) -> Result<()>) -> Result<()> {
    let (prev_toml, from_daemon) = match &e.file {
        Some(f) => (std::fs::read_to_string(f)?, false),
        None => {
            let v = admin(Request::MeshCurrent).await?;
            (v["toml"].as_str().unwrap_or_default().to_string(), true)
        }
    };
    let prev = Mesh::parse(&prev_toml)?;
    // The previous version's owners sign the next one.
    let key = match (&e.key, e.no_sign) {
        (_, true) => None,
        (Some(k), _) => Some(k.clone()),
        (None, false) => Some(tearmesh::setup::owner_key(&prev)?),
    };
    let mut m = prev;
    change(&mut m)?;
    m.bump(&prev_toml)?;
    let out = match (&e.file, &e.out) {
        (_, Some(o)) => o.clone(),
        (Some(f), None) => f.clone(),
        (None, None) => PathBuf::from(format!("mesh-v{}.toml", m.version)),
    };
    std::fs::write(&out, m.to_toml()?)?;
    let _ = std::fs::remove_file(sig_path(&out));
    println!("{} is now version {}", out.display(), m.version);
    match &key {
        Some(k) => {
            ssh_sign(k, &out)?;
            // A local file signed offline is applied only if a daemon is there to take it.
            let daemon = from_daemon || Client::connect(&socket_path()).await.is_ok();
            if !e.no_apply && daemon {
                // The bytes this process wrote, not the file read back: the daemon refuses a
                // signature that doesn't match them.
                let sig = std::fs::read_to_string(sig_path(&out))?;
                let v = admin(Request::ApplyMesh {
                    toml: m.to_toml()?,
                    sig,
                })
                .await?;
                println!("applied mesh version {}", v["version"]);
            }
        }
        None => println!(
            "sign it with `tearmesh mesh sign {} --key <owner key>`, then `tearmesh mesh apply`",
            out.display()
        ),
    }
    Ok(())
}

async fn apply_file(file: &Path) -> Result<()> {
    let toml = std::fs::read_to_string(file)?;
    let sig = std::fs::read_to_string(sig_path(file))
        .context("no signature: run `tearmesh mesh sign` first")?;
    let v = admin(Request::ApplyMesh { toml, sig }).await?;
    println!("applied mesh version {}", v["version"]);
    Ok(())
}

async fn mesh_cmd(cmd: MeshCmd) -> Result<()> {
    match cmd {
        MeshCmd::New {
            file,
            name,
            owner_keys,
            boundaries,
            id,
        } => {
            ensure!(!file.exists(), "{} already exists", file.display());
            let owners = owner_keys
                .iter()
                .map(|p| Ok(std::fs::read_to_string(p)?.trim().to_string()))
                .collect::<Result<Vec<_>>>()?;
            let m = Mesh::new(&name, owners, boundaries, id)?;
            std::fs::write(&file, m.to_toml()?)?;
            println!(
                "{} is version 1 (mail allowed among all machines; add machines, then sign)",
                file.display()
            );
        }
        MeshCmd::Show { file } => {
            let t = match file {
                Some(f) => std::fs::read_to_string(f)?,
                None => admin(Request::MeshCurrent).await?["toml"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            };
            print!("{t}");
        }
        MeshCmd::Add {
            name,
            node_id,
            boundaries,
            replace,
            edit: e,
        } => {
            let id = node_id.parse().map_err(|e| anyhow::anyhow!("node id: {e}"))?;
            edit(e, |m| {
                m.add_machine(
                    Machine {
                        name,
                        id,
                        boundaries,
                    },
                    replace,
                )
            })
            .await?
        }
        MeshCmd::Remove { name, edit: e } => edit(e, |m| m.remove_machine(&name)).await?,
        MeshCmd::Grant {
            from,
            to,
            categories,
            edit: e,
        } => {
            edit(e, |m| {
                m.grant(&from, &to, &categories);
                Ok(())
            })
            .await?
        }
        MeshCmd::Revoke {
            from,
            to,
            categories,
            edit: e,
        } => edit(e, |m| change(m, Change::Revoke(Grant { from, to, allow: categories }))).await?,
        MeshCmd::ApproveOffer {
            machine,
            boundary,
            server,
            tools,
            edit: e,
        } => {
            let offers = admin(Request::Offers {
                boundary: Some(boundary.clone()),
            })
            .await?;
            let o = offers
                .as_array()
                .into_iter()
                .flatten()
                .find(|o| o["machine"] == machine.as_str() && o["server"] == server.as_str())
                .with_context(|| format!("{machine} offers no {server} in {boundary} that this machine has seen"))?
                .clone();
            let all: Vec<String> = serde_json::from_value(o["tools"].clone())?;
            if let Some(t) = &tools {
                for x in t {
                    ensure!(all.contains(x), "{server} has no tool {x}");
                }
            }
            println!("{machine}/{server} in {boundary}: tools {}", all.join(", "));
            if let Some(exe) = o["exe"].as_str() {
                println!("executable hash (the machine's own claim): {exe}");
            }
            let full: Offer = serde_json::from_value(o["offer"].clone()).context("offer details")?;
            let pin = tearmesh::offer::pin(full.instructions.as_deref(), &full.tools, tools.as_deref());
            edit(e, |m| {
                m.approvals
                    .retain(|a| !(a.machine == machine && a.boundary == boundary && a.server == server));
                m.approvals.push(Approval {
                    machine,
                    boundary,
                    server,
                    pin,
                    tools,
                });
                Ok(())
            })
            .await?
        }
        MeshCmd::Unapprove {
            machine,
            boundary,
            server,
            edit: e,
        } => {
            edit(e, |m| {
                let n = m.approvals.len();
                m.approvals
                    .retain(|a| !(a.machine == machine && a.boundary == boundary && a.server == server));
                ensure!(m.approvals.len() < n, "no such approval");
                Ok(())
            })
            .await?
        }
        MeshCmd::Set {
            setting,
            value,
            edit: e,
        } => edit(e, |m| change(m, Change::Set { setting, value })).await?,
        MeshCmd::OwnerAdd { pubkey, edit: e } => {
            let k = std::fs::read_to_string(pubkey)?;
            edit(e, |m| change(m, Change::OwnerAdd(k))).await?
        }
        MeshCmd::OwnerRemove {
            fingerprint,
            edit: e,
        } => edit(e, |m| change(m, Change::OwnerRemove(fingerprint))).await?,
        MeshCmd::Boundary(BoundaryCmd::Add {
            boundary,
            hosts,
            edit: e,
        }) => {
            edit(e, |m| {
                change(m, Change::AddBoundary(boundary.clone()))?;
                for h in hosts {
                    let mut b = m.machine(&h).with_context(|| format!("no machine named {h}"))?.boundaries.clone();
                    b.push(boundary.clone());
                    change(m, Change::SetHosts { machine: h, boundaries: b })?;
                }
                Ok(())
            })
            .await?
        }
        MeshCmd::Hosts {
            machine,
            boundaries,
            edit: e,
        } => edit(e, |m| change(m, Change::SetHosts { machine, boundaries })).await?,
        MeshCmd::Migrate { edit: e } => {
            ensure!(e.file.is_some(), "migrate needs --file <0.1 circle.toml>");
            edit(e, |_| Ok(())).await?
        }
        MeshCmd::Sign { file, key } => {
            let m = Mesh::parse(&std::fs::read_to_string(&file)?)?;
            let key = match key {
                Some(k) => k,
                None => tearmesh::setup::owner_key(&m)?,
            };
            let _ = std::fs::remove_file(sig_path(&file));
            ssh_sign(&key, &file)?;
            println!("wrote {}", sig_path(&file).display());
        }
        MeshCmd::Apply { file } => apply_file(&file).await?,
        MeshCmd::Invite {
            name,
            boundaries,
            replace,
            expires,
        } => {
            let ttl = parse_duration(&expires)?;
            let v = admin(Request::Invite {
                name: name.clone(),
                boundaries,
                replace,
                ttl_secs: Some(ttl.as_secs()),
            })
            .await?;
            println!("{}", v["ticket"].as_str().unwrap_or_default());
            let n = name.as_deref().unwrap_or("<name>");
            eprintln!(
                "On the new machine: `tearmesh menu` (J, then paste it), `tearmesh setup`, or `sudo tearmesh join <ticket>`. Then here: `tearmesh mesh approve {n}` once both screens show the same code."
            );
        }
        MeshCmd::Pending => {
            let p: Vec<PendingInfo> = serde_json::from_value(admin(Request::Pending).await?)?;
            if p.is_empty() {
                println!("no join requests waiting");
            }
            for x in p {
                println!(
                    "{}  code {}  node {}  boundaries {}  {}{}{}",
                    x.name,
                    x.code,
                    x.node_id,
                    x.boundaries.join(","),
                    if x.waiting { "waiting" } else { "away" },
                    if x.replace { "  (replaces the existing machine)" } else { "" },
                    if x.contested { "\n  WARNING: another machine also tried this ticket; approve only if the code matches on the right machine's own screen" } else { "" }
                );
            }
        }
        MeshCmd::Approve {
            name,
            add_boundaries,
            grants,
            key,
            yes,
        } => {
            let p: Vec<PendingInfo> = serde_json::from_value(admin(Request::Pending).await?)?;
            let x = p
                .into_iter()
                .find(|x| x.name == name)
                .with_context(|| format!("no join request from {name} is waiting"))?;
            let cur = admin(Request::MeshCurrent).await?;
            let mesh = Mesh::parse(cur["toml"].as_str().unwrap_or_default())?;
            let changes = x.changes(&mesh, &add_boundaries, &grants)?;
            println!(
                "{} (node {}) wants to join with boundaries {}.\nCode: {} (read it off {}'s own screen)",
                x.name,
                x.node_id,
                x.boundaries.join(", "),
                x.code,
                x.name
            );
            if x.contested {
                println!("WARNING: another machine also tried this ticket.");
            }
            for c in &changes {
                println!("  {c}");
            }
            ensure!(!(yes && x.contested), "another machine also tried this ticket; approve without --yes, after comparing codes");
            if !yes && !confirm("Does the new machine show the same code? Approve and sign?")? {
                bail!("not approved");
            }
            let dir = tearmesh::setup::private_dir("tearmesh-")?;
            let e = Edit {
                file: None,
                out: Some(dir.join(format!("{name}.toml"))),
                key,
                no_sign: false,
                no_apply: false,
            };
            let r = edit(e, |m| {
                for c in changes {
                    change(m, c)?;
                }
                Ok(())
            })
            .await;
            let _ = std::fs::remove_dir_all(&dir);
            r?;
            if !x.waiting {
                println!("{name} is away; it gets the file when it runs join again with the same ticket.");
            }
        }
        MeshCmd::Reject { name, .. } => {
            let v = admin(Request::Reject { name }).await?;
            println!("refused {} request(s) or invite(s)", v["rejected"]);
        }
        MeshCmd::Reset { yes } => {
            if !yes
                && !confirm("Forget this machine's mesh? Logs stay; the next file you apply is trusted as a first one.")?
            {
                bail!("not reset");
            }
            admin(Request::Reset).await?;
            println!("reset; apply a new membership file with `tearmesh mesh apply`");
        }
    }
    Ok(())
}

/// One change, printing its note.
fn change(m: &mut Mesh, c: Change) -> Result<()> {
    if let Some(n) = m.change(&c)? {
        eprintln!("note: {n}");
    }
    Ok(())
}

fn launch(boundary: &str, mailbox: Option<&str>, config: &Path, command: &[String]) -> Result<()> {
    let cfg = Config::load(config)?;
    let user = cfg.boundary_user(boundary).with_context(|| {
        format!(
            "no OS user maps to boundary {boundary} in {}",
            config.display()
        )
    })?;
    let mut env = vec![(
        "TEARMESH_SOCKET".to_string(),
        cfg.socket.display().to_string(),
    )];
    if let Some(m) = mailbox {
        env.push(("TEARMESH_MAILBOX".into(), m.into()));
    }
    tearmesh::os::launch(user, &env, command)
}

#[cfg(test)]
mod cli_tests {
    #[test]
    fn every_subcommand_parses() {
        // Catches clashing argument names (owner-add's KEY once collided with --key).
        <super::Cli as clap::CommandFactory>::command().debug_assert();
    }
}
