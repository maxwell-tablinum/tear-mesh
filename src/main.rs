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
use tearmesh::mesh::{Approval, Category, Machine, Mesh, Sharing, ssh_sign};
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
    /// The membership file: machines, grants, approvals, owners (admin).
    #[command(subcommand)]
    Mesh(MeshCmd),
    /// Join a mesh with a ticket from its owner node (admin, on the new machine).
    Join { ticket: String },
    /// Daemon status (admin).
    Status,
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
    /// Sign with this owner key, then apply to the local daemon.
    #[arg(long)]
    key: Option<PathBuf>,
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
        key: PathBuf,
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
        #[arg(long)]
        key: PathBuf,
    },
    /// Hand a signed file (FILE and FILE.sig) to the local daemon.
    Apply { file: PathBuf },
    /// Print a one-time ticket for a new machine (on the owner node).
    Invite {
        name: String,
        #[arg(long = "boundary", required = true)]
        boundaries: Vec<String>,
        #[arg(long)]
        replace: bool,
        /// How long the ticket works: e.g. 30m, 2h, 1d.
        #[arg(long, default_value = "1h")]
        expires: String,
    },
    /// Join requests waiting for approval.
    Pending,
    /// Approve a waiting join: compare its code with the new machine's screen, then sign.
    Approve {
        name: String,
        #[arg(long)]
        key: PathBuf,
        /// Skip the confirmation (for scripts that compared the code).
        #[arg(long)]
        yes: bool,
    },
    /// Forget the adopted membership file (logs stay), to adopt a new first one.
    Reset {
        #[arg(long)]
        yes: bool,
    },
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
        let status = c.status().with_context(|| format!("running {}", command[0]))?;
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
        Cmd::Setup { config } => setup(&config).await?,
        Cmd::Mesh(c) => mesh_cmd(c).await?,
        Cmd::Join { ticket } => {
            let mut c = Client::connect(&socket_path()).await?;
            let v = c
                .call_each(&Request::Join { ticket }, |d| {
                    println!(
                        "code {}: check that the owner node shows the same code, then wait for approval.",
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
                    (k, t) => format!(" [{}{}]", k.as_str(), if t == tearmesh::envelope::Trust::Member { String::new() } else { format!(", {}", t.as_str()) }),
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
        Cmd::Bio(BioCmd::Show { machine }) => {
            let who: Who = serde_json::from_value(session(Request::Who).await?)?;
            for m in who.machines {
                if machine.as_ref().is_some_and(|x| *x != m.name) {
                    continue;
                }
                println!("== {}\n{}\n", m.name, m.bio.as_deref().unwrap_or("(no bio)"));
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
            let req = Request::Offers { boundary: boundary.clone() };
            let v = if boundary.is_some() { admin(req).await? } else { session(req).await? };
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        Cmd::Mcp { remote, http } => match (remote, http) {
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
    let mut m = Mesh::parse(&prev_toml)?;
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
    match &e.key {
        Some(k) => {
            ssh_sign(k, &out)?;
            // A local file signed offline is applied only if a daemon is there to take it.
            let daemon = from_daemon || Client::connect(&socket_path()).await.is_ok();
            if !e.no_apply && daemon {
                apply_file(&out).await?;
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
        } => {
            edit(e, |m| {
                let still = m.revoke(&from, &to, &categories)?;
                if !still.is_empty() {
                    eprintln!(
                        "note: a wildcard grant still allows {still:?} for {from} -> {to}; replace it with explicit grants to exclude this pair"
                    );
                }
                Ok(())
            })
            .await?
        }
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
        } => {
            edit(e, |m| {
                match setting.as_str() {
                    "tools-sharing" => {
                        m.settings.tools_sharing = match value.as_str() {
                            "approval" => Sharing::Approval,
                            "free" => Sharing::Free,
                            _ => bail!("tools-sharing is approval or free"),
                        }
                    }
                    "relays" => {
                        m.settings.relays = match value.as_str() {
                            "n0" | "none" => tearmesh::config::Relay::Preset(value),
                            urls => tearmesh::config::Relay::Urls(
                                urls.split(',').map(String::from).collect(),
                            ),
                        }
                    }
                    "lookup" => {
                        m.settings.lookup = value
                            .split(',')
                            .filter(|s| !s.is_empty())
                            .map(String::from)
                            .collect()
                    }
                    _ => bail!("unknown setting {setting} (tools-sharing, relays, lookup)"),
                }
                Ok(())
            })
            .await?
        }
        MeshCmd::OwnerAdd { key, edit: e } => {
            let k = std::fs::read_to_string(key)?.trim().to_string();
            edit(e, |m| {
                m.owners.push(k);
                Ok(())
            })
            .await?
        }
        MeshCmd::OwnerRemove {
            fingerprint,
            edit: e,
        } => {
            edit(e, |m| {
                let keys = m.owner_keys()?;
                let n = m.owners.len();
                let owners = std::mem::take(&mut m.owners);
                m.owners = owners
                    .into_iter()
                    .zip(keys)
                    .filter(|(_, k)| k.fingerprint(Default::default()).to_string() != fingerprint)
                    .map(|(s, _)| s)
                    .collect();
                ensure!(m.owners.len() < n, "no owner key with fingerprint {fingerprint}");
                Ok(())
            })
            .await?
        }
        MeshCmd::Migrate { edit: e } => {
            ensure!(e.file.is_some(), "migrate needs --file <0.1 circle.toml>");
            edit(e, |_| Ok(())).await?
        }
        MeshCmd::Sign { file, key } => {
            Mesh::parse(&std::fs::read_to_string(&file)?)?;
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
            eprintln!(
                "On {name}: `sudo tearmesh join <ticket>`. Then `tearmesh mesh approve {name} --key <owner key>` here, after checking both screens show the same code."
            );
        }
        MeshCmd::Pending => {
            let p: Vec<PendingInfo> = serde_json::from_value(admin(Request::Pending).await?)?;
            if p.is_empty() {
                println!("no join requests waiting");
            }
            for x in p {
                println!(
                    "{}  code {}  node {}  boundaries {}{}",
                    x.name,
                    x.code,
                    x.node_id,
                    x.boundaries.join(","),
                    if x.replace { "  (replaces the existing machine)" } else { "" }
                );
            }
        }
        MeshCmd::Approve { name, key, yes } => {
            let p: Vec<PendingInfo> = serde_json::from_value(admin(Request::Pending).await?)?;
            let x = p
                .into_iter()
                .find(|x| x.name == name)
                .with_context(|| format!("no join request from {name} is waiting"))?;
            println!(
                "{} (node {}) wants to join with boundaries {}.\nCode: {}",
                x.name,
                x.node_id,
                x.boundaries.join(", "),
                x.code
            );
            if !yes && !confirm("Does the new machine show the same code? Approve and sign?")? {
                bail!("not approved");
            }
            let e = Edit {
                file: None,
                out: Some(std::env::temp_dir().join(format!("tearmesh-approve-{name}.toml"))),
                key: Some(key),
                no_apply: false,
            };
            edit(e, |m| {
                m.add_machine(
                    Machine {
                        name: x.name,
                        id: x.node_id,
                        boundaries: x.boundaries,
                    },
                    x.replace,
                )
            })
            .await?;
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

async fn setup(config: &Path) -> Result<()> {
    let cfg = Config::load(config).with_context(|| {
        format!(
            "{} not found or invalid: install the daemon first (deploy/setup-linux.sh or deploy/setup-windows.ps1)",
            config.display()
        )
    })?;
    let ask = |q: &str| -> Result<String> {
        eprint!("{q} ");
        std::io::stderr().flush()?;
        let mut a = String::new();
        std::io::stdin().lock().read_line(&mut a)?;
        Ok(a.trim().to_string())
    };
    let choice = ask("Create a mesh (c) or join one (j)?")?;
    if choice.starts_with('j') {
        let ticket = ask("Paste the ticket from the owner node:")?;
        return Box::pin(run(Cmd::Join { ticket })).await;
    }
    ensure!(choice.starts_with('c'), "answer c or j");
    let name = ask("Name for the mesh (a-z, 0-9, -):")?;
    let boundaries: Vec<String> = {
        let mut b: Vec<String> = cfg.users.values().cloned().collect();
        b.sort();
        b.dedup();
        b
    };
    ensure!(!boundaries.is_empty(), "the config maps no users to boundaries");
    let ssh = tearmesh::os::home_dir().join(".ssh");
    std::fs::create_dir_all(&ssh)?;
    eprintln!("\nOwner keys sign every change to the mesh. You need two: an everyday key on this machine and a portable one.");
    let everyday = ask(&format!(
        "Everyday owner key (path to an existing private key, or Enter to create {}):",
        ssh.join("tearmesh-owner").display()
    ))?;
    let everyday = if everyday.is_empty() {
        let p = ssh.join("tearmesh-owner");
        eprintln!("Creating {} (choose a passphrase: any process running as you could otherwise sign with it)", p.display());
        keygen(&["-t", "ed25519", "-a", "100", "-C", "tearmesh owner"], &p)?;
        p
    } else {
        PathBuf::from(everyday)
    };
    ensure!(
        !std::process::Command::new("ssh-keygen")
            .args(["-y", "-P", ""])
            .arg("-f")
            .arg(&everyday)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?
            .success()
            || is_sk(&everyday),
        "{} has no passphrase; any process running as you could sign with it. Add one with `ssh-keygen -p -f {}`",
        everyday.display(),
        everyday.display()
    );
    let kind = ask("Portable key: a security key such as a YubiKey (s, recommended) or a key file on removable media (f)?")?;
    let portable = if kind.starts_with('s') {
        let p = ssh.join("tearmesh-portable-sk");
        eprintln!("Touch the security key when it blinks; set a PIN when asked.");
        keygen(
            &["-t", "ed25519-sk", "-O", "resident", "-O", "verify-required", "-C", "tearmesh portable"],
            &p,
        )?;
        p
    } else {
        let p = PathBuf::from(ask("Path for the key file (on the removable drive):")?);
        keygen(&["-t", "ed25519", "-a", "100", "-C", "tearmesh portable"], &p)?;
        eprintln!("Keep {} off this machine and never email it.", p.display());
        p
    };
    let pubkey = |p: &Path| -> Result<String> { Ok(std::fs::read_to_string(pub_path(p))?.trim().to_string()) };
    let mut m = Mesh::new(
        &name,
        vec![pubkey(&everyday)?, pubkey(&portable)?],
        boundaries.clone(),
        None,
    )?;
    let status = admin(Request::Status).await?;
    let id = status["node_id"]
        .as_str()
        .context("the daemon didn't report its node id")?
        .parse()
        .map_err(|e| anyhow::anyhow!("node id: {e}"))?;
    m.add_machine(
        Machine {
            name: cfg.machine.clone(),
            id,
            boundaries,
        },
        false,
    )?;
    let file = PathBuf::from(format!("{name}-mesh.toml"));
    std::fs::write(&file, m.to_toml()?)?;
    ssh_sign(&everyday, &file)?;
    apply_file(&file).await?;
    eprintln!(
        "\nMesh {name} created with this machine ({}) in it. Add machines with `tearmesh mesh invite <name> --boundary <b>`.",
        cfg.machine
    );
    Ok(())
}

/// `key.pub` next to `key`, as ssh-keygen names it.
fn pub_path(key: &Path) -> PathBuf {
    let mut s = key.as_os_str().to_owned();
    s.push(".pub");
    s.into()
}

fn is_sk(key: &Path) -> bool {
    std::fs::read_to_string(pub_path(key)).is_ok_and(|k| k.starts_with("sk-"))
}

fn keygen(args: &[&str], path: &Path) -> Result<()> {
    ensure!(!path.exists(), "{} already exists", path.display());
    let ok = std::process::Command::new("ssh-keygen")
        .args(args)
        .arg("-f")
        .arg(path)
        .status()
        .context("running ssh-keygen")?
        .success();
    ensure!(ok, "ssh-keygen failed");
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
