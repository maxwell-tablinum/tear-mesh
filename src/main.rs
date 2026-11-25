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
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon (normally as a service).
    #[command(hide = true)]
    Daemon {
        #[arg(long, env = "TEARMESH_CONFIG", default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        /// Run under the Windows service manager.
        #[arg(long, hide = true)]
        service: bool,
    },
    /// Print this machine's node id, creating its key on first use.
    #[command(hide = true)]
    Id {
        #[arg(long, env = "TEARMESH_CONFIG", default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Deprecated; the menu does this.
    #[command(hide = true)]
    Setup {
        #[arg(long, env = "TEARMESH_CONFIG", default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Install tear-mesh on this machine (root, or an elevated prompt on Windows): the service, a
    /// user per boundary (tm-<boundary>), the config and the Claude Code plugin. Run it again to
    /// upgrade or to add boundaries.
    Install {
        /// This machine's name in the mesh. Default: the installed one, else its hostname.
        machine: Option<String>,
        /// None is fine: an owner picks them when this machine joins.
        boundaries: Vec<String>,
        /// Start a steward per boundary user (systemd, or a scheduled task on Windows).
        #[arg(long)]
        stewards: bool,
        /// Also map your own OS user (the one who ran sudo, or the elevated prompt) to this
        /// boundary, so agents you run as yourself are its sessions.
        #[arg(long, value_name = "BOUNDARY")]
        me: Option<String>,
        /// Then join a mesh with this ticket, and add the users of the boundaries an owner picks.
        #[arg(long)]
        join: Option<String>,
    },
    /// Remove tear-mesh from this machine, telling the other machines it is leaving. Deletes the
    /// boundary users install made (tm-<boundary>), or only those of the boundaries given.
    Uninstall {
        boundaries: Vec<String>,
        /// Delete no users.
        #[arg(long, conflicts_with = "boundaries")]
        keep_users: bool,
        /// Skip the questions; your own ~/.config/tearmesh and ~/.local/state/tearmesh stay.
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
    Status {
        #[arg(long)]
        ping: bool,
    },
    /// Your address, the machines in your boundary with their bios and offers, known addresses.
    Who,
    /// Send a letter. `--body -` reads the body from stdin.
    Post {
        /// Recipients, as mailbox@machine (for example admin@alpha), or * for everyone.
        #[arg(long, required = true, num_args = 1..)]
        to: Vec<String>,
        /// The subject line.
        #[arg(long)]
        subject: String,
        /// The text of the letter, or - to read it from stdin.
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
    /// This mailbox as an agent: its status record, and claims (TEARMESH_MAILBOX, default `admin`).
    #[command(subcommand)]
    Agent(AgentCmd),
    /// Full-screen menu: the mesh and its live map, mail, settings, and owner actions.
    Menu {
        #[arg(long, env = "TEARMESH_CONFIG", default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Deprecated; the menu does this.
    #[command(hide = true)]
    Tui {
        #[arg(long)]
        mailbox: Option<String>,
    },
    /// Letters the screener flagged in your boundary, and how many still wait for it.
    Quarantine {
        #[command(subcommand)]
        cmd: Option<QuarantineCmd>,
        /// For admins not mapped to a boundary.
        #[arg(long, global = true)]
        boundary: Option<String>,
    },
    /// This machine's bio in your boundary.
    #[command(subcommand)]
    Bio(BioCmd),
    /// MCP servers your boundary shares (run as the boundary's user).
    #[command(subcommand)]
    Offer(OfferCmd),
    /// Deprecated; the menu does this.
    #[command(hide = true)]
    Offers {
        /// For admins not mapped to a boundary.
        #[arg(long)]
        boundary: Option<String>,
    },
    /// MCP server for agent harnesses: stdio mail tools, or a shim for a remote server.
    Mcp {
        #[command(subcommand)]
        hub: Option<HubCmd>,
        /// Be a shim for `<machine>/<server>`, another machine's offered server.
        #[arg(long)]
        remote: Option<String>,
    },
    /// The gateway (Linux): Claude's apps (voice, phone, web) reach the mesh through it as a custom
    /// connector.
    #[command(subcommand)]
    Gateway(GatewayCmd),
    /// Claude Code hook: report new mail to the session.
    #[command(hide = true)]
    Hook,
    /// Wake sessions for unheld mailboxes and run offered servers (run as the boundary's user).
    #[command(alias = "waker", hide = true)]
    Steward {
        #[arg(long)]
        mailboxes: Option<PathBuf>,
        #[arg(long)]
        offers: Option<PathBuf>,
        #[arg(long)]
        screen: Option<PathBuf>,
    },
    /// Carry an SSH connection to another machine: `ssh -o ProxyCommand='tearmesh shell-proxy %h'`.
    #[command(hide = true)]
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
    #[command(hide = true)]
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
    #[command(hide = true)]
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
    /// Let FROM act on TO (FROM speaks, TO listens): converse, tools, shell. `*` matches any
    /// machine (not for shell).
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
    /// Sign a file with an owner key (`ssh-keygen -Y sign`); writes FILE.sig. Needs no daemon.
    #[command(hide = true)]
    Sign {
        file: PathBuf,
        /// Default: the file's one owner key in ~/.ssh.
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Hand a signed file (FILE and FILE.sig) to the local daemon.
    #[command(hide = true)]
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
        /// How long the ticket works: e.g. 30m, 2h, 1d (a bare number is minutes).
        #[arg(long, default_value = "1h")]
        expires: String,
    },
    /// Join requests waiting for approval.
    Pending,
    /// Approve a waiting join: compare its code with the new machine's screen, then sign. One
    /// version adds the machine, any new boundaries and grants.
    Approve {
        name: String,
        /// Host this boundary of the mesh on the machine (repeat for more). Without it, the machine
        /// hosts what it asked for that the mesh has.
        #[arg(long = "host")]
        hosts: Vec<String>,
        /// Add this boundary the machine asked for to the mesh, and host it (repeat for more).
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
    /// Dissolve the mesh: a last version with no machines, after which nothing can follow. Every
    /// machine leaves, keeps its logs (moved aside) and may then create or join another mesh.
    Dissolve {
        /// Skip typing the mesh name to confirm.
        #[arg(long)]
        yes: bool,
        /// Then uninstall tear-mesh from this machine too (`tearmesh uninstall --yes`, elevated).
        #[arg(long)]
        uninstall: bool,
        #[command(flatten)]
        edit: Edit,
    },
    /// Tell the other machines this one is leaving, then leave the mesh (admin). Logs are kept,
    /// moved aside; the machine can then create or join a mesh.
    Leave {
        #[arg(long)]
        yes: bool,
    },
    /// Forget the adopted membership file (logs stay bound to this mesh), to adopt a new first one.
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

/// The gateway: an MCP server on 127.0.0.1 for Claude's custom connectors, behind a sign-in and a tunnel.
#[derive(Subcommand)]
enum GatewayCmd {
    /// Make this machine a gateway for BOUNDARY (as root): config, passphrase, service.
    Setup {
        boundary: String,
        /// The connector URL as it will be entered in Claude, e.g. https://mesh.example.com/mcp.
        #[arg(long)]
        url: String,
        #[arg(long)]
        port: Option<u16>,
        /// The mailbox its letters come from (default claude).
        #[arg(long)]
        mailbox: Option<String>,
        /// Replace the passphrase (sign-ins stay).
        #[arg(long)]
        new_passphrase: bool,
    },
    /// Run the gateway (the service does).
    #[command(hide = true)]
    Serve,
    /// The config, whether the gateway and the daemon answer, the sign-ins and the last call.
    Status,
    /// List the sign-ins.
    Grants,
    /// End a sign-in, or all of them.
    Revoke {
        id: Option<String>,
        #[arg(long)]
        all: bool,
    },
    /// Make a new passphrase and print it once.
    Passphrase {
        /// Also end every sign-in.
        #[arg(long)]
        revoke_all: bool,
        /// Only when there is none yet (setup uses this).
        #[arg(long, hide = true)]
        if_missing: bool,
    },
    /// Stop and remove the service, the config and the state directory (as root).
    Remove {
        #[arg(long)]
        yes: bool,
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

/// A starter bio. The daemon stores a bio as text; the field names are A2A Agent Card's
/// (name, description, skills: id, name, description, tags, examples), so the two map across.
const BIO_TEMPLATE: &str = "\
# About this machine, for the agents on your other machines. They read it before asking it
# for anything, so say what it is, what it can do, and what to leave alone.
name: workstation
description: What this machine is and what it is for, in a sentence or two.
agent: none   # or who answers mail here, e.g. Claude Code at the mailbox admin
skills:
  - id: cad-export
    name: CAD export
    description: What a caller gets, and how - the offered MCP server or the mailbox to ask.
    tags: [cad, step]
    examples:
      - Export part 1234 as STEP
notes: Where things live, and what a visiting agent should not touch.
";

#[derive(Subcommand)]
enum AgentCmd {
    /// Write this mailbox's status record, keeping the fields not given; with no flag, print it.
    Status {
        /// What this agent is and can answer (empty clears it).
        #[arg(long)]
        about: Option<String>,
        /// Its current task, one line (empty clears it).
        #[arg(long)]
        task: Option<String>,
        /// How many questions wait for the owner.
        #[arg(long)]
        pending: Option<u64>,
    },
    /// Answer a letter with a claim ("working on it") so its sender knows to wait.
    Claim {
        /// The letter's id (6 or more characters).
        letter: String,
        /// Seconds until the real answer.
        #[arg(long)]
        secs: Option<u64>,
        /// A short note (default "working on it").
        #[arg(long)]
        note: Option<String>,
    },
}

#[derive(Subcommand)]
enum QuarantineCmd {
    /// Let sessions see a flagged letter.
    Release { id: String },
    /// Print a flagged letter, for a person to read.
    Show { id: String },
}

#[derive(Subcommand)]
enum BioCmd {
    /// Show the bios in your boundary.
    Show { machine: Option<String> },
    /// Print a starter bio to edit: `tearmesh bio template > bio.yaml`, then `bio set bio.yaml`.
    Template,
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
    if let Some(Cmd::Launch {
        boundary,
        mailbox,
        config,
        command,
    }) = &cli.cmd
    {
        return launch(boundary, mailbox.as_deref(), config, command);
    }
    if let Some(Cmd::EnvRun { set, command }) = &cli.cmd {
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
    if let Some(Cmd::Daemon {
        config,
        service: true,
    }) = &cli.cmd
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

async fn run(cmd: Option<Cmd>) -> Result<()> {
    let cmd = match cmd {
        Some(cmd) => cmd,
        // Bare `tearmesh`: the menu, with the config from the environment or the default path.
        None => {
            let config = std::env::var_os("TEARMESH_CONFIG")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
            return tearmesh::menu::run(&config).await;
        }
    };
    match cmd {
        Cmd::Daemon { config, .. } => daemon(config).await?,
        Cmd::Id { config } => {
            let cfg = Config::load(&config)?;
            println!("{}", load_or_create_key(&cfg.state_dir)?.public());
        }
        Cmd::Setup { config } => tearmesh::setup::run(&config).await?,
        Cmd::Mesh(c) => mesh_cmd(c).await?,
        Cmd::Install { machine, boundaries, stewards, me, join } => {
            let machine = machine.unwrap_or_else(tearmesh::install::default_machine);
            let added = tearmesh::install::install(&machine, &boundaries, stewards, me.as_deref())?;
            match join {
                Some(ticket) => install_join(&machine, ticket, stewards).await?,
                None => {
                    if let Some(log) = tearmesh::install::service_log() {
                        let mut up = false;
                        for _ in 0..10 {
                            if admin(Request::Status).await.is_ok() {
                                up = true;
                                break;
                            }
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                        ensure!(up, "the daemon didn't answer within 10 s; its log: {log}");
                    }
                    if added {
                        println!(
                            "New boundaries are only local until an owner adds them to this machine in the mesh (tearmesh mesh hosts {machine} ...)."
                        );
                    }
                }
            }
        }
        Cmd::Uninstall { boundaries, keep_users, yes } => uninstall(boundaries, keep_users, yes).await?,
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
        Cmd::Status { ping } => {
            let mut v = admin(Request::Status).await?;
            if ping {
                v["ping"] = admin(Request::Ping).await?;
            }
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        Cmd::Who => {
            let (mut c, _) = Client::session(false).await?;
            let mut v = c.call(&Request::Who).await?;
            v["offers"] = c.call(&Request::Offers { boundary: None }).await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
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
                idem: None,
            })
            .await?;
            println!("{}", v["id"].as_str().unwrap_or_default());
        }
        Cmd::Inbox { all } => {
            let letters: Vec<Letter> =
                serde_json::from_value(session(Request::inbox(all)).await?)?;
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
                let eta = l.expect_secs.map(|s| format!(" (answer expected in {s} s)")).unwrap_or_default();
                println!(
                    "{} {} {:<24} {}{tag}{eta}",
                    &l.id[..12],
                    if l.read { " " } else { "*" },
                    plain(&l.from),
                    plain(&l.subject)
                );
            }
        }
        Cmd::Agent(AgentCmd::Status { about, task, pending }) => {
            let show = about.is_none() && task.is_none() && pending.is_none();
            let v = session(Request::SetStatus { about, task, pending_questions: pending }).await?;
            match (show, v.is_null()) {
                (true, true) => println!("no status record yet"),
                (true, false) => println!("{}", plain(&serde_json::to_string_pretty(&v)?)),
                (false, _) => println!("{}", v["id"].as_str().unwrap_or_default()),
            }
        }
        Cmd::Agent(AgentCmd::Claim { letter, secs, note }) => {
            let v = session(Request::Claim { thread: letter, expect_secs: secs, note }).await?;
            println!("{}", v["id"].as_str().unwrap_or_default());
        }
        Cmd::Read { id } => {
            let l: Letter = serde_json::from_value(session(Request::Read { id }).await?)?;
            println!(
                "id:      {}\nfrom:    {}\nto:      {}\nsubject: {}\nkind:    {}\ntrust:   {}",
                l.id,
                plain(&l.from),
                plain(&l.to.join(", ")),
                plain(&l.subject),
                l.kind.as_str(),
                l.trust.as_str()
            );
            if let Some(t) = &l.thread {
                println!("thread:  {}", plain(t));
            }
            println!("\n{}", plain(&l.body.unwrap_or_default()));
        }
        Cmd::Quarantine { cmd, boundary } => {
            let call = async |req: Request| {
                if boundary.is_some() {
                    admin(req).await
                } else {
                    session(req).await
                }
            };
            match cmd {
                None => {
                    let v = call(Request::Quarantine { boundary: boundary.clone(), id: None }).await?;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_millis() as u64;
                    let flagged = v["flagged"].as_array().cloned().unwrap_or_default();
                    for f in &flagged {
                        let mins = now.saturating_sub(f["ts"].as_u64().unwrap_or(now)) / 60_000;
                        println!(
                            "{} {:<24} {}\n    {} ({})",
                            f["id"].as_str().unwrap_or_default().get(..12).unwrap_or_default(),
                            plain(f["from"].as_str().unwrap_or_default()),
                            plain(f["subject"].as_str().unwrap_or_default()),
                            plain(f["reason"].as_str().unwrap_or_default()),
                            if mins < 120 { format!("{mins} min ago") } else { format!("{} h ago", mins / 60) }
                        );
                    }
                    println!("{} flagged, {} waiting for the screener", flagged.len(), v["waiting"]);
                    println!(
                        "To block a sender, on the owner node: tearmesh mesh revoke <sender's machine> <this machine> converse"
                    );
                }
                Some(QuarantineCmd::Release { id }) => {
                    let v = call(Request::Release { boundary: boundary.clone(), id }).await?;
                    println!("released {}", v["released"].as_str().unwrap_or_default());
                }
                Some(QuarantineCmd::Show { id }) => {
                    let l: Letter = serde_json::from_value(
                        call(Request::Quarantine { boundary: boundary.clone(), id: Some(id) }).await?,
                    )?;
                    println!(
                        "!! Flagged by the screener: it tried to make a reader act. Read it; don't paste it into an agent.\n"
                    );
                    println!(
                        "id:      {}\nfrom:    {}\nto:      {}\nsubject: {}\n\n{}",
                        l.id,
                        plain(&l.from),
                        plain(&l.to.join(", ")),
                        plain(&l.subject),
                        plain(&l.body.unwrap_or_default())
                    );
                }
            }
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
                    plain(&m.name),
                    plain(m.bio.as_deref().unwrap_or("(no bio)"))
                );
            }
        }
        Cmd::Bio(BioCmd::Template) => print!("{BIO_TEMPLATE}"),
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
            // Nothing else tells the publisher that an owner still has to approve it.
            let who: Who = serde_json::from_value(session(Request::Who).await?)?;
            let me = who.machines.iter().find(|m| m.this_machine).map_or("<this machine>", |m| m.name.as_str());
            println!("Next, on the owner node, unless the mesh shares tools freely: tearmesh mesh approve-offer {me} {} {name}", who.boundary);
            println!("A steward running as this user serves it: tearmesh steward (or the tearmesh-steward@ service).");
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
        Cmd::Mcp { remote, .. } => match remote {
            Some(target) => mcp::remote(&target).await?,
            None => mcp::run().await?,
        },
        Cmd::Gateway(g) => gateway(g).await?,
        Cmd::Hook => hook::run().await?,
        Cmd::Steward { mailboxes, offers, screen } => {
            steward::run(
                &mailboxes.unwrap_or_else(steward::default_config),
                &offers.unwrap_or_else(steward::default_offers),
                &screen.unwrap_or_else(steward::default_screen),
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
async fn gateway(cmd: GatewayCmd) -> Result<()> {
    use tearmesh::gateway as g;
    match cmd {
        GatewayCmd::Setup { boundary, url, port, mailbox, new_passphrase } => {
            g::setup(&boundary, &url, port, mailbox, new_passphrase).await
        }
        GatewayCmd::Serve => g::serve().await,
        GatewayCmd::Status => g::status().await,
        GatewayCmd::Grants => g::grants(),
        GatewayCmd::Revoke { id, all } => match (id, all) {
            (Some(id), false) => g::revoke(Some(&id)),
            (None, true) => g::revoke(None),
            _ => bail!("name one sign-in (see tearmesh gateway grants), or --all"),
        },
        GatewayCmd::Passphrase { revoke_all, if_missing } => g::passphrase(revoke_all, if_missing),
        GatewayCmd::Remove { yes } => g::remove(yes),
    }
}

#[cfg(not(target_os = "linux"))]
async fn gateway(_cmd: GatewayCmd) -> Result<()> {
    bail!("the gateway runs on Linux")
}

async fn daemon(config: PathBuf) -> Result<()> {
    let cfg = Config::load(&config)?;
    // Root and the daemon's own user are admins, so neither can be held to a guest's limits.
    let me = tearmesh::os::my_identity()?;
    for id in cfg.guest_map()?.keys() {
        anyhow::ensure!(*id != me && !(cfg!(unix) && id == "0"), "a user under [guests] is root or the daemon's own user");
    }
    let node = Node::start(cfg).await?;
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

/// Text another machine wrote, for the screen: control characters (terminal escapes) become U+FFFD.
fn plain(s: &str) -> String {
    s.replace(|c: char| c.is_control() && c != '\n' && c != '\t', "\u{fffd}")
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
            edit(e, |m| change(m, Change::Approve(Approval { machine, boundary, server, pin, tools }))).await?
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
            let ticket = v["ticket"].as_str().unwrap_or_default();
            println!("{ticket}");
            let n = name.as_deref().unwrap_or("<name>");
            let [linux, windows] = tearmesh::install::one_liners(ticket, name.as_deref());
            eprintln!(
                "On a new Linux machine, to install and join:\n  {linux}\nOn Windows, in PowerShell as Administrator:\n  {windows}\nWith tear-mesh already installed: `tearmesh menu` (J, then paste it), or `sudo tearmesh join <ticket>`. Then here: `tearmesh mesh approve {n}` once both screens show the same code."
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
            mut hosts,
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
            if hosts.is_empty() && !add_boundaries.is_empty() {
                hosts = x.default_hosts(&mesh);
            }
            for b in add_boundaries {
                if !hosts.contains(&b) {
                    hosts.push(b);
                }
            }
            let changes = x.changes(&mesh, &hosts, &grants)?;
            println!(
                "{} (node {}) wants to join with boundaries {}.\nCode: {} (read it off {}'s own screen)",
                x.name,
                x.node_id,
                if x.boundaries.is_empty() { "(none: pick them with --host)".into() } else { x.boundaries.join(", ") },
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
        MeshCmd::Dissolve { yes, uninstall, edit: mut e } => {
            let prev = match &e.file {
                Some(f) => std::fs::read_to_string(f)?,
                None => admin(Request::MeshCurrent).await?["toml"].as_str().unwrap_or_default().to_string(),
            };
            let m = Mesh::parse(&prev)?;
            ensure!(!m.closed, "mesh {} is already dissolved", m.name);
            println!(
                "Dissolving mesh {} removes all {} machines from it, for good. Each keeps its logs, moved aside, and can then create or join another mesh.",
                m.name,
                m.machines.len()
            );
            if !yes {
                eprint!("Type the mesh name ({}) to dissolve it: ", m.name);
                std::io::stderr().flush()?;
                let mut a = String::new();
                std::io::stdin().lock().read_line(&mut a)?;
                ensure!(a.trim() == m.name, "not dissolved");
            }
            // Written where no other user can swap the file between writing and signing.
            let dir = tearmesh::setup::private_dir("tearmesh-")?;
            if e.file.is_none() && e.out.is_none() {
                e.out = Some(dir.join("dissolve.toml"));
            }
            let r = edit(e, |m| change(m, Change::Dissolve)).await;
            let _ = std::fs::remove_dir_all(&dir);
            r?;
            // Hand the closed version to the machines now, if this daemon took it.
            let mut applied = false;
            if let Ok(st) = admin(Request::Status).await
                && st["dissolved"] == m.name
            {
                applied = true;
                let v = admin(Request::SyncNow).await?;
                let k = v["synced"].as_array().map_or(0, |a| a.len());
                let n = m.machines.iter().filter(|x| st["machine"] != x.name.as_str()).count();
                // A completed session means the machine was offered the version, not that it took it
                // (a 0.3.0 daemon can't read it).
                println!("Reached {k} of {n} machines; the rest fetch it on their next sync.");
            }
            if uninstall {
                ensure!(applied, "not uninstalling: the dissolve wasn't applied");
                tearmesh::install::elevated(&["uninstall", "--yes"])?;
            }
        }
        MeshCmd::Leave { yes } => {
            if !yes {
                let name = admin(Request::Status).await.ok().and_then(|s| s["mesh"]["name"].as_str().or(s["dissolved"].as_str()).map(String::from));
                ensure!(
                    confirm(&format!(
                        "Leave mesh {}? This machine tells the others it is leaving and forgets the mesh; its logs are kept, moved to boundaries-<mesh id>/ in the state directory.",
                        name.as_deref().unwrap_or("?")
                    ))?,
                    "not left"
                );
            }
            tell_leaving().await;
            admin(Request::LeaveMesh).await?;
            println!("left the mesh; this machine can create or join a mesh now");
        }
        MeshCmd::Reset { yes } => {
            if !yes
                && !confirm("Forget this machine's membership file? Logs stay bound to this mesh, so only a file for the same mesh can follow (to leave for good: tearmesh mesh leave).")?
            {
                bail!("not reset");
            }
            tell_leaving().await;
            admin(Request::Reset).await?;
            println!("reset; apply a new membership file with `tearmesh mesh apply`");
        }
    }
    Ok(())
}

/// Best effort: the others mark this machine as leaving, so the owner node can remove it.
async fn tell_leaving() {
    if let Ok(v) = admin(Request::Leave).await
        && let Some(h) = v["heard"].as_array().filter(|h| !h.is_empty())
    {
        let h: Vec<&str> = h.iter().filter_map(|x| x.as_str()).collect();
        println!("told {} that this machine is leaving", h.join(", "));
    }
}

/// `install --join`: waits for the new daemon, joins unless this machine already is in a mesh
/// (so a re-run only adds users), then creates the users of the boundaries it hosts.
async fn install_join(machine: &str, ticket: String, stewards: bool) -> Result<()> {
    let mut status = None;
    for _ in 0..30 {
        if let Ok(v) = admin(Request::Status).await {
            status = Some(v);
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let status = status.context("the daemon didn't answer within 30 s; check the service, then run `sudo tearmesh join <ticket>`")?;
    if status["mesh"].is_null() {
        let mut c = Client::connect(&socket_path()).await?;
        let v = c
            .call_each(&Request::Join { ticket }, |d| {
                let code = d["code"].as_str().unwrap_or_default();
                let code = if code.len() == 6 { format!("{} {}", &code[..3], &code[3..]) } else { code.into() };
                println!("Code {code} — check the owner node shows the same code, then approve it there.");
            })
            .await?;
        println!("joined; mesh version {}", v["version"]);
    } else {
        println!("already in mesh {}; not joining again", status["mesh"]["name"].as_str().unwrap_or_default());
    }
    let status = admin(Request::Status).await?;
    let hosts: Vec<String> = serde_json::from_value(status["mesh"]["hosts"].clone()).unwrap_or_default();
    let cfg = tearmesh::install::installed().context("no installed config")?;
    let missing = tearmesh::install::missing_users(&cfg, &hosts);
    if !missing.is_empty() {
        println!("adding the users for {}", missing.join(", "));
        tearmesh::install::install(machine, &missing, stewards, None)?;
    }
    Ok(())
}

/// `tearmesh uninstall`: confirm, tell the others, run the script, then offer to remove this
/// person's own tear-mesh files. Owner keys in ~/.ssh are never touched.
async fn uninstall(boundaries: Vec<String>, keep_users: bool, yes: bool) -> Result<()> {
    use tearmesh::install;
    install::require_admin("uninstall")?;
    let cfg = install::installed();
    let (ours, kept) = cfg.as_ref().map(|c| install::created_users(c, &install::created_record())).unwrap_or_default();
    let boundaries = match (keep_users, boundaries.is_empty()) {
        (true, _) => vec![],
        (false, true) => ours,
        (false, false) => boundaries,
    };
    let users: Vec<String> = boundaries.iter().map(|b| format!("tm-{b}")).collect();
    let status = admin(Request::Status).await.ok();
    let mesh = status.as_ref().map(|s| &s["mesh"]).filter(|m| m.is_object());
    let home = install::invoker_home();
    let owners: Vec<String> = mesh
        .and_then(|m| m["owners"].as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let keys = tearmesh::setup::find_owner_keys_in(&home, &owners);
    println!(
        "Uninstall removes {}{}, and stops running hubs and stewards.",
        install::REMOVES,
        if users.is_empty() { String::new() } else { format!(", and users {} with their homes", users.join(", ")) }
    );
    let kept: Vec<&String> = kept.iter().filter(|u| !users.contains(u)).collect();
    if !kept.is_empty() {
        println!("Users kept (not created by install): {}.", kept.iter().map(|u| u.as_str()).collect::<Vec<_>>().join(", "));
    }
    if !keys.is_empty() {
        println!(
            "This is an owner node of mesh {}. Afterwards only the other owner keys (the recovery key) can sign for it. To end the mesh instead, run `tearmesh mesh dissolve` first.",
            mesh.and_then(|m| m["name"].as_str()).unwrap_or_default()
        );
    }
    if !yes && !confirm("Remove tear-mesh from this machine?")? {
        bail!("not removed");
    }
    if mesh.is_some() {
        let name = status.as_ref().and_then(|s| s["machine"].as_str()).unwrap_or_default().to_string();
        let heard: Vec<String> = match admin(Request::Leave).await {
            Ok(v) => v["heard"].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect(),
            Err(_) => vec![],
        };
        if heard.is_empty() {
            println!("No other machine heard that this one is leaving: on the owner node run `tearmesh mesh remove {name}`.");
        } else {
            println!("Told {} that this machine is leaving; the owner node still removes it (`tearmesh mesh remove {name}`).", heard.join(", "));
        }
    } else if let (None, Some(c)) = (&status, &cfg) {
        println!("The daemon isn't answering, so no machine heard that this one is leaving: if it is in a mesh, on the owner node run `tearmesh mesh remove {}`.", c.machine);
    }
    install::uninstall(&boundaries)?;
    let mine = [home.join(".config").join("tearmesh"), home.join(".local").join("state").join("tearmesh")];
    let mine: Vec<&PathBuf> = mine.iter().filter(|p| p.exists()).collect();
    if !yes
        && !mine.is_empty()
        && confirm(&format!(
            "Also remove {} (mailboxes, offers, hub settings)?",
            mine.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(" and ")
        ))?
    {
        for p in mine {
            std::fs::remove_dir_all(p).with_context(|| format!("removing {}", p.display()))?;
        }
    }
    for k in &keys {
        println!("Owner key kept: {}", k.display());
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

    fn parse(args: &[&str]) -> Result<super::Cli, clap::Error> {
        <super::Cli as clap::Parser>::try_parse_from(args)
    }

    #[test]
    fn bare_tearmesh_opens_the_menu() {
        assert!(parse(&["tearmesh"]).unwrap().cmd.is_none());
    }

    #[test]
    fn hidden_commands_still_parse() {
        let cases: &[&[&str]] = &[
            &["tearmesh", "daemon"],
            &["tearmesh", "id"],
            &["tearmesh", "setup"],
            &["tearmesh", "tui"],
            &["tearmesh", "offers"],
            &["tearmesh", "hook"],
            &["tearmesh", "steward"],
            &["tearmesh", "shell-proxy", "ws"],
            &["tearmesh", "env-run", "--", "true"],
            &[
                "tearmesh",
                "mesh",
                "new",
                "m.toml",
                "--name",
                "n",
                "--owner-key",
                "a",
                "--owner-key",
                "b",
                "--boundary",
                "work",
            ],
            &["tearmesh", "mesh", "add", "m", "deadbeef", "--boundary", "work"],
            &["tearmesh", "mesh", "sign", "m.toml"],
            &["tearmesh", "mesh", "apply", "m.toml"],
        ];
        for args in cases {
            assert!(parse(args).is_ok(), "{args:?}");
        }
    }

    #[test]
    fn mesh_leave_and_reset_parse() {
        assert!(parse(&["tearmesh", "mesh", "leave"]).is_ok());
        assert!(parse(&["tearmesh", "mesh", "leave", "--yes"]).is_ok());
        assert!(parse(&["tearmesh", "mesh", "reset", "--yes"]).is_ok());
        assert!(parse(&["tearmesh", "mesh", "leave", "--now"]).is_err());
    }

    #[test]
    fn post_and_invite_flags_are_described() {
        let cmd = <super::Cli as clap::CommandFactory>::command();
        let post = cmd.find_subcommand("post").unwrap();
        for a in ["to", "subject", "body", "thread", "kind"] {
            assert!(post.get_arguments().find(|x| x.get_id() == a).unwrap().get_help().is_some(), "post --{a}");
        }
        let invite = cmd.find_subcommand("mesh").unwrap().find_subcommand("invite").unwrap();
        let help = invite.get_arguments().find(|x| x.get_id() == "expires").unwrap().get_help().unwrap().to_string();
        assert!(help.contains("bare number is minutes"), "{help}");
    }

    #[test]
    fn terminal_escapes_in_letters_are_replaced() {
        assert_eq!(super::plain("a\u{1b}[31mb\nc\td"), "a\u{fffd}[31mb\nc\td");
    }

    #[test]
    fn dropped_commands_dont_parse() {
        assert!(parse(&["tearmesh", "ping"]).is_err());
        assert!(parse(&["tearmesh", "mesh", "migrate", "--file", "circle.toml"]).is_err());
    }

    /// The command names a rendered `--help` lists: a row starts with two spaces, then the name.
    fn listed_commands(mut cmd: clap::Command) -> Vec<String> {
        cmd.render_help()
            .to_string()
            .lines()
            .filter_map(|l| Some(l.strip_prefix("  ")?.split_whitespace().next()?.to_string()))
            .collect()
    }

    #[test]
    fn the_help_lists_no_hidden_command() {
        let mut cmd = <super::Cli as clap::CommandFactory>::command();
        let mesh = cmd.find_subcommand_mut("mesh").unwrap().clone();
        for name in [
            "daemon",
            "id",
            "setup",
            "tui",
            "offers",
            "hook",
            "steward",
            "shell-proxy",
            "env-run",
        ] {
            assert!(!listed_commands(cmd.clone()).contains(&name.to_string()), "{name} shows in --help");
        }
        for name in ["new", "add", "sign", "apply"] {
            assert!(!listed_commands(mesh.clone()).contains(&name.to_string()), "mesh {name} shows in --help");
        }
    }
}
