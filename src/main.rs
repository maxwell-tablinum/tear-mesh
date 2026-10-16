use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde_json::Value;

use tearmesh::circle::{Circle, Machine, ssh_sign};
use tearmesh::config::{Config, DEFAULT_CONFIG};
use tearmesh::ipc::{Client, Request, socket_path};
use tearmesh::node::{Letter, Node, load_or_create_key};
use tearmesh::{hook, ipc, mcp, tui, waker};

#[derive(Parser)]
#[command(
    name = "tearmesh",
    version,
    about = "Mail between AI agents on your own machines, kept inside boundaries."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon (normally under systemd).
    Daemon {
        #[arg(long, env = "TEARMESH_CONFIG", default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Print this machine's node id, creating its key on first use.
    Id {
        #[arg(long, env = "TEARMESH_CONFIG", default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Edit, sign and apply the circle file.
    #[command(subcommand)]
    Circle(CircleCmd),
    /// Print an invite code for a machine already listed in the circle (admin).
    Invite,
    /// Join a circle with an invite code (admin, on the new machine).
    Join {
        code: String,
        /// Skip the owner-key confirmation (for scripts that already checked the fingerprints).
        #[arg(long)]
        yes: bool,
    },
    /// Daemon status (admin).
    Status,
    /// Your address, the machines in your boundary, and known addresses.
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
    /// Stdio MCP server for agent harnesses.
    Mcp,
    /// Claude Code hook: report new mail to the session.
    Hook,
    /// Wake sessions when mail reaches an unheld mailbox (run as the boundary's user).
    Waker {
        #[arg(long)]
        config: Option<PathBuf>,
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
}

#[derive(Subcommand)]
enum CircleCmd {
    /// Start a circle file (version 1, no machines yet).
    New {
        file: PathBuf,
        #[arg(long)]
        name: String,
        /// OpenSSH public key file (.pub). Give at least two.
        #[arg(long = "owner-key", required = true)]
        owner_keys: Vec<PathBuf>,
        #[arg(long = "boundary", required = true)]
        boundaries: Vec<String>,
    },
    /// Add or update a machine (bumps the version).
    Add {
        file: PathBuf,
        name: String,
        node_id: String,
        #[arg(long = "boundary", required = true)]
        boundaries: Vec<String>,
    },
    /// Remove (revoke) a machine (bumps the version).
    Remove { file: PathBuf, name: String },
    /// Sign with an owner key: runs `ssh-keygen -Y sign`, writes FILE.sig.
    Sign {
        file: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    /// Hand the signed file (FILE and FILE.sig) to the local daemon (admin).
    Apply { file: PathBuf },
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
        Cmd::Daemon { config } => {
            let node = Node::start(Config::load(&config)?).await?;
            let server = tokio::spawn(ipc::serve(node.clone()));
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            tokio::select! {
                r = server => r??,
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            node.shutdown().await;
        }
        Cmd::Id { config } => {
            let cfg = Config::load(&config)?;
            println!("{}", load_or_create_key(&cfg.state_dir)?.public());
        }
        Cmd::Circle(c) => circle(c).await?,
        Cmd::Invite => println!(
            "{}",
            admin(Request::Invite).await?["code"]
                .as_str()
                .unwrap_or_default()
        ),
        Cmd::Join { code, yes } => {
            let preview = Circle::parse(&invite_circle(&code)?)?;
            println!(
                "circle {} ({}), version {}",
                preview.name, preview.id, preview.version
            );
            for k in preview.owner_keys()? {
                println!("  owner key {}", k.fingerprint(Default::default()));
            }
            // The first circle a machine adopts is trusted on these keys alone.
            if !yes {
                eprint!("Trust these owner keys for this machine? [y/N] ");
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                if !answer.trim().eq_ignore_ascii_case("y") {
                    bail!("not joined");
                }
            }
            let v = admin(Request::Join { code }).await?;
            println!("joined; circle version {}", v["version"]);
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
        } => {
            let body = if body == "-" {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s
            } else {
                body
            };
            println!(
                "{}",
                session(Request::Post {
                    to,
                    subject,
                    body,
                    thread
                })
                .await?["id"]
                    .as_str()
                    .unwrap_or_default()
            );
        }
        Cmd::Inbox { all } => {
            let letters: Vec<Letter> =
                serde_json::from_value(session(Request::Inbox { all }).await?)?;
            for l in letters {
                println!(
                    "{} {} {:<24} {}",
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
                "id:      {}\nfrom:    {}\nto:      {}\nsubject: {}",
                l.id,
                l.from,
                l.to.join(", "),
                l.subject
            );
            if let Some(t) = &l.thread {
                println!("thread:  {t}");
            }
            println!("\n{}", l.body.unwrap_or_default());
        }
        Cmd::Tui { mailbox } => tui::run(mailbox).await?,
        Cmd::Mcp => mcp::run().await?,
        Cmd::Hook => hook::run().await?,
        Cmd::Waker { config } => waker::run(&config.unwrap_or_else(waker::default_config)).await?,
        Cmd::Launch { .. } => unreachable!(),
    }
    Ok(())
}

async fn session(req: Request) -> Result<Value> {
    let (mut c, _) = Client::session(false).await?;
    c.call(&req).await
}

async fn admin(req: Request) -> Result<Value> {
    Client::connect(&socket_path()).await?.call(&req).await
}

fn invite_circle(code: &str) -> Result<String> {
    use base64::Engine;
    let raw = code
        .trim()
        .strip_prefix("tm1-")
        .context("not a tear-mesh invite")?;
    let v: Value =
        serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw)?)?;
    Ok(v["circle"]
        .as_str()
        .context("invite has no circle")?
        .to_string())
}

fn sig_path(file: &Path) -> PathBuf {
    let mut s = file.as_os_str().to_owned();
    s.push(".sig");
    s.into()
}

async fn circle(cmd: CircleCmd) -> Result<()> {
    let load = |f: &Path| -> Result<Circle> { Circle::parse(&std::fs::read_to_string(f)?) };
    let save = |f: &Path, c: &Circle| -> Result<()> {
        std::fs::write(f, c.to_toml()?)?;
        // The old signature no longer matches.
        let _ = std::fs::remove_file(sig_path(f));
        println!(
            "{} is now version {}; sign it with `tearmesh circle sign`.",
            f.display(),
            c.version
        );
        Ok(())
    };
    match cmd {
        CircleCmd::New {
            file,
            name,
            owner_keys,
            boundaries,
        } => {
            if file.exists() {
                bail!("{} already exists", file.display());
            }
            let owners = owner_keys
                .iter()
                .map(|p| Ok(std::fs::read_to_string(p)?.trim().to_string()))
                .collect::<Result<Vec<_>>>()?;
            save(&file, &Circle::new(&name, owners, boundaries)?)?;
        }
        CircleCmd::Add {
            file,
            name,
            node_id,
            boundaries,
        } => {
            let mut c = load(&file)?;
            let id = node_id
                .parse()
                .map_err(|e| anyhow::anyhow!("node id: {e}"))?;
            c.set_machine(Machine {
                name,
                id,
                boundaries,
            })?;
            save(&file, &c)?;
        }
        CircleCmd::Remove { file, name } => {
            let mut c = load(&file)?;
            c.remove_machine(&name)?;
            save(&file, &c)?;
        }
        CircleCmd::Sign { file, key } => {
            load(&file)?;
            let _ = std::fs::remove_file(sig_path(&file));
            ssh_sign(&key, &file)?;
            println!("wrote {}", sig_path(&file).display());
        }
        CircleCmd::Apply { file } => {
            let toml = std::fs::read_to_string(&file)?;
            let sig = std::fs::read_to_string(sig_path(&file))
                .context("no signature: run `tearmesh circle sign` first")?;
            let v = admin(Request::ApplyCircle { toml, sig }).await?;
            println!("applied circle version {}", v["version"]);
        }
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
    let mut env = vec![format!("TEARMESH_SOCKET={}", cfg.socket.display())];
    if let Some(m) = mailbox {
        env.push(format!("TEARMESH_MAILBOX={m}"));
    }
    let err = std::process::Command::new("sudo")
        .args(["-u", user, "-i", "env"])
        .args(&env)
        .args(command)
        .exec();
    Err(err).context("running sudo")
}
