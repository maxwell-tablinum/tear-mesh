//! `tearmesh mcp serve`: the MCP hub, one long-running service per OS user (so per boundary).
//! Any MCP client reaches it two ways:
//! - by URL, `http://127.0.0.1:<port>/mcp` with `Authorization: Bearer <token>` (streamable HTTP);
//! - by `tearmesh mcp connect`, a stdio command for clients that only start processes. It
//!   connects to the running hub over a socket only this user can use, or starts the hub first.
//!   The hub it starts keeps running after the client exits.
//!
//! Only `serve` binds anything. A second `serve` sees the first and exits, and `connect` (or the
//! plain stdio `tearmesh mcp`) holds no port, lock or database, so a harness that starts its own
//! copy can't collide with the service.
//!
//! Three channels, each both ways:
//! - conversation: the tools of `talk`, and new mail pushed to the client;
//! - tools: call servers other machines offer; this machine's offers answer their calls (steward);
//! - shell: run commands or keep a shell open on another machine; others reach this one's sshd.
//!   The daemons check the owner's grants on every one of them.
//!
//! It also starts agent harnesses (`start_chat`), from commands the user configured.

// MCP log notifications are deprecated (SEP-2577) but are still what clients show; they carry the
// new-mail push until resource subscriptions are worth their code.
#![allow(deprecated)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, Implementation, ListToolsResult, LoggingLevel,
    LoggingMessageNotificationParam, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::{NotificationContext, RequestContext, RoleServer};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, ServerHandler, ServiceExt, schemars, tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::ipc::{Client, Request, socket_path};
use crate::node::Event;
use crate::talk::{Door, Talk};
use crate::valid_name;

pub const DEFAULT_PORT: u16 = 7787;
/// Most output a tool returns from a shell or a chat.
const MAX_OUT: usize = 256 * 1024;
const MAX_SHELLS: usize = 16;
const MAX_CHATS: usize = 16;
/// Connections open at once, local and HTTP together.
const MAX_CONNECTIONS: usize = 128;
/// Longest JSON-RPC line read from another machine's server.
const MAX_LINE: u64 = 4 << 20;

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct HubConfig {
    /// The HTTP port on 127.0.0.1 (default: 7787 to 8786, picked from the OS user).
    #[serde(default)]
    pub port: Option<u16>,
    /// The mailbox this hub's letters come from and go to (default `agent`).
    #[serde(default)]
    pub mailbox: Option<String>,
    /// Harnesses `start_chat` may start, by name. Without any, `claude` is offered when it's on
    /// the PATH.
    #[serde(default)]
    pub harness: HashMap<String, Harness>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Harness {
    /// The command; `{prompt}` is replaced by the prompt, which otherwise goes last.
    pub command: Vec<String>,
    /// Working directory (default the home directory).
    #[serde(default)]
    pub dir: Option<PathBuf>,
}

impl HubConfig {
    /// The configured port, or one derived from the OS user, so each boundary user on a machine
    /// gets its own without configuring anything.
    pub fn port(&self) -> u16 {
        self.port.unwrap_or_else(|| {
            let id = crate::os::my_identity().unwrap_or_default();
            let h = blake3::hash(id.as_bytes());
            DEFAULT_PORT + u16::from_le_bytes([h.as_bytes()[0], h.as_bytes()[1]]) % 1000
        })
    }
    pub fn mailbox(&self) -> String {
        self.mailbox.clone().unwrap_or_else(|| "agent".into())
    }
    fn harnesses(&self) -> HashMap<String, Harness> {
        if !self.harness.is_empty() {
            return self.harness.clone();
        }
        let mut h = HashMap::new();
        if which("claude") {
            h.insert(
                "claude".into(),
                Harness {
                    command: vec!["claude".into(), "-p".into(), "{prompt}".into()],
                    dir: None,
                },
            );
        }
        h
    }
}

fn which(exe: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| {
        std::env::split_paths(&p).any(|d| {
            d.join(exe).is_file() || (cfg!(windows) && d.join(format!("{exe}.exe")).is_file())
        })
    })
}

pub fn config_path() -> PathBuf {
    std::env::var_os("TEARMESH_HUB_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::os::home_dir().join(".config/tearmesh/hub.toml"))
}

pub fn load(path: &Path) -> Result<HubConfig> {
    let c: HubConfig = match std::fs::read_to_string(path) {
        Ok(t) => toml::from_str(&t).with_context(|| format!("parsing {}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => HubConfig::default(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    ensure!(valid_name(&c.mailbox()), "bad mailbox name {:?}", c.mailbox());
    for (n, h) in &c.harness {
        ensure!(valid_name(n), "bad harness name {n:?}");
        ensure!(!h.command.is_empty(), "harness {n} has an empty command");
    }
    Ok(c)
}

/// The hub's private directory: its token, chat logs and (on Unix) its socket.
/// Refuses a relative state directory (no HOME): it would resolve against a directory that
/// may be shared, where another user could plant the socket.
fn check_dir(d: &Path) -> Result<()> {
    ensure!(d.is_absolute(), "no home directory (HOME is unset), so the hub has nowhere private to live");
    Ok(())
}

pub fn state_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("TEARMESH_HUB_DIR") {
        return d.into();
    }
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(crate::os::home_dir)
            .join("tearmesh")
            .join("hub")
    }
    #[cfg(not(windows))]
    crate::os::home_dir().join(".local/state/tearmesh/hub")
}

pub fn socket(dir: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let _ = dir;
        // The SID, not the user name: names can collide once cleaned up, SIDs can't.
        let sid = crate::os::my_identity().unwrap_or_default();
        PathBuf::from(format!(r"\\.\pipe\tearmesh-hub-{sid}"))
    }
    #[cfg(not(windows))]
    dir.join("hub.sock")
}

fn ensure_dir(d: &Path) -> Result<()> {
    std::fs::create_dir_all(d).with_context(|| format!("creating {}", d.display()))?;
    #[cfg(unix)]
    crate::os::secure_dir(d)?;
    Ok(())
}

/// The hub's lock file, held for as long as the returned handle lives. None when another hub
/// holds it.
fn lock(dir: &Path) -> Result<Option<impl Sized>> {
    let path = dir.join("hub.lock");
    #[cfg(unix)]
    {
        let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&path)?;
        match nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusiveNonblock) {
            Ok(l) => Ok(Some(l)),
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => Ok(None),
            Err((_, e)) => Err(e).with_context(|| format!("locking {}", path.display())),
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // No sharing: a second open fails while this handle is open.
        match std::fs::OpenOptions::new().create(true).truncate(false).write(true).share_mode(0).open(&path) {
            Ok(f) => Ok(Some(f)),
            Err(e) if e.raw_os_error() == Some(32) => Ok(None),
            Err(e) => Err(e).with_context(|| format!("locking {}", path.display())),
        }
    }
}

/// The bearer token for the HTTP door, made on first use.
pub fn token(dir: &Path) -> Result<String> {
    let p = dir.join("token");
    if let Ok(t) = std::fs::read_to_string(&p) {
        let t = t.trim().to_string();
        if t.len() >= 32 {
            return Ok(t);
        }
    }
    ensure_dir(dir)?;
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("random: {e}"))?;
    let t = crate::envelope::hex(&b);
    crate::os::write_private(&p, t.as_bytes())?;
    Ok(t)
}

/// Equal-time comparison, so the token can't be guessed a byte at a time.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Shared by every MCP session the hub serves.
struct Shared {
    cfg: HubConfig,
    dir: PathBuf,
    exe: PathBuf,
    talk: Talk,
    /// Each shell has its own lock, so a stalled one doesn't hold up the rest.
    shells: Mutex<HashMap<String, Arc<Mutex<Shell>>>>,
    chats: Mutex<HashMap<String, tokio::process::Child>>,
}

struct Shell {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    out: Arc<std::sync::Mutex<Vec<u8>>>,
}

#[derive(Clone)]
pub struct Hub {
    s: Arc<Shared>,
    tool_router: ToolRouter<Self>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ServerArgs {
    /// The machine that offers the server.
    pub machine: String,
    /// The server's name, as `offers` lists it.
    pub server: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct CallArgs {
    pub machine: String,
    pub server: String,
    /// The tool to call.
    pub tool: String,
    /// The tool's arguments, an object matching its input schema.
    #[serde(default)]
    pub arguments: Option<serde_json::Map<String, Value>>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ExecArgs {
    /// The machine to run on (its name in the mesh).
    pub machine: String,
    /// A shell command line, run by the remote user's shell.
    pub command: String,
    /// The OS user to log in as there (default: the same name as here).
    #[serde(default)]
    pub user: Option<String>,
    /// Seconds before it's stopped (default 60, at most 3600).
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct OpenArgs {
    pub machine: String,
    #[serde(default)]
    pub user: Option<String>,
    /// The shell to run there, e.g. `cmd` or `powershell` for a Windows machine, whose sshd
    /// won't start a login shell without a terminal. Default: the user's login shell.
    #[serde(default)]
    pub shell: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct SendArgs {
    /// The id `shell_open` returned.
    pub id: String,
    /// Text for the shell's input. End a command with a newline.
    pub input: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct IdArgs {
    pub id: String,
    /// For `shell_read`: wait up to this many milliseconds for output (default 500, at most
    /// 30000). It returns sooner once output has started and then paused.
    #[serde(default)]
    pub wait_ms: Option<u64>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ChatArgs {
    /// A harness `harnesses` lists, e.g. `claude`.
    pub harness: String,
    /// What to ask it.
    pub prompt: String,
}

fn err(e: anyhow::Error) -> String {
    format!("{e:#}")
}

#[tool_router]
impl Hub {
    // ---- tools ----

    #[tool(
        description = "MCP servers the machines in your boundary offer, their tools, and whether the owner approved them. Call one with `call_tool`."
    )]
    async fn offers(&self) -> Result<String, String> {
        self.call(Request::Offers { boundary: None }).await
    }

    #[tool(description = "The tools (with input schemas) of a server another machine offers.")]
    async fn remote_tools(&self, Parameters(a): Parameters<ServerArgs>) -> Result<String, String> {
        let v = remote_rpc(&a.machine, &a.server, "tools/list", json!({}))
            .await
            .map_err(err)?;
        Ok(serde_json::to_string_pretty(&v).unwrap_or_default())
    }

    #[tool(
        description = "Call a tool on a server another machine offers. The daemons check the owner's tools grant and approval, and pass only approved tools."
    )]
    async fn call_tool(&self, Parameters(a): Parameters<CallArgs>) -> Result<String, String> {
        let v = remote_rpc(
            &a.machine,
            &a.server,
            "tools/call",
            json!({ "name": a.tool, "arguments": a.arguments.unwrap_or_default() }),
        )
        .await
        .map_err(err)?;
        Ok(serde_json::to_string_pretty(&v).unwrap_or_default())
    }

    // ---- shell ----

    #[tool(
        description = "Run a command on another machine over the mesh (SSH carried by tear-mesh). Needs the owner's shell grant and an SSH login there for this user's key. Returns exit code, stdout and stderr."
    )]
    async fn shell_exec(&self, Parameters(a): Parameters<ExecArgs>) -> Result<String, String> {
        let mut cmd = self.ssh(&a.machine, a.user.as_deref()).map_err(err)?;
        cmd.arg("--").arg(&a.command);
        cmd.stdin(Stdio::null()).kill_on_drop(true);
        let secs = a.timeout_secs.unwrap_or(60).clamp(1, 3600);
        let mut child = cmd.spawn().map_err(|e| format!("running ssh: {e}"))?;
        // Read at most MAX_OUT of each: the other machine decides how much it sends. Stop at the
        // cap on either stream; waiting for the other would run a chatty command into the timeout.
        let (mut so, mut se) = (child.stdout.take(), child.stderr.take());
        let work = async {
            let (mut o, mut e) = (Vec::new(), Vec::new());
            let (mut bo, mut be) = (vec![0u8; 8192], vec![0u8; 8192]);
            let (mut od, mut ed) = (so.is_none(), se.is_none());
            while !(od && ed) && o.len() < MAX_OUT && e.len() < MAX_OUT {
                tokio::select! {
                    n = async { so.as_mut().unwrap().read(&mut bo).await }, if !od => match n {
                        Ok(n) if n > 0 => o.extend_from_slice(&bo[..n]),
                        _ => od = true,
                    },
                    n = async { se.as_mut().unwrap().read(&mut be).await }, if !ed => match n {
                        Ok(n) if n > 0 => e.extend_from_slice(&be[..n]),
                        _ => ed = true,
                    },
                }
            }
            // Past the cap the rest isn't read; stop ssh rather than let it block.
            if o.len() >= MAX_OUT || e.len() >= MAX_OUT {
                let _ = child.kill().await;
            }
            (child.wait().await, o, e)
        };
        let (status, o, e) = tokio::time::timeout(Duration::from_secs(secs), work)
            .await
            .map_err(|_| format!("stopped after {secs} s"))?;
        let status = status.map_err(|e| format!("running ssh: {e}"))?;
        Ok(serde_json::to_string_pretty(&json!({
            "exit_code": status.code(),
            "stdout": cap(&o),
            "stderr": cap(&e),
            "truncated": o.len() >= MAX_OUT || e.len() >= MAX_OUT,
        }))
        .unwrap_or_default())
    }

    #[tool(
        description = "Open a shell on another machine that stays open: write to it with `shell_send`, read with `shell_read`, end with `shell_close`. Returns its id. For a Windows machine set `shell` to `cmd` or `powershell`."
    )]
    async fn shell_open(&self, Parameters(a): Parameters<OpenArgs>) -> Result<String, String> {
        let mut shells = self.s.shells.lock().await;
        // Shells that ended don't count against the cap.
        let mut ended = vec![];
        for (id, sh) in shells.iter() {
            if sh.try_lock().is_ok_and(|mut s| matches!(s.child.try_wait(), Ok(Some(_)))) {
                ended.push(id.clone());
            }
        }
        for id in ended {
            shells.remove(&id);
        }
        ensure_str(shells.len() < MAX_SHELLS, "too many open shells; close one")?;
        let mut cmd = self.ssh(&a.machine, a.user.as_deref()).map_err(err)?;
        cmd.arg("-T");
        if let Some(sh) = &a.shell {
            cmd.arg("--").arg(sh);
        }
        cmd.stdin(Stdio::piped()).kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| format!("running ssh: {e}"))?;
        let out = Arc::new(std::sync::Mutex::new(Vec::new()));
        for r in [
            child.stdout.take().map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
            child.stderr.take().map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let out = out.clone();
            tokio::spawn(async move {
                let mut r = r;
                let mut buf = [0u8; 8192];
                while let Ok(n) = r.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let mut o = out.lock().unwrap();
                    o.extend_from_slice(&buf[..n]);
                    // Keep the newest output when nobody reads.
                    if o.len() > MAX_OUT {
                        let cut = o.len() - MAX_OUT;
                        o.drain(..cut);
                    }
                }
            });
        }
        let stdin = child.stdin.take().ok_or("no shell input")?;
        let id = random_id();
        shells.insert(id.clone(), Arc::new(Mutex::new(Shell { child, stdin, out })));
        Ok(json!({ "id": id }).to_string())
    }

    #[tool(description = "Write to an open shell.")]
    async fn shell_send(&self, Parameters(a): Parameters<SendArgs>) -> Result<String, String> {
        let sh = self.shell(&a.id).await?;
        let mut sh = sh.lock().await;
        sh.stdin
            .write_all(a.input.as_bytes())
            .await
            .map_err(|e| format!("the shell has closed: {e}"))?;
        sh.stdin.flush().await.map_err(|e| e.to_string())?;
        Ok("sent".into())
    }

    #[tool(description = "Output from an open shell since the last read, and whether it's still running.")]
    async fn shell_read(&self, Parameters(a): Parameters<IdArgs>) -> Result<String, String> {
        let wait = Duration::from_millis(a.wait_ms.unwrap_or(500).min(30_000));
        let deadline = tokio::time::Instant::now() + wait;
        let mut got = Vec::new();
        let mut quiet = 0;
        let sh = self.shell(&a.id).await?;
        loop {
            let mut sh = sh.lock().await;
            let data: Vec<u8> = std::mem::take(&mut *sh.out.lock().unwrap());
            let exited = sh.child.try_wait().ok().flatten();
            quiet = if data.is_empty() { quiet + 1 } else { 0 };
            got.extend_from_slice(&data);
            // Once output has started, return when it pauses, so one read gets a whole answer.
            let paused = !got.is_empty() && quiet >= 3;
            if paused || exited.is_some() || tokio::time::Instant::now() >= deadline {
                return Ok(serde_json::to_string_pretty(&json!({
                    "output": String::from_utf8_lossy(&got),
                    "running": exited.is_none(),
                    "exit_code": exited.and_then(|s| s.code()),
                }))
                .unwrap_or_default());
            }
            drop(sh);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    #[tool(description = "Close an open shell.")]
    async fn shell_close(&self, Parameters(a): Parameters<IdArgs>) -> Result<String, String> {
        let sh = self.s.shells.lock().await.remove(&a.id).ok_or("no such shell")?;
        let _ = sh.lock().await.child.kill().await;
        Ok("closed".into())
    }

    // ---- harnesses ----

    #[tool(description = "Agent harnesses this hub can start chats in.")]
    async fn harnesses(&self) -> Result<String, String> {
        let h = self.s.cfg.harnesses();
        let mut names: Vec<_> = h.keys().cloned().collect();
        names.sort();
        Ok(json!({ "harnesses": names }).to_string())
    }

    #[tool(
        description = "Start a chat in an agent harness on this machine with a prompt. It runs on after this call; read it with `chat_status`."
    )]
    async fn start_chat(&self, Parameters(a): Parameters<ChatArgs>) -> Result<String, String> {
        start_chat(&self.s, &a.harness, &a.prompt).await.map_err(err)
    }

    #[tool(description = "Whether a chat is still running, and its output so far.")]
    async fn chat_status(&self, Parameters(a): Parameters<IdArgs>) -> Result<String, String> {
        ensure_str(valid_id(&a.id), "no such chat")?;
        let mut chats = self.s.chats.lock().await;
        let state = match chats.get_mut(&a.id) {
            Some(c) => match c.try_wait() {
                Ok(None) => json!("running"),
                Ok(Some(s)) => json!({ "exited": s.code() }),
                Err(e) => json!(format!("unknown: {e}")),
            },
            None => json!("finished earlier"),
        };
        let log = std::fs::read(self.s.dir.join("chats").join(format!("{}.log", a.id)))
            .map_err(|_| "no such chat".to_string())?;
        let tail = &log[log.len().saturating_sub(MAX_OUT)..];
        Ok(serde_json::to_string_pretty(&json!({
            "state": state,
            "output": String::from_utf8_lossy(tail),
        }))
        .unwrap_or_default())
    }
}

fn ensure_str(ok: bool, msg: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(msg.into()) }
}

fn cap(b: &[u8]) -> String {
    String::from_utf8_lossy(&b[..b.len().min(MAX_OUT)]).into_owned()
}

fn random_id() -> String {
    let mut b = [0u8; 8];
    let _ = getrandom::fill(&mut b);
    crate::envelope::hex(&b)
}

fn valid_id(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

/// An OS user name for ssh: no leading `-`, so it can't be read as an option.
fn valid_user(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 64
        && !u.starts_with('-')
        && u.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

async fn start_chat(s: &Shared, harness: &str, prompt: &str) -> Result<String> {
    let all = s.cfg.harnesses();
    let h = all
        .get(harness)
        .with_context(|| format!("no harness {harness:?}; configure one in {}", config_path().display()))?;
    ensure!(prompt.len() <= 64 * 1024, "the prompt is over 64 KiB");
    // A prompt like `--dangerously-skip-permissions` would be read as an option by the harness.
    ensure!(!prompt.trim_start().starts_with('-'), "a prompt can't start with -");
    let args = crate::steward::command_args(&h.command[1..], prompt);
    let dir = s.dir.join("chats");
    ensure_dir(&dir)?;
    let id = random_id();
    let log = std::fs::File::create(dir.join(format!("{id}.log")))?;
    let mut cmd = tokio::process::Command::new(&h.command[0]);
    cmd.args(&args)
        .current_dir(h.dir.clone().unwrap_or_else(crate::os::home_dir))
        .env("TEARMESH_MAILBOX", s.cfg.mailbox())
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    let child = cmd
        .spawn()
        .with_context(|| format!("starting {}", h.command[0]))?;
    let mut chats = s.chats.lock().await;
    // Forget finished chats so the table doesn't grow forever.
    chats.retain(|_, c| matches!(c.try_wait(), Ok(None)));
    if chats.len() >= MAX_CHATS {
        let mut child = child;
        let _ = child.kill().await;
        bail!("{MAX_CHATS} chats are running; wait for one to finish");
    }
    chats.insert(id.clone(), child);
    info!(%harness, %id, "chat started");
    Ok(json!({ "id": id, "harness": harness }).to_string())
}

impl Hub {
    fn new(s: Arc<Shared>) -> Hub {
        Hub {
            s,
            tool_router: Hub::tool_router(),
        }
    }

    async fn shell(&self, id: &str) -> Result<Arc<Mutex<Shell>>, String> {
        self.s.shells.lock().await.get(id).cloned().ok_or_else(|| "no such shell".into())
    }

    async fn call(&self, req: Request) -> Result<String, String> {
        self.s
            .talk
            .request(&req)
            .await
            .map(|v| serde_json::to_string_pretty(&v).unwrap_or_default())
    }

    async fn subscribe(&self) -> Result<Client> {
        let mut c = Client::connect(&socket_path()).await?;
        c.call(&Request::Hello {
            mailbox: Some(self.s.cfg.mailbox()),
            hold: false,
            trust: None,
        })
        .await?;
        c.call(&Request::Subscribe).await?;
        Ok(c)
    }

    /// ssh to `machine` through `tearmesh shell-proxy`, which carries it over the mesh.
    fn ssh(&self, machine: &str, user: Option<&str>) -> Result<tokio::process::Command> {
        ensure!(valid_name(machine), "bad machine name {machine:?}");
        let user = match user {
            Some(u) => u.to_string(),
            None => whoami(),
        };
        ensure!(valid_user(&user), "bad user name {user:?}");
        let exe = self.s.exe.display().to_string();
        let mut c = tokio::process::Command::new("ssh");
        c.args([
            "-o",
            &format!("ProxyCommand=\"{exe}\" shell-proxy %h"),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            &format!(
                "UserKnownHostsFile=\"{}\"",
                self.s.dir.join("known_hosts").display()
            ),
            "-o",
            "ConnectTimeout=30",
            // Notice a machine that dropped off within about 15 s instead of hanging.
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=3",
            "-l",
            &user,
            machine,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        Ok(c)
    }
}

fn whoami() -> String {
    std::env::var(if cfg!(windows) { "USERNAME" } else { "USER" }).unwrap_or_default()
}

/// One request to a server another machine offers: initialize, then `method`.
async fn remote_rpc(machine: &str, server: &str, method: &str, params: Value) -> Result<Value> {
    ensure!(
        valid_name(machine) && valid_name(server),
        "bad machine or server name"
    );
    let mut c = Client::connect(&socket_path()).await?;
    c.call(&Request::Remote {
        machine: machine.into(),
        server: server.into(),
    })
    .await?;
    let (mut r, mut w) = c.into_raw();
    let mut send = async |v: Value| -> Result<()> {
        w.write_all(format!("{v}\n").as_bytes()).await?;
        w.flush().await?;
        Ok(())
    };
    let work = async {
        send(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "tearmesh-hub", "version": env!("CARGO_PKG_VERSION")}}}))
        .await?;
        let mut answered = false;
        loop {
            let mut line = Vec::new();
            let n = (&mut r).take(MAX_LINE + 1).read_until(b'\n', &mut line).await?;
            ensure!(n > 0, "the remote server closed");
            ensure!((n as u64) <= MAX_LINE, "the remote server sent a line over {MAX_LINE} bytes");
            let Ok(v) = serde_json::from_slice::<Value>(&line) else {
                continue;
            };
            if v["id"] == json!(1) && !answered {
                if let Some(e) = v.get("error") {
                    bail!("initialize failed: {e}");
                }
                answered = true;
                send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await?;
                send(json!({"jsonrpc": "2.0", "id": 2, "method": method, "params": params})).await?;
            } else if v["id"] == json!(2) {
                if let Some(e) = v.get("error") {
                    bail!("{method} failed: {e}");
                }
                return Ok(v["result"].clone());
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(120), work)
        .await
        .context("the remote server didn't answer within 120 s")?
}

impl ServerHandler for Hub {
    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_logging()
                .build(),
        )
        .with_server_info(Implementation::new("tearmesh-hub", env!("CARGO_PKG_VERSION")));
        info.instructions = Some(format!(
            "{} New mail for this hub's mailbox is also pushed as a log notification. Tools on other \
             machines: `offers`, `remote_tools`, `call_tool`. Shells on other machines: `shell_exec`, or \
             `shell_open`/`shell_send`/`shell_read`/`shell_close`. Agent chats here: `harnesses`, \
             `start_chat`, `chat_status`. The owner's grants decide what reaches where.",
            self.s.talk.instructions()
        ));
        info
    }

    /// The conversation tools first, then the hub's own.
    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let mut tools = self.s.talk.tools();
        tools.extend(self.tool_router.list_all());
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        req: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if self.s.talk.has(&req.name) {
            let r = self.s.talk.call(&req.name, req.arguments.unwrap_or_default()).await;
            return Ok(crate::talk::to_result(r).into());
        }
        self.tool_router.call(ToolCallContext::new(self, req, ctx)).await
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        let talk = self.s.talk.tools().into_iter().find(|t| t.name == name);
        talk.or_else(|| self.tool_router.get(name).cloned())
    }

    /// Pushes new mail to the client as log notifications, for as long as it stays connected.
    async fn on_initialized(&self, ctx: NotificationContext<RoleServer>) {
        let hub = self.clone();
        tokio::spawn(async move {
            let Ok(mut sub) = hub.subscribe().await else {
                return;
            };
            loop {
                let ev = tokio::select! {
                    ev = sub.next_event() => match ev {
                        Ok(Some(ev)) => ev,
                        _ => return,
                    },
                    // The client left: drop the subscription instead of keeping it until mail comes.
                    _ = async { while !ctx.peer.is_transport_closed() { tokio::time::sleep(Duration::from_secs(2)).await } } => return,
                };
                let Event::Mail(m) = ev else { continue };
                if m.mailbox != hub.s.cfg.mailbox() {
                    continue;
                }
                let p = LoggingMessageNotificationParam::new(
                    LoggingLevel::Info,
                    json!({ "new_mail": { "id": m.id, "from": m.from, "subject": m.subject } }),
                )
                .with_logger("tearmesh");
                if ctx.peer.notify_logging_message(p).await.is_err() {
                    return;
                }
            }
        });
    }
}

/// The hub's address for clients that take a URL.
pub fn url(cfg: &HubConfig) -> String {
    format!("http://127.0.0.1:{}/mcp", cfg.port())
}

/// Runs the hub until stopped. Exits quietly when one is already running.
pub async fn serve() -> Result<()> {
    let cfg = load(&config_path())?;
    let dir = state_dir();
    check_dir(&dir)?;
    ensure_dir(&dir)?;
    let sock = socket(&dir);
    // A lock file, held while the hub runs, makes it one per user. Not the port: another user
    // can hold any port, and that mustn't keep this user's hub from starting.
    let Some(_lock) = lock(&dir)? else {
        eprintln!("the hub is already running ({})", url(&cfg));
        return Ok(());
    };
    let tcp = match tokio::net::TcpListener::bind(("127.0.0.1", cfg.port())).await {
        Ok(l) => Some(l),
        Err(e) => {
            // `mcp connect` still works over the private socket.
            warn!(
                "HTTP is off: port {} on 127.0.0.1 is taken ({e}); set `port` in {}",
                cfg.port(),
                config_path().display()
            );
            None
        }
    };
    let token = token(&dir)?;
    let shared = Arc::new(Shared {
        cfg: cfg.clone(),
        dir: dir.clone(),
        exe: std::env::current_exe()?,
        talk: Talk::new(Door {
            mailbox: Some(cfg.mailbox()),
            trust: None,
            hold: false,
            agent_tools: true,
        }),
        shells: Mutex::new(HashMap::new()),
        chats: Mutex::new(HashMap::new()),
    });
    // For the address in the instructions; with no daemon yet, the first tool call connects.
    let _ = shared.talk.address().await;
    let local = crate::os::listen(&sock).await?;
    let me = crate::os::my_identity()?;
    info!("hub listening on {} and {}", url(&cfg), sock.display());
    let s = shared.clone();
    // Anyone can connect before the hub knows who they are, so cap how many may at once.
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let local_slots = slots.clone();
    let sockets = tokio::spawn(async move {
        loop {
            let Ok(slot) = local_slots.clone().acquire_owned().await else { return };
            let inc = match local.accept().await {
                Ok(i) => i,
                Err(e) => {
                    warn!("hub socket: {e:#}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let (s, me) = (s.clone(), me.clone());
            tokio::spawn(async move {
                let _slot = slot;
                if let Err(e) = serve_local(s, inc, &me).await {
                    warn!("hub session: {e:#}");
                }
            });
        }
    });
    let http = async {
        match tcp {
            Some(t) => serve_http(shared, t, token, slots).await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        r = http => r?,
        r = sockets => r?,
        r = crate::os::shutdown_signal() => r?,
    }
    Ok(())
}

/// One stdio-style session from `tearmesh mcp connect`: JSON-RPC lines on the socket.
async fn serve_local(s: Arc<Shared>, inc: crate::os::Incoming, me: &str) -> Result<()> {
    let crate::os::Incoming {
        read,
        write,
        mut caller,
    } = inc;
    // Windows names a pipe client only after reading from it, so read the first line here and
    // hand it on.
    let mut reader = BufReader::new(read);
    let mut first = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(30),
        (&mut reader).take(1 << 20).read_until(b'\n', &mut first),
    )
    .await??;
    let c = caller()?;
    ensure!(c.id == me, "refused a hub connection from another user ({})", c.id);
    let read = std::io::Cursor::new(first).chain(reader);
    Hub::new(s).serve((read, write)).await?.waiting().await?;
    Ok(())
}

async fn serve_http(
    s: Arc<Shared>,
    tcp: tokio::net::TcpListener,
    token: String,
    slots: Arc<tokio::sync::Semaphore>,
) -> Result<()> {
    let mut http = StreamableHttpServerConfig::default();
    let port = s.cfg.port();
    http.allowed_hosts
        .extend([format!("localhost:{port}"), format!("127.0.0.1:{port}")]);
    let service = StreamableHttpService::new(
        move || Ok(Hub::new(s.clone())),
        Arc::new(LocalSessionManager::default()),
        http,
    );
    let want = Arc::new(format!("Bearer {token}"));
    loop {
        let slot = slots.clone().acquire_owned().await?;
        // An accept error (out of file descriptors, say) must not end the hub.
        let stream = match tcp.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                warn!("hub http accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let (svc, want) = (service.clone(), want.clone());
        tokio::spawn(async move {
            let _slot = slot;
            let io = hyper_util::rt::TokioIo::new(stream);
            let f = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let svc = svc.clone();
                let ok = req
                    .headers()
                    .get(hyper::header::AUTHORIZATION)
                    .is_some_and(|v| same(v.as_bytes(), want.as_bytes()));
                async move {
                    if !ok {
                        let body = http_body_util::Full::new(bytes::Bytes::from_static(
                            b"missing or wrong bearer token (see `tearmesh mcp info`)\n",
                        ));
                        let mut r =
                            hyper::Response::new(http_body_util::BodyExt::boxed(body));
                        *r.status_mut() = hyper::StatusCode::UNAUTHORIZED;
                        return Ok::<_, std::convert::Infallible>(r);
                    }
                    Ok(tower_service::Service::call(&mut svc.clone(), req).await.unwrap_or_else(|e| match e {}))
                }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .serve_connection(io, f)
                .await
            {
                warn!("hub http: {e}");
            }
        });
    }
}

/// `tearmesh mcp connect`: stdio for MCP clients that start a command. Connects to the hub, or
/// starts one (which then outlives this process) and connects.
pub async fn connect() -> Result<()> {
    let dir = state_dir();
    check_dir(&dir)?;
    let sock = socket(&dir);
    let conn = match crate::os::connect_mine(&sock).await {
        Ok(c) => c,
        Err(_) => {
            start_detached(&dir)?;
            let mut last = None;
            let mut got = None;
            for _ in 0..100 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                match crate::os::connect_mine(&sock).await {
                    Ok(c) => {
                        got = Some(c);
                        break;
                    }
                    Err(e) => last = Some(e),
                }
            }
            got.with_context(|| {
                format!(
                    "the hub didn't start; see {} ({})",
                    dir.join("hub.log").display(),
                    last.map(|e| format!("{e:#}")).unwrap_or_default()
                )
            })?
        }
    };
    let (mut r, mut w) = conn;
    let (mut stdin, mut stdout) = (tokio::io::stdin(), tokio::io::stdout());
    let up = async {
        let _ = tokio::io::copy(&mut stdin, &mut w).await;
        let _ = w.shutdown().await;
    };
    let down = async {
        let r = tokio::io::copy(&mut r, &mut stdout).await;
        let _ = stdout.flush().await;
        r
    };
    tokio::pin!(down);
    tokio::select! {
        r = &mut down => { r?; return Ok(()); }
        _ = up => {}
    }
    // The client closed its input. A named pipe can't be half-closed, so the hub may not see
    // that; give replies already on their way a moment, then end.
    let _ = tokio::time::timeout(Duration::from_secs(5), down).await;
    Ok(())
}

/// Starts `tearmesh mcp serve` in the background, apart from this process's session, so it
/// keeps running when the client that started it exits.
pub fn start_detached(dir: &Path) -> Result<()> {
    ensure_dir(dir)?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("hub.log"))?;
    let mut c = std::process::Command::new(std::env::current_exe()?);
    c.args(["mcp", "serve"])
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // A new session: no controlling terminal to hang up, no process group to be killed with.
        unsafe {
            c.pre_exec(|| {
                nix::unistd::setsid().map_err(std::io::Error::other)?;
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x8;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x200;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        // Out of the client's job object when it allows that, so closing the client doesn't end it.
        c.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB);
        if c.spawn().is_ok() {
            return Ok(());
        }
        c.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    c.spawn().context("starting the hub")?;
    Ok(())
}

/// What `tearmesh mcp info` prints: the URL, the token, and how to register the hub. The
/// `claude mcp add` line reads the token from its file, so the line itself holds no secret.
pub fn info_text(config: &Path, dir: &Path) -> Result<String> {
    let cfg = load(config)?;
    let token = token(dir)?;
    let exe = std::env::current_exe()?;
    Ok(format!(
        "URL:    {url}\nHeader: Authorization: Bearer {token}\n\
         (token file {tok}; anyone with it can use your mesh as you, so keep it private)\n\n\
         Clients that take a URL (Claude Code, Cursor, custom), reading the token from its file so\n\
         it stays out of your shell history:\n  \
         claude mcp add --transport http tearmesh {url} --header \"Authorization: Bearer $(cat '{tok}')\"\n\n\
         Clients that start a command (Claude Desktop, others): command `{exe}`, args [\"mcp\", \"connect\"].\n  \
         It connects to the running hub, or starts it; the hub keeps running afterwards.",
        url = url(&cfg),
        tok = dir.join("token").display(),
        exe = exe.display(),
    ))
}

/// `tearmesh mcp info`: how to register the hub with clients.
pub fn info() -> Result<()> {
    println!("{}", info_text(&config_path(), &state_dir())?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_tokens() {
        assert!(valid_user("tm-work") && valid_user("Alice.B"));
        assert!(!valid_user("-oProxyCommand=x") && !valid_user("a b") && !valid_user(""));
        assert!(valid_id("0123456789abcdef") && !valid_id("../../etc/passwd"));
        assert!(same(b"Bearer abc", b"Bearer abc"));
        assert!(!same(b"Bearer abc", b"Bearer abd") && !same(b"Bearer ab", b"Bearer abc"));
        let d = tempfile::tempdir().unwrap();
        let t = token(d.path()).unwrap();
        assert_eq!(t.len(), 64);
        assert_eq!(token(d.path()).unwrap(), t, "the token is stable");
    }

    #[test]
    fn tools_are_21() {
        let talk = Talk::at(
            Door { mailbox: None, trust: None, hold: false, agent_tools: true },
            "/nonexistent".into(),
        );
        let own: Vec<_> = Hub::tool_router().list_all().into_iter().map(|t| t.name).collect();
        assert_eq!(own.len() + talk.tools().len(), 21);
        assert!(own.iter().all(|n| !talk.has(n)), "no name is served twice");
    }

    #[test]
    fn config_defaults_and_checks() {
        let d = tempfile::tempdir().unwrap();
        let c = load(&d.path().join("missing.toml")).unwrap();
        assert_eq!(c.port(), c.port(), "the default port is stable");
        assert!((DEFAULT_PORT..DEFAULT_PORT + 1000).contains(&c.port()));
        assert_eq!(c.mailbox(), "agent");
        let p = d.path().join("hub.toml");
        std::fs::write(&p, "port = 9000\n[harness.x]\ncommand = []\n").unwrap();
        assert!(load(&p).is_err(), "empty harness command");
        std::fs::write(&p, "mailbox = \"Bad\"\n").unwrap();
        assert!(load(&p).is_err());
        std::fs::write(&p, "nonsense = 1\n").unwrap();
        assert!(load(&p).is_err());
    }
}
