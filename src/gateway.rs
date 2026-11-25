//! The gateway (spec 18.4): the one process that faces the internet. Claude's apps (voice, phone, web)
//! reach the mesh through it as an MCP custom connector. It is a plain client of the local socket, run
//! as an OS user of its own (tm-<boundary>-gw) that the daemon's config lists under [guests], so the
//! daemon, not this process, holds it to one mailbox, guest trust and six requests. It serves the seven conversation tools and nothing else, behind the
//! OAuth sign-in of src/oauth.rs. A tunnel in front gives it a public host name and TLS.

// The request path hands back whole responses, as oauth.rs does.
#![allow(clippy::result_large_err)]

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::http::{self, StatusCode, header};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, Implementation, ListToolsResult, PaginatedRequestParams,
    ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, ServerHandler};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, warn};

use crate::config::Guest;
use crate::envelope::Trust;
use crate::ipc::{Client, Request};
use crate::oauth::{self, Grant, OAuth};
use crate::talk::{Door, Talk};

pub const CONFIG: &str = "/etc/tearmesh/gateway.toml";
pub const DIR: &str = "/var/lib/tearmesh-gateway";
const UNIT: &str = include_str!("../deploy/tearmesh-gateway.service");
const UNIT_PATH: &str = "/etc/systemd/system/tearmesh-gateway.service";
const MAX_BODY: usize = 1 << 20;
const MAX_CONNECTIONS: usize = 512;
/// Daemon sessions open at once, gateway-wide: the daemon has 256 for the whole machine.
const MAX_SESSIONS: usize = 32;
const AUDIT_CAP: u64 = 8 << 20;
/// Audit lines a minute, in each group (see Audit::unsigned), from requests without a valid token.
const UNSIGNED_PER_MINUTE: u32 = 60;
const NOT_GUEST: &str = "the daemon does not hold this user to a guest's limits; run sudo tearmesh gateway setup";

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// The boundary served; its OS user runs the gateway.
    pub boundary: String,
    /// The connector URL exactly as entered in Claude.
    pub url: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_mailbox")]
    pub mailbox: String,
    #[serde(default = "default_calls")]
    pub calls_per_hour: u32,
}

fn default_port() -> u16 {
    8787
}
fn default_mailbox() -> String {
    "claude".into()
}
fn default_calls() -> u32 {
    600
}

impl GatewayConfig {
    pub fn check(&self) -> Result<()> {
        ensure!(crate::valid_name(&self.boundary), "bad boundary name {:?}: use a-z, 0-9 and -", self.boundary);
        ensure!(crate::valid_name(&self.mailbox), "bad mailbox name {:?}: use a-z, 0-9 and -", self.mailbox);
        // Every session's default mailbox: the guest would be taken for its letters' sender.
        ensure!(self.mailbox != "admin", "the gateway's mailbox can't be admin, every session's default");
        ensure!(self.port != 0, "port must be 1 to 65535");
        ensure!(self.calls_per_hour >= 1, "calls_per_hour must be at least 1");
        oauth::Config::new(&self.url, Path::new("."))?;
        Ok(())
    }

    /// The host of url, which the tunnel passes on in Host.
    fn host(&self) -> String {
        let rest = self.url.split_once("://").map_or(self.url.as_str(), |(_, r)| r);
        let authority = rest.split('/').next().unwrap_or_default();
        let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
        host.to_ascii_lowercase()
    }

    /// The path of url: where MCP is served.
    fn path(&self) -> String {
        let rest = self.url.split_once("://").map_or(self.url.as_str(), |(_, r)| r);
        match rest.find('/') {
            Some(i) => rest[i..].to_string(),
            None => "/".into(),
        }
    }
}

pub fn config_path() -> PathBuf {
    std::env::var_os("TEARMESH_GATEWAY_CONFIG").map_or_else(|| PathBuf::from(CONFIG), PathBuf::from)
}

pub fn state_dir() -> PathBuf {
    std::env::var_os("TEARMESH_GATEWAY_DIR").map_or_else(|| PathBuf::from(DIR), PathBuf::from)
}

pub fn load(path: &Path) -> Result<GatewayConfig> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let c: GatewayConfig = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    c.check().with_context(|| format!("in {}", path.display()))?;
    Ok(c)
}

/// The audit log: one JSON line per tool call and per sign-in event, never a body, token or passphrase.
struct Audit {
    path: PathBuf,
    lock: Mutex<()>,
    /// Per group (everything else, security): this minute's start, its lines from requests without a
    /// valid token, and the ones left out.
    flood: [Mutex<(Instant, u32, u64)>; 2],
}

/// The groups of Audit::unsigned, by index into Audit::flood.
const FLOOD_GROUPS: [&str; 2] = ["register", "security"];

impl Audit {
    fn new(path: PathBuf) -> Audit {
        let f = || Mutex::new((Instant::now(), 0, 0));
        Audit { path, lock: Mutex::new(()), flood: [f(), f()] }
    }

    /// A line caused by a request anyone can send: at most UNSIGNED_PER_MINUTE a minute per group, so a
    /// flood can't push the record of real calls out, and a flood of registrations can't hide the lines
    /// that signal an attack on the passphrase or the tokens (security).
    fn unsigned(&self, v: Value) {
        let security = matches!(v["event"].as_str(), Some("consent_wrong" | "revoked_used" | "replaced_used"));
        let g = usize::from(security);
        let mut f = self.flood[g].lock().unwrap_or_else(|e| e.into_inner());
        self.roll(g, &mut f);
        if f.1 < UNSIGNED_PER_MINUTE {
            f.1 += 1;
            drop(f);
            self.write(v);
        } else {
            f.2 += 1;
        }
    }

    /// Ends the minute once it is over, with one line for what was left out.
    fn roll(&self, group: usize, f: &mut (Instant, u32, u64)) {
        if f.0.elapsed() >= Duration::from_secs(60) {
            if f.2 > 0 {
                self.write(json!({"event": "left_out", "of": FLOOD_GROUPS[group], "lines": f.2}));
            }
            *f = (Instant::now(), 0, 0);
        }
    }

    fn tick(&self) {
        for (g, f) in self.flood.iter().enumerate() {
            self.roll(g, &mut f.lock().unwrap_or_else(|e| e.into_inner()));
        }
    }

    fn write(&self, mut v: Value) {
        v["time"] = crate::talk::utc(crate::now_ms()).into();
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        if std::fs::metadata(&self.path).is_ok_and(|m| m.len() >= AUDIT_CAP) {
            let _ = std::fs::rename(&self.path, self.path.with_extension("log.1"));
        }
        let r = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
            .and_then(|mut f| writeln!(f, "{v}"));
        if let Err(e) = r {
            warn!("gateway audit log {}: {e}", self.path.display());
        }
    }
}

struct State {
    cfg: GatewayConfig,
    path: String,
    socket: PathBuf,
    oauth: OAuth,
    audit: Arc<Audit>,
    sessions: Arc<tokio::sync::Semaphore>,
    budgets: Mutex<HashMap<String, VecDeque<Instant>>>,
}

type Body = BoxBody<Bytes, std::convert::Infallible>;

fn plain(status: StatusCode, text: &str) -> http::Response<Body> {
    let mut r = http::Response::new(Full::new(Bytes::from(format!("{text}\n"))).boxed());
    *r.status_mut() = status;
    r.headers_mut().insert(header::CONTENT_TYPE, http::HeaderValue::from_static("text/plain; charset=utf-8"));
    r
}

/// The MCP door: exactly the conversation tools, with the sign-in named in the audit log.
#[derive(Clone)]
struct Gate {
    /// For the tool list and the instructions; calls open sessions of their own.
    talk: Talk,
    socket: PathBuf,
    mailbox: String,
    audit: Arc<Audit>,
    /// Held for the life of every daemon session a call opens.
    sessions: Arc<tokio::sync::Semaphore>,
}

fn door(mailbox: &str) -> Door {
    Door { mailbox: Some(mailbox.into()), trust: Some(Trust::Guest), hold: false, agent_tools: false }
}

impl ServerHandler for Gate {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("tearmesh-gateway", env!("CARGO_PKG_VERSION")))
            .with_instructions(format!(
                "{} Through this connector the owner's Claude speaks into the owner's own mesh: your messages \
                 reach the agents as guest letters, from outside the mesh.",
                self.talk.instructions()
            ))
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(self.talk.tools()))
    }

    async fn call_tool(
        &self,
        req: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        // rmcp hands the HTTP request's parts to the handler; the grant was put in them after the token check.
        let grant = ctx.extensions.get::<http::request::Parts>().and_then(|p| p.extensions.get::<Grant>()).cloned();
        let args = req.arguments.unwrap_or_default();
        let to = match req.name.as_ref() {
            "board_post" => Some("*".to_string()),
            _ => args.get("to").and_then(Value::as_str).map(|s| s.chars().take(200).collect()),
        };
        let start = Instant::now();
        // A daemon session per call: one caller's 30 s inbox wait or 4 s ping holds up nobody else.
        let permit = self.sessions.acquire().await;
        let r = Talk::at(door(&self.mailbox), self.socket.clone()).call(&req.name, args).await;
        drop(permit);
        let mut line = json!({
            "event": "tool",
            "grant": grant.as_ref().map(|g| g.id.as_str()),
            "client": grant.as_ref().map(|g| g.client.as_str()),
            "tool": req.name.chars().take(64).collect::<String>(),
            "ms": start.elapsed().as_millis() as u64,
        });
        if let Some(to) = to {
            line["to"] = to.into();
        }
        match &r {
            Ok(_) => line["ok"] = true.into(),
            Err(e) => line["error"] = e.chars().take(200).collect::<String>().into(),
        }
        self.audit.write(line);
        Ok(crate::talk::to_result(r).into())
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.talk.tools().into_iter().find(|t| t.name == name)
    }
}

/// Whether the daemon holds this process's session to a guest's limits, for this boundary and mailbox.
/// Err: no daemon, or it refused the hello.
async fn guest_hello(socket: &Path, cfg: &GatewayConfig) -> Result<bool> {
    let mut c = Client::connect(socket).await?;
    let v = c.call(&Request::Hello { mailbox: Some(cfg.mailbox.clone()), hold: false, trust: Some(Trust::Guest) }).await?;
    Ok(v["guest"] == true && v["boundary"] == cfg.boundary.as_str())
}

/// Whether the daemon answers this gateway as its guest, within 2 s.
async fn mesh_up(socket: &Path, cfg: &GatewayConfig) -> bool {
    matches!(tokio::time::timeout(Duration::from_secs(2), guest_hello(socket, cfg)).await, Ok(Ok(true)))
}

/// Any JSON, refused when an object anywhere in it has a key twice.
struct NoDup;

impl<'de> Deserialize<'de> for NoDup {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<NoDup, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = NoDup;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON")
            }
            fn visit_bool<E>(self, _: bool) -> Result<NoDup, E> {
                Ok(NoDup)
            }
            fn visit_i64<E>(self, _: i64) -> Result<NoDup, E> {
                Ok(NoDup)
            }
            fn visit_u64<E>(self, _: u64) -> Result<NoDup, E> {
                Ok(NoDup)
            }
            fn visit_f64<E>(self, _: f64) -> Result<NoDup, E> {
                Ok(NoDup)
            }
            fn visit_str<E>(self, _: &str) -> Result<NoDup, E> {
                Ok(NoDup)
            }
            fn visit_unit<E>(self) -> Result<NoDup, E> {
                Ok(NoDup)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<NoDup, A::Error> {
                while a.next_element::<NoDup>()?.is_some() {}
                Ok(NoDup)
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A) -> Result<NoDup, A::Error> {
                let mut keys = std::collections::HashSet::new();
                while let Some(k) = a.next_key::<String>()? {
                    if !keys.insert(k) {
                        return Err(serde::de::Error::custom("a key appears twice"));
                    }
                    a.next_value::<NoDup>()?;
                }
                Ok(NoDup)
            }
        }
        d.deserialize_any(V)
    }
}

/// Tool calls in a JSON-RPC body (a message or a batch). Err for a body that isn't JSON, which can't
/// be counted, or JSON with a key twice in an object: which copy counts would be up to the parser, so a
/// second "method" could slip a call past the budget.
fn tool_calls(body: &[u8]) -> Result<usize, &'static str> {
    let is_call = |m: &Value| m["method"] == "tools/call";
    let v = serde_json::from_slice::<Value>(body).map_err(|_| "the request body is not JSON")?;
    serde_json::from_slice::<NoDup>(body).map_err(|_| "an object in the body has a key twice")?;
    Ok(match v {
        Value::Array(a) => a.iter().filter(|m| is_call(m)).count(),
        m => usize::from(is_call(&m)),
    })
}

async fn handle<S>(s: Arc<State>, mut mcp: S, req: http::Request<hyper::body::Incoming>) -> http::Response<Body>
where
    S: tower_service::Service<http::Request<Full<Bytes>>, Response = http::Response<Body>, Error = std::convert::Infallible>,
{
    if req.uri().path() == "/health" {
        let up = {
            let _permit = s.sessions.acquire().await;
            mesh_up(&s.socket, &s.cfg).await
        };
        let body = json!({"ok": true, "version": env!("CARGO_PKG_VERSION"), "mesh": up}).to_string();
        let mut r = http::Response::new(Full::new(Bytes::from(body)).boxed());
        r.headers_mut().insert(header::CONTENT_TYPE, http::HeaderValue::from_static("application/json"));
        return r;
    }
    let req = match s.oauth.route(req).await {
        Ok(r) => return r.map(|b| b.boxed()),
        Err(req) => req,
    };
    if req.uri().path() != s.path {
        return plain(StatusCode::NOT_FOUND, "not found");
    }
    let too_long = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().parse::<u64>().map_or(true, |n| n > MAX_BODY as u64));
    if too_long {
        return plain(StatusCode::PAYLOAD_TOO_LARGE, "the request body is over 1 MiB");
    }
    let grant = match s.oauth.check(req.headers()) {
        Ok(g) => g,
        Err(r) => return r.map(|b| b.boxed()),
    };
    let (mut parts, body) = req.into_parts();
    // Stops reading at the cap, and gives up on a body that trickles in.
    let body = match tokio::time::timeout(Duration::from_secs(30), Limited::new(body, MAX_BODY).collect()).await {
        Ok(Ok(b)) => b.to_bytes(),
        Ok(Err(e)) if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() => {
            return plain(StatusCode::PAYLOAD_TOO_LARGE, "the request body is over 1 MiB");
        }
        Ok(Err(_)) => return plain(StatusCode::BAD_REQUEST, "the request body could not be read"),
        Err(_) => return plain(StatusCode::REQUEST_TIMEOUT, "the request body took too long"),
    };
    // Only POST carries JSON-RPC; GET and DELETE go on to rmcp as they are.
    let calls = if parts.method == http::Method::POST {
        match tool_calls(&body) {
            Ok(n) => n,
            Err(why) => return plain(StatusCode::BAD_REQUEST, why),
        }
    } else {
        0
    };
    if calls > 0 {
        let mut budgets = s.budgets.lock().unwrap_or_else(|e| e.into_inner());
        let log = budgets.entry(grant.id.clone()).or_default();
        let now = Instant::now();
        if !(0..calls).all(|_| crate::within_budget(log, s.cfg.calls_per_hour, now)) {
            let wait = log.front().map_or(3600, |t| 3600u64.saturating_sub(now.duration_since(*t).as_secs()).max(1));
            drop(budgets);
            s.audit.write(json!({"event": "budget", "grant": grant.id, "client": grant.client}));
            let text = format!("more than {} tool calls in an hour for this sign-in", s.cfg.calls_per_hour);
            let mut r = plain(StatusCode::TOO_MANY_REQUESTS, &text);
            r.headers_mut().insert(header::RETRY_AFTER, wait.into());
            return r;
        }
    }
    parts.extensions.insert(grant);
    match mcp.call(http::Request::from_parts(parts, Full::new(body))).await {
        Ok(r) => r,
        Err(e) => match e {},
    }
}

/// Runs the gateway on an already-bound listener (tests start it in-process). The state directory
/// ocfg.dir must exist; it holds gateway.db and audit.log.
pub async fn serve_on(cfg: GatewayConfig, ocfg: oauth::Config, socket: PathBuf, listener: tokio::net::TcpListener) -> Result<()> {
    cfg.check()?;
    ensure!(ocfg.url == cfg.url, "the sign-in and the gateway must use the same url");
    // The daemon, not this process, sets what a gateway that is taken over can do: no start without it.
    let start = Instant::now();
    while Client::connect(&socket).await.is_err() && start.elapsed() < Duration::from_secs(30) {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    match guest_hello(&socket, &cfg).await {
        Ok(true) => {}
        Ok(false) => bail!(NOT_GUEST),
        Err(e) => bail!("{NOT_GUEST} ({e:#})"),
    }
    let audit = Arc::new(Audit::new(ocfg.dir.join("audit.log")));
    let sink = audit.clone();
    let oauth = OAuth::open(
        ocfg,
        Arc::new(move |e: &oauth::Event| {
            let v = serde_json::to_value(e).unwrap_or_default();
            // Registrations, wrong passphrases and refused tokens come from requests anyone can send.
            match v["event"].as_str() {
                Some("register" | "consent_wrong" | "refused" | "revoked_used" | "replaced_used") => sink.unsigned(v),
                _ => sink.write(v),
            }
        }),
    )?;
    let ticker = audit.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            ticker.tick();
        }
    });
    let talk = Talk::at(door(&cfg.mailbox), socket.clone());
    // For the address in the instructions.
    let _ = talk.address().await;
    let mut http = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_max_request_body_bytes(MAX_BODY);
    // The tunnel passes on the public Host. Origin is not checked: Claude's own requests may carry one
    // (docs/research/connector-platform-facts.md, A.17), and the bearer token is the lock.
    http.allowed_hosts.push(cfg.host());
    let sessions = Arc::new(tokio::sync::Semaphore::new(MAX_SESSIONS));
    let gate = Gate { talk, socket: socket.clone(), mailbox: cfg.mailbox.clone(), audit: audit.clone(), sessions: sessions.clone() };
    let mcp = StreamableHttpService::new(move || Ok(gate.clone()), Arc::new(NeverSessionManager::default()), http);
    let state = Arc::new(State {
        path: cfg.path(),
        cfg,
        socket,
        oauth,
        audit,
        sessions,
        budgets: Mutex::new(HashMap::new()),
    });
    info!("gateway for boundary {} listening on {}", state.cfg.boundary, listener.local_addr()?);
    // Anyone on the internet can connect, so cap how many may at once.
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let slot = slots.clone().acquire_owned().await?;
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                warn!("gateway accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let (s, mcp) = (state.clone(), mcp.clone());
        tokio::spawn(async move {
            let _slot = slot;
            let io = hyper_util::rt::TokioIo::new(stream);
            let f = hyper::service::service_fn(move |req| {
                let (s, mcp) = (s.clone(), mcp.clone());
                async move { Ok::<_, std::convert::Infallible>(handle(s, mcp, req).await) }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .serve_connection(io, f)
                .await
            {
                info!("gateway connection: {e}");
            }
        });
    }
}

/// `tearmesh gateway serve`: the service.
pub async fn serve() -> Result<()> {
    ensure!(!nix::unistd::geteuid().is_root(), "the gateway faces the internet, so it doesn't run as root: run it as its own user, tm-<boundary>-gw");
    let cfg = load(&config_path())?;
    let dir = state_dir();
    let meta = std::fs::metadata(&dir)
        .with_context(|| format!("no state directory {}: run sudo tearmesh gateway setup", dir.display()))?;
    ensure!(meta.permissions().mode() & 0o077 == 0, "{} must be private to the gateway's user (mode 0700)", dir.display());
    let socket = crate::ipc::socket_path();
    let ocfg = oauth::Config::new(&cfg.url, &dir)?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", cfg.port))
        .await
        .with_context(|| format!("listening on 127.0.0.1:{}", cfg.port))?;
    tokio::select! {
        r = serve_on(cfg, ocfg, socket, listener) => r,
        r = crate::os::shutdown_signal() => r,
    }
}

fn daemon_config_path() -> PathBuf {
    std::env::var_os("TEARMESH_CONFIG").map_or_else(|| PathBuf::from(crate::config::DEFAULT_CONFIG), PathBuf::from)
}

/// The daemon's config, which lists the gateway's user under [guests].
fn daemon_config() -> Result<crate::config::Config> {
    crate::config::Config::load(&daemon_config_path())
}

/// The gateway's own OS user (Linux names are at most 32 characters, so a boundary at most 26).
fn user_name(boundary: &str) -> String {
    format!("tm-{boundary}-gw")
}

/// The gateway's user, as the daemon's config lists it under [guests] for this boundary and mailbox.
fn gateway_user(cfg: &GatewayConfig) -> Result<nix::unistd::User> {
    let name = user_name(&cfg.boundary);
    let want = Guest { boundary: cfg.boundary.clone(), mailbox: cfg.mailbox.clone() };
    ensure!(
        daemon_config()?.guests.get(&name) == Some(&want),
        "the daemon's config doesn't list {name} under [guests] with boundary {} and mailbox {}; run sudo tearmesh gateway setup",
        cfg.boundary,
        cfg.mailbox
    );
    nix::unistd::User::from_name(&name)?.with_context(|| format!("no OS user {name}; run sudo tearmesh gateway setup"))
}

/// Whether install made a service for the daemon, which a changed config needs restarted.
fn daemon_service() -> bool {
    Path::new("/etc/systemd/system/tearmesh.service").exists() || Path::new("/etc/init.d/tearmesh").exists()
}

/// Restarts the daemon so it reads its changed config, and waits until it answers.
async fn restart_daemon(socket: &Path) -> Result<()> {
    if !daemon_service() {
        println!("No tearmesh service here: restart the daemon yourself so it reads the [guests] entry.");
        return Ok(());
    }
    crate::install::restart_service()?;
    for _ in 0..30 {
        if let Ok(mut c) = Client::connect(socket).await
            && c.call(&Request::Status).await.is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("the daemon didn't answer within 30 s of its restart")
}

/// Root runs the gateway's own commands as the gateway's user, so it never opens files that user
/// controls. False: this process is to do the work itself.
fn as_gateway_user() -> Result<bool> {
    if !nix::unistd::geteuid().is_root() {
        return Ok(false);
    }
    let cfg = load(&config_path())?;
    run_as(&gateway_user(&cfg)?, &std::env::args_os().skip(1).collect::<Vec<_>>())?;
    Ok(true)
}

/// The child gets no terminal: a session of its own (no controlling tty to inject input into),
/// stdin from /dev/null, and its output captured; root prints that cleaned, as it may come from files
/// the gateway's user can write. Nothing it runs asks a question.
fn run_as(user: &nix::unistd::User, args: &[std::ffi::OsString]) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    // std drops root's supplementary groups when it sets the uid.
    cmd.args(args)
        .uid(user.uid.as_raw())
        .gid(user.gid.as_raw())
        .env("HOME", &user.dir)
        .env("TEARMESH_GATEWAY_CONFIG", config_path())
        .env("TEARMESH_GATEWAY_DIR", state_dir())
        .stdin(std::process::Stdio::null());
    // SAFETY: setsid is async-signal-safe and touches no memory of the parent.
    unsafe {
        cmd.pre_exec(|| nix::unistd::setsid().map(drop).map_err(std::io::Error::from));
    }
    let out = cmd.output().with_context(|| format!("running as {}", user.name))?;
    print!("{}", printable(&String::from_utf8_lossy(&out.stdout)));
    eprint!("{}", printable(&String::from_utf8_lossy(&out.stderr)));
    std::io::stdout().flush()?;
    if !out.status.success() {
        std::process::exit(out.status.code().unwrap_or(1));
    }
    Ok(())
}

/// Text safe for a terminal: no control characters but newline and tab (C1 ones such as CSI U+009B
/// included), and no bidi overrides or isolates that would show it in another order.
fn printable(s: &str) -> String {
    s.chars()
        .filter(|&c| c == '\n' || c == '\t' || !(c.is_control() || ('\u{202a}'..='\u{202e}').contains(&c) || ('\u{2066}'..='\u{2069}').contains(&c)))
        .collect()
}

/// `gateway passphrase`: a new passphrase, printed once. if_missing: only when none is set (setup).
pub fn passphrase(revoke_all: bool, if_missing: bool) -> Result<()> {
    if as_gateway_user()? {
        return Ok(());
    }
    let dir = state_dir();
    if if_missing && oauth::has_passphrase(&dir)? {
        println!("The gateway passphrase is kept (a new one: tearmesh gateway passphrase).");
        return Ok(());
    }
    let p = crate::keys::passphrase();
    oauth::set_passphrase(&dir, &p)?;
    println!("Gateway passphrase (shown only now; Claude's sign-in page asks for it):\n\n    {}\n", p.as_str());
    if revoke_all {
        println!("Ended {} sign-ins.", oauth::revoke(&dir, None)?);
    }
    Ok(())
}

pub fn grants() -> Result<()> {
    if as_gateway_user()? {
        return Ok(());
    }
    print_grants()
}

fn print_grants() -> Result<()> {
    let list = oauth::grants(&state_dir())?;
    if list.is_empty() {
        println!("No sign-ins.");
    }
    for g in list {
        println!(
            "{}  {}  made {}  last used {}  {} calls",
            g.id,
            g.client,
            crate::talk::utc(g.created_ms),
            crate::talk::utc(g.last_used_ms),
            g.calls
        );
    }
    Ok(())
}

pub fn revoke(id: Option<&str>) -> Result<()> {
    if as_gateway_user()? {
        return Ok(());
    }
    let n = oauth::revoke(&state_dir(), id)?;
    match id {
        Some(id) if n == 0 => bail!("no sign-in {id} (see tearmesh gateway grants)"),
        _ => println!("Ended {n} sign-in{}.", if n == 1 { "" } else { "s" }),
    }
    Ok(())
}

/// What /health on this machine says.
async fn health(port: u16) -> Result<Value> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let c = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;
    Ok(c.get(format!("http://127.0.0.1:{port}/health")).send().await?.error_for_status()?.json().await?)
}

pub async fn status() -> Result<()> {
    if as_gateway_user()? {
        return Ok(());
    }
    let path = config_path();
    let cfg = load(&path)?;
    print!("{}:\n{}", path.display(), toml::to_string(&cfg)?);
    match health(cfg.port).await {
        Ok(h) => println!(
            "The gateway answers on 127.0.0.1:{}; the daemon {}.",
            cfg.port,
            if h["mesh"] == true { "answers it" } else { "does NOT answer it" }
        ),
        Err(e) => println!("The gateway does not answer on 127.0.0.1:{} ({e:#}).", cfg.port),
    }
    print_grants()?;
    let log = std::fs::read_to_string(state_dir().join("audit.log")).unwrap_or_default();
    match log.lines().rev().find(|l| l.contains("\"event\":\"tool\"")) {
        Some(l) => println!("Last call: {l}"),
        None => println!("No calls yet."),
    }
    Ok(())
}

fn systemd() -> bool {
    Path::new("/run/systemd/system").exists()
}

fn systemctl(args: &[&str]) -> Result<()> {
    let st = std::process::Command::new("systemctl").args(args).status().context("running systemctl")?;
    ensure!(st.success(), "systemctl {} failed ({st})", args.join(" "));
    Ok(())
}

/// Makes the state directory 0700 and the gateway user's. Root touches the directory alone, never
/// what is in it: a hard link planted there would hand a root-owned file over.
fn own_dir(dir: &Path, user: &nix::unistd::User) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    if std::fs::symlink_metadata(dir).is_err() {
        std::fs::DirBuilder::new().mode(0o700).create(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let m = std::fs::symlink_metadata(dir)?;
    // Root's and empty: made by a run that stopped before handing it over.
    let ours = m.uid() == user.uid.as_raw() || (m.uid() == 0 && std::fs::read_dir(dir)?.next().is_none());
    ensure!(m.is_dir() && ours, "{} belongs to someone else; run tearmesh gateway remove first", dir.display());
    nix::unistd::chown(dir, Some(user.uid), Some(user.gid))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// `gateway setup`: as root, makes this machine a gateway. Safe to run again: the passphrase and the
/// sign-ins stay unless new_passphrase.
pub async fn setup(boundary: &str, url: &str, port: Option<u16>, mailbox: Option<String>, new_passphrase: bool) -> Result<()> {
    crate::install::require_admin("gateway setup BOUNDARY --url URL")?;
    let cfg = GatewayConfig {
        boundary: boundary.into(),
        url: url.into(),
        port: port.unwrap_or_else(default_port),
        mailbox: mailbox.unwrap_or_else(default_mailbox),
        calls_per_hour: default_calls(),
    };
    cfg.check()?;
    ensure!(
        boundary.len() <= 26,
        "boundary {boundary:?} is too long for a gateway: its user {} would be over 32 characters",
        user_name(boundary)
    );
    let (path, dir) = (config_path(), state_dir());
    if systemd() {
        ensure!(
            path == Path::new(CONFIG) && dir == Path::new(DIR),
            "the service uses {CONFIG} and {DIR}; unset TEARMESH_GATEWAY_CONFIG and TEARMESH_GATEWAY_DIR"
        );
    }
    if path.exists() {
        let old = load(&path)?;
        ensure!(
            (&old.boundary, &old.url, &old.mailbox) == (&cfg.boundary, &cfg.url, &cfg.mailbox),
            "this machine is already a gateway for {} at {}; run tearmesh gateway remove first",
            old.boundary,
            old.url
        );
    }
    let dpath = daemon_config_path();
    let daemon = crate::config::Config::load(&dpath)?;
    daemon.boundary_user(boundary).with_context(|| {
        format!("boundary {boundary} has no OS user on this machine; add it first: sudo tearmesh install {} {boundary}", daemon.machine)
    })?;
    // Boundary <boundary>-gw gives its own user the same name: under [guests] too, the daemon would refuse its config.
    let name = user_name(boundary);
    ensure!(
        !daemon.users.contains_key(&name) && !daemon.admins.contains(&name),
        "the user {name} is already the user of a boundary on this machine (or an admin); the gateway needs a user of its own"
    );
    // Every step below can run again, so a setup that stopped halfway is finished by running it again.
    // The config first: remove takes the user's name from it.
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    // Rewritten every run; root's and readable by all, as it holds no secret.
    std::fs::write(&path, format!("# Written by tearmesh gateway setup (spec 18.4).\n{}", toml::to_string(&cfg)?))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    if nix::unistd::User::from_name(&name)?.is_none() {
        crate::install::run_script(&["--gateway-user".into(), name.clone()])?;
    }
    let user = nix::unistd::User::from_name(&name)?.with_context(|| format!("couldn't create the OS user {name}"))?;
    let entry = Guest { boundary: boundary.into(), mailbox: cfg.mailbox.clone() };
    if crate::install::set_guest(&dpath, &name, Some(&entry))? {
        restart_daemon(&daemon.socket).await?;
    }
    own_dir(&dir, &user)?;
    let mut args: Vec<std::ffi::OsString> = vec!["gateway".into(), "passphrase".into()];
    if !new_passphrase {
        args.push("--if-missing".into());
    }
    run_as(&user, &args)?;
    if systemd() {
        std::fs::write(UNIT_PATH, UNIT.replace("@USER@", &user.name))?;
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", "tearmesh-gateway"])?;
        systemctl(&["restart", "tearmesh-gateway"])?;
        let mut answer = None;
        for _ in 0..10 {
            if let Ok(h) = health(cfg.port).await {
                answer = Some(h);
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let h = answer.context("the gateway didn't answer within 10 s; its log: journalctl -u tearmesh-gateway -n 20")?;
        println!(
            "The gateway answers on 127.0.0.1:{}{}.",
            cfg.port,
            if h["mesh"] == true {
                ""
            } else {
                ", but the daemon doesn't answer it as its guest yet (is tearmesh running with the [guests] entry, and does this machine host the boundary?)"
            }
        );
    } else {
        println!("No systemd here, so no service was made. Run the gateway yourself as {}: tearmesh gateway serve", user.name);
    }
    let (host, port) = (cfg.host(), cfg.port);
    println!(
        "\nGive it a public host name with a tunnel to 127.0.0.1:{port}, one of:\n\
         \x20 Cloudflare Tunnel: cloudflared tunnel create tearmesh && cloudflared tunnel route dns tearmesh {host} && cloudflared tunnel run --url http://127.0.0.1:{port} tearmesh\n\
         \x20 Tailscale Funnel (the host is then this machine's ts.net name): sudo tailscale funnel --bg {port}\n\
         Then in Claude: Customize, Connectors, Add custom connector, with the URL\n\n    {url}\n\n\
         and sign in with the passphrase."
    );
    if !url.to_ascii_lowercase().starts_with("https://") {
        println!("This URL is plain http: for tests on this machine only. Claude needs https.");
    }
    Ok(())
}

/// `gateway remove`: the service, the [guests] entry, the user setup made, the state directory and the config.
pub fn remove(yes: bool) -> Result<()> {
    crate::install::require_admin("gateway remove")?;
    let (path, dir) = (config_path(), state_dir());
    if !yes {
        print!("Remove the gateway: its service, {} and {} (every sign-in and the audit log)? [y/N] ", path.display(), dir.display());
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        ensure!(matches!(line.trim(), "y" | "Y" | "yes"), "not removed");
    }
    remove_all()?;
    println!("The gateway is removed.");
    Ok(())
}

/// Removes what setup made; what isn't there is fine, and the config goes last, so a remove that
/// stopped halfway can run again. Uninstall calls it too.
pub fn remove_all() -> Result<()> {
    if Path::new(UNIT_PATH).exists() {
        let _ = systemctl(&["disable", "--now", "tearmesh-gateway"]);
        std::fs::remove_file(UNIT_PATH)?;
        let _ = systemctl(&["daemon-reload"]);
    }
    let path = config_path();
    if let Ok(cfg) = load(&path) {
        let name = user_name(&cfg.boundary);
        let dpath = daemon_config_path();
        if dpath.exists() && crate::install::set_guest(&dpath, &name, None)? && daemon_service() {
            crate::install::restart_service()?;
        }
        // Only a user setup made: one that was there before stays.
        if crate::install::created_record().lines().any(|l| l.trim() == name) {
            crate::install::run_script(&["--gateway-user-remove".into(), name])?;
        }
    }
    let dir = state_dir();
    if dir.exists() {
        // remove_dir_all doesn't follow links, so the user's files can't point it elsewhere.
        std::fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
    }
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(url: &str) -> GatewayConfig {
        toml::from_str(&format!("boundary = \"work\"\nurl = \"{url}\"\n")).unwrap()
    }

    #[test]
    fn config_keys_and_checks() {
        let c = cfg("https://mesh.example.com/mcp");
        assert_eq!((c.port, c.mailbox.as_str(), c.calls_per_hour), (8787, "claude", 600));
        c.check().unwrap();
        assert_eq!((c.host(), c.path()), ("mesh.example.com".to_string(), "/mcp".to_string()));
        let c = cfg("http://127.0.0.1:9/x/mcp");
        assert_eq!((c.host(), c.path()), ("127.0.0.1".to_string(), "/x/mcp".to_string()));
        assert!(toml::from_str::<GatewayConfig>("boundary = \"work\"\nurl = \"https://a.b/mcp\"\nhosts = []\n").is_err(), "unknown key");
        for url in ["http://mesh.example.com/mcp", "https://a.b/mcp?x=1", "ftp://a.b/mcp"] {
            assert!(cfg(url).check().is_err(), "{url}");
        }
        assert!(GatewayConfig { calls_per_hour: 0, ..cfg("https://a.b/mcp") }.check().is_err());
        assert!(GatewayConfig { boundary: "Work".into(), ..cfg("https://a.b/mcp") }.check().is_err());
        assert!(GatewayConfig { mailbox: "admin".into(), ..cfg("https://a.b/mcp") }.check().is_err());
    }

    #[test]
    fn tool_calls_are_counted_in_messages_and_batches() {
        assert_eq!(tool_calls(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#), Ok(1));
        assert_eq!(tool_calls(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#), Ok(0));
        assert_eq!(tool_calls(br#"[{"method":"tools/call"},{"method":"tools/call"},{"method":"ping"}]"#), Ok(2));
        assert_eq!(tool_calls(b"not json"), Err("the request body is not JSON"));
        assert_eq!(tool_calls(b""), Err("the request body is not JSON"));
        // A second "method", in either order or escaped, or a key twice deeper down: refused.
        for dup in [
            r#"{"method":"tools/call","method":"tools/list"}"#,
            r#"{"method":"tools/list","params":{},"\u006dethod":"tools/call"}"#,
            r#"[{"method":"ping"},{"method":"tools/call","params":{"name":"a","name":"b"}}]"#,
        ] {
            assert_eq!(tool_calls(dup.as_bytes()), Err("an object in the body has a key twice"), "{dup}");
        }
    }

    #[test]
    fn unsigned_lines_are_capped_a_minute_and_counted() {
        let d = tempfile::tempdir().unwrap();
        let a = Audit::new(d.path().join("audit.log"));
        for _ in 0..70 {
            a.unsigned(json!({"event": "register"}));
        }
        a.write(json!({"event": "tool"}));
        a.tick();
        let lines = |a: &Audit| std::fs::read_to_string(&a.path).unwrap().lines().map(|l| serde_json::from_str::<Value>(l).unwrap()).collect::<Vec<_>>();
        let l = lines(&a);
        assert_eq!((l.len(), &l[60]["event"]), (61, &json!("tool")), "60 kept, the call never dropped");
        a.flood[0].lock().unwrap().0 -= Duration::from_secs(61);
        a.tick();
        let l = lines(&a);
        assert_eq!((&l[61]["event"], &l[61]["of"], &l[61]["lines"]), (&json!("left_out"), &json!("register"), &json!(10)));
        a.unsigned(json!({"event": "register"}));
        assert_eq!(lines(&a).len(), 63, "a new minute");
    }

    #[test]
    fn a_flood_of_registrations_hides_no_attack_on_the_passphrase() {
        let d = tempfile::tempdir().unwrap();
        let a = Audit::new(d.path().join("audit.log"));
        for _ in 0..100 {
            a.unsigned(json!({"event": "register"}));
            a.unsigned(json!({"event": "refused"}));
        }
        for e in ["consent_wrong", "revoked_used", "replaced_used"] {
            for _ in 0..30 {
                a.unsigned(json!({"event": e}));
            }
        }
        let text = || std::fs::read_to_string(&a.path).unwrap();
        let t = text();
        assert_eq!(t.lines().count(), 120, "60 in each group");
        assert_eq!((t.matches("consent_wrong").count(), t.matches("revoked_used").count(), t.matches("replaced_used").count()), (30, 30, 0));
        for f in &a.flood {
            f.lock().unwrap().0 -= Duration::from_secs(61);
        }
        a.tick();
        let left: Vec<(Value, Value)> = text()
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter(|v| v["event"] == "left_out")
            .map(|v| (v["of"].clone(), v["lines"].clone()))
            .collect();
        assert_eq!(left, [(json!("register"), json!(140)), (json!("security"), json!(30))]);
    }

    #[test]
    fn printable_keeps_text_and_drops_terminal_controls() {
        assert_eq!(printable("a\tb\nc d é\n"), "a\tb\nc d é\n");
        assert_eq!(printable("x\u{1b}[2J\u{1b}]0;title\u{7}y\r"), "x[2J]0;titley");
        assert_eq!(printable("x\u{9b}31my\u{85}\u{7f}"), "x31my");
        assert_eq!(printable("ok \u{202e}gnp.exe\u{202c} \u{2066}a\u{2069}"), "ok gnp.exe a");
    }

    #[test]
    fn the_audit_log_rotates_and_is_private() {
        let d = tempfile::tempdir().unwrap();
        let a = Audit::new(d.path().join("audit.log"));
        a.write(json!({"event": "x"}));
        assert_eq!(std::fs::metadata(&a.path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::write(&a.path, vec![b'a'; AUDIT_CAP as usize]).unwrap();
        a.write(json!({"event": "y"}));
        assert_eq!(std::fs::metadata(d.path().join("audit.log.1")).unwrap().len(), AUDIT_CAP);
        let now = std::fs::read_to_string(&a.path).unwrap();
        assert!(now.starts_with('{') && now.contains("\"y\"") && now.contains("\"time\""), "{now}");
    }
}
