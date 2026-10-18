//! The local socket (a named pipe on Windows): JSON lines. The OS reports each caller's identity
//! (a uid, or a SID on Windows); the identity maps to a boundary in the config. Nothing in a
//! request can choose the boundary. A few requests turn the connection into a pipe afterwards:
//! a remote tool call, a steward attaching to a stream, a shell.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tracing::debug;

use crate::config::DEFAULT_SOCKET;
use crate::envelope::{Kind, Trust};
use crate::node::{Event, Node};
use crate::offer::Offer;
use crate::os::{BoxRead, BoxWrite, Caller};
use crate::{bridge, join, shell, valid_name};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Picks the mailbox for this connection (default `admin`). `hold: true` marks it as held by a
    /// live session for as long as the connection stays open, so mail doesn't wake another one.
    /// `trust` may lower what this connection's posts carry (the connector asks for `guest`).
    Hello {
        mailbox: Option<String>,
        #[serde(default)]
        hold: bool,
        #[serde(default)]
        trust: Option<Trust>,
    },
    Who,
    Post {
        to: Vec<String>,
        subject: String,
        body: String,
        thread: Option<String>,
        #[serde(default)]
        kind: Option<Kind>,
    },
    Inbox {
        #[serde(default)]
        all: bool,
    },
    Read {
        id: String,
    },
    Notify,
    /// Streams events (`node::Event`) for the caller's boundary until the connection closes.
    Subscribe,
    /// Sets this machine's bio in the caller's boundary.
    Bio {
        text: String,
    },
    /// Publishes (or, with `withdrawn`, withdraws) an offer in the caller's boundary.
    PublishOffer {
        offer: Offer,
    },
    /// Current offers in the caller's boundary (admins name one), with their approval state.
    Offers {
        #[serde(default)]
        boundary: Option<String>,
    },
    /// Opens a tool stream to `machine`'s `server`; the connection then carries MCP lines.
    Remote {
        machine: String,
        server: String,
    },
    /// A steward attaching to stream `stream`; the connection then carries MCP lines.
    Attach {
        stream: u64,
    },
    /// Opens a shell stream to `machine`; the connection then carries bytes. Admin callers who
    /// aren't mapped to a boundary name one.
    Shell {
        machine: String,
        #[serde(default)]
        boundary: Option<String>,
    },
    // ---- admin ----
    Status,
    /// The current membership file, for editing and signing.
    MeshCurrent,
    ApplyMesh {
        toml: String,
        sig: String,
    },
    /// A one-time ticket for a new machine (on the owner node).
    Invite {
        name: String,
        boundaries: Vec<String>,
        #[serde(default)]
        replace: bool,
        #[serde(default)]
        ttl_secs: Option<u64>,
    },
    Pending,
    /// Joins with a ticket. Replies twice: the 6-digit code, then the adopted version.
    Join {
        ticket: String,
    },
    /// Forgets the mesh (logs stay) so a new first file can be adopted.
    Reset,
    /// Sets this machine's bio in `boundary` with admin trust.
    AdminBio {
        boundary: String,
        text: String,
    },
}

/// Longest request line: a 256 KiB body JSON-escaped at worst, plus room.
const MAX_LINE: u64 = 2 << 20;
pub const MAX_BIO: usize = 16 * 1024;

pub fn socket_path() -> PathBuf {
    std::env::var_os("TEARMESH_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| DEFAULT_SOCKET.into())
}

pub async fn serve(node: Arc<Node>) -> Result<()> {
    let listener = crate::os::listen(&node.cfg.socket).await?;
    let ids = Arc::new(node.cfg.identity_map()?);
    let admins = Arc::new(node.cfg.admin_identities()?);
    loop {
        let inc = match listener.accept().await {
            Ok(i) => i,
            Err(e) => {
                debug!("socket accept: {e:#}");
                continue;
            }
        };
        let (node, ids, admins) = (node.clone(), ids.clone(), admins.clone());
        tokio::spawn(async move {
            if let Err(e) = handle(node, inc, &ids, &admins).await {
                debug!("socket client: {e:#}");
            }
        });
    }
}

async fn read_request(reader: &mut BufReader<BoxRead>) -> Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    if (&mut *reader)
        .take(MAX_LINE + 1)
        .read_until(b'\n', &mut buf)
        .await?
        == 0
    {
        return Ok(None);
    }
    ensure!(buf.len() as u64 <= MAX_LINE, "request too long");
    Ok(Some(buf))
}

async fn handle(
    node: Arc<Node>,
    inc: crate::os::Incoming,
    ids: &HashMap<String, String>,
    admins: &[String],
) -> Result<()> {
    let crate::os::Incoming {
        read,
        mut write,
        mut caller,
    } = inc;
    let mut reader = BufReader::new(read);
    let mut who: Option<(Caller, Option<String>, bool)> = None;
    let mut mailbox = "admin".to_string();
    let mut trust = Trust::Member;
    let mut _hold = None;
    loop {
        let buf = match read_request(&mut reader).await {
            Ok(Some(b)) => b,
            Ok(None) => break,
            Err(e) => {
                reply(&mut write, Err(e)).await?;
                break;
            }
        };
        // Windows can name the caller only after reading from it, so identify on the first line.
        if who.is_none() {
            let c = caller()?;
            let boundary = ids.get(&c.id).cloned();
            let admin = c.admin || admins.contains(&c.id);
            if boundary.is_none() && !admin {
                reply(
                    &mut write,
                    Err(anyhow::anyhow!(
                        "OS user {} isn't mapped to a boundary on this machine",
                        c.id
                    )),
                )
                .await?;
                return Ok(());
            }
            who = Some((c, boundary, admin));
        }
        let (_, boundary, admin) = who.clone().expect("set above");
        let line = String::from_utf8_lossy(&buf);
        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                reply(&mut write, Err(anyhow::anyhow!("bad request: {e}"))).await?;
                continue;
            }
        };
        let b = || {
            boundary
                .clone()
                .context("this OS user isn't mapped to a boundary")
        };
        let need_admin = || {
            if admin {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "admin only (root or an Administrator, the daemon's user, or a configured admin)"
                ))
            }
        };
        let res: Result<Value> = match req {
            Request::Hello {
                mailbox: m,
                hold,
                trust: t,
            } => (|| {
                let b = b()?;
                if let Some(m) = m {
                    ensure!(valid_name(&m), "bad mailbox name {m:?}");
                    mailbox = m;
                }
                if let Some(t) = t {
                    ensure!(t <= Trust::Member, "a session can lower its trust, never raise it");
                    trust = t;
                }
                if hold {
                    _hold = Some(node.hold(&b, &mailbox));
                }
                Ok(json!({ "address": format!("{mailbox}@{}", node.cfg.machine), "boundary": b }))
            })(),
            Request::Who => b().and_then(|b| Ok(serde_json::to_value(node.who(&b, &mailbox)?)?)),
            Request::Post {
                to,
                subject,
                body,
                thread,
                kind,
            } => b().and_then(|b| {
                let kind = kind.unwrap_or_default();
                ensure!(kind.is_letter(), "post sends letters (info, task, question)");
                Ok(json!({ "id": node.post_as(&b, &mailbox, trust, kind, to, subject, body, thread)? }))
            }),
            Request::Inbox { all } => {
                b().and_then(|b| Ok(serde_json::to_value(node.inbox(&b, &mailbox, all)?)?))
            }
            Request::Read { id } => {
                b().and_then(|b| Ok(serde_json::to_value(node.read(&b, &mailbox, &id)?)?))
            }
            Request::Notify => {
                b().and_then(|b| Ok(serde_json::to_value(node.notify(&b, &mailbox)?)?))
            }
            Request::Bio { text } => b().and_then(|b| post_bio(&node, &b, &mailbox, trust, text)),
            Request::AdminBio { boundary, text } => need_admin()
                .and_then(|_| post_bio(&node, &boundary, "admin", Trust::Admin, text)),
            Request::PublishOffer { offer } => b().and_then(|b| {
                // Rebuild so the pin is computed here, not taken from the request.
                let o = if offer.withdrawn {
                    Offer::withdrawn(&offer.server)
                } else {
                    Offer::new(
                        &offer.server,
                        offer.description,
                        offer.server_info,
                        offer.instructions,
                        offer.tools,
                        offer.exe,
                    )?
                };
                let body = serde_json::to_string(&o)?;
                let id = node.post_as(
                    &b,
                    &mailbox,
                    trust,
                    Kind::Offer,
                    vec!["*".into()],
                    o.server.clone(),
                    body,
                    None,
                )?;
                Ok(json!({ "id": id, "pin": o.pin }))
            }),
            Request::Offers { boundary: asked } => {
                pick_boundary(boundary.clone(), asked, admin).and_then(|b| offers(&node, &b))
            }
            Request::Subscribe => {
                let b = match b() {
                    Ok(b) => b,
                    Err(e) => {
                        reply(&mut write, Err(e)).await?;
                        continue;
                    }
                };
                let mut rx = node.subscribe();
                reply(&mut write, Ok(json!({ "subscribed": b }))).await?;
                loop {
                    match rx.recv().await {
                        Ok(ev) if node.events_for(&ev, &b) => {
                            let mut line = serde_json::to_vec(&ev)?;
                            line.push(b'\n');
                            write.write_all(&line).await?;
                        }
                        Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(_) => return Ok(()),
                    }
                }
            }
            Request::Remote { machine, server } => {
                let b = match b() {
                    Ok(b) => b,
                    Err(e) => {
                        reply(&mut write, Err(e)).await?;
                        continue;
                    }
                };
                match bridge::call(&node, &b, &machine, &server).await {
                    Ok((sr, sw, filter, conn)) => {
                        reply(&mut write, Ok(json!({ "connected": format!("{machine}/{server}") }))).await?;
                        let r = bridge::pipe(reader, write, sr, sw, filter).await;
                        conn.close(0u32.into(), b"done");
                        return r;
                    }
                    Err(e) => Err(e),
                }
            }
            Request::Attach { stream } => {
                let b = match b() {
                    Ok(b) => b,
                    Err(e) => {
                        reply(&mut write, Err(e)).await?;
                        continue;
                    }
                };
                reply(&mut write, Ok(json!({ "attached": stream }))).await?;
                // The daemon side of the stream owns the connection from here on.
                if let Err(e) = node.streams.attach(stream, &b, (reader, write)) {
                    debug!("attach: {e:#}");
                }
                return Ok(());
            }
            Request::Shell {
                machine,
                boundary: asked,
            } => {
                let b = match pick_boundary(boundary.clone(), asked, admin) {
                    Ok(b) => b,
                    Err(e) => {
                        reply(&mut write, Err(e)).await?;
                        continue;
                    }
                };
                match shell::open(&node, &b, &machine).await {
                    Ok((sr, sw, conn)) => {
                        reply(&mut write, Ok(json!({ "connected": machine }))).await?;
                        let r = shell::splice(reader, write, sr, sw).await;
                        conn.close(0u32.into(), b"done");
                        return r;
                    }
                    Err(e) => Err(e),
                }
            }
            Request::Status => need_admin().and_then(|_| Ok(serde_json::to_value(node.status())?)),
            Request::MeshCurrent => need_admin().and_then(|_| {
                let s = node.signed()?;
                Ok(json!({ "toml": s.toml, "sig": s.sig }))
            }),
            Request::ApplyMesh { toml, sig } => {
                need_admin().and_then(|_| Ok(json!({ "version": node.apply(&toml, &sig)? })))
            }
            Request::Invite {
                name,
                boundaries,
                replace,
                ttl_secs,
            } => need_admin().and_then(|_| {
                let ttl = Duration::from_secs(ttl_secs.unwrap_or(3600));
                Ok(json!({ "ticket": node.invite(&name, boundaries, replace, ttl)? }))
            }),
            Request::Pending => {
                need_admin().and_then(|_| Ok(serde_json::to_value(node.joins.pending())?))
            }
            Request::Join { ticket } => {
                if let Err(e) = need_admin() {
                    reply(&mut write, Err(e)).await?;
                    continue;
                }
                match join::start(&node, &ticket).await {
                    Ok(j) => {
                        let mut line =
                            serde_json::to_vec(&json!({ "ok": true, "more": true, "data": { "code": j.code } }))?;
                        line.push(b'\n');
                        write.write_all(&line).await?;
                        j.finish(&node).await.map(|v| json!({ "version": v }))
                    }
                    Err(e) => Err(e),
                }
            }
            Request::Reset => need_admin().and_then(|_| {
                node.reset()?;
                Ok(json!({ "reset": true }))
            }),
        };
        reply(&mut write, res).await?;
    }
    Ok(())
}

/// A session's boundary is its own; an admin who isn't mapped to one names it.
fn pick_boundary(mine: Option<String>, asked: Option<String>, admin: bool) -> Result<String> {
    match (mine, asked) {
        (Some(mine), None) => Ok(mine),
        (Some(mine), Some(a)) if a == mine => Ok(mine),
        (Some(_), Some(_)) => bail!("a session can't pick another boundary"),
        (None, Some(a)) if admin => Ok(a),
        (None, _) => bail!("name a boundary with --boundary"),
    }
}

fn post_bio(node: &Node, boundary: &str, mailbox: &str, trust: Trust, text: String) -> Result<Value> {
    ensure!(text.len() <= MAX_BIO, "a bio is at most {MAX_BIO} bytes");
    let id = node.post_as(
        boundary,
        mailbox,
        trust,
        Kind::Bio,
        vec!["*".into()],
        "bio".into(),
        text,
        None,
    )?;
    Ok(json!({ "id": id }))
}

fn offers(node: &Node, boundary: &str) -> Result<Value> {
    let mesh = node.mesh()?;
    let mut out = vec![];
    for (machine, st) in node.latest(boundary, Kind::Offer)? {
        let Ok(o) = Offer::parse(&st.body) else { continue };
        if o.withdrawn {
            continue;
        }
        let approval = mesh.approval(&machine, boundary, &o.server);
        let state = match approval {
            Some(a) if a.pin == crate::offer::pin(o.instructions.as_deref(), &o.tools, a.tools.as_deref()) => "approved",
            Some(_) => "changed since approval",
            None if mesh.settings.tools_sharing == crate::mesh::Sharing::Free => "free",
            None => "pending approval",
        };
        out.push(json!({
            "machine": machine,
            "server": o.server,
            "description": o.description,
            "tools": o.tool_names(),
            "pin": o.pin,
            "exe": o.exe,
            "state": state,
            "approved_tools": approval.and_then(|a| a.tools.clone()),
            "subset_pin": approval.and_then(|a| a.tools.as_ref()).map(|t| crate::offer::pin(o.instructions.as_deref(), &o.tools, Some(t))),
            "trust": st.env.label.trust,
            "offer": o,
        }));
    }
    Ok(Value::Array(out))
}

async fn reply(w: &mut BoxWrite, res: Result<Value>) -> Result<()> {
    let v = match res {
        Ok(data) => json!({ "ok": true, "data": data }),
        Err(e) => json!({ "ok": false, "error": format!("{e:#}") }),
    };
    let mut line = serde_json::to_vec(&v)?;
    line.push(b'\n');
    w.write_all(&line).await?;
    w.flush().await?;
    Ok(())
}

/// A connection to the local daemon.
pub struct Client {
    reader: BufReader<BoxRead>,
    w: BoxWrite,
}

impl Client {
    pub async fn connect(path: &Path) -> Result<Client> {
        let (r, w) = crate::os::connect(path).await?;
        Ok(Client {
            reader: BufReader::new(r),
            w,
        })
    }

    /// Connects and says hello with the mailbox from `TEARMESH_MAILBOX` (or `admin`).
    pub async fn session(hold: bool) -> Result<(Client, String)> {
        Self::session_with(hold, None).await
    }

    pub async fn session_with(hold: bool, trust: Option<Trust>) -> Result<(Client, String)> {
        let mut c = Client::connect(&socket_path()).await?;
        let mailbox = std::env::var("TEARMESH_MAILBOX").ok();
        let v = c.call(&Request::Hello { mailbox, hold, trust }).await?;
        let addr = v["address"].as_str().unwrap_or_default().to_string();
        Ok((c, addr))
    }

    async fn line(&mut self) -> Result<Value> {
        let mut l = String::new();
        let n = self.reader.read_line(&mut l).await?;
        ensure!(n > 0, "daemon closed the connection");
        Ok(serde_json::from_str(&l)?)
    }

    pub async fn send(&mut self, req: &Request) -> Result<()> {
        let mut line = serde_json::to_vec(req)?;
        line.push(b'\n');
        self.w.write_all(&line).await?;
        self.w.flush().await?;
        Ok(())
    }

    pub async fn call(&mut self, req: &Request) -> Result<Value> {
        self.send(req).await?;
        self.response().await
    }

    /// The next reply. Replies marked `more` (the join code) come before the final one; use
    /// `call_each` to see them.
    pub async fn response(&mut self) -> Result<Value> {
        let v = self.line().await?;
        if v["ok"].as_bool() == Some(true) {
            Ok(v["data"].clone())
        } else {
            bail!("{}", v["error"].as_str().unwrap_or("unknown error"))
        }
    }

    /// Sends a request and passes every reply to `each`, the final one last.
    pub async fn call_each(&mut self, req: &Request, mut each: impl FnMut(&Value)) -> Result<Value> {
        self.send(req).await?;
        loop {
            let v = self.line().await?;
            if v["ok"].as_bool() != Some(true) {
                bail!("{}", v["error"].as_str().unwrap_or("unknown error"));
            }
            if v["more"].as_bool() == Some(true) {
                each(&v["data"]);
                continue;
            }
            return Ok(v["data"].clone());
        }
    }

    pub async fn next_event(&mut self) -> Result<Option<Event>> {
        let mut l = String::new();
        if self.reader.read_line(&mut l).await? == 0 {
            return Ok(None);
        }
        Ok(Some(serde_json::from_str(&l)?))
    }

    /// The raw connection, with anything already buffered, for pipes after a `Remote`, `Attach`
    /// or `Shell` reply.
    pub fn into_raw(self) -> (BufReader<BoxRead>, BoxWrite) {
        (self.reader, self.w)
    }
}
