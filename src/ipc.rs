//! The local socket: JSON lines. The kernel reports each caller's uid (SO_PEERCRED); the uid maps to
//! a boundary in the config. Nothing in a request can choose the boundary.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::UnixListener;
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tracing::debug;

use crate::config::DEFAULT_SOCKET;
use crate::node::{MailEvent, Node};
use crate::valid_name;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Picks the mailbox for this connection (default `admin`). `hold: true` marks it as held by a
    /// live session for as long as the connection stays open, so mail doesn't wake another one.
    Hello {
        mailbox: Option<String>,
        #[serde(default)]
        hold: bool,
    },
    Who,
    Post {
        to: Vec<String>,
        subject: String,
        body: String,
        thread: Option<String>,
    },
    Inbox {
        #[serde(default)]
        all: bool,
    },
    Read {
        id: String,
    },
    Notify,
    /// Streams `MailEvent`s for the caller's boundary until the connection closes.
    Subscribe,
    Status,
    ApplyCircle {
        toml: String,
        sig: String,
    },
    Invite,
    Join {
        code: String,
    },
}

/// Longest request line: a 256 KiB body JSON-escaped at worst, plus room.
const MAX_LINE: u64 = 2 << 20;

pub fn socket_path() -> PathBuf {
    std::env::var_os("TEARMESH_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| DEFAULT_SOCKET.into())
}

pub async fn serve(node: Arc<Node>) -> Result<()> {
    let path = node.cfg.socket.clone();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(&path);
    let listener =
        UnixListener::bind(&path).with_context(|| format!("binding {}", path.display()))?;
    // Anyone may connect; the uid the kernel reports decides what they get.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
    let uids = Arc::new(node.cfg.uid_map()?);
    let own = nix::unistd::geteuid().as_raw();
    loop {
        let (stream, _) = listener.accept().await?;
        let (node, uids) = (node.clone(), uids.clone());
        tokio::spawn(async move {
            if let Err(e) = handle(node, stream, &uids, own).await {
                debug!("socket client: {e:#}");
            }
        });
    }
}

async fn handle(
    node: Arc<Node>,
    stream: UnixStream,
    uids: &HashMap<u32, String>,
    own: u32,
) -> Result<()> {
    let uid = stream.peer_cred()?.uid();
    let boundary = uids.get(&uid).cloned();
    let admin = uid == 0 || uid == own;
    let (r, mut w) = stream.into_split();
    if boundary.is_none() && !admin {
        reply(
            &mut w,
            Err(anyhow::anyhow!(
                "OS user {uid} isn't mapped to a boundary on this machine"
            )),
        )
        .await?;
        return Ok(());
    }
    let mut reader = BufReader::new(r);
    let mut mailbox = "admin".to_string();
    let mut _hold = None;
    loop {
        let mut buf = Vec::new();
        if (&mut reader)
            .take(MAX_LINE + 1)
            .read_until(b'\n', &mut buf)
            .await?
            == 0
        {
            break;
        }
        if buf.len() as u64 > MAX_LINE {
            reply(&mut w, Err(anyhow::anyhow!("request too long"))).await?;
            break;
        }
        let line = String::from_utf8_lossy(&buf);
        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                reply(&mut w, Err(anyhow::anyhow!("bad request: {e}"))).await?;
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
                Err(anyhow::anyhow!("admin only (root or the daemon's user)"))
            }
        };
        let res: Result<Value> = match req {
            Request::Hello { mailbox: m, hold } => (|| {
                let b = b()?;
                if let Some(m) = m {
                    anyhow::ensure!(valid_name(&m), "bad mailbox name {m:?}");
                    mailbox = m;
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
            } => b().and_then(|b| {
                Ok(json!({ "id": node.post(&b, &mailbox, to, subject, body, thread)? }))
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
            Request::Subscribe => {
                let b = match b() {
                    Ok(b) => b,
                    Err(e) => {
                        reply(&mut w, Err(e)).await?;
                        continue;
                    }
                };
                let mut rx = node.subscribe();
                reply(&mut w, Ok(json!({ "subscribed": b }))).await?;
                loop {
                    match rx.recv().await {
                        Ok(ev) if ev.boundary == b => {
                            let mut line = serde_json::to_vec(&ev)?;
                            line.push(b'\n');
                            w.write_all(&line).await?;
                        }
                        Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(_) => return Ok(()),
                    }
                }
            }
            Request::Status => need_admin().and_then(|_| Ok(serde_json::to_value(node.status())?)),
            Request::ApplyCircle { toml, sig } => {
                need_admin().and_then(|_| Ok(json!({ "version": node.adopt(&toml, &sig)? })))
            }
            Request::Invite => need_admin().and_then(|_| Ok(json!({ "code": node.invite()? }))),
            Request::Join { code } => {
                need_admin().and_then(|_| Ok(json!({ "version": node.join(&code)? })))
            }
        };
        reply(&mut w, res).await?;
    }
    Ok(())
}

async fn reply(w: &mut OwnedWriteHalf, res: Result<Value>) -> Result<()> {
    let v = match res {
        Ok(data) => json!({ "ok": true, "data": data }),
        Err(e) => json!({ "ok": false, "error": format!("{e:#}") }),
    };
    let mut line = serde_json::to_vec(&v)?;
    line.push(b'\n');
    w.write_all(&line).await?;
    Ok(())
}

/// A connection to the local daemon.
pub struct Client {
    lines: Lines<BufReader<OwnedReadHalf>>,
    w: OwnedWriteHalf,
}

impl Client {
    pub async fn connect(path: &Path) -> Result<Client> {
        let s = UnixStream::connect(path)
            .await
            .with_context(|| format!("connecting to the tear-mesh daemon at {}", path.display()))?;
        let (r, w) = s.into_split();
        Ok(Client {
            lines: BufReader::new(r).lines(),
            w,
        })
    }

    /// Connects and says hello with the mailbox from `TEARMESH_MAILBOX` (or `admin`).
    pub async fn session(hold: bool) -> Result<(Client, String)> {
        let mut c = Client::connect(&socket_path()).await?;
        let mailbox = std::env::var("TEARMESH_MAILBOX").ok();
        let v = c.call(&Request::Hello { mailbox, hold }).await?;
        let addr = v["address"].as_str().unwrap_or_default().to_string();
        Ok((c, addr))
    }

    pub async fn call(&mut self, req: &Request) -> Result<Value> {
        let mut line = serde_json::to_vec(req)?;
        line.push(b'\n');
        self.w.write_all(&line).await?;
        let resp = self
            .lines
            .next_line()
            .await?
            .context("daemon closed the connection")?;
        let v: Value = serde_json::from_str(&resp)?;
        if v["ok"].as_bool() == Some(true) {
            Ok(v["data"].clone())
        } else {
            bail!("{}", v["error"].as_str().unwrap_or("unknown error"))
        }
    }

    pub async fn next_event(&mut self) -> Result<Option<MailEvent>> {
        match self.lines.next_line().await? {
            Some(l) => Ok(Some(serde_json::from_str(&l)?)),
            None => Ok(None),
        }
    }
}
