//! Joining with a ticket. The owner node prints a one-time ticket; the new machine dials the owner
//! node with it and proves it holds the ticket's secret. Both screens then show the same 6-digit
//! code, and the person approves on the owner node by signing a version that lists the machine.
//! The owner node hands that file to the waiting machine, which adopts it only if it lists the
//! machine and is signed by the owner set the ticket named. A leaked ticket alone gets nobody in.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{EndpointAddr, EndpointId, RelayUrl, TransportAddr};
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, watch};
use tracing::{info, warn};

use crate::mesh::{Change, Grant, Machine, Mesh, SignedMesh};
use crate::node::Node;
use crate::sync::{recv_json, recv_json_max, send_json};
use crate::{now_ms, valid_name};

pub const ALPN: &[u8] = b"tear-mesh/join/1";
const PREFIX: &str = "tm2-";
/// Join attempts accepted per hour, across all invites.
const ATTEMPTS_PER_HOUR: u32 = 30;

/// What a ticket carries. Built at the moment it's printed, from the current addresses.
#[derive(Clone, Debug, PartialEq)]
pub struct Ticket {
    pub mesh: String,
    /// `Mesh::owner_set_hash` of the file the joiner will be handed.
    pub owners: [u8; 16],
    pub secret: [u8; 16],
    /// Unix seconds.
    pub expires: u64,
    pub owner_node: EndpointAddr,
}

impl Ticket {
    pub fn encode(&self) -> String {
        let mut b = vec![2u8, self.mesh.len() as u8];
        b.extend_from_slice(self.mesh.as_bytes());
        b.extend_from_slice(&self.owners);
        b.extend_from_slice(&self.secret);
        b.extend_from_slice(&self.expires.to_be_bytes());
        b.extend_from_slice(self.owner_node.id.as_bytes());
        let addrs: Vec<&TransportAddr> = self
            .owner_node
            .addrs
            .iter()
            // Link-local addresses lose their scope id here, so they never worked.
            .filter(|a| match a {
                TransportAddr::Ip(SocketAddr::V6(v6)) => !v6.ip().is_unicast_link_local(),
                a => a.is_relay() || a.is_ip(),
            })
            .take(8)
            .collect();
        b.push(addrs.len() as u8);
        for a in addrs {
            match a {
                TransportAddr::Relay(u) => {
                    let s = u.to_string();
                    b.push(0);
                    b.push(s.len().min(255) as u8);
                    b.extend_from_slice(&s.as_bytes()[..s.len().min(255)]);
                }
                TransportAddr::Ip(SocketAddr::V4(v4)) => {
                    b.push(4);
                    b.extend_from_slice(&v4.ip().octets());
                    b.extend_from_slice(&v4.port().to_be_bytes());
                }
                TransportAddr::Ip(SocketAddr::V6(v6)) => {
                    b.push(6);
                    b.extend_from_slice(&v6.ip().octets());
                    b.extend_from_slice(&v6.port().to_be_bytes());
                }
                _ => unreachable!("filtered above"),
            }
        }
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(b))
    }

    pub fn decode(s: &str) -> Result<Ticket> {
        let raw = s
            .trim()
            .strip_prefix(PREFIX)
            .context("not a tear-mesh ticket (they start with tm2-)")?;
        let b = URL_SAFE_NO_PAD.decode(raw).context("ticket encoding")?;
        let mut r = Reader(&b);
        ensure!(r.u8()? == 2, "unknown ticket version");
        let n = r.u8()? as usize;
        let mesh = String::from_utf8(r.take(n)?.to_vec()).context("mesh id")?;
        let owners = r.take(16)?.try_into().expect("16");
        let secret = r.take(16)?.try_into().expect("16");
        let expires = u64::from_be_bytes(r.take(8)?.try_into().expect("8"));
        let id_bytes: [u8; 32] = r.take(32)?.try_into().expect("32");
        let id = EndpointId::from_bytes(&id_bytes).context("owner node id")?;
        let mut addrs = vec![];
        for _ in 0..r.u8()? {
            addrs.push(match r.u8()? {
                0 => {
                    let n = r.u8()? as usize;
                    let u: RelayUrl = std::str::from_utf8(r.take(n)?)?.parse()?;
                    TransportAddr::Relay(u)
                }
                4 => {
                    let ip: [u8; 4] = r.take(4)?.try_into().expect("4");
                    let port = u16::from_be_bytes(r.take(2)?.try_into().expect("2"));
                    TransportAddr::Ip(SocketAddr::from((ip, port)))
                }
                6 => {
                    let ip: [u8; 16] = r.take(16)?.try_into().expect("16");
                    let port = u16::from_be_bytes(r.take(2)?.try_into().expect("2"));
                    TransportAddr::Ip(SocketAddr::from((ip, port)))
                }
                t => bail!("unknown address type {t} in ticket"),
            });
        }
        ensure!(r.0.is_empty(), "trailing bytes in ticket");
        Ok(Ticket {
            mesh,
            owners,
            secret,
            expires,
            owner_node: EndpointAddr::from_parts(id, addrs),
        })
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(self.0.len() >= n, "ticket is truncated");
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
}

fn key(secret: &[u8; 16]) -> [u8; 32] {
    blake3::derive_key("tear-mesh join v1", secret)
}

/// Proof that the joiner holds the ticket, bound to both node ids so it can't be replayed by
/// another machine or against another owner node.
fn proof(secret: &[u8; 16], joiner: &EndpointId, owner: &EndpointId) -> blake3::Hash {
    let mut h = blake3::Hasher::new_keyed(&key(secret));
    h.update(b"proof");
    h.update(joiner.as_bytes());
    h.update(owner.as_bytes());
    h.finalize()
}

/// The 6-digit code both screens show.
pub fn code(secret: &[u8; 16], joiner: &EndpointId, owner: &EndpointId) -> String {
    let mut h = blake3::Hasher::new_keyed(&key(secret));
    h.update(b"code");
    h.update(owner.as_bytes());
    h.update(joiner.as_bytes());
    let n = u32::from_be_bytes(h.finalize().as_bytes()[..4].try_into().expect("4"));
    format!("{:06}", n % 1_000_000)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "t", rename_all = "snake_case")]
enum Frame {
    Request {
        mesh: String,
        name: String,
        /// The boundaries the joiner's config maps users to; the owner decides what to admit.
        boundaries: Vec<String>,
        proof: String,
    },
    Pending {
        code: String,
    },
    Approved {
        toml: String,
        sig: String,
    },
    Refused {
        reason: String,
    },
}

/// A join request from a stranger is small; anything bigger is refused unread.
const MAX_REQUEST: usize = 4096;
const MAX_BOUNDARIES: usize = 16;
/// How long a claimed ticket waits for approval at least.
const WAIT_MS: u64 = 3_600_000;

#[derive(Serialize, Deserialize, Debug)]
struct Invite {
    secret: [u8; 16],
    /// Pinned by the owner; None lets the new machine propose its name.
    name: Option<String>,
    /// Pinned by the owner; empty lets the new machine propose.
    boundaries: Vec<String>,
    replace: bool,
    expires_ms: u64,
    /// The node that proved this ticket first. Only it may use the ticket from then on.
    claim: Option<Claim>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Claim {
    id: EndpointId,
    name: String,
    boundaries: Vec<String>,
    code: String,
    /// Another node proved this ticket after it was claimed: it leaked.
    #[serde(default)]
    contested: bool,
    /// Approved while the joiner was away; it gets the file when it comes back.
    #[serde(default)]
    approved: bool,
    #[serde(skip)]
    tx: Option<oneshot::Sender<Result<SignedMesh, String>>>,
}

/// A join waiting for the person to approve it, as `mesh pending` shows it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PendingInfo {
    pub name: String,
    pub node_id: EndpointId,
    pub boundaries: Vec<String>,
    pub replace: bool,
    pub code: String,
    pub expires_ms: u64,
    /// The new machine is connected and waiting (not away).
    #[serde(default)]
    pub waiting: bool,
    /// Another machine also tried this ticket: read the code off the right machine's own screen.
    #[serde(default)]
    pub contested: bool,
}

impl PendingInfo {
    /// Approval as one version: `add` boundaries (only ones the machine asked for), the machine
    /// hosting what it asked for that the mesh then has, then `grants`.
    pub fn changes(&self, mesh: &Mesh, add: &[String], grants: &[Grant]) -> Result<Vec<Change>> {
        let mut out = vec![];
        for b in add {
            ensure!(self.boundaries.contains(b), "{} didn't ask to host {b}", self.name);
            if !mesh.boundaries.contains(b) {
                out.push(Change::AddBoundary(b.clone()));
            }
        }
        let hosts: Vec<String> = self
            .boundaries
            .iter()
            .filter(|b| mesh.boundaries.contains(b) || add.contains(b))
            .cloned()
            .collect();
        ensure!(
            !hosts.is_empty(),
            "{} would host no boundary the mesh has; add one of {}",
            self.name,
            self.boundaries.join(", ")
        );
        out.push(Change::AddMachine {
            machine: Machine {
                name: self.name.clone(),
                id: self.node_id,
                boundaries: hosts,
            },
            replace: self.replace,
        });
        out.extend(grants.iter().cloned().map(Change::Grant));
        Ok(out)
    }
}

/// This machine's own join, as `status` shows it. It runs in the daemon, with or without a client.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum JoinProgress {
    Dialing,
    Waiting { code: String },
    Joined { version: u64 },
    Failed { reason: String },
}

#[derive(Debug)]
struct Mine {
    ticket: String,
    task: tokio::task::AbortHandle,
    progress: watch::Sender<JoinProgress>,
}

#[derive(Default, Debug)]
pub struct Joins {
    inner: Mutex<Inner>,
    /// Where open invites are kept, so a daemon restart doesn't void them.
    path: Option<PathBuf>,
    mine: Mutex<Option<Mine>>,
}

#[derive(Default, Debug)]
struct Inner {
    invites: Vec<Invite>,
    attempts: VecDeque<Instant>,
}

impl Inner {
    fn expire(&mut self) {
        let now = now_ms();
        self.invites.retain(|i| i.expires_ms > now);
    }
}

impl Joins {
    /// Open invites from `dir/invites.json`. A broken file starts empty, with a warning.
    pub fn load(dir: &Path) -> Joins {
        let path = dir.join("invites.json");
        let invites = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                warn!("{}: {e}; starting with no open invites", path.display());
                vec![]
            }),
            Err(_) => vec![],
        };
        let mut inner = Inner { invites, ..Default::default() };
        inner.expire();
        Joins {
            inner: Mutex::new(inner),
            path: Some(path),
            mine: Mutex::new(None),
        }
    }

    fn save(&self, i: &Inner) -> Result<()> {
        if let Some(p) = &self.path {
            crate::os::write_private(p, &serde_json::to_vec(&i.invites)?)?;
        }
        Ok(())
    }

    fn save_or_warn(&self, i: &Inner) {
        if let Err(e) = self.save(i) {
            warn!("saving open invites: {e:#}");
        }
    }

    /// Whether strangers may open the join protocol right now.
    pub fn open(&self) -> bool {
        let mut i = self.inner.lock().unwrap();
        i.expire();
        !i.invites.is_empty()
    }

    pub fn pending(&self) -> Vec<PendingInfo> {
        let mut i = self.inner.lock().unwrap();
        i.expire();
        i.invites
            .iter()
            .filter_map(|inv| {
                let c = inv.claim.as_ref().filter(|c| !c.approved)?;
                Some(PendingInfo {
                    name: c.name.clone(),
                    node_id: c.id,
                    boundaries: c.boundaries.clone(),
                    replace: inv.replace,
                    code: c.code.clone(),
                    expires_ms: inv.expires_ms,
                    waiting: c.tx.as_ref().is_some_and(|t| !t.is_closed()),
                    contested: c.contested,
                })
            })
            .collect()
    }

    /// Hands a newly adopted file to every waiting joiner it lists by node id. One that is away
    /// gets it when it comes back with the same ticket.
    pub fn on_adopt(&self, cur: &SignedMesh) {
        let mut i = self.inner.lock().unwrap();
        let mut changed = false;
        i.invites.retain_mut(|inv| {
            let Some(c) = inv.claim.as_mut().filter(|c| cur.mesh.machine_by_id(&c.id).is_some()) else {
                return true;
            };
            info!(machine = %c.name, "approved join");
            changed = true;
            let sent = c.tx.take().is_some_and(|tx| tx.send(Ok(cur.clone())).is_ok());
            c.approved = !sent;
            !sent
        });
        if changed {
            self.save_or_warn(&i);
        }
    }

    /// Refuses the waiting request from `name`, or closes every open invite. Returns how many.
    pub fn reject(&self, name: Option<&str>) -> Result<usize> {
        let mut i = self.inner.lock().unwrap();
        i.expire();
        let before = i.invites.len();
        let mut out = vec![];
        i.invites.retain_mut(|inv| {
            let hit = match name {
                None => true,
                Some(n) => inv.claim.as_ref().is_some_and(|c| c.name == n && !c.approved),
            };
            if hit && let Some(tx) = inv.claim.as_mut().and_then(|c| c.tx.take()) {
                out.push(tx);
            }
            !hit
        });
        let n = before - i.invites.len();
        if let Some(name) = name {
            ensure!(n > 0, "no join request from {name} is waiting");
        }
        self.save(&i)?;
        for tx in out {
            let _ = tx.send(Err("the owner refused this machine".into()));
        }
        Ok(n)
    }

    /// This machine's own join, if one ran since the daemon started.
    pub fn progress(&self) -> Option<JoinProgress> {
        self.mine.lock().unwrap().as_ref().map(|m| m.progress.borrow().clone())
    }
}

/// Checks a joiner's untrusted proposal against an invite. Returns the name and boundaries.
fn admit(inv: &Invite, name: &str, boundaries: &[String]) -> Result<(String, Vec<String>)> {
    ensure!(valid_name(name), "bad machine name {name:?}");
    ensure!(boundaries.len() <= MAX_BOUNDARIES, "too many boundaries");
    let mut seen = std::collections::BTreeSet::new();
    for b in boundaries {
        ensure!(valid_name(b), "bad boundary name {b:?}");
        ensure!(seen.insert(b), "boundary {b} listed twice");
    }
    if let Some(n) = &inv.name {
        ensure!(n == name, "the ticket is for {n}, but this machine is configured as {name}");
    }
    let b = if inv.boundaries.is_empty() {
        boundaries.to_vec()
    } else {
        let pin: std::collections::BTreeSet<_> = inv.boundaries.iter().collect();
        ensure!(
            boundaries.is_empty() || pin == seen,
            "the ticket is for boundaries {}, but this machine's config maps {}",
            inv.boundaries.join(", "),
            boundaries.join(", ")
        );
        inv.boundaries.clone()
    };
    ensure!(
        !b.is_empty(),
        "this machine's config maps no OS users to boundaries ([users]); add them and restart the daemon, or ask for a ticket that names them"
    );
    Ok((name.to_string(), b))
}

impl Node {
    /// A one-time ticket for a new machine (admin, on the owner node). With no `name`, the new
    /// machine proposes its own name and boundaries, and the person approves what they see.
    pub fn invite(
        &self,
        name: Option<&str>,
        boundaries: Vec<String>,
        replace: bool,
        ttl: Duration,
    ) -> Result<String> {
        let mesh = self.mesh()?;
        match name {
            Some(n) => {
                ensure!(valid_name(n), "bad machine name {n:?}");
                ensure!(
                    replace || mesh.machine(n).is_none(),
                    "{n} is already in the mesh; pass --replace to give it a new node id"
                );
            }
            None => ensure!(!replace, "--replace needs a name: it gives that machine a new node id"),
        }
        let mut boundaries = boundaries;
        boundaries.sort();
        boundaries.dedup();
        for b in &boundaries {
            ensure!(mesh.boundaries.contains(b), "the mesh has no boundary {b}");
        }
        ensure!(
            ttl <= Duration::from_secs(7 * 24 * 3600),
            "tickets last at most 7 days"
        );
        let mut secret = [0u8; 16];
        getrandom::fill(&mut secret).map_err(|e| anyhow::anyhow!("random: {e}"))?;
        let expires_ms = now_ms() + ttl.as_millis() as u64;
        let mut i = self.joins.inner.lock().unwrap();
        i.invites.push(Invite {
            secret,
            name: name.map(String::from),
            boundaries,
            replace,
            expires_ms,
            claim: None,
        });
        self.joins.save(&i)?;
        Ok(Ticket {
            mesh: mesh.id.clone(),
            owners: mesh.owner_set_hash()?,
            secret,
            expires: expires_ms / 1000,
            owner_node: self.endpoint.addr(),
        }
        .encode())
    }

    /// Joins with `ticket` in the background. The same ticket again (a client that came back)
    /// follows the join already running; another one replaces it.
    pub fn join(self: &Arc<Self>, ticket: &str) -> Result<watch::Receiver<JoinProgress>> {
        let ticket = ticket.trim().to_string();
        let t = Ticket::decode(&ticket)?;
        let mut mine = self.joins.mine.lock().unwrap();
        if let Some(m) = mine.as_ref()
            && m.ticket == ticket
            && !m.task.is_finished()
        {
            return Ok(m.progress.subscribe());
        }
        check(self, &t)?;
        if let Some(m) = mine.take() {
            m.task.abort();
        }
        let (tx, rx) = watch::channel(JoinProgress::Dialing);
        let (node, progress) = (self.clone(), tx.clone());
        let task = tokio::spawn(async move {
            let r = async {
                let j = dial(&node, t).await?;
                if !j.code.is_empty() {
                    progress.send_replace(JoinProgress::Waiting { code: j.code.clone() });
                }
                j.finish(&node).await
            }
            .await;
            progress.send_replace(match r {
                Ok(version) => JoinProgress::Joined { version },
                Err(e) => JoinProgress::Failed { reason: format!("{e:#}") },
            });
        });
        *mine = Some(Mine {
            ticket,
            task: task.abort_handle(),
            progress: tx,
        });
        Ok(rx)
    }

    /// Refuses the waiting request from `name`, or closes every open invite.
    pub fn reject_join(&self, name: Option<&str>) -> Result<usize> {
        self.joins.reject(name)
    }

    /// Stops this machine's join, if one is running. The owner then sees it as away.
    pub fn cancel_join(&self) -> bool {
        let mine = self.joins.mine.lock().unwrap();
        match mine.as_ref() {
            Some(m) if !m.task.is_finished() => {
                m.task.abort();
                m.progress.send_replace(JoinProgress::Failed { reason: "cancelled".into() });
                true
            }
            _ => false,
        }
    }
}

/// The owner node's side of one join attempt.
pub async fn serve(node: &Arc<Node>, conn: Connection) -> Result<()> {
    let joiner = conn.remote_id();
    let (mut send, mut recv) = conn.accept_bi().await?;
    let r = owner_side(node, &conn, &joiner, &mut send, &mut recv).await;
    if let Err(e) = &r {
        warn!("join attempt from {}: {e:#}", joiner.fmt_short());
        let _ = send_json(
            &mut send,
            &Frame::Refused {
                reason: format!("{e:#}"),
            },
        )
        .await;
    }
    let _ = send.finish();
    let _ = tokio::time::timeout(Duration::from_secs(10), conn.closed()).await;
    r
}

enum Answer {
    /// Approved while away: here is the file.
    Approved(SignedMesh),
    Wait(String, oneshot::Receiver<Result<SignedMesh, String>>, u64),
}

async fn owner_side(
    node: &Arc<Node>,
    conn: &Connection,
    joiner: &EndpointId,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<()> {
    let Frame::Request {
        mesh,
        name,
        boundaries,
        proof: p,
    } = tokio::time::timeout(Duration::from_secs(30), recv_json_max(recv, MAX_REQUEST)).await??
    else {
        bail!("expected a join request")
    };
    let cur = node.signed()?;
    let answer = claim(node, &cur, joiner, &mesh, &name, &boundaries, &p)?;
    let (code, rx, deadline) = match answer {
        Answer::Approved(s) => {
            send_json(send, &Frame::Approved { toml: s.toml, sig: s.sig }).await?;
            return Ok(());
        }
        Answer::Wait(c, rx, d) => (c, rx, d),
    };
    send_json(send, &Frame::Pending { code }).await?;
    let wait = Duration::from_millis(deadline.saturating_sub(now_ms()));
    tokio::select! {
        r = rx => match r {
            Ok(Ok(s)) => send_json(send, &Frame::Approved { toml: s.toml, sig: s.sig }).await?,
            Ok(Err(reason)) => send_json(send, &Frame::Refused { reason }).await?,
            // Replaced by the same machine's newer attempt.
            Err(_) => {}
        },
        // The joiner left; its claim stays, and it can come back with the same ticket.
        _ = conn.closed() => {}
        _ = tokio::time::sleep(wait) => bail!("not approved in time"),
    }
    Ok(())
}

/// Matches a proof to an open invite and records (or renews) the joiner's claim on it.
fn claim(
    node: &Node,
    cur: &SignedMesh,
    joiner: &EndpointId,
    mesh: &str,
    name: &str,
    boundaries: &[String],
    p: &str,
) -> Result<Answer> {
    let mut i = node.joins.inner.lock().unwrap();
    i.expire();
    // Only failed attempts count against the budget, so strangers can't use it up and
    // block the real joiner, whose proof matches.
    let got = blake3::Hash::from_hex(p).ok();
    let pos = i.invites.iter().position(|inv| {
        // blake3::Hash compares in constant time.
        mesh == cur.mesh.id && got == Some(proof(&inv.secret, joiner, &node.id()))
    });
    let Some(pos) = pos else {
        ensure!(
            crate::within_budget(&mut i.attempts, ATTEMPTS_PER_HOUR, Instant::now()),
            "too many failed join attempts this hour"
        );
        bail!("no open invite matches this ticket (used, expired, or wrong)");
    };
    if let Some(c) = i.invites[pos].claim.as_mut()
        && c.id != *joiner
    {
        c.contested = true;
        let other = c.id.fmt_short().to_string();
        node.joins.save_or_warn(&i);
        ensure!(
            crate::within_budget(&mut i.attempts, ATTEMPTS_PER_HOUR, Instant::now()),
            "too many failed join attempts this hour"
        );
        bail!("this ticket was already used by another machine (node {other}). Tell the owner to refuse that request");
    }
    if let Some(m) = cur.mesh.machine_by_id(joiner) {
        ensure!(
            i.invites[pos].claim.is_some(),
            "this node is already in the mesh as {}",
            m.name
        );
        i.invites.remove(pos);
        node.joins.save_or_warn(&i);
        return Ok(Answer::Approved(cur.clone()));
    }
    let (name, boundaries) = admit(&i.invites[pos], name, boundaries)?;
    ensure!(
        i.invites[pos].replace || cur.mesh.machine(&name).is_none(),
        "a machine named {name} is already in the mesh; change `machine` in this machine's config and restart the daemon, or ask for a ticket made with `mesh invite {name} --replace`"
    );
    ensure!(
        !i.invites.iter().enumerate().any(|(n, inv)| n != pos
            && inv.claim.as_ref().is_some_and(|c| c.name == name && !c.approved)),
        "another machine named {name} is already waiting for approval"
    );
    let code = code(&i.invites[pos].secret, joiner, &node.id());
    let (tx, rx) = oneshot::channel();
    let inv = &mut i.invites[pos];
    let contested = inv.claim.as_ref().is_some_and(|c| c.contested);
    if inv.claim.is_none() {
        inv.expires_ms = inv.expires_ms.max(now_ms() + WAIT_MS);
    }
    inv.claim = Some(Claim {
        id: *joiner,
        name: name.clone(),
        boundaries,
        code: code.clone(),
        contested,
        approved: false,
        tx: Some(tx),
    });
    let deadline = inv.expires_ms;
    info!(machine = %name, code = %code, "join request waiting for approval");
    node.joins.save_or_warn(&i);
    Ok(Answer::Wait(code, rx, deadline))
}

/// The new machine's side: dials the owner node and waits for the code.
pub struct Joining {
    /// Empty when the owner approved this machine while it was away: the file came at once.
    pub code: String,
    early: Option<Frame>,
    ticket: Ticket,
    conn: Connection,
    recv: RecvStream,
    _send: SendStream,
}

pub async fn start(node: &Arc<Node>, ticket: &str) -> Result<Joining> {
    let t = Ticket::decode(ticket)?;
    check(node, &t)?;
    dial(node, t).await
}

/// What this machine can check about a ticket before dialing.
fn check(node: &Node, t: &Ticket) -> Result<()> {
    ensure!(
        node.state().is_err(),
        "this machine already belongs to a mesh (run `tearmesh mesh reset` first to leave it)"
    );
    // An hour's grace: a machine that proved in time may come back for an approval.
    ensure!(
        t.expires + 3600 > now_ms() / 1000,
        "the ticket has expired; ask for a new one"
    );
    if let Ok(old) = std::fs::read_to_string(node.cfg.state_dir.join("mesh-id")) {
        ensure!(
            old.trim() == t.mesh,
            "this machine was reset from mesh {}, and the ticket is for {}",
            old.trim(),
            t.mesh
        );
    }
    Ok(())
}

async fn dial(node: &Arc<Node>, t: Ticket) -> Result<Joining> {
    let owner = t.owner_node.id;
    node.learn_ticket_addr(t.owner_node.clone());
    let conn = tokio::time::timeout(
        Duration::from_secs(30),
        node.endpoint.connect(t.owner_node.clone(), ALPN),
    )
    .await
    .map_err(|_| anyhow::anyhow!("owner node {} not reachable", owner.fmt_short()))?
    .with_context(|| format!("owner node {} not reachable", owner.fmt_short()))?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send_json(
        &mut send,
        &Frame::Request {
            mesh: t.mesh.clone(),
            name: node.cfg.machine.clone(),
            boundaries: {
                let mut b: Vec<String> = node.cfg.users.values().cloned().collect();
                b.sort();
                b.dedup();
                b
            },
            proof: proof(&t.secret, &node.id(), &owner).to_hex().to_string(),
        },
    )
    .await?;
    match tokio::time::timeout(Duration::from_secs(30), recv_json(&mut recv)).await?? {
        Frame::Pending { code: c } => {
            ensure!(
                c == code(&t.secret, &node.id(), &owner),
                "the owner node showed a different code; don't approve"
            );
            Ok(Joining {
                code: c,
                early: None,
                ticket: t,
                conn,
                recv,
                _send: send,
            })
        }
        f @ Frame::Approved { .. } => Ok(Joining {
            code: String::new(),
            early: Some(f),
            ticket: t,
            conn,
            recv,
            _send: send,
        }),
        Frame::Refused { reason } => bail!("refused: {reason}"),
        _ => bail!("unexpected reply from the owner node"),
    }
}

impl Joining {
    /// Waits for approval and adopts the file: it must list this machine and be signed by the
    /// owner set the ticket promised.
    pub async fn finish(mut self, node: &Arc<Node>) -> Result<u64> {
        let frame = match self.early.take() {
            Some(f) => f,
            None => tokio::time::timeout(Duration::from_secs(3600), recv_json(&mut self.recv))
                .await
                .context("not approved within an hour")??,
        };
        let r = match frame {
            Frame::Approved { toml, sig } => {
                let s = SignedMesh::verify_first(&toml, &sig)?;
                ensure!(
                    s.mesh.id == self.ticket.mesh,
                    "the file is for another mesh"
                );
                ensure!(
                    s.mesh.owner_set_hash()? == self.ticket.owners,
                    "the file's owner keys aren't the ones the ticket named"
                );
                let v = node.adopt_first(&toml, &sig)?;
                node.learn_addr(self.ticket.owner_node.clone());
                Ok(v)
            }
            Frame::Refused { reason } => Err(anyhow::anyhow!("refused: {reason}")),
            _ => Err(anyhow::anyhow!("unexpected reply from the owner node")),
        };
        self.conn.close(0u32.into(), b"done");
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_round_trip_and_codes() {
        let owner = iroh::SecretKey::generate().public();
        let joiner = iroh::SecretKey::generate().public();
        let t = Ticket {
            mesh: "9f3c".repeat(8),
            owners: [7; 16],
            secret: [9; 16],
            expires: 1_900_000_000,
            owner_node: EndpointAddr::new(owner)
                .with_relay_url("https://relay.example.com./".parse().unwrap())
                .with_ip_addr("192.168.1.5:7777".parse().unwrap())
                .with_ip_addr("[fe80::1]:7777".parse().unwrap()),
        };
        let s = t.encode();
        assert!(s.len() < 250, "{} chars", s.len());
        let mut want = t.clone();
        want.owner_node = EndpointAddr::new(owner)
            .with_relay_url("https://relay.example.com./".parse().unwrap())
            .with_ip_addr("192.168.1.5:7777".parse().unwrap());
        assert_eq!(Ticket::decode(&s).unwrap(), want, "link-local addresses are left out");
        assert!(Ticket::decode(&s[..s.len() - 4]).is_err(), "truncated");
        assert!(Ticket::decode("tm1-abc").is_err());

        let c = code(&t.secret, &joiner, &owner);
        assert_eq!(c.len(), 6);
        assert_ne!(
            c,
            code(&[8; 16], &joiner, &owner),
            "another ticket, another code"
        );
        assert_ne!(
            proof(&t.secret, &joiner, &owner),
            proof(&t.secret, &owner, &joiner),
            "proof is bound to who is joining whom"
        );
    }
}
