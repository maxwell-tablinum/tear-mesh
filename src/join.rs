//! Joining with a ticket. The owner node prints a one-time ticket; the new machine dials the owner
//! node with it and proves it holds the ticket's secret. Both screens then show the same 6-digit
//! code, and the person approves on the owner node by signing a version that lists the machine.
//! The owner node hands that file to the waiting machine, which adopts it only if it lists the
//! machine and is signed by the owner set the ticket named. A leaked ticket alone gets nobody in.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{EndpointAddr, EndpointId, RelayUrl, TransportAddr};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tracing::{info, warn};

use crate::mesh::SignedMesh;
use crate::node::Node;
use crate::sync::{recv_json, send_json};
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
            .filter(|a| a.is_relay() || a.is_ip())
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

#[derive(Debug)]
struct Invite {
    secret: [u8; 16],
    name: String,
    boundaries: Vec<String>,
    replace: bool,
    expires_ms: u64,
}

#[derive(Debug)]
struct Pending {
    name: String,
    id: EndpointId,
    boundaries: Vec<String>,
    replace: bool,
    code: String,
    expires_ms: u64,
    tx: Option<oneshot::Sender<SignedMesh>>,
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
}

#[derive(Default, Debug)]
pub struct Joins {
    inner: Mutex<Inner>,
}

#[derive(Default, Debug)]
struct Inner {
    invites: Vec<Invite>,
    pending: Vec<Pending>,
    attempts: VecDeque<Instant>,
}

impl Inner {
    fn expire(&mut self) {
        let now = now_ms();
        self.invites.retain(|i| i.expires_ms > now);
        self.pending
            .retain(|p| p.expires_ms > now && p.tx.as_ref().is_some_and(|t| !t.is_closed()));
    }
}

impl Joins {
    /// Whether strangers may open the join protocol right now.
    pub fn open(&self) -> bool {
        let mut i = self.inner.lock().unwrap();
        i.expire();
        !i.invites.is_empty()
    }

    pub fn pending(&self) -> Vec<PendingInfo> {
        let mut i = self.inner.lock().unwrap();
        i.expire();
        i.pending
            .iter()
            .map(|p| PendingInfo {
                name: p.name.clone(),
                node_id: p.id,
                boundaries: p.boundaries.clone(),
                replace: p.replace,
                code: p.code.clone(),
                expires_ms: p.expires_ms,
            })
            .collect()
    }

    /// Hands a newly adopted file to every waiting joiner it lists with the right node id.
    pub fn on_adopt(&self, cur: &SignedMesh) {
        let mut i = self.inner.lock().unwrap();
        i.pending.retain_mut(|p| {
            if cur.mesh.machine(&p.name).is_some_and(|m| m.id == p.id) {
                if let Some(tx) = p.tx.take() {
                    let _ = tx.send(cur.clone());
                }
                info!(machine = %p.name, "approved join");
                false
            } else {
                true
            }
        });
    }
}

impl Node {
    /// A one-time ticket for a new machine `name` hosting `boundaries` (admin, on the owner node).
    pub fn invite(
        &self,
        name: &str,
        boundaries: Vec<String>,
        replace: bool,
        ttl: Duration,
    ) -> Result<String> {
        let mesh = self.mesh()?;
        ensure!(valid_name(name), "bad machine name {name:?}");
        ensure!(
            replace || mesh.machine(name).is_none(),
            "{name} is already in the mesh; pass --replace to give it a new node id"
        );
        ensure!(!boundaries.is_empty(), "name at least one boundary");
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
        self.joins.inner.lock().unwrap().invites.push(Invite {
            secret,
            name: name.into(),
            boundaries,
            replace,
            expires_ms,
        });
        Ok(Ticket {
            mesh: mesh.id.clone(),
            owners: mesh.owner_set_hash()?,
            secret,
            expires: expires_ms / 1000,
            owner_node: self.endpoint.addr(),
        }
        .encode())
    }
}

/// The owner node's side of one join attempt.
pub async fn serve(node: &Arc<Node>, conn: Connection) -> Result<()> {
    let joiner = conn.remote_id();
    let (mut send, mut recv) = conn.accept_bi().await?;
    let r = owner_side(node, &joiner, &mut send, &mut recv).await;
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

async fn owner_side(
    node: &Arc<Node>,
    joiner: &EndpointId,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<()> {
    let Frame::Request {
        mesh,
        name,
        proof: p,
    } = tokio::time::timeout(Duration::from_secs(30), recv_json(recv)).await??
    else {
        bail!("expected a join request")
    };
    let mesh_id = node.mesh()?.id;
    let (rx, code) = {
        let mut i = node.joins.inner.lock().unwrap();
        i.expire();
        // Only failed attempts count against the budget, so strangers can't use it up and
        // block the real joiner, whose proof matches.
        let got = blake3::Hash::from_hex(&p).ok();
        let pos = i.invites.iter().position(|inv| {
            // blake3::Hash compares in constant time.
            mesh == mesh_id && got == Some(proof(&inv.secret, joiner, &node.id()))
        });
        let Some(pos) = pos else {
            ensure!(
                crate::within_budget(&mut i.attempts, ATTEMPTS_PER_HOUR, Instant::now()),
                "too many failed join attempts this hour"
            );
            bail!("no open invite matches this ticket (used, expired, or wrong)");
        };
        // A wrong name doesn't burn the ticket.
        ensure!(
            name == i.invites[pos].name,
            "the ticket is for {}, but this machine is configured as {name}",
            i.invites[pos].name
        );
        let inv = i.invites.remove(pos);
        let (tx, rx) = oneshot::channel();
        let code = code(&inv.secret, joiner, &node.id());
        info!(machine = %inv.name, code = %code, "join request waiting for approval");
        i.pending.push(Pending {
            name: inv.name,
            id: *joiner,
            boundaries: inv.boundaries,
            replace: inv.replace,
            code: code.clone(),
            expires_ms: inv.expires_ms.max(now_ms() + 3_600_000),
            tx: Some(tx),
        });
        (rx, code)
    };
    send_json(send, &Frame::Pending { code }).await?;
    let signed = tokio::time::timeout(Duration::from_secs(3600), rx)
        .await
        .context("not approved within an hour")?
        .context("the request was dropped")?;
    send_json(
        send,
        &Frame::Approved {
            toml: signed.toml,
            sig: signed.sig,
        },
    )
    .await?;
    Ok(())
}

/// The new machine's side: dials the owner node and waits for the code.
pub struct Joining {
    pub code: String,
    ticket: Ticket,
    conn: Connection,
    recv: RecvStream,
    _send: SendStream,
}

pub async fn start(node: &Arc<Node>, ticket: &str) -> Result<Joining> {
    let t = Ticket::decode(ticket)?;
    ensure!(
        node.state().is_err(),
        "this machine already belongs to a mesh (run `tearmesh mesh reset` first to leave it)"
    );
    ensure!(
        t.expires > now_ms() / 1000,
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
                ticket: t,
                conn,
                recv,
                _send: send,
            })
        }
        Frame::Refused { reason } => bail!("refused: {reason}"),
        _ => bail!("unexpected reply from the owner node"),
    }
}

impl Joining {
    /// Waits for approval and adopts the file: it must list this machine and be signed by the
    /// owner set the ticket promised.
    pub async fn finish(mut self, node: &Arc<Node>) -> Result<u64> {
        let frame = tokio::time::timeout(Duration::from_secs(3600), recv_json(&mut self.recv))
            .await
            .context("not approved within an hour")??;
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
        assert_eq!(Ticket::decode(&s).unwrap(), t);
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
