//! Reachability for the map: a member dials another on `tear-mesh/ping/1`, sends one byte and
//! gets it back. Only members are admitted, so a reply also proves the peer still counts this
//! machine as one.
//!
//! The byte `L` also says "I'm leaving": the peer marks this machine as leaving in its status,
//! so the owner node can remove it, and answers `l`. An older daemon echoes `L` and marks
//! nothing, so only `l` counts as told; any answer still counts as a ping.
//!
//! The byte `V` asks for the version: from 0.5.0 on the answer is `v` and the version text,
//! up to 32 bytes; an older daemon echoes `V`. Any other byte is echoed, as 0.4.0 sends `7`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use iroh::EndpointId;
use iroh::endpoint::Connection;
use serde::{Deserialize, Serialize};

use crate::node::{Node, Reach};

pub const ALPN: &[u8] = b"tear-mesh/ping/1";
const DIAL: Duration = Duration::from_secs(6);
/// How long `reach` waits for each machine: a session wants an answer within seconds.
const REACH: Duration = Duration::from_secs(4);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Ping {
    pub name: String,
    pub node_id: String,
    /// Round trip of the echo once connected; None when the machine didn't answer.
    pub rtt_ms: Option<u64>,
    /// How long dialing took (hole punching, relays).
    pub dial_ms: Option<u64>,
    /// The machine's tear-mesh version; None from a daemon older than 0.5.0 or one that didn't answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

const LEAVE: u8 = b'L';
/// The answer to `LEAVE` once marked.
const MARKED: u8 = b'l';
const VERSION: u8 = b'V';
/// The answer to `VERSION`, followed by the version text.
const VERSIONED: u8 = b'v';
const MAX_VERSION: usize = 32;

/// The version another machine sent after `v`, if it looks like one: 1 to 32 of `[0-9A-Za-z.+-]`.
fn version_of(back: u8, rest: &[u8]) -> Option<String> {
    let ok = back == VERSIONED
        && (1..=MAX_VERSION).contains(&rest.len())
        && rest.iter().all(|c| c.is_ascii_alphanumeric() || b".-+".contains(c));
    ok.then(|| String::from_utf8_lossy(rest).into_owned())
}

pub async fn serve(node: &Arc<Node>, conn: Connection) -> Result<()> {
    let (mut send, mut recv) = tokio::time::timeout(DIAL, conn.accept_bi()).await??;
    let mut b = [0u8; 1];
    tokio::time::timeout(DIAL, recv.read_exact(&mut b)).await??;
    // The handshake admitted a member, and the id is the connection's own.
    if b[0] == LEAVE && node.mark_leaving(&conn.remote_id()) {
        b[0] = MARKED;
    }
    if b[0] == VERSION {
        let v = env!("CARGO_PKG_VERSION").as_bytes();
        send.write_all(&[VERSIONED]).await?;
        send.write_all(&v[..v.len().min(MAX_VERSION)]).await?;
    } else {
        send.write_all(&b).await?;
    }
    send.finish()?;
    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
    Ok(())
}

/// Round trip, dial time, the byte that came back and the version sent after a `v`.
async fn one(node: &Arc<Node>, id: EndpointId, byte: u8) -> Result<(u64, u64, u8, Option<String>)> {
    let start = Instant::now();
    let conn = tokio::time::timeout(DIAL, node.endpoint.connect(id, ALPN))
        .await
        .context("no answer")??;
    let dial = start.elapsed().as_millis() as u64;
    let echo = async {
        let t = Instant::now();
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(&[byte]).await?;
        send.finish()?;
        let mut b = [0u8; 1];
        recv.read_exact(&mut b).await?;
        let rtt = t.elapsed().as_millis() as u64;
        // Every daemon finishes the stream after its answer, so this ends at once.
        // One byte more than a version may have: a longer answer is refused, not cut short.
        let (mut v, mut n) = ([0u8; MAX_VERSION + 1], 0);
        while n < v.len() {
            match recv.read(&mut v[n..]).await? {
                Some(k) => n += k,
                None => break,
            }
        }
        anyhow::Ok((rtt, b[0], version_of(b[0], &v[..n])))
    };
    let r = tokio::time::timeout(DIAL, echo).await.context("no echo");
    conn.close(0u32.into(), b"done");
    let (rtt, back, version) = r??;
    Ok((rtt, dial, back, version))
}

/// Pings every other machine in the membership file at once.
pub async fn all(node: &Arc<Node>) -> Result<Vec<Ping>> {
    Ok(round(node, VERSION).await?.into_iter().map(|p| p.0).collect())
}

/// For sessions: one ping to each named machine of `boundary` (every machine hosting it when
/// none are named), all at once, each given 4 s. Machines outside the boundary can't be named.
pub async fn reach(node: &Arc<Node>, boundary: &str, names: Vec<String>) -> Result<Vec<Reach>> {
    let mesh = node.mesh()?;
    let mut names = names;
    let mut seen = std::collections::HashSet::new();
    names.retain(|n| seen.insert(n.clone())); // one ping per name
    let hosts: Vec<_> = mesh.machines.iter().filter(|m| m.boundaries.iter().any(|b| b == boundary)).collect();
    let picked = if names.is_empty() {
        hosts.clone()
    } else {
        let list = || hosts.iter().map(|m| m.name.as_str()).collect::<Vec<_>>().join(", ");
        names
            .iter()
            .map(|n| {
                hosts
                    .iter()
                    .find(|m| m.name == *n)
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("no node {n:?} in this boundary; nodes: {}", list()))
            })
            .collect::<Result<_>>()?
    };
    let tasks: Vec<_> = picked
        .into_iter()
        .map(|m| {
            let (n, name, id) = (node.clone(), m.name.clone(), m.id);
            let here = name == node.cfg.machine;
            tokio::spawn(async move {
                let start = Instant::now();
                let ok = here || matches!(tokio::time::timeout(REACH, one(&n, id, 7)).await, Ok(Ok(_)));
                if ok && !here {
                    n.saw(&id);
                }
                let rtt_ms = (ok && !here).then(|| start.elapsed().as_millis() as u64);
                Reach { name, online: ok, rtt_ms }
            })
        })
        .collect();
    let mut out = vec![];
    for t in tasks {
        out.push(t.await?);
    }
    Ok(out)
}

/// Tells every other machine this one is leaving (members can't tell which is the owner node).
/// Returns the names that answered.
pub async fn leave(node: &Arc<Node>) -> Result<Vec<String>> {
    Ok(round(node, LEAVE).await?.into_iter().filter(|p| p.1 == Some(MARKED)).map(|p| p.0.name).collect())
}

/// Each ping, with the byte that came back.
async fn round(node: &Arc<Node>, byte: u8) -> Result<Vec<(Ping, Option<u8>)>> {
    let mesh = node.mesh()?;
    let me = node.cfg.machine.clone();
    let tasks: Vec<_> = mesh
        .machines
        .iter()
        .filter(|m| m.name != me)
        .map(|m| {
            let (n, name, id) = (node.clone(), m.name.clone(), m.id);
            tokio::spawn(async move {
                let r = one(&n, id, byte).await;
                if r.is_ok() {
                    n.saw(&id);
                }
                let (rtt_ms, dial_ms, back, version, error) = match r {
                    Ok((rtt, dial, back, version)) => (Some(rtt), Some(dial), Some(back), version, None),
                    Err(e) => (None, None, None, None, Some(format!("{e:#}"))),
                };
                let p = Ping {
                    name,
                    node_id: id.to_string(),
                    rtt_ms,
                    dial_ms,
                    version,
                    error,
                };
                (p, back)
            })
        })
        .collect();
    let mut out = vec![];
    for t in tasks {
        out.push(t.await?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_from_the_wire() {
        assert_eq!(version_of(b'v', b"0.5.0").as_deref(), Some("0.5.0"));
        assert_eq!(version_of(b'v', b"1.0.0-rc.1+g12ab").as_deref(), Some("1.0.0-rc.1+g12ab"));
        assert_eq!(version_of(b'V', b""), None, "an older daemon's echo");
        assert_eq!(version_of(b'V', b"0.5.0"), None);
        for odd in [&b""[..], b"0.5 .0", b"0.5.0\n", b"\x1b[2J", "0.5.é".as_bytes(), &[b'1'; 33]] {
            assert_eq!(version_of(b'v', odd), None, "{odd:?}");
        }
    }
}
