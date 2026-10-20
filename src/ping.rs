//! Reachability for the map: a member dials another on `tear-mesh/ping/1`, sends one byte and
//! gets it back. Only members are admitted, so a reply also proves the peer still counts this
//! machine as one.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use iroh::EndpointId;
use iroh::endpoint::Connection;
use serde::{Deserialize, Serialize};

use crate::node::Node;

pub const ALPN: &[u8] = b"tear-mesh/ping/1";
const DIAL: Duration = Duration::from_secs(6);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Ping {
    pub name: String,
    pub node_id: String,
    /// Round trip of the echo once connected; None when the machine didn't answer.
    pub rtt_ms: Option<u64>,
    /// How long dialing took (hole punching, relays).
    pub dial_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn serve(conn: Connection) -> Result<()> {
    let (mut send, mut recv) = tokio::time::timeout(DIAL, conn.accept_bi()).await??;
    let mut b = [0u8; 1];
    tokio::time::timeout(DIAL, recv.read_exact(&mut b)).await??;
    send.write_all(&b).await?;
    send.finish()?;
    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
    Ok(())
}

async fn one(node: &Arc<Node>, id: EndpointId) -> Result<(u64, u64)> {
    let start = Instant::now();
    let conn = tokio::time::timeout(DIAL, node.endpoint.connect(id, ALPN))
        .await
        .context("no answer")??;
    let dial = start.elapsed().as_millis() as u64;
    let echo = async {
        let t = Instant::now();
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(&[7]).await?;
        send.finish()?;
        let mut b = [0u8; 1];
        recv.read_exact(&mut b).await?;
        anyhow::Ok(t.elapsed().as_millis() as u64)
    };
    let r = tokio::time::timeout(DIAL, echo).await.context("no echo");
    conn.close(0u32.into(), b"done");
    Ok((r??, dial))
}

/// Pings every other machine in the membership file at once.
pub async fn all(node: &Arc<Node>) -> Result<Vec<Ping>> {
    let mesh = node.mesh()?;
    let me = node.cfg.machine.clone();
    let tasks: Vec<_> = mesh
        .machines
        .iter()
        .filter(|m| m.name != me)
        .map(|m| {
            let (n, name, id) = (node.clone(), m.name.clone(), m.id);
            tokio::spawn(async move {
                let r = one(&n, id).await;
                if r.is_ok() {
                    n.saw(&id);
                }
                let (rtt_ms, dial_ms, error) = match r {
                    Ok((rtt, dial)) => (Some(rtt), Some(dial), None),
                    Err(e) => (None, None, Some(format!("{e:#}"))),
                };
                Ping {
                    name,
                    node_id: id.to_string(),
                    rtt_ms,
                    dial_ms,
                    error,
                }
            })
        })
        .collect();
    let mut out = vec![];
    for t in tasks {
        out.push(t.await?);
    }
    Ok(out)
}
