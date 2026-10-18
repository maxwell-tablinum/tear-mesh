//! Machine-to-machine sync over iroh. One bidirectional stream per session:
//! hello (mesh version and hash, heads for shared boundaries only) → the membership versions the
//! other side lacks → missing entries both ways.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail, ensure};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{EndpointAddr, EndpointId};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::envelope::Entry;
use crate::node::Node;

pub const ALPN: &[u8] = b"tear-mesh/sync/2";
const MAX_FRAME: usize = 4 << 20;
const BATCH_BYTES: usize = 1 << 20;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "t", rename_all = "snake_case")]
enum Frame {
    Hello {
        mesh: String,
        version: u64,
        hash: String,
        addr: EndpointAddr,
        /// boundary → author → highest seq held. Only boundaries shared with this peer.
        heads: BTreeMap<String, BTreeMap<String, u64>>,
    },
    /// `(version, toml, sig)` for each version the other side lacks, oldest first.
    Mesh {
        versions: Vec<(u64, String, String)>,
    },
    Entries {
        boundary: String,
        entries: Vec<Entry>,
    },
    End,
}

/// One length-prefixed JSON frame.
pub(crate) async fn send_json<T: Serialize>(send: &mut SendStream, f: &T) -> Result<()> {
    let b = serde_json::to_vec(f)?;
    ensure!(b.len() <= MAX_FRAME, "frame too large");
    send.write_all(&(b.len() as u32).to_be_bytes()).await?;
    send.write_all(&b).await?;
    Ok(())
}

pub(crate) async fn recv_json<T: serde::de::DeserializeOwned>(recv: &mut RecvStream) -> Result<T> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    ensure!(n <= MAX_FRAME, "frame too large");
    let mut buf = vec![0; n];
    recv.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

async fn write(send: &mut SendStream, f: &Frame) -> Result<()> {
    send_json(send, f).await
}

async fn read(recv: &mut RecvStream) -> Result<Frame> {
    recv_json(recv).await
}

pub async fn initiate(node: &Arc<Node>, peer: EndpointId) -> Result<()> {
    let conn = node.endpoint.connect(peer, ALPN).await?;
    let (send, recv) = conn.open_bi().await?;
    let r = session(node, &conn, send, recv).await;
    conn.close(0u32.into(), b"done");
    r
}

pub async fn serve(node: &Arc<Node>, conn: Connection) -> Result<()> {
    // A member that stalls can't park this task forever.
    let r = tokio::time::timeout(Duration::from_secs(60), async {
        let (send, recv) = conn.accept_bi().await?;
        session(node, &conn, send, recv).await
    })
    .await
    .unwrap_or_else(|_| Err(anyhow::anyhow!("inbound sync timed out")));
    // The initiator closes once both sides have everything.
    let _ = tokio::time::timeout(Duration::from_secs(10), conn.closed()).await;
    r
}

async fn session(
    node: &Arc<Node>,
    conn: &Connection,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<()> {
    let peer = conn.remote_id();
    let me = node.signed()?;
    let mut heads = BTreeMap::new();
    for b in node.shared_with(&peer) {
        heads.insert(b.clone(), node.heads(&b)?);
    }
    let hello = Frame::Hello {
        mesh: me.mesh.id.clone(),
        version: me.mesh.version,
        hash: me.hash.clone(),
        addr: node.endpoint.addr(),
        heads,
    };
    write(&mut send, &hello).await?;
    let Frame::Hello {
        mesh,
        version,
        hash,
        addr,
        heads: theirs,
    } = read(&mut recv).await?
    else {
        bail!("expected hello")
    };
    ensure!(mesh == me.mesh.id, "peer is in another mesh");
    if addr.id == peer {
        node.learn_addr(addr);
    }

    let versions = node.versions_for(version, &hash);
    write(&mut send, &Frame::Mesh { versions }).await?;
    let Frame::Mesh { versions } = read(&mut recv).await? else {
        bail!("expected mesh versions")
    };
    if !versions.is_empty()
        && let Err(e) = node.adopt(&versions)
    {
        warn!(
            "peer {} offered membership versions we refused: {e:#}",
            peer.fmt_short()
        );
    }

    // Placement uses the membership file as it stands now, possibly just updated.
    let shared = node.shared_with(&peer);
    let send_side = async {
        for b in shared.iter().filter(|b| theirs.contains_key(*b)) {
            let their_heads = &theirs[b];
            for author in node.heads(b)?.into_keys() {
                let mut after = their_heads.get(&author).copied().unwrap_or(0);
                loop {
                    let batch = node.entries_since(b, &author, after, BATCH_BYTES)?;
                    if batch.is_empty() {
                        break;
                    }
                    after += batch.len() as u64;
                    write(
                        &mut send,
                        &Frame::Entries {
                            boundary: b.clone(),
                            entries: batch,
                        },
                    )
                    .await?;
                }
            }
        }
        write(&mut send, &Frame::End).await?;
        send.finish()?;
        // Resolves once the peer has acknowledged every byte.
        send.stopped().await?;
        anyhow::Ok(())
    };
    let recv_side = async {
        loop {
            match read(&mut recv).await? {
                Frame::Entries { boundary, entries } => {
                    node.receive(&peer, &boundary, entries)?;
                }
                Frame::End => break,
                _ => bail!("unexpected frame"),
            }
        }
        anyhow::Ok(())
    };
    tokio::try_join!(send_side, recv_side)?;
    node.saw(&peer);
    Ok(())
}
