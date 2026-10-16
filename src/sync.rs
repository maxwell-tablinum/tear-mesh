//! Machine-to-machine sync over iroh. One bidirectional stream per session:
//! hello (heads for shared boundaries only) → newer circle, if any → missing entries both ways.

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

pub const ALPN: &[u8] = b"tear-mesh/1";
const MAX_FRAME: usize = 4 << 20;
const BATCH_BYTES: usize = 1 << 20;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "t", rename_all = "snake_case")]
enum Frame {
    Hello {
        circle: String,
        version: u64,
        addr: EndpointAddr,
        /// boundary → author → highest seq held. Only boundaries shared with this peer.
        heads: BTreeMap<String, BTreeMap<String, u64>>,
    },
    Circle {
        signed: Option<(String, String)>,
    },
    Entries {
        boundary: String,
        entries: Vec<Entry>,
    },
    End,
}

async fn write(send: &mut SendStream, f: &Frame) -> Result<()> {
    let b = serde_json::to_vec(f)?;
    ensure!(b.len() <= MAX_FRAME, "frame too large");
    send.write_all(&(b.len() as u32).to_be_bytes()).await?;
    send.write_all(&b).await?;
    Ok(())
}

async fn read(recv: &mut RecvStream) -> Result<Frame> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    ensure!(n <= MAX_FRAME, "frame too large");
    let mut buf = vec![0; n];
    recv.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
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
        circle: me.circle.id.clone(),
        version: me.circle.version,
        addr: node.endpoint.addr(),
        heads,
    };
    write(&mut send, &hello).await?;
    let Frame::Hello {
        circle,
        version,
        addr,
        heads: theirs,
    } = read(&mut recv).await?
    else {
        bail!("expected hello")
    };
    ensure!(circle == me.circle.id, "peer is in another circle");
    if addr.id == peer {
        node.learn_addr(addr);
    }

    let offer = (me.circle.version > version).then(|| (me.toml.clone(), me.sig.clone()));
    write(&mut send, &Frame::Circle { signed: offer }).await?;
    let Frame::Circle { signed } = read(&mut recv).await? else {
        bail!("expected circle")
    };
    if let Some((toml, sig)) = signed
        && let Err(e) = node.adopt(&toml, &sig)
    {
        warn!(
            "peer {} offered a circle we refused: {e:#}",
            peer.fmt_short()
        );
    }

    // Placement uses the circle as it stands now, possibly just updated.
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
