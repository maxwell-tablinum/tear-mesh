//! Shell over the mesh: a byte forwarder to the target machine's sshd, for `ssh -o ProxyCommand`.
//! Two locks: the owner's shell grant, checked here at both ends, and sshd's own authentication.
//! tear-mesh can't see inside SSH, so which user logs in is up to sshd and `authorized_keys`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use iroh::endpoint::Connection;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::info;

use crate::bridge::Ack;
use crate::node::Node;
use crate::policy;
use crate::sync::{recv_json, send_json};

pub const ALPN: &[u8] = b"tear-mesh/shell/1";

#[derive(Serialize, Deserialize, Debug)]
struct Header {
    boundary: String,
}

/// The target's side: checks the grant, then connects the stream to the local sshd.
pub async fn serve(node: &Arc<Node>, conn: Connection) -> Result<()> {
    let peer = conn.remote_id();
    let _slot = node.streams.claim(peer)?;
    let (mut send, mut recv) = conn.accept_bi().await?;
    let setup = async {
        let h: Header =
            tokio::time::timeout(Duration::from_secs(30), recv_json(&mut recv)).await??;
        let mesh = node.mesh()?;
        let caller = mesh
            .machine_by_id(&peer)
            .context("not a member")?
            .name
            .clone();
        policy::may_shell(&mesh, &caller, &node.cfg.machine, &h.boundary)?;
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", node.cfg.shell_port))
            .await
            .with_context(|| format!("no sshd on 127.0.0.1:{}", node.cfg.shell_port))?;
        info!(caller = %caller, boundary = %h.boundary, "shell stream open");
        anyhow::Ok((tcp, caller, h.boundary))
    };
    let (tcp, caller, boundary) = match setup.await {
        Ok(t) => t,
        Err(e) => {
            let _ = send_json(
                &mut send,
                &Ack {
                    ok: false,
                    error: format!("{e:#}"),
                },
            )
            .await;
            let _ = send.finish();
            let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
            return Err(e);
        }
    };
    send_json(
        &mut send,
        &Ack {
            ok: true,
            error: String::new(),
        },
    )
    .await?;
    let (tr, tw) = tcp.into_split();
    let live = node
        .streams
        .live(&caller, crate::bridge::Purpose::Shell { boundary });
    let r = tokio::select! {
        r = splice(recv, send, tr, tw) => r,
        _ = live.stop.notified() => Err(anyhow::anyhow!("closed: the mesh no longer allows it")),
    };
    // The caller closes once it has everything; closing here could drop bytes still in flight.
    let _ = tokio::time::timeout(Duration::from_secs(10), conn.closed()).await;
    r
}

/// The calling side: opens a shell stream to `machine` for a session in `boundary`.
pub async fn open(
    node: &Arc<Node>,
    boundary: &str,
    machine: &str,
) -> Result<(
    iroh::endpoint::RecvStream,
    iroh::endpoint::SendStream,
    Connection,
)> {
    let mesh = node.mesh()?;
    policy::may_shell(&mesh, &node.cfg.machine, machine, boundary)?;
    let target = mesh.machine(machine).context("no such machine")?.id;
    let conn = tokio::time::timeout(Duration::from_secs(30), node.endpoint.connect(target, ALPN))
        .await
        .map_err(|_| anyhow::anyhow!("{machine} not reachable"))??;
    let (mut send, mut recv) = conn.open_bi().await?;
    send_json(
        &mut send,
        &Header {
            boundary: boundary.into(),
        },
    )
    .await?;
    let ack: Ack = tokio::time::timeout(Duration::from_secs(30), recv_json(&mut recv)).await??;
    ensure!(ack.ok, "{machine} refused: {}", ack.error);
    Ok((recv, send, conn))
}

/// Copies bytes both ways until both directions finish.
pub async fn splice<AR, AW, BR, BW>(mut ar: AR, mut aw: AW, mut br: BR, mut bw: BW) -> Result<()>
where
    AR: AsyncRead + Unpin,
    AW: AsyncWrite + Unpin,
    BR: AsyncRead + Unpin,
    BW: AsyncWrite + Unpin,
{
    let a_to_b = async {
        tokio::io::copy(&mut ar, &mut bw).await?;
        bw.shutdown().await
    };
    let b_to_a = async {
        tokio::io::copy(&mut br, &mut aw).await?;
        aw.shutdown().await
    };
    let (x, y) = tokio::join!(a_to_b, b_to_a);
    x?;
    y?;
    Ok(())
}
