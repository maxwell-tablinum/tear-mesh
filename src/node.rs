//! The daemon's core: the node key, the adopted membership file and its history, one store per
//! hosted boundary and the iroh endpoint. The socket, MCP server, hooks and steward all go through it.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use iroh::address_lookup::memory::MemoryLookup;
use iroh::address_lookup::{DnsAddressLookup, PkarrPublisher, PkarrResolver};
use iroh::endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks, Side, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, broadcast};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::config::{Config, Relay};
use crate::envelope::{
    Entry, Envelope, Kind, MAX_BODY, MAX_SUBJECT, MAX_TO, Trust, hash_hex, parse_address,
};
use crate::mesh::{Mesh, SignedMesh};
use crate::os::write_private;
use crate::store::{Seen, Store, Stored};
use crate::{bridge, join, now_ms, ping, policy, shell, sync, valid_name};

/// New mail for a local mailbox that no session currently holds.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MailEvent {
    pub boundary: String,
    pub mailbox: String,
    pub id: String,
    pub from: String,
    pub subject: String,
    #[serde(default)]
    pub trust: Trust,
}

/// What a boundary's steward hears on its subscription.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "ev", rename_all = "snake_case")]
pub enum Event {
    Mail(MailEvent),
    /// A peer opened a tool stream to one of this boundary's offers; attach to it.
    Open {
        boundary: String,
        stream: u64,
        server: String,
    },
    /// A letter is waiting for the screener.
    Screen { boundary: String },
}

impl Event {
    fn boundary(&self) -> &str {
        match self {
            Event::Mail(m) => &m.boundary,
            Event::Open { boundary, .. } | Event::Screen { boundary } => boundary,
        }
    }
}

/// A letter as shown to sessions.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Letter {
    pub id: String,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub thread: Option<String>,
    pub ts: u64,
    pub read: bool,
    #[serde(default)]
    pub kind: Kind,
    #[serde(default)]
    pub trust: Trust,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// The body's length in bytes, so a reader can decide before fetching it.
    #[serde(default)]
    pub size: u64,
    /// On a claim: the seconds until the real reply, as its sender estimated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect_secs: Option<u64>,
}

/// An agent's newest status record (spec: status records). Written by that agent: untrusted text.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct AgentStatus {
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_questions: Option<u64>,
    pub updated_ms: u64,
}

/// Whether one machine answered a ping just now.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Reach {
    pub name: String,
    pub online: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Who {
    pub you: String,
    pub boundary: String,
    pub machines: Vec<PeerInfo>,
    /// Addresses that have sent mail in this boundary, plus mailboxes held here now.
    pub addresses: Vec<String>,
    /// The mailboxes of this machine a live session holds now, as addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub held: Vec<String>,
    /// The newest status record of each agent whose machine may mail this one, by address.
    #[serde(default)]
    pub status: Vec<AgentStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PeerInfo {
    pub name: String,
    pub this_machine: bool,
    pub last_sync_ms: Option<u64>,
    /// The machine's current bio in this boundary. Written by that machine: untrusted text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,
    /// Servers the machine offers in this boundary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub offers: Vec<String>,
}

/// A letter the screener flagged, as listed for a person.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Flagged {
    pub id: String,
    pub from: String,
    pub subject: String,
    pub reason: String,
    /// When it was flagged (ms).
    pub ts: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ScreenCounts {
    pub waiting: u64,
    pub flagged: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    /// This daemon's tear-mesh version.
    #[serde(default)]
    pub version: String,
    pub machine: String,
    pub node_id: EndpointId,
    pub mesh: Option<MeshInfo>,
    pub entries: BTreeMap<String, u64>,
    pub peers: Vec<PeerInfo>,
    pub pending_joins: Vec<join::PendingInfo>,
    /// This machine's own join, while one runs (and its outcome after).
    #[serde(default)]
    pub joining: Option<join::JoinProgress>,
    pub warnings: Vec<String>,
    /// The mesh's name when it was dissolved: `mesh` is then `None` until the person creates,
    /// joins or resets.
    #[serde(default)]
    pub dissolved: Option<String>,
    /// Boundaries this machine hosts in the mesh that no OS user maps to (`[users]`).
    #[serde(default)]
    pub unmapped: Vec<String>,
    /// Machines that said they are leaving (an uninstall or reset there), for an owner to remove.
    #[serde(default)]
    pub leaving: Vec<String>,
    /// Per screened boundary: letters waiting for the screener, and flagged ones.
    #[serde(default)]
    pub screening: BTreeMap<String, ScreenCounts>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshInfo {
    pub id: String,
    pub name: String,
    pub version: u64,
    pub hash: String,
    pub owners: Vec<String>,
    pub hosts: Vec<String>,
    /// The release the membership file names (`[settings] release`), if any.
    #[serde(default)]
    pub release: Option<String>,
}

/// The adopted membership file and the versions before it, oldest first, contiguous.
#[derive(Clone, Debug)]
pub struct MeshState {
    pub history: Vec<SignedMesh>,
}

impl MeshState {
    pub fn current(&self) -> &SignedMesh {
        self.history.last().expect("never empty")
    }

    /// The stored file at version `v`, if this machine has it.
    pub fn at(&self, v: u64) -> Option<&SignedMesh> {
        let base = self.history[0].mesh.version;
        v.checked_sub(base)
            .and_then(|i| self.history.get(i as usize))
    }

    /// The latest version that dropped machine `id`, if any stored version did. A dissolved mesh
    /// drops every machine in its closed version.
    pub fn removed_at(&self, id: &EndpointId) -> Option<u64> {
        self.history
            .windows(2)
            .rev()
            .find(|w| w[0].mesh.machine_by_id(id).is_some() && w[1].mesh.machine_by_id(id).is_none())
            .map(|w| w[1].mesh.version)
    }

    /// Versions a peer at `(v, hash)` lacks, to send it. Includes this machine's file at `v` when
    /// the peer's differs, so the peer can settle the split. A peer that isn't a member gets
    /// versions only up to the one that removed it, and one that never was gets none.
    pub fn versions_for(&self, v: u64, hash: &str, peer: &EndpointId) -> Vec<(u64, String, String)> {
        let cur = self.current().mesh.version;
        let last = if self.current().mesh.machine_by_id(peer).is_some() {
            cur
        } else {
            match self.removed_at(peer) {
                Some(r) => r,
                None => return vec![],
            }
        };
        let from = match self.at(v) {
            Some(mine) if mine.hash == hash => v + 1,
            Some(_) => v,
            None => return vec![],
        };
        (from..=last)
            .take(MAX_VERSIONS)
            .filter_map(|x| self.at(x))
            .map(|s| (s.mesh.version, s.toml.clone(), s.sig.clone()))
            .collect()
    }
}

/// Most versions sent in one sync session; a far-behind machine catches up over several.
pub const MAX_VERSIONS: usize = 32;

pub struct Node {
    pub cfg: Config,
    key: SecretKey,
    mesh: Arc<RwLock<Option<MeshState>>>,
    stores: Mutex<HashMap<String, Store>>,
    pub endpoint: Endpoint,
    lookup: MemoryLookup,
    peers: Mutex<BTreeMap<EndpointId, EndpointAddr>>,
    events: broadcast::Sender<Event>,
    holders: Mutex<HashMap<(String, String), usize>>,
    last_seen: Mutex<HashMap<String, u64>>,
    // shortcut: in memory; an owner restart forgets it
    /// By id, with the name it had: a rejoin under the name (a new id) isn't the one that left.
    leaving: Mutex<HashMap<EndpointId, (String, u64)>>,
    sync_now: Notify,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    posts: Mutex<HashMap<String, VecDeque<Instant>>>,
    warnings: Mutex<Vec<String>>,
    /// (boundary, machine) pairs whose first refused entry has been logged as a warning.
    refused: Mutex<HashSet<(String, String)>>,
    /// Makes set_status's read-merge-write one step.
    status_lock: Mutex<()>,
    pub(crate) joins: Arc<join::Joins>,
    pub(crate) streams: bridge::Streams,
}

/// Admits members on the sync, tool and shell protocols, and strangers only on the join protocol
/// while an invite is open. Applies to connections in both directions.
///
/// The farewell rule: a machine some stored version removed (every machine, once the mesh is
/// dissolved) is also admitted on the sync protocol, and only there, so it can learn that it was
/// removed. The session gives it no heads, no entries (`policy::may_sync` refuses it) and no
/// addresses, and only the versions up to and including the one that removed it
/// (`MeshState::versions_for`). A machine that was never in a stored version gets nothing.
#[derive(Debug)]
struct Members {
    mesh: Arc<RwLock<Option<MeshState>>>,
    joins: Arc<join::Joins>,
}

impl EndpointHooks for Members {
    fn after_handshake<'a>(
        &'a self,
        conn: &'a Connection,
    ) -> impl Future<Output = AfterHandshakeOutcome> + Send + 'a {
        let (member, removed) = self
            .mesh
            .read()
            .unwrap()
            .as_ref()
            .map(|s| {
                let id = conn.remote_id();
                (s.current().mesh.machine_by_id(&id).is_some(), s.removed_at(&id).is_some())
            })
            .unwrap_or_default();
        let alpn = conn.alpn();
        let ok = if alpn == join::ALPN {
            conn.side() == Side::Client || self.joins.open()
        } else if member {
            [sync::ALPN, bridge::ALPN, shell::ALPN, ping::ALPN].contains(&alpn)
        } else {
            removed && alpn == sync::ALPN
        };
        async move {
            if ok {
                AfterHandshakeOutcome::accept()
            } else {
                AfterHandshakeOutcome::Reject {
                    error_code: 403u32.into(),
                    reason: b"not a mesh member".to_vec(),
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StoredMesh {
    toml: String,
    sig: String,
}

/// Whether mesh `id` was dissolved and forgotten in state dir `dir`.
fn tombstoned_in(dir: &Path, id: &str) -> bool {
    std::fs::read_to_string(dir.join("dissolved")).is_ok_and(|s| s.lines().any(|l| l.trim() == id))
}

/// Removes `mesh/` in one step (a rename), so a crash can't leave some versions behind.
fn drop_mesh_dir(dir: &Path) -> Result<()> {
    let (mdir, trash) = (dir.join("mesh"), dir.join("mesh.old"));
    let _ = std::fs::remove_dir_all(&trash);
    match std::fs::rename(&mdir, &trash) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e).context("removing mesh/"),
        _ => {}
    }
    let _ = std::fs::remove_dir_all(&trash);
    Ok(())
}

/// The rest of a leave (`Node::leave_locked`): moves the logs to `boundaries-<id>/` (kept, never
/// deleted), removes `mesh-id` and `mesh/`, then the `leaving` mark. Safe to run again.
fn finish_leave(dir: &Path, id: &str) -> Result<std::path::PathBuf> {
    // Mesh ids are letters and digits only (`Mesh::validate`), so this stays in the state dir.
    ensure!(!id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric()), "bad mesh id {id:?}");
    let logs = dir.join("boundaries");
    let mut to = dir.join(format!("boundaries-{id}"));
    for n in 1.. {
        if !to.exists() {
            break;
        }
        to = dir.join(format!("boundaries-{id}.{n}"));
    }
    // An empty log directory (a second run) stays where it is.
    if std::fs::read_dir(&logs).is_ok_and(|mut d| d.next().is_some()) {
        std::fs::rename(&logs, &to).with_context(|| format!("moving the logs to {}", to.display()))?;
    }
    std::fs::create_dir_all(&logs)?;
    match std::fs::remove_file(dir.join("mesh-id")) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e).context("removing mesh-id"),
        _ => {}
    }
    drop_mesh_dir(dir)?;
    let _ = std::fs::remove_file(dir.join("leaving"));
    Ok(to)
}

/// The stored chain, or none. A mesh dissolved and forgotten here (a crash halfway through
/// `forget_closed` can leave its files) counts as none.
fn load_history(dir: &Path) -> Result<Option<MeshState>> {
    let mdir = dir.join("mesh");
    let mut files: Vec<(u64, StoredMesh)> = vec![];
    if let Ok(rd) = std::fs::read_dir(&mdir) {
        for e in rd {
            let p = e?.path();
            let Some(v) = p
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            if p.extension().is_some_and(|x| x == "json") {
                files.push((v, serde_json::from_slice(&std::fs::read(&p)?)?));
            }
        }
    }
    files.sort_by_key(|(v, _)| *v);
    if files.is_empty() {
        // A 0.1.0 machine's circle becomes the start of the chain.
        return match std::fs::read(dir.join("circle.json")) {
            Ok(b) => {
                let c: StoredMesh = serde_json::from_slice(&b).context("stored circle")?;
                let s = SignedMesh::verify_first(&c.toml, &c.sig).context("stored circle")?;
                if tombstoned_in(dir, &s.mesh.id) {
                    return Ok(None);
                }
                save_version(dir, &s)?;
                let _ = std::fs::remove_file(dir.join("circle.json"));
                Ok(Some(MeshState { history: vec![s] }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context("reading the stored circle"),
        };
    }
    let mut it = files.into_iter();
    let (_, first) = it.next().expect("non-empty");
    let mut history =
        vec![SignedMesh::verify_first(&first.toml, &first.sig).context("stored mesh")?];
    if tombstoned_in(dir, &history[0].mesh.id) {
        warn!("ignoring stored versions of mesh {}, which was dissolved", history[0].mesh.id);
        drop_mesh_dir(dir)?;
        return Ok(None);
    }
    for (v, f) in it {
        match SignedMesh::verify_next(&f.toml, &f.sig, history.last().expect("non-empty")) {
            Ok(s) => history.push(s),
            Err(e) => {
                warn!(
                    "stored mesh version {v} doesn't follow the one before; ignoring it and later ones: {e:#}"
                );
                break;
            }
        }
    }
    Ok(Some(MeshState { history }))
}

fn save_version(dir: &Path, s: &SignedMesh) -> Result<()> {
    let mdir = dir.join("mesh");
    std::fs::create_dir_all(&mdir)?;
    write_private(
        &mdir.join(format!("{}.json", s.mesh.version)),
        &serde_json::to_vec(&StoredMesh {
            toml: s.toml.clone(),
            sig: s.sig.clone(),
        })?,
    )
}

impl Node {
    pub async fn start(cfg: Config) -> Result<Arc<Node>> {
        cfg.validate()?;
        let dir = &cfg.state_dir;
        std::fs::create_dir_all(dir.join("boundaries"))
            .with_context(|| format!("creating {}", dir.display()))?;
        crate::os::secure_dir(dir)?;
        let key = load_or_create_key(dir)?;
        if let Ok(id) = std::fs::read_to_string(dir.join("leaving")) {
            finish_leave(dir, id.trim()).context("finishing an interrupted leave")?;
        }
        let state = load_history(dir)?;
        let settings = state
            .as_ref()
            .map(|s| s.current().mesh.settings.clone())
            .unwrap_or_default();
        let mesh = Arc::new(RwLock::new(state));
        let joins = Arc::new(join::Joins::load(dir));

        let lookup = MemoryLookup::new();
        let mut b = Endpoint::builder(presets::Minimal)
            .secret_key(key.clone())
            .alpns(vec![
                sync::ALPN.to_vec(),
                join::ALPN.to_vec(),
                bridge::ALPN.to_vec(),
                shell::ALPN.to_vec(),
                ping::ALPN.to_vec(),
            ])
            .hooks(Members {
                mesh: mesh.clone(),
                joins: joins.clone(),
            })
            .address_lookup(lookup.clone());
        let methods = cfg.network.lookup.clone().unwrap_or(settings.lookup);
        if methods.iter().any(|m| m == "n0-dns") {
            b = b
                .address_lookup(PkarrPublisher::n0_dns())
                .address_lookup(PkarrResolver::n0_dns())
                .address_lookup(DnsAddressLookup::n0_dns());
        }
        if methods.iter().any(|m| m == "mdns") {
            b = b.address_lookup(
                iroh_mdns_address_lookup::MdnsAddressLookup::builder().service_name("tearmesh"),
            );
        }
        b = b.relay_mode(
            match cfg.network.relay.as_ref().unwrap_or(&settings.relays) {
                Relay::Preset(p) if p == "n0" => RelayMode::Default,
                Relay::Preset(_) => RelayMode::Disabled,
                Relay::Urls(urls) => {
                    let urls: Vec<RelayUrl> = urls
                        .iter()
                        .map(|u| u.parse())
                        .collect::<Result<_, _>>()
                        .context("relay url")?;
                    RelayMode::Custom(urls.into_iter().collect::<RelayMap>())
                }
            },
        );
        if let Some(addr) = cfg.network.bind {
            b = b.clear_ip_transports().bind_addr(addr)?;
        }
        let endpoint = b.bind().await.context("binding the iroh endpoint")?;

        let peers: BTreeMap<EndpointId, EndpointAddr> = std::fs::read(dir.join("peers.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        for addr in peers.values() {
            lookup.add_endpoint_info(addr.clone());
        }

        let node = Arc::new(Node {
            cfg,
            key,
            mesh,
            stores: Mutex::new(HashMap::new()),
            endpoint,
            lookup,
            peers: Mutex::new(peers),
            events: broadcast::channel(256).0,
            holders: Mutex::new(HashMap::new()),
            last_seen: Mutex::new(HashMap::new()),
            leaving: Mutex::new(HashMap::new()),
            sync_now: Notify::new(),
            tasks: Mutex::new(vec![]),
            posts: Mutex::new(HashMap::new()),
            warnings: Mutex::new(vec![]),
            refused: Mutex::new(HashSet::new()),
            status_lock: Mutex::new(()),
            joins,
            streams: bridge::Streams::default(),
        });

        let n = node.clone();
        let accept = tokio::spawn(async move {
            while let Some(incoming) = n.endpoint.accept().await {
                let n = n.clone();
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => return debug!("inbound connection: {e:#}"),
                    };
                    let alpn = conn.alpn().to_vec();
                    let r = if alpn == sync::ALPN {
                        sync::serve(&n, conn).await
                    } else if alpn == join::ALPN {
                        join::serve(&n, conn).await
                    } else if alpn == bridge::ALPN {
                        bridge::serve(&n, conn).await
                    } else if alpn == shell::ALPN {
                        shell::serve(&n, conn).await
                    } else if alpn == ping::ALPN {
                        ping::serve(&n, conn).await
                    } else {
                        Ok(())
                    };
                    if let Err(e) = r {
                        debug!("inbound {}: {e:#}", String::from_utf8_lossy(&alpn));
                    }
                });
            }
        });
        let n = node.clone();
        let syncer = tokio::spawn(async move {
            let every = Duration::from_secs(n.cfg.sync_interval_secs);
            // The first round runs at start, not one interval later.
            loop {
                // A dissolved node pushed its closed version once (`SyncNow`); machines that were
                // away pull it themselves.
                if n.dissolved().is_none() {
                    n.sync_all().await;
                }
                tokio::select! {
                    _ = tokio::time::sleep(every) => {}
                    _ = n.sync_now.notified() => {}
                }
            }
        });
        node.tasks.lock().unwrap().extend([accept, syncer]);
        info!(machine = %node.cfg.machine, id = %node.id(), "tear-mesh node started");
        Ok(node)
    }

    pub async fn shutdown(&self) {
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
        self.endpoint.close().await;
    }

    pub fn id(&self) -> EndpointId {
        self.key.public()
    }

    pub fn mesh(&self) -> Result<Mesh> {
        Ok(self.signed()?.mesh)
    }

    pub fn signed(&self) -> Result<SignedMesh> {
        Ok(self.state()?.current().clone())
    }

    pub fn state(&self) -> Result<MeshState> {
        self.mesh
            .read()
            .unwrap()
            .clone()
            .context("no mesh yet: run `tearmesh mesh apply` or `tearmesh join`")
    }

    fn warn_once(&self, w: String) {
        warn!("{w}");
        let mut ws = self.warnings.lock().unwrap();
        if !ws.contains(&w) {
            ws.push(w);
        }
    }

    /// The first membership file this machine adopts (from `mesh apply` or a ticket). It must
    /// list this machine with this node id, and, after a `mesh reset`, keep the mesh's id. A mesh
    /// dissolved here is never adopted again.
    pub fn adopt_first(&self, toml: &str, sig: &str) -> Result<u64> {
        let mut guard = self.mesh.write().unwrap();
        ensure!(guard.is_none(), "this machine already has a mesh");
        let s = self.check_first(toml, sig, None)?;
        let id_file = self.cfg.state_dir.join("mesh-id");
        write_private(&id_file, s.mesh.id.as_bytes())?;
        save_version(&self.cfg.state_dir, &s)?;
        let v = s.mesh.version;
        info!(version = v, "adopted the mesh");
        *guard = Some(MeshState { history: vec![s] });
        drop(guard);
        self.sync_now.notify_one();
        Ok(v)
    }

    /// Every check `adopt_first` makes. `dissolved` is the id of this machine's dissolved mesh,
    /// not yet forgotten: refused too, and its `mesh-id` is about to go.
    fn check_first(&self, toml: &str, sig: &str, dissolved: Option<&str>) -> Result<SignedMesh> {
        let s = SignedMesh::verify_first(toml, sig)?;
        ensure!(
            !self.tombstoned(&s.mesh.id) && dissolved != Some(s.mesh.id.as_str()),
            "mesh {} ({}) was dissolved; it can't be adopted again",
            s.mesh.name,
            s.mesh.id
        );
        ensure!(
            s.mesh
                .machine(&self.cfg.machine)
                .is_some_and(|m| m.id == self.id()),
            "the membership file doesn't list this machine ({}) with this node id ({})",
            self.cfg.machine,
            self.id()
        );
        if let Ok(old) = std::fs::read_to_string(self.cfg.state_dir.join("mesh-id"))
            && dissolved.is_none()
        {
            ensure!(
                old.trim() == s.mesh.id,
                "this machine was reset from mesh {}; a file for mesh {} would strand its logs (to leave that mesh for good: tearmesh mesh leave)",
                old.trim(),
                s.mesh.id
            );
        }
        Ok(s)
    }

    /// A first file from `mesh apply` or a join. On a dissolved node, every check passes first,
    /// then the dissolved mesh is forgotten, then the file is adopted.
    pub fn adopt_new(&self, toml: &str, sig: &str) -> Result<u64> {
        let closed = self.signed().ok().filter(|s| s.mesh.closed).map(|s| s.mesh.id);
        if let Some(id) = &closed {
            self.check_first(toml, sig, Some(id))?;
            self.forget_closed()?;
        }
        self.adopt_first(toml, sig)
    }

    /// Adopts later versions, each `(declared version, toml, sig)`, in order.
    ///
    /// Two owners may sign different files for the same version. Only the tip is ever replaced,
    /// never an older version, and only by a sibling whose signer is still an owner in this
    /// machine's tip, so a key that a version removed can't come back and rewrite history.
    /// Between such siblings, one that removes the other's signer wins, then the one with more
    /// versions built on it, then the lower hash. Every machine applies the same rule.
    pub fn adopt(&self, files: &[(u64, String, String)]) -> Result<u64> {
        self.adopt_tip(files).1
    }

    /// `adopt`, also returning the new tip's hash when the tip changed, even if a later version
    /// was refused: the versions before it are kept and acted on.
    pub(crate) fn adopt_tip(&self, files: &[(u64, String, String)]) -> (Option<String>, Result<u64>) {
        let mut guard = self.mesh.write().unwrap();
        let Some(state) = guard.as_mut() else {
            return (None, Err(anyhow::anyhow!("no mesh yet")));
        };
        let mut changed = false;
        let r = self.adopt_into(state, files, &mut changed);
        let cur = state.current().clone();
        drop(guard);
        if changed {
            info!(version = cur.mesh.version, "adopted mesh version");
            if cur.mesh.closed {
                self.close_tickets();
            }
            self.joins.on_adopt(&cur);
            self.streams.recheck(self, &cur.mesh);
            self.sync_now.notify_one();
        }
        (changed.then(|| cur.hash.clone()), r.map(|_| cur.mesh.version))
    }

    fn adopt_into(&self, state: &mut MeshState, files: &[(u64, String, String)], changed: &mut bool) -> Result<()> {
        let mut files = files.to_vec();
        files.sort_by_key(|f| f.0);
        files.truncate(MAX_VERSIONS);
        for (i, (v, toml, sig)) in files.iter().enumerate() {
            let cur = state.current().mesh.version;
            if *v == cur + 1 {
                let s = SignedMesh::verify_next(toml, sig, state.current())?;
                save_version(&self.cfg.state_dir, &s)?;
                state.history.push(s);
                *changed = true;
            } else if *v == cur && crate::mesh::hash(toml) != state.current().hash {
                let Some(prev) = state.at(cur - 1) else {
                    self.warn_once(format!(
                        "a peer has a different version {cur}, and this machine has no version {} to check it against",
                        cur - 1
                    ));
                    break;
                };
                let mut branch = vec![SignedMesh::verify_next(toml, sig, prev)?];
                for (w, t, g) in &files[i + 1..] {
                    let last = branch.last().expect("non-empty");
                    if *w != last.mesh.version + 1 {
                        break;
                    }
                    match SignedMesh::verify_next(t, g, last) {
                        Ok(x) => branch.push(x),
                        Err(_) => break,
                    }
                }
                let mine = state.current().clone();
                if sibling_wins(&branch[0], &mine, branch.len() > 1) {
                    state.history.pop();
                    for b in branch {
                        save_version(&self.cfg.state_dir, &b)?;
                        state.history.push(b);
                    }
                    *changed = true;
                    self.warn_once(format!(
                        "two owners signed different version {cur}s; this machine dropped its own ({}) for the other ({}). Re-apply the dropped changes on top of the current version",
                        &mine.hash[..12],
                        &state.at(cur).expect("just pushed").hash[..12]
                    ));
                } else {
                    self.warn_once(format!(
                        "a peer has a different version {cur} ({}); this machine keeps its own ({})",
                        &branch[0].hash[..12],
                        &mine.hash[..12]
                    ));
                }
                break;
            } else if *v < cur {
                if state
                    .at(*v)
                    .is_some_and(|m| m.hash != crate::mesh::hash(toml))
                {
                    self.warn_once(format!(
                        "a peer has a different version {v}; this machine is past it and keeps its own"
                    ));
                }
            } else if *v > cur {
                bail!("version {v} doesn't follow {cur}; missing the versions between");
            }
        }
        Ok(())
    }

    /// `mesh apply` from the admin socket: a first file, or the next version. On a dissolved node
    /// it is a new mesh's first file, checked before the dissolved one is forgotten.
    pub fn apply(&self, toml: &str, sig: &str) -> Result<u64> {
        if self.dissolved().is_some() || self.mesh.read().unwrap().is_none() {
            return self.adopt_new(toml, sig);
        }
        let v = Mesh::parse(toml)?.version;
        let tip = self.adopt(&[(v, toml.into(), sig.into())])?;
        let h = crate::mesh::hash(toml);
        ensure!(
            self.state()?.at(v).is_some_and(|s| s.hash == h),
            "version {v} ({}) wasn't adopted: this machine keeps its own version {tip}",
            &h[..12]
        );
        Ok(tip)
    }

    /// Forgets the adopted membership file (logs stay) so the next one is adopted as a first one:
    /// the re-pin after losing every owner key. Only from this machine's admin socket, or from
    /// `settle`. A dissolved mesh is forgotten for good (`forget_closed`).
    pub fn reset(&self) -> Result<()> {
        let mut guard = self.mesh.write().unwrap();
        self.reset_locked(&mut guard)
    }

    fn reset_locked(&self, guard: &mut Option<MeshState>) -> Result<()> {
        if guard.as_ref().is_some_and(|s| s.current().mesh.closed) {
            return self.forget_locked(guard);
        }
        drop_mesh_dir(&self.cfg.state_dir)?;
        *guard = None;
        info!("forgot the mesh; adopt a new file with `tearmesh mesh apply`");
        Ok(())
    }

    /// Leaves the mesh by this machine's own choice (`mesh leave`, the menu), as `settle` does for
    /// a removed machine: the logs move aside and `mesh-id` goes, so it can create or join any
    /// mesh, this one included. A dissolved mesh is forgotten for good. After a `mesh reset` (no
    /// file, but `mesh-id` still binds the logs) it frees the machine the same way.
    pub fn leave(&self) -> Result<()> {
        let mut guard = self.mesh.write().unwrap();
        match guard.as_ref().map(|s| s.current().mesh.closed) {
            Some(true) => self.forget_locked(&mut guard),
            Some(false) => self.leave_locked(&mut guard, false),
            None => {
                let dir = &self.cfg.state_dir;
                let file = dir.join("mesh-id");
                let id = std::fs::read_to_string(&file).unwrap_or_default();
                let id = id.trim();
                ensure!(!id.is_empty(), "this machine isn't in a mesh");
                ensure!(
                    id.bytes().all(|b| b.is_ascii_alphanumeric()),
                    "{} doesn't hold a mesh id ({id:?}); delete that file and leave again",
                    file.display()
                );
                // No `leaving` mark: `finish_leave` is safe to run again, and a crash leaves
                // `mesh-id` for the next leave.
                self.stores.lock().unwrap_or_else(|e| e.into_inner()).clear();
                self.close_tickets();
                let to = finish_leave(dir, id)?;
                info!(logs = %to.display(), "left the mesh");
                Ok(())
            }
        }
    }

    /// Called by a sync session only, after it adopted versions from a member and the tip became
    /// `tip`: if that tip is still the newest version, is open and no longer lists this node, this
    /// machine was removed and leaves the mesh. Its logs move aside and `mesh-id` goes, so it can
    /// create or join any mesh, this one included. A local `mesh apply` never gets here, and
    /// `adopt` verified every version first.
    pub fn settle(&self, tip: &str) -> Result<()> {
        let mut guard = self.mesh.write().unwrap();
        let Some(c) = guard.as_ref().map(|s| s.current()) else {
            return Ok(());
        };
        if c.hash != tip || c.mesh.closed || c.mesh.machine_by_id(&self.id()).is_some() {
            return Ok(());
        }
        self.warn_once(format!(
            "version {} of mesh {} removed this machine, so it left the mesh (its logs moved to boundaries-{}/)",
            c.mesh.version, c.mesh.name, c.mesh.id
        ));
        self.leave_locked(&mut guard, false)
    }

    /// The mesh's name, while the adopted version is a closed (dissolved) one.
    pub fn dissolved(&self) -> Option<String> {
        self.mesh
            .read()
            .unwrap()
            .as_ref()
            .map(|s| &s.current().mesh)
            .filter(|m| m.closed)
            .map(|m| m.name.clone())
    }

    /// Whether mesh `id` was dissolved and forgotten on this machine.
    pub(crate) fn tombstoned(&self, id: &str) -> bool {
        tombstoned_in(&self.cfg.state_dir, id)
    }

    /// Forgets a dissolved mesh for good, so this machine can create or join another: the mesh id
    /// goes in the `dissolved` file (never adopted again), `mesh/` and `mesh-id` go, and the logs
    /// move to `boundaries-<id>/`, kept, never deleted. Does nothing on a mesh that isn't
    /// dissolved.
    pub fn forget_closed(&self) -> Result<()> {
        let mut guard = self.mesh.write().unwrap();
        self.forget_locked(&mut guard)
    }

    fn forget_locked(&self, guard: &mut Option<MeshState>) -> Result<()> {
        if guard.as_ref().is_some_and(|s| s.current().mesh.closed) {
            self.leave_locked(guard, true)?;
        }
        Ok(())
    }

    /// Leaves the adopted mesh: with `tombstone`, its id goes in the `dissolved` file first, so it
    /// is never adopted again. A `leaving` file then marks the leave until `finish_leave` is done,
    /// so a crash halfway is finished at the next start.
    fn leave_locked(&self, guard: &mut Option<MeshState>, tombstone: bool) -> Result<()> {
        let Some(id) = guard.as_ref().map(|s| s.current().mesh.id.clone()) else {
            return Ok(());
        };
        let dir = &self.cfg.state_dir;
        if tombstone {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("dissolved"))?;
            std::io::Write::write_all(&mut f, format!("{id}\n").as_bytes())?;
            f.sync_all()?;
        }
        write_private(&dir.join("leaving"), id.as_bytes())?;
        self.stores.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.close_tickets();
        let to = finish_leave(dir, &id)?;
        *guard = None;
        info!(logs = %to.display(), "left the mesh");
        Ok(())
    }

    /// Out of a mesh, its tickets and the join requests waiting on them are void.
    fn close_tickets(&self) {
        if let Err(e) = self.joins.reject(None) {
            warn!("closing open invites: {e:#}");
        }
    }

    /// Versions the peer lacks (see `MeshState::versions_for`).
    pub(crate) fn versions_for(&self, v: u64, hash: &str, peer: &EndpointId) -> Vec<(u64, String, String)> {
        self.state().map(|s| s.versions_for(v, hash, peer)).unwrap_or_default()
    }

    pub fn learn_addr(&self, addr: EndpointAddr) {
        let member = self
            .mesh
            .read()
            .unwrap()
            .as_ref()
            .is_some_and(|s| s.current().mesh.machine_by_id(&addr.id).is_some());
        // A member supplies its own addresses; keep a sane number.
        if !member || addr.id == self.id() || addr.is_empty() || addr.addrs.len() > 16 {
            return;
        }
        self.lookup.add_endpoint_info(addr.clone());
        let mut peers = self.peers.lock().unwrap();
        if peers.get(&addr.id) != Some(&addr) {
            peers.insert(addr.id, addr);
            if let Ok(b) = serde_json::to_vec(&*peers) {
                let _ = write_private(&self.cfg.state_dir.join("peers.json"), &b);
            }
        }
    }

    /// An address from a ticket, for a machine that isn't a member yet (the owner node).
    pub(crate) fn learn_ticket_addr(&self, addr: EndpointAddr) {
        self.lookup.add_endpoint_info(addr);
    }

    pub(crate) fn shared_with(&self, peer: &EndpointId) -> Vec<String> {
        match self.mesh.read().unwrap().as_ref() {
            Some(s) => policy::shared_boundaries(&s.current().mesh, &self.cfg.machine, peer),
            None => vec![],
        }
    }

    pub(crate) fn saw(&self, peer: &EndpointId) {
        if let Some(m) = self
            .mesh
            .read()
            .unwrap()
            .as_ref()
            .and_then(|s| s.current().mesh.machine_by_id(peer).map(|m| m.name.clone()))
        {
            self.last_seen.lock().unwrap().insert(m, now_ms());
        }
    }

    /// A completed sync with `peer`, begun at `started` (ms): it is in the mesh, so not leaving
    /// (it came back). A mark made during the sync stays: that sync was from before the leave.
    pub(crate) fn synced(&self, peer: &EndpointId, started: u64) {
        self.saw(peer);
        self.leaving.lock().unwrap().retain(|id, (_, at)| id != peer || *at > started);
    }

    /// A member said it is leaving. Only marks it; the mesh changes only when an owner signs.
    /// Whether it was marked.
    pub(crate) fn mark_leaving(&self, peer: &EndpointId) -> bool {
        let name = self
            .mesh
            .read()
            .unwrap()
            .as_ref()
            .and_then(|s| s.current().mesh.machine_by_id(peer).map(|m| m.name.clone()));
        name.map(|m| self.leaving.lock().unwrap().insert(*peer, (m, now_ms()))).is_some()
    }

    fn with_store<T>(&self, boundary: &str, f: impl FnOnce(&mut Store) -> Result<T>) -> Result<T> {
        // Held to the end (mesh, then stores, as `leave_locked`), so a leave can't clear the cache
        // between this check and the open below. `f` must not take the mesh lock again.
        let mesh = self.mesh.read().unwrap();
        let hosted = mesh
            .as_ref()
            .is_some_and(|s| s.current().mesh.hosts(&self.cfg.machine, boundary));
        ensure!(hosted, "this machine doesn't host boundary {boundary}");
        // A panic elsewhere must not take every boundary's store down with it.
        let mut stores = self.stores.lock().unwrap_or_else(|e| e.into_inner());
        if !stores.contains_key(boundary) {
            let path = self
                .cfg
                .state_dir
                .join("boundaries")
                .join(format!("{boundary}.db"));
            let store = Store::open(&path, self.cfg.max_log_mb.saturating_mul(1 << 20))?;
            if self.screening(boundary) {
                store.screen_start()?;
            }
            stores.insert(boundary.to_string(), store);
        }
        f(stores.get_mut(boundary).expect("just inserted"))
    }

    pub(crate) fn heads(&self, boundary: &str) -> Result<BTreeMap<String, u64>> {
        self.with_store(boundary, |s| s.heads())
    }

    /// Up to about `max_bytes` of the author's entries after `after`.
    pub(crate) fn entries_since(
        &self,
        boundary: &str,
        author: &str,
        after: u64,
        max_bytes: usize,
    ) -> Result<Vec<Entry>> {
        let all = self.with_store(boundary, |s| s.since(author, after, 256))?;
        let mut total = 0;
        Ok(all
            .into_iter()
            .take_while(|e| {
                total += e.envelope.len() + e.body.len() + e.sig.len();
                total <= max_bytes || total == e.envelope.len() + e.body.len() + e.sig.len()
            })
            .collect())
    }

    /// Stores entries a peer sent for `boundary`, each one through the policy check.
    pub fn receive(&self, peer: &EndpointId, boundary: &str, entries: Vec<Entry>) -> Result<usize> {
        let mesh = self.mesh()?;
        ensure!(
            policy::may_sync(&mesh, &self.cfg.machine, peer, boundary),
            "peer {} may not send boundary {boundary}",
            peer.fmt_short()
        );
        let mut new = vec![];
        let mut full = false;
        self.with_store(boundary, |s| {
            for e in &entries {
                let env = match policy::check_entry(&mesh, boundary, e) {
                    Ok(env) => env,
                    Err(err) => {
                        // The author is read from the raw envelope: an entry of a kind this
                        // build doesn't know has no typed envelope.
                        let who = serde_json::from_str::<serde_json::Value>(&e.envelope)
                            .ok()
                            .and_then(|v| v["author"].as_str()?.parse::<EndpointId>().ok())
                            .map(|a| mesh.machine_by_id(&a).map_or_else(|| a.fmt_short().to_string(), |m| m.name.clone()))
                            .unwrap_or_else(|| "an unknown machine".into());
                        // Every later entry of that machine is refused too (limit/chain-stall).
                        if self.refused.lock().unwrap().insert((boundary.into(), who.clone())) {
                            warn!("{boundary}: rejected an entry of {who}'s (sent by {}): {err:#}; its later entries are refused too", peer.fmt_short());
                        } else {
                            debug!("{boundary}: rejected an entry of {who}'s (sent by {}): {err:#}", peer.fmt_short());
                        }
                        continue;
                    }
                };
                match s.insert(e, &env) {
                    Ok(true) => new.push((e.id(), env)),
                    Ok(false) => {}
                    // A fork means the author signed two different entries with one seq.
                    Err(err) if err.to_string().starts_with("fork") => {
                        warn!("{boundary}: {err:#} (sent by {})", peer.fmt_short())
                    }
                    Err(err) => {
                        full |= err.to_string().starts_with("boundary log is full");
                        debug!("not stored: {err:#}")
                    }
                }
            }
            Ok(())
        })?;
        if full {
            self.warn_once(format!(
                "boundary {boundary}'s log is full ({} MB): mail for it is not being stored; raise max_log_mb",
                self.cfg.max_log_mb
            ));
        }
        for (id, env) in &new {
            self.announce(&mesh, boundary, id, env);
        }
        Ok(new.len())
    }

    /// Tells the steward about letters for local mailboxes nobody holds.
    fn announce(&self, mesh: &Mesh, boundary: &str, id: &str, env: &Envelope) {
        if !policy::visible(mesh, &self.cfg.machine, env) || !env.kind.is_letter() {
            return;
        }
        if self.needs_screening(boundary, env)
            && !self
                .with_store(boundary, |s| s.screened_ok(id))
                .unwrap_or(false)
        {
            let _ = self.events.send(Event::Screen {
                boundary: boundary.into(),
            });
            return;
        }
        // A claim says "hold on": it never wakes anyone.
        if env.kind == Kind::Claim {
            return;
        }
        for to in &env.to {
            let Some((mailbox, host)) = parse_address(to) else {
                continue;
            };
            if host != self.cfg.machine || env.from == *to || self.held(boundary, mailbox) {
                continue;
            }
            let _ = self.events.send(Event::Mail(MailEvent {
                boundary: boundary.into(),
                mailbox: mailbox.into(),
                id: id.into(),
                from: env.from.clone(),
                subject: env.subject.clone(),
                trust: env.label.trust,
            }));
        }
    }

    pub(crate) fn emit(&self, ev: Event) -> bool {
        self.events.send(ev).is_ok()
    }

    /// Syncs with every machine that shares a boundary with this one; on a dissolved node, with
    /// the machines of the last open version, to hand them the closed one. Returns the names of
    /// the machines it completed a session with.
    pub async fn sync_all(self: &Arc<Self>) -> Vec<String> {
        let peers: Vec<(EndpointId, String)> = match self.mesh.read().unwrap().as_ref() {
            Some(s) if s.current().mesh.closed => match s.history.len().checked_sub(2) {
                Some(i) => s.history[i]
                    .mesh
                    .machines
                    .iter()
                    .filter(|x| x.id != self.id())
                    .map(|x| (x.id, x.name.clone()))
                    .collect(),
                None => vec![],
            },
            Some(s) => {
                let m = &s.current().mesh;
                m.machines
                    .iter()
                    .filter(|x| !policy::shared_boundaries(m, &self.cfg.machine, &x.id).is_empty())
                    .map(|x| (x.id, x.name.clone()))
                    .collect()
            }
            None => return vec![],
        };
        let mut set = JoinSet::new();
        for (p, name) in peers {
            let n = self.clone();
            set.spawn(async move {
                match tokio::time::timeout(Duration::from_secs(30), sync::initiate(&n, p)).await {
                    Ok(Ok(())) => return Some(name),
                    Ok(Err(e)) => debug!("sync with {}: {e:#}", p.fmt_short()),
                    Err(_) => debug!("sync with {}: timed out", p.fmt_short()),
                }
                None
            });
        }
        set.join_all().await.into_iter().flatten().collect()
    }

    // ---- what sessions can do (boundary comes from the OS user, never from the request) ----

    /// A letter from a session, with member trust.
    pub fn post(
        &self,
        boundary: &str,
        mailbox: &str,
        to: Vec<String>,
        subject: String,
        body: String,
        thread: Option<String>,
    ) -> Result<String> {
        self.post_as(
            boundary,
            mailbox,
            Trust::Member,
            Kind::Info,
            to,
            subject,
            body,
            thread,
        )
    }

    /// Writes one entry: a letter, an offer, a bio or a status record.
    #[allow(clippy::too_many_arguments)]
    pub fn post_as(
        &self,
        boundary: &str,
        mailbox: &str,
        trust: Trust,
        kind: Kind,
        to: Vec<String>,
        subject: String,
        body: String,
        thread: Option<String>,
    ) -> Result<String> {
        Ok(self.post_with(boundary, mailbox, trust, kind, to, subject, body, thread, None)?.0)
    }

    /// `post_as`, plus: no recipient with a thread goes to the sender of the letter the thread
    /// names, and a key (`idem`) this mailbox used in the last 24 hours writes nothing and returns
    /// the first letter's id with true.
    #[allow(clippy::too_many_arguments)]
    pub fn post_with(
        &self,
        boundary: &str,
        mailbox: &str,
        trust: Trust,
        kind: Kind,
        to: Vec<String>,
        subject: String,
        body: String,
        thread: Option<String>,
        idem: Option<&str>,
    ) -> Result<(String, bool)> {
        ensure!(valid_name(mailbox), "bad mailbox name {mailbox:?}");
        let mesh = self.mesh()?;
        // What was asked, as given: the key's second half.
        let asked = hash_hex(serde_json::to_string(&(&to, &subject, &body, &thread))?.as_bytes());
        let to = match (&thread, to.is_empty()) {
            (Some(t), true) => self.with_store(boundary, |s| {
                let env = s
                    .get(t)?
                    .filter(|r| r.env.kind.is_letter() && self.shown(&mesh, boundary, s, r))
                    .with_context(|| format!("no letter {t} in this boundary"))?
                    .env;
                // Your own letter: the answer goes on to whoever it was addressed to.
                Ok(if env.from == format!("{mailbox}@{}", self.cfg.machine) { env.to } else { vec![env.from] })
            })?,
            _ => to,
        };
        ensure!(
            !to.is_empty() && to.len() <= MAX_TO,
            "1-{MAX_TO} recipients"
        );
        ensure!(
            subject.chars().count() <= MAX_SUBJECT,
            "subject is over {MAX_SUBJECT} characters"
        );
        ensure!(body.len() <= MAX_BODY, "body is over {MAX_BODY} bytes");
        policy::check_recipients(&mesh, boundary, &to)?;
        if kind.is_letter() {
            policy::check_converse(&mesh, &self.cfg.machine, &to)?;
        }
        let me = self.cfg.machine.clone();
        let (id, env) = self.with_store(boundary, |s| {
            const DAY_MS: u64 = 24 * 3600 * 1000;
            if let Some(k) = idem
                && let Some((id, what)) = s.idem(mailbox, k, now_ms().saturating_sub(DAY_MS))?
            {
                ensure!(what == asked, "this key was already used for a different message; use a new key");
                return Ok((id, None));
            }
            let thread = match thread {
                Some(t) => {
                    let root = s
                        .get(&t)?
                        .filter(|r| r.env.kind.is_letter() && self.shown(&mesh, boundary, s, r))
                        .with_context(|| format!("no letter {t} in this boundary"))?;
                    let root = root.env.thread.clone().unwrap_or(root.id);
                    let n = s.thread_len(&root)?;
                    ensure!(
                        n < self.cfg.max_thread_len,
                        "thread {} has reached {n} letters (the limit); start a new thread",
                        root.get(..10).unwrap_or(&root)
                    );
                    Some(root)
                }
                None => None,
            };
            // Last of the checks, so a refused post doesn't use one of the hour's posts.
            ensure!(
                crate::within_budget(
                    self.posts
                        .lock()
                        .unwrap()
                        .entry(boundary.into())
                        .or_default(),
                    self.cfg.max_posts_per_hour,
                    Instant::now()
                ),
                "boundary {boundary} has reached {} posts this hour on this machine",
                self.cfg.max_posts_per_hour
            );
            let (seq, prev) = match s.head(&self.id())? {
                Some((seq, id)) => (seq + 1, Some(id)),
                None => (1, None),
            };
            let env = Envelope {
                v: 2,
                mesh: mesh.id.clone(),
                boundary: boundary.into(),
                author: self.id(),
                seq,
                prev,
                ts: now_ms(),
                from: format!("{mailbox}@{me}"),
                to,
                thread,
                subject,
                body_hash: hash_hex(body.as_bytes()),
                body_len: body.len() as u64,
                label: policy::post_label(boundary, trust),
                kind,
            };
            let entry = Entry::sign(&env, body, &self.key)?;
            let env = policy::check_entry(&mesh, boundary, &entry)?;
            s.insert(&entry, &env)?;
            if let Some(k) = idem {
                s.set_idem(mailbox, k, &entry.id(), now_ms(), &asked)?;
            }
            Ok((entry.id(), Some(env)))
        })?;
        let Some(env) = env else {
            return Ok((id, true));
        };
        self.announce(&mesh, boundary, &id, &env);
        self.sync_now.notify_one();
        Ok((id, false))
    }

    /// "Working on it", to the sender of the letter `thread` names, in its thread.
    pub fn claim(
        &self,
        boundary: &str,
        mailbox: &str,
        trust: Trust,
        thread: String,
        expect_secs: Option<u64>,
        note: Option<String>,
    ) -> Result<String> {
        ensure!(expect_secs.is_none_or(|s| s <= 99_999_999), "expect_secs is at most 99999999 (8 digits)");
        let subject = note.unwrap_or_else(|| "working on it".into());
        let body = expect_secs.map(|s| s.to_string()).unwrap_or_default();
        self.post_as(boundary, mailbox, trust, Kind::Claim, vec![], subject, body, Some(thread))
    }

    /// The newest status record of each address in the boundary, by address.
    fn statuses(&self, boundary: &str) -> Result<BTreeMap<String, AgentStatus>> {
        let mut by = BTreeMap::new();
        for st in self.with_store(boundary, |s| s.newest_per_sender(Kind::Status))? {
            let m: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&st.body).unwrap_or_default();
            let a = AgentStatus {
                address: st.env.from.clone(),
                about: m.get("about").and_then(|v| v.as_str()).map(String::from),
                task: Some(st.env.subject).filter(|t| !t.is_empty()),
                pending_questions: m.get("pending_questions").and_then(|v| v.as_u64()),
                updated_ms: st.env.ts,
            };
            by.insert(st.env.from, a);
        }
        Ok(by)
    }

    /// Merges the given fields into this mailbox's newest status record and writes it whole; an
    /// empty `about` or `task` clears it. With nothing given, returns the record and writes nothing.
    pub fn set_status(
        &self,
        boundary: &str,
        mailbox: &str,
        trust: Trust,
        about: Option<String>,
        task: Option<String>,
        pending_questions: Option<u64>,
    ) -> Result<serde_json::Value> {
        let addr = format!("{mailbox}@{}", self.cfg.machine);
        let _one_at_a_time = self.status_lock.lock().unwrap();
        let cur = self.statuses(boundary)?.remove(&addr);
        if about.is_none() && task.is_none() && pending_questions.is_none() {
            return Ok(serde_json::to_value(cur)?);
        }
        let cur = cur.unwrap_or_default();
        let mut body = serde_json::Map::new();
        if let Some(a) = about.or(cur.about).filter(|a| !a.is_empty()) {
            body.insert("about".into(), a.into());
        }
        if let Some(p) = pending_questions.or(cur.pending_questions) {
            body.insert("pending_questions".into(), p.into());
        }
        let body = serde_json::to_string(&body)?;
        policy::check_status(&body)?;
        let subject = task.or(cur.task).unwrap_or_default();
        let id = self.post_as(boundary, mailbox, trust, Kind::Status, vec!["*".into()], subject, body, None)?;
        Ok(serde_json::json!({ "id": id }))
    }

    pub fn inbox(&self, boundary: &str, mailbox: &str, all: bool) -> Result<Vec<Letter>> {
        self.inbox_thread(boundary, mailbox, all, None)
    }

    /// The inbox, narrowed to one thread when `thread` names any letter of it (one this mailbox
    /// sent too).
    pub fn inbox_thread(&self, boundary: &str, mailbox: &str, all: bool, thread: Option<&str>) -> Result<Vec<Letter>> {
        let mesh = self.mesh()?;
        let addr = format!("{mailbox}@{}", self.cfg.machine);
        self.with_store(boundary, |s| {
            let root = match thread {
                Some(t) => {
                    let st = s
                        .get(t)?
                        .filter(|st| st.env.kind.is_letter() && self.shown(&mesh, boundary, s, st))
                        .with_context(|| format!("no letter {t} in this boundary"))?;
                    Some(st.env.thread.unwrap_or(st.id))
                }
                None => None,
            };
            Ok(s.mail_for(mailbox, &addr, Seen::Read)?
                .into_iter()
                .filter(|(st, read)| {
                    (all || !read)
                        && root.as_ref().is_none_or(|r| st.id == *r || st.env.thread.as_ref() == Some(r))
                        && self.shown(&mesh, boundary, s, st)
                })
                .map(|(st, read)| letter(st, read, false))
                .collect())
        })
    }

    /// Any letter this machine delivers in the session's own boundary, by id or prefix. Marks it
    /// read for the mailbox.
    pub fn read(&self, boundary: &str, mailbox: &str, id: &str) -> Result<Letter> {
        let mesh = self.mesh()?;
        self.with_store(boundary, |s| {
            let st = s
                .get(id)?
                .filter(|st| {
                    st.env.kind.is_letter() && self.shown(&mesh, boundary, s, st)
                })
                .with_context(|| format!("no letter {id} in this boundary"))?;
            s.mark(mailbox, &st.id, Seen::Read)?;
            Ok(letter(st, true, true))
        })
    }

    /// Unread letters the mailbox hasn't been told about yet; marks them told.
    pub fn notify(&self, boundary: &str, mailbox: &str) -> Result<Vec<Letter>> {
        let mesh = self.mesh()?;
        let addr = format!("{mailbox}@{}", self.cfg.machine);
        self.with_store(boundary, |s| {
            let told = s.mail_for(mailbox, &addr, Seen::Notified)?;
            let read: HashMap<String, bool> = s
                .mail_for(mailbox, &addr, Seen::Read)?
                .into_iter()
                .map(|(st, r)| (st.id, r))
                .collect();
            let mut out = vec![];
            for (st, notified) in told {
                if notified
                    || read.get(&st.id).copied().unwrap_or(false)
                    || !self.shown(&mesh, boundary, s, &st)
                {
                    continue;
                }
                s.mark(mailbox, &st.id, Seen::Notified)?;
                out.push(letter(st, false, false));
            }
            Ok(out)
        })
    }

    /// Whether a letter in a screened boundary must wait for a verdict: one from another machine,
    /// or a guest's (the connector writes those on this machine).
    fn needs_screening(&self, boundary: &str, env: &Envelope) -> bool {
        env.kind.is_letter()
            && self.screening(boundary)
            && (env.author != self.id() || env.label.trust == Trust::Guest)
    }

    pub fn screening(&self, boundary: &str) -> bool {
        self.cfg.screen.iter().any(|b| b == boundary)
    }

    /// The one rule for showing a letter to sessions, hooks, wakes and tools: the converse grant,
    /// and, where screening applies, a clean or released verdict. A store error hides it.
    fn shown(&self, mesh: &Mesh, boundary: &str, s: &Store, st: &Stored) -> bool {
        policy::visible(mesh, &self.cfg.machine, &st.env)
            && (!self.needs_screening(boundary, &st.env) || s.screened_ok(&st.id).unwrap_or(false))
    }

    /// Letters waiting for the screener, oldest first, with bodies.
    pub fn screen_next(&self, boundary: &str, limit: usize) -> Result<Vec<Letter>> {
        Ok(self
            .unscreened(boundary)?
            .into_iter()
            .take(limit)
            .map(|st| letter(st, false, true))
            .collect())
    }

    // shortcut: rescans every unscreened letter (ungranted ones never get a verdict), fine for a
    // personal mesh's volume; keep a cursor if a boundary ever holds many thousands.
    fn unscreened(&self, boundary: &str) -> Result<Vec<Stored>> {
        if !self.screening(boundary) {
            return Ok(vec![]);
        }
        let mesh = self.mesh()?;
        let all = self.with_store(boundary, |s| s.unscreened(&self.id().to_string(), &self.cfg.machine))?;
        Ok(all
            .into_iter()
            .filter(|st| self.needs_screening(boundary, &st.env) && policy::visible(&mesh, &self.cfg.machine, &st.env))
            .collect())
    }

    /// Stores the screener's verdict (`clean` or `flagged`) on a letter that waits for one.
    pub fn screen_verdict(&self, boundary: &str, id: &str, verdict: &str, reason: &str) -> Result<()> {
        ensure!(
            verdict == "clean" || verdict == "flagged",
            "a verdict is clean or flagged"
        );
        let mesh = self.mesh()?;
        let reason: String = reason.chars().take(500).collect();
        let st = self.with_store(boundary, |s| {
            let st = s
                .get(id)?
                .filter(|st| self.needs_screening(boundary, &st.env))
                .with_context(|| format!("no letter {id} waits for screening"))?;
            ensure!(
                s.set_verdict(&st.id, verdict, &reason, now_ms())?,
                "letter {id} already has a verdict"
            );
            Ok(st)
        })?;
        if verdict == "clean" {
            self.announce(&mesh, boundary, &st.id, &st.env);
        }
        Ok(())
    }

    /// Flagged letters, and how many still wait for the screener.
    pub fn quarantine(&self, boundary: &str) -> Result<(Vec<Flagged>, usize)> {
        let flagged = self
            .with_store(boundary, |s| s.flagged())?
            .into_iter()
            .map(|(st, reason, ts)| Flagged {
                id: st.id,
                from: st.env.from,
                subject: st.env.subject,
                reason,
                ts,
            })
            .collect();
        Ok((flagged, self.unscreened(boundary)?.len()))
    }

    /// One flagged letter with its body, for a person to look at.
    pub fn quarantined(&self, boundary: &str, id: &str) -> Result<Letter> {
        self.with_store(boundary, |s| {
            let st = s.get(id)?.with_context(|| format!("no letter {id}"))?;
            ensure!(
                s.flagged()?.iter().any(|(f, _, _)| f.id == st.id),
                "letter {id} isn't in quarantine"
            );
            Ok(letter(st, false, true))
        })
    }

    /// Flagged -> released: sessions see the letter from now on.
    pub fn release(&self, boundary: &str, id: &str) -> Result<String> {
        let mesh = self.mesh()?;
        let st = self.with_store(boundary, |s| {
            let st = s.get(id)?.with_context(|| format!("no letter {id}"))?;
            ensure!(s.release(&st.id, now_ms())?, "letter {id} isn't in quarantine");
            Ok(st)
        })?;
        self.announce(&mesh, boundary, &st.id, &st.env);
        Ok(st.id)
    }

    /// The latest entry of `kind` per (machine, subject) in a boundary: current offers or bios.
    pub fn latest(&self, boundary: &str, kind: Kind) -> Result<Vec<(String, Stored)>> {
        let mesh = self.mesh()?;
        let all = self.with_store(boundary, |s| s.of_kind(kind))?;
        let mut by: BTreeMap<(String, String), Stored> = BTreeMap::new();
        for st in all {
            let Some(m) = mesh.machine_by_id(&st.env.author) else {
                continue;
            };
            by.insert((m.name.clone(), st.env.subject.clone()), st);
        }
        Ok(by.into_iter().map(|((m, _), st)| (m, st)).collect())
    }

    pub fn who(&self, boundary: &str, mailbox: &str) -> Result<Who> {
        let mesh = self.mesh()?;
        let seen = self.last_seen.lock().unwrap().clone();
        let me = &self.cfg.machine;
        use crate::mesh::Category;
        // A bio is the machine talking to this one, so it needs a converse grant like a letter.
        // Offers are listed where this machine may call them (and its own).
        let bios: HashMap<String, String> = self
            .latest(boundary, Kind::Bio)?
            .into_iter()
            .filter(|(m, _)| mesh.allows(m, me, Category::Converse))
            .map(|(m, st)| (m, st.body))
            .collect();
        let mut offers: HashMap<String, Vec<String>> = HashMap::new();
        for (m, st) in self.latest(boundary, Kind::Offer)? {
            if (m == *me || mesh.allows(me, &m, Category::Tools))
                && crate::offer::Offer::parse(&st.body).is_ok_and(|o| !o.withdrawn)
            {
                offers.entry(m).or_default().push(st.env.subject);
            }
        }
        let machines = mesh
            .machines
            .iter()
            .filter(|m| m.boundaries.iter().any(|b| b == boundary))
            .map(|m| PeerInfo {
                name: m.name.clone(),
                this_machine: m.name == self.cfg.machine,
                last_sync_ms: seen.get(&m.name).copied(),
                bio: bios.get(&m.name).cloned(),
                offers: offers.remove(&m.name).unwrap_or_default(),
            })
            .collect();
        let mut addresses: Vec<String> = self
            .with_store(boundary, |s| s.senders())?
            .into_iter()
            .filter(|a| {
                parse_address(a).is_some_and(|(_, host)| mesh.allows(host, me, Category::Converse))
            })
            .collect();
        let mut held = vec![];
        for ((b, mb), n) in self.holders.lock().unwrap().iter() {
            let a = format!("{mb}@{me}");
            if b == boundary && *n > 0 {
                held.push(a.clone());
            }
            if b == boundary && !addresses.contains(&a) {
                addresses.push(a);
            }
        }
        addresses.sort();
        held.sort();
        Ok(Who {
            you: format!("{mailbox}@{me}"),
            boundary: boundary.into(),
            machines,
            addresses,
            held,
            // Like a bio: shown only where its machine may mail this one.
            status: self
                .statuses(boundary)?
                .into_values()
                .filter(|a| parse_address(&a.address).is_some_and(|(_, host)| mesh.allows(host, me, Category::Converse)))
                .collect(),
        })
    }

    /// Join requests waiting for the person to approve them.
    pub fn joins_pending(&self) -> Vec<join::PendingInfo> {
        self.joins.pending()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    /// Events for one boundary only.
    pub fn events_for(&self, ev: &Event, boundary: &str) -> bool {
        ev.boundary() == boundary
    }

    pub fn hold(self: &Arc<Self>, boundary: &str, mailbox: &str) -> HoldGuard {
        let key = (boundary.to_string(), mailbox.to_string());
        *self.holders.lock().unwrap().entry(key.clone()).or_default() += 1;
        HoldGuard {
            node: self.clone(),
            key,
        }
    }

    pub fn held(&self, boundary: &str, mailbox: &str) -> bool {
        self.holders
            .lock()
            .unwrap()
            .get(&(boundary.to_string(), mailbox.to_string()))
            .is_some_and(|n| *n > 0)
    }

    // ---- admin ----

    pub fn status(&self) -> Status {
        let guard = self.mesh.read().unwrap().clone();
        let mut warnings = self.warnings.lock().unwrap().clone();
        let seen = self.last_seen.lock().unwrap().clone();
        let dissolved = guard.as_ref().map(|s| &s.current().mesh).filter(|m| m.closed).map(|m| m.name.clone());
        let (mesh, peers, hosts) = match &guard {
            Some(_) if dissolved.is_some() => {
                warnings.push(format!(
                    "mesh {} was dissolved; create or join another mesh (this one's logs move aside)",
                    dissolved.as_deref().unwrap_or_default()
                ));
                (None, vec![], vec![])
            }
            Some(s) => {
                let c = s.current();
                let hosts = c
                    .mesh
                    .machine(&self.cfg.machine)
                    .map(|m| m.boundaries.clone())
                    .unwrap_or_default();
                if hosts.is_empty() {
                    warnings.push("the adopted membership file doesn't list this machine; it has been revoked or renamed".into());
                }
                let peers = c
                    .mesh
                    .machines
                    .iter()
                    .filter(|m| m.name != self.cfg.machine)
                    .map(|m| PeerInfo {
                        name: m.name.clone(),
                        last_sync_ms: seen.get(&m.name).copied(),
                        ..Default::default()
                    })
                    .collect();
                let info = MeshInfo {
                    id: c.mesh.id.clone(),
                    name: c.mesh.name.clone(),
                    version: c.mesh.version,
                    hash: c.hash.clone(),
                    owners: c
                        .mesh
                        .owner_keys()
                        .map(|ks| {
                            ks.iter()
                                .map(|k| k.fingerprint(Default::default()).to_string())
                                .collect()
                        })
                        .unwrap_or_default(),
                    hosts: hosts.clone(),
                    release: c.mesh.settings.release.clone(),
                };
                (Some(info), peers, hosts)
            }
            None => {
                warnings.push("no mesh yet".into());
                (None, vec![], vec![])
            }
        };
        for (user, b) in &self.cfg.users {
            if guard.is_some() && dissolved.is_none() && !hosts.contains(b) {
                warnings.push(format!(
                    "user {user} maps to boundary {b}, which this machine doesn't host"
                ));
            }
        }
        let leaving = {
            let mut l = self.leaving.lock().unwrap();
            let current = guard.as_ref().filter(|_| dissolved.is_none()).map(|s| &s.current().mesh);
            l.retain(|id, (n, _)| current.and_then(|m| m.machine_by_id(id)).is_some_and(|m| m.name == *n));
            let mut v: Vec<String> = l.values().map(|(n, _)| n.clone()).collect();
            v.sort();
            v
        };
        let unmapped = hosts.iter().filter(|b| !self.cfg.users.values().any(|u| u == *b)).cloned().collect();
        let entries = hosts
            .iter()
            .filter_map(|b| Some((b.clone(), self.with_store(b, |s| s.count()).ok()?)))
            .collect();
        let screening: BTreeMap<String, ScreenCounts> = hosts
            .iter()
            .filter(|b| self.screening(b))
            .filter_map(|b| {
                let (flagged, waiting) = self.quarantine(b).ok()?;
                Some((b.clone(), ScreenCounts { waiting: waiting as u64, flagged: flagged.len() as u64 }))
            })
            .collect();
        for (b, c) in screening.iter().filter(|(_, c)| c.flagged > 0) {
            warnings.push(format!("{} letter(s) in quarantine in {b}: tearmesh quarantine --boundary {b}", c.flagged));
        }
        // A misspelt name would leave a boundary unscreened without a word.
        for b in self.cfg.screen.iter().filter(|b| !hosts.is_empty() && !hosts.contains(b)) {
            warnings.push(format!("config: screen names boundary {b}, which this machine doesn't host"));
        }
        Status {
            version: env!("CARGO_PKG_VERSION").into(),
            machine: self.cfg.machine.clone(),
            node_id: self.id(),
            mesh,
            entries,
            peers,
            pending_joins: self.joins.pending(),
            joining: self.joins.progress(),
            warnings,
            dissolved,
            unmapped,
            leaving,
            screening,
        }
    }
}

/// Whether `theirs` should replace `mine`, two different files for the same version.
fn sibling_wins(theirs: &SignedMesh, mine: &SignedMesh, longer: bool) -> bool {
    // A key this machine's version removed can't replace it.
    if !mine.mesh.has_owner(&theirs.signer) {
        return false;
    }
    // A version that removed the other's signer wins.
    if !theirs.mesh.has_owner(&mine.signer) {
        return true;
    }
    // Then a branch with versions built on it, even against a dissolve: owners who kept going
    // mean every machine must end on that branch, and nothing can be built on a closed one.
    if longer {
        return true;
    }
    // Then a dissolve, against an open tip with nothing built on it.
    if theirs.mesh.closed != mine.mesh.closed {
        return theirs.mesh.closed;
    }
    theirs.hash < mine.hash
}

pub struct HoldGuard {
    node: Arc<Node>,
    key: (String, String),
}

impl Drop for HoldGuard {
    fn drop(&mut self) {
        let mut h = self.node.holders.lock().unwrap();
        if let Some(n) = h.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                h.remove(&self.key);
            }
        }
    }
}

fn letter(st: Stored, read: bool, with_body: bool) -> Letter {
    Letter {
        id: st.id,
        from: st.env.from,
        to: st.env.to,
        subject: st.env.subject,
        thread: st.env.thread,
        ts: st.env.ts,
        read,
        kind: st.env.kind,
        trust: st.env.label.trust,
        size: st.body.len() as u64,
        expect_secs: if st.env.kind == Kind::Claim { st.body.parse().ok() } else { None },
        body: with_body.then_some(st.body),
    }
}

pub fn load_or_create_key(dir: &Path) -> Result<SecretKey> {
    let path = dir.join("node.key");
    match std::fs::read_to_string(&path) {
        Ok(s) => s
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = SecretKey::generate();
            std::fs::create_dir_all(dir)?;
            write_private(&path, crate::envelope::hex(&key.to_bytes()).as_bytes())?;
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::{Change, Machine, next_version};

    const KEYS: [&str; 3] = [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEh1s2NuBoKhxcvWTjGSNaub4y0oVf2jVMCY6/Vte2+7 a",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHbEX1BV4qNsFeEx/SwLH8TpPC0RDcmOCYdkRWTe/boC b",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM4Q3wip7DK3EhN5Y2JI0ofQxH/h9hK7Bzx5ZhALfUi1 c",
    ];

    /// A stored version as `adopt` would leave it, without a real signature.
    fn signed(toml: String, signer: &str) -> SignedMesh {
        SignedMesh {
            mesh: Mesh::parse(&toml).unwrap(),
            hash: crate::mesh::hash(&toml),
            toml,
            sig: String::new(),
            signer: ssh_key::PublicKey::from_openssh(signer).unwrap().key_data().clone(),
        }
    }

    fn v1(machines: &[(&str, EndpointId)]) -> String {
        let mut m = Mesh::new("home", vec![KEYS[0].into(), KEYS[1].into()], vec!["work".into()], None).unwrap();
        for (name, id) in machines {
            let machine = Machine { name: (*name).into(), id: *id, boundaries: vec!["work".into()] };
            m.add_machine(machine, false).unwrap();
        }
        m.to_toml().unwrap()
    }

    /// A store operation holds the mesh lock, so a leave waits for it, and the log it opened is
    /// dropped by the leave, not cached past it.
    #[tokio::test]
    async fn a_leave_waits_for_a_store_operation() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::new("ws");
        cfg.state_dir = dir.path().join("ws");
        cfg.socket = dir.path().join("ws.sock");
        cfg.network = crate::config::Network {
            relay: Some(Relay::Preset("none".into())),
            lookup: Some(vec![]),
            bind: Some("127.0.0.1:0".parse().unwrap()),
        };
        let node = Node::start(cfg).await.unwrap();
        *node.mesh.write().unwrap() = Some(MeshState { history: vec![signed(v1(&[("ws", node.id())]), KEYS[0])] });
        let stores = node.stores.lock().unwrap();
        let reader = std::thread::spawn({
            let n = node.clone();
            move || n.heads("work").is_ok()
        });
        std::thread::sleep(Duration::from_millis(200));
        let leaver = std::thread::spawn({
            let n = node.clone();
            move || n.leave().is_ok()
        });
        std::thread::sleep(Duration::from_millis(200));
        assert!(!node.cfg.state_dir.join("leaving").exists(), "the leave waits for the store operation");
        drop(stores);
        assert!(reader.join().unwrap() && leaver.join().unwrap());
        assert!(node.stores.lock().unwrap().is_empty(), "no log of the mesh it left stays open");
        node.shutdown().await;
    }

    #[test]
    fn removed_machines_get_versions_up_to_their_removal() {
        let [a, b, c, stranger] = [1u8, 2, 3, 4].map(|i| SecretKey::from_bytes(&[i; 32]).public());
        // v2 removes c, v3 removes b, v4 dissolves the mesh.
        let mut tomls = vec![v1(&[("a", a), ("b", b), ("c", c)])];
        for ch in [Change::RemoveMachine("c".into()), Change::RemoveMachine("b".into()), Change::Dissolve] {
            let (_, t, _) = next_version(tomls.last().unwrap(), &[ch]).unwrap();
            tomls.push(t);
        }
        let all: Vec<SignedMesh> = tomls.into_iter().map(|t| signed(t, KEYS[0])).collect();
        let upto = |n: usize| MeshState { history: all[..n].to_vec() };
        let sent = |s: &MeshState, v: u64, peer: &EndpointId| -> Vec<u64> {
            s.versions_for(v, &s.at(v).unwrap().hash, peer).iter().map(|x| x.0).collect()
        };

        let open = upto(3);
        assert_eq!(
            [a, b, c, stranger].map(|x| open.removed_at(&x)),
            [None, Some(3), Some(2), None]
        );
        assert_eq!(sent(&open, 1, &a), [2, 3], "a member gets every version");
        assert_eq!(sent(&open, 1, &c), [2], "a removed machine only up to its removal");
        assert!(sent(&open, 2, &c).is_empty(), "and nothing once it has that one");
        assert_eq!(sent(&open, 1, &b), [2, 3]);
        assert!(sent(&open, 1, &stranger).is_empty(), "a machine never in the mesh gets nothing");
        assert!(open.versions_for(1, "other", &stranger).is_empty());

        let closed = upto(4);
        assert_eq!(closed.removed_at(&a), Some(4), "dissolving removes every machine");
        assert_eq!(sent(&closed, 3, &a), [4]);
        assert_eq!(sent(&closed, 1, &c), [2], "c still gets nothing past its own removal");
    }

    #[test]
    fn a_closed_sibling_wins_after_the_removed_signer_and_longer_rules() {
        let first = v1(&[]);
        let (_, open, _) = next_version(&first, &[Change::AddBoundary("lab".into())]).unwrap();
        let (_, closed, _) = next_version(&first, &[Change::Dissolve]).unwrap();
        let (o, c) = (signed(open, KEYS[0]), signed(closed.clone(), KEYS[1]));
        assert!(sibling_wins(&c, &o, false) && !sibling_wins(&o, &c, false), "closed beats an open tip");
        assert!(sibling_wins(&o, &c, true), "but not an open branch with versions built on it");

        // A version by a, removing b's key, still beats b's dissolve.
        let fp = ssh_key::PublicKey::from_openssh(KEYS[1]).unwrap().fingerprint(Default::default()).to_string();
        let (_, t, _) =
            next_version(&first, &[Change::OwnerAdd(KEYS[2].into()), Change::OwnerRemove(fp)]).unwrap();
        let r = signed(t, KEYS[0]);
        assert!(!sibling_wins(&c, &r, false) && sibling_wins(&r, &c, false));
    }
}
