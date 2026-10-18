//! The daemon's core: the node key, the adopted membership file and its history, one store per
//! hosted boundary and the iroh endpoint. The socket, MCP server, hooks and steward all go through it.

use std::collections::{BTreeMap, HashMap, VecDeque};
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
use crate::{bridge, join, now_ms, policy, shell, sync, valid_name};

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
}

impl Event {
    fn boundary(&self) -> &str {
        match self {
            Event::Mail(m) => &m.boundary,
            Event::Open { boundary, .. } => boundary,
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
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Who {
    pub you: String,
    pub boundary: String,
    pub machines: Vec<PeerInfo>,
    /// Addresses that have sent mail in this boundary, plus mailboxes held here now.
    pub addresses: Vec<String>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub machine: String,
    pub node_id: EndpointId,
    pub mesh: Option<MeshInfo>,
    pub entries: BTreeMap<String, u64>,
    pub peers: Vec<PeerInfo>,
    pub pending_joins: Vec<join::PendingInfo>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshInfo {
    pub id: String,
    pub name: String,
    pub version: u64,
    pub hash: String,
    pub owners: Vec<String>,
    pub hosts: Vec<String>,
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
    sync_now: Notify,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    posts: Mutex<HashMap<String, VecDeque<Instant>>>,
    warnings: Mutex<Vec<String>>,
    pub(crate) joins: Arc<join::Joins>,
    pub(crate) streams: bridge::Streams,
}

/// Admits members on the sync, tool and shell protocols, and strangers only on the join protocol
/// while an invite is open. Applies to connections in both directions.
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
        let member = self.mesh.read().unwrap().as_ref().is_some_and(|s| {
            s.current()
                .mesh
                .machine_by_id(&conn.remote_id())
                .is_some()
        });
        let alpn = conn.alpn();
        let ok = if alpn == join::ALPN {
            conn.side() == Side::Client || self.joins.open()
        } else {
            member && [sync::ALPN, bridge::ALPN, shell::ALPN].contains(&alpn)
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
    for (v, f) in it {
        match SignedMesh::verify_next(&f.toml, &f.sig, history.last().expect("non-empty")) {
            Ok(s) => history.push(s),
            Err(e) => {
                warn!("stored mesh version {v} doesn't follow the one before; ignoring it and later ones: {e:#}");
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
        let state = load_history(dir)?;
        let settings = state
            .as_ref()
            .map(|s| s.current().mesh.settings.clone())
            .unwrap_or_default();
        let mesh = Arc::new(RwLock::new(state));
        let joins = Arc::new(join::Joins::default());

        let lookup = MemoryLookup::new();
        let mut b = Endpoint::builder(presets::Minimal)
            .secret_key(key.clone())
            .alpns(vec![
                sync::ALPN.to_vec(),
                join::ALPN.to_vec(),
                bridge::ALPN.to_vec(),
                shell::ALPN.to_vec(),
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
        b = b.relay_mode(match cfg.network.relay.as_ref().unwrap_or(&settings.relays) {
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
        });
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
            sync_now: Notify::new(),
            tasks: Mutex::new(vec![]),
            posts: Mutex::new(HashMap::new()),
            warnings: Mutex::new(vec![]),
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
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(every) => {}
                    _ = n.sync_now.notified() => {}
                }
                n.sync_all().await;
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
    /// list this machine with this node id, and, after a `mesh reset`, keep the mesh's id.
    pub fn adopt_first(&self, toml: &str, sig: &str) -> Result<u64> {
        let mut guard = self.mesh.write().unwrap();
        ensure!(guard.is_none(), "this machine already has a mesh");
        let s = SignedMesh::verify_first(toml, sig)?;
        ensure!(
            s.mesh
                .machine(&self.cfg.machine)
                .is_some_and(|m| m.id == self.id()),
            "the membership file doesn't list this machine ({}) with this node id ({})",
            self.cfg.machine,
            self.id()
        );
        let id_file = self.cfg.state_dir.join("mesh-id");
        if let Ok(old) = std::fs::read_to_string(&id_file) {
            ensure!(
                old.trim() == s.mesh.id,
                "this machine was reset from mesh {}; a file for mesh {} would strand its logs",
                old.trim(),
                s.mesh.id
            );
        }
        write_private(&id_file, s.mesh.id.as_bytes())?;
        save_version(&self.cfg.state_dir, &s)?;
        let v = s.mesh.version;
        info!(version = v, "adopted the mesh");
        *guard = Some(MeshState { history: vec![s] });
        drop(guard);
        self.sync_now.notify_one();
        Ok(v)
    }

    /// Adopts later versions, each `(declared version, toml, sig)`, in order. A version this
    /// machine already has with a different hash is a sibling: the lower hash wins on every
    /// machine, so a split heals the same way everywhere. Returns the current version.
    pub fn adopt(&self, files: &[(u64, String, String)]) -> Result<u64> {
        let mut files = files.to_vec();
        files.sort_by_key(|f| f.0);
        let mut guard = self.mesh.write().unwrap();
        let state = guard.as_mut().context("no mesh yet")?;
        let mut changed = false;
        for (v, toml, sig) in files.iter().take(MAX_VERSIONS) {
            let cur = state.current().mesh.version;
            if *v == cur + 1 {
                let s = SignedMesh::verify_next(toml, sig, state.current())?;
                save_version(&self.cfg.state_dir, &s)?;
                state.history.push(s);
                changed = true;
            } else if *v <= cur {
                let Some(mine) = state.at(*v) else { continue };
                let h = crate::mesh::hash(toml);
                if h == mine.hash || h > mine.hash {
                    continue;
                }
                let prev = state
                    .at(v - 1)
                    .with_context(|| format!("can't check sibling version {v}: no version {}", v - 1))?;
                let s = SignedMesh::verify_next(toml, sig, prev)?;
                let dropped: Vec<String> = state
                    .history
                    .iter()
                    .filter(|x| x.mesh.version >= *v)
                    .map(|x| format!("{} ({})", x.mesh.version, &x.hash[..12]))
                    .collect();
                state.history.retain(|x| x.mesh.version < *v);
                for d in &dropped {
                    let n = d.split(' ').next().unwrap_or_default();
                    let _ = std::fs::remove_file(self.cfg.state_dir.join("mesh").join(format!("{n}.json")));
                }
                save_version(&self.cfg.state_dir, &s)?;
                state.history.push(s);
                changed = true;
                self.warn_once(format!(
                    "two owners signed different version {v}s; the other one won (lower hash). Dropped {}; re-apply those changes on top of the current version",
                    dropped.join(", ")
                ));
            } else {
                bail!("version {v} doesn't follow {cur}; missing the versions between");
            }
        }
        let cur = state.current().clone();
        drop(guard);
        if changed {
            info!(version = cur.mesh.version, "adopted mesh version");
            self.joins.on_adopt(&cur);
            self.sync_now.notify_one();
        }
        Ok(cur.mesh.version)
    }

    /// `mesh apply` from the admin socket: a first file, or the next version.
    pub fn apply(&self, toml: &str, sig: &str) -> Result<u64> {
        if self.mesh.read().unwrap().is_none() {
            return self.adopt_first(toml, sig);
        }
        let v = Mesh::parse(toml)?.version;
        self.adopt(&[(v, toml.into(), sig.into())])
    }

    /// Forgets the adopted membership file (logs stay) so the next one is adopted as a first one:
    /// the re-pin after losing every owner key. Only from this machine's admin socket.
    pub fn reset(&self) -> Result<()> {
        let mut guard = self.mesh.write().unwrap();
        let _ = std::fs::remove_dir_all(self.cfg.state_dir.join("mesh"));
        *guard = None;
        info!("forgot the mesh; adopt a new file with `tearmesh mesh apply`");
        Ok(())
    }

    /// Versions a peer at `(v, hash)` lacks, to send it. Includes this machine's file at `v` when
    /// the peer's differs, so the peer can settle the split.
    pub(crate) fn versions_for(&self, v: u64, hash: &str) -> Vec<(u64, String, String)> {
        let Ok(state) = self.state() else { return vec![] };
        let cur = state.current().mesh.version;
        let from = match state.at(v) {
            Some(mine) if mine.hash == hash => v + 1,
            Some(_) => v,
            None => return vec![],
        };
        (from..=cur)
            .take(MAX_VERSIONS)
            .filter_map(|x| state.at(x))
            .map(|s| (s.mesh.version, s.toml.clone(), s.sig.clone()))
            .collect()
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

    fn with_store<T>(&self, boundary: &str, f: impl FnOnce(&mut Store) -> Result<T>) -> Result<T> {
        let hosted = self
            .mesh
            .read()
            .unwrap()
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
            stores.insert(
                boundary.to_string(),
                Store::open(&path, self.cfg.max_log_mb << 20)?,
            );
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
        self.with_store(boundary, |s| {
            for e in &entries {
                let env = match policy::check_entry(&mesh, boundary, e) {
                    Ok(env) => env,
                    Err(err) => {
                        warn!("rejected an entry from {}: {err:#}", peer.fmt_short());
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
                    Err(err) => debug!("not stored: {err:#}"),
                }
            }
            Ok(())
        })?;
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

    pub async fn sync_all(self: &Arc<Self>) {
        let peers: Vec<EndpointId> = match self.mesh.read().unwrap().as_ref() {
            Some(s) => {
                let m = &s.current().mesh;
                m.machines
                    .iter()
                    .filter(|x| !policy::shared_boundaries(m, &self.cfg.machine, &x.id).is_empty())
                    .map(|x| x.id)
                    .collect()
            }
            None => return,
        };
        let mut set = JoinSet::new();
        for p in peers {
            let n = self.clone();
            set.spawn(async move {
                match tokio::time::timeout(Duration::from_secs(30), sync::initiate(&n, p)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => debug!("sync with {}: {e:#}", p.fmt_short()),
                    Err(_) => debug!("sync with {}: timed out", p.fmt_short()),
                }
            });
        }
        set.join_all().await;
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

    /// Writes one entry: a letter, an offer or a bio.
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
        ensure!(valid_name(mailbox), "bad mailbox name {mailbox:?}");
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
        ensure!(
            !to.is_empty() && to.len() <= MAX_TO,
            "1-{MAX_TO} recipients"
        );
        ensure!(
            subject.chars().count() <= MAX_SUBJECT,
            "subject is over {MAX_SUBJECT} characters"
        );
        ensure!(body.len() <= MAX_BODY, "body is over {MAX_BODY} bytes");
        let mesh = self.mesh()?;
        policy::check_recipients(&mesh, boundary, &to)?;
        if kind.is_letter() {
            policy::check_converse(&mesh, &self.cfg.machine, &to)?;
        }
        let me = self.cfg.machine.clone();
        let (id, env) = self.with_store(boundary, |s| {
            let thread = match thread {
                Some(t) => {
                    let root = s
                        .get(&t)?
                        .filter(|r| r.env.kind.is_letter() && policy::visible(&mesh, &me, &r.env))
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
            Ok((entry.id(), env))
        })?;
        self.announce(&mesh, boundary, &id, &env);
        self.sync_now.notify_one();
        Ok(id)
    }

    pub fn inbox(&self, boundary: &str, mailbox: &str, all: bool) -> Result<Vec<Letter>> {
        let mesh = self.mesh()?;
        let addr = format!("{mailbox}@{}", self.cfg.machine);
        self.with_store(boundary, |s| {
            Ok(s.mail_for(mailbox, &addr, Seen::Read)?
                .into_iter()
                .filter(|(st, read)| (all || !read) && policy::visible(&mesh, &self.cfg.machine, &st.env))
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
                .filter(|st| st.env.kind.is_letter() && policy::visible(&mesh, &self.cfg.machine, &st.env))
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
                    || !policy::visible(&mesh, &self.cfg.machine, &st.env)
                {
                    continue;
                }
                s.mark(mailbox, &st.id, Seen::Notified)?;
                out.push(letter(st, false, false));
            }
            Ok(out)
        })
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
        let bios: HashMap<String, String> = self
            .latest(boundary, Kind::Bio)?
            .into_iter()
            .map(|(m, st)| (m, st.body))
            .collect();
        let mut offers: HashMap<String, Vec<String>> = HashMap::new();
        for (m, st) in self.latest(boundary, Kind::Offer)? {
            if crate::offer::Offer::parse(&st.body).is_ok_and(|o| !o.withdrawn) {
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
        let me = &self.cfg.machine;
        let mut addresses: Vec<String> = self
            .with_store(boundary, |s| s.senders())?
            .into_iter()
            .filter(|a| {
                parse_address(a)
                    .is_some_and(|(_, host)| mesh.allows(host, me, crate::mesh::Category::Converse))
            })
            .collect();
        for (b, mb) in self.holders.lock().unwrap().keys() {
            let a = format!("{mb}@{me}");
            if b == boundary && !addresses.contains(&a) {
                addresses.push(a);
            }
        }
        addresses.sort();
        Ok(Who {
            you: format!("{mailbox}@{me}"),
            boundary: boundary.into(),
            machines,
            addresses,
        })
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
        let (mesh, peers, hosts) = match &guard {
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
                };
                (Some(info), peers, hosts)
            }
            None => {
                warnings.push("no mesh yet".into());
                (None, vec![], vec![])
            }
        };
        for (user, b) in &self.cfg.users {
            if guard.is_some() && !hosts.contains(b) {
                warnings.push(format!(
                    "user {user} maps to boundary {b}, which this machine doesn't host"
                ));
            }
        }
        let entries = hosts
            .iter()
            .filter_map(|b| Some((b.clone(), self.with_store(b, |s| s.count()).ok()?)))
            .collect();
        Status {
            machine: self.cfg.machine.clone(),
            node_id: self.id(),
            mesh,
            entries,
            peers,
            pending_joins: self.joins.pending(),
            warnings,
        }
    }
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
