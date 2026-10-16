//! The daemon's core: the node key, the adopted circle, one store per hosted boundary and the
//! iroh endpoint. The socket, MCP server, hooks and waker all go through it.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::address_lookup::{DnsAddressLookup, PkarrPublisher, PkarrResolver};
use iroh::endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, broadcast};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::circle::{Circle, SignedCircle};
use crate::config::{Config, Relay};
use crate::envelope::{Entry, Envelope, MAX_BODY, MAX_SUBJECT, MAX_TO, hash_hex, parse_address};
use crate::store::{Seen, Store, Stored};
use crate::{now_ms, policy, sync, valid_name};

/// New mail for a local mailbox that no session currently holds.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MailEvent {
    pub boundary: String,
    pub mailbox: String,
    pub id: String,
    pub from: String,
    pub subject: String,
}

/// A letter as shown to sessions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Letter {
    pub id: String,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub thread: Option<String>,
    pub ts: u64,
    pub read: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Who {
    pub you: String,
    pub boundary: String,
    pub machines: Vec<PeerInfo>,
    /// Addresses that have sent mail in this boundary, plus mailboxes held here now.
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub name: String,
    pub this_machine: bool,
    pub last_sync_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub machine: String,
    pub node_id: EndpointId,
    pub circle: Option<CircleInfo>,
    pub entries: BTreeMap<String, u64>,
    pub peers: Vec<PeerInfo>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircleInfo {
    pub id: String,
    pub name: String,
    pub version: u64,
    pub owners: Vec<String>,
    pub hosts: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Invite {
    v: u32,
    circle: String,
    sig: String,
    peer: EndpointAddr,
}

pub struct Node {
    pub cfg: Config,
    key: SecretKey,
    circle: Arc<RwLock<Option<SignedCircle>>>,
    stores: Mutex<HashMap<String, Store>>,
    pub endpoint: Endpoint,
    lookup: MemoryLookup,
    peers: Mutex<BTreeMap<EndpointId, EndpointAddr>>,
    events: broadcast::Sender<MailEvent>,
    holders: Mutex<HashMap<(String, String), usize>>,
    last_seen: Mutex<HashMap<String, u64>>,
    sync_now: Notify,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    posts: Mutex<HashMap<String, VecDeque<Instant>>>,
}

/// Refuses connections, in and out, with any key the adopted circle doesn't list.
#[derive(Debug)]
struct Members(Arc<RwLock<Option<SignedCircle>>>);

impl EndpointHooks for Members {
    fn after_handshake<'a>(
        &'a self,
        conn: &'a Connection,
    ) -> impl Future<Output = AfterHandshakeOutcome> + Send + 'a {
        let ok = conn.alpn() == sync::ALPN
            && self
                .0
                .read()
                .unwrap()
                .as_ref()
                .is_some_and(|c| c.circle.machine_by_id(&conn.remote_id()).is_some());
        async move {
            if ok {
                AfterHandshakeOutcome::accept()
            } else {
                AfterHandshakeOutcome::Reject {
                    error_code: 403u32.into(),
                    reason: b"not a circle member".to_vec(),
                }
            }
        }
    }
}

/// Write-then-rename with fsync, mode 0600, so a crash leaves the old file or the new one.
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// The adopted circle and its signature, stored together so they can't get out of step.
#[derive(Serialize, Deserialize)]
struct StoredCircle {
    toml: String,
    sig: String,
}

impl Node {
    pub async fn start(cfg: Config) -> Result<Arc<Node>> {
        cfg.validate()?;
        let dir = &cfg.state_dir;
        std::fs::create_dir_all(dir.join("boundaries"))
            .with_context(|| format!("creating {}", dir.display()))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        let key = load_or_create_key(dir)?;

        let circle = match std::fs::read(dir.join("circle.json")) {
            Ok(b) => {
                let c: StoredCircle = serde_json::from_slice(&b).context("stored circle")?;
                Some(SignedCircle::verify(&c.toml, &c.sig, None).context("stored circle")?)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).context("reading the stored circle"),
        };
        let circle = Arc::new(RwLock::new(circle));

        let lookup = MemoryLookup::new();
        let mut b = Endpoint::builder(presets::Minimal)
            .secret_key(key.clone())
            .alpns(vec![sync::ALPN.to_vec()])
            .hooks(Members(circle.clone()))
            .address_lookup(lookup.clone());
        if cfg.network.n0_dns {
            b = b
                .address_lookup(PkarrPublisher::n0_dns())
                .address_lookup(PkarrResolver::n0_dns())
                .address_lookup(DnsAddressLookup::n0_dns());
        }
        b = b.relay_mode(match &cfg.network.relay {
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
            circle,
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
        });

        let n = node.clone();
        let accept = tokio::spawn(async move {
            while let Some(incoming) = n.endpoint.accept().await {
                let n = n.clone();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            if let Err(e) = sync::serve(&n, conn).await {
                                debug!("inbound sync: {e:#}");
                            }
                        }
                        Err(e) => debug!("inbound connection: {e:#}"),
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

    pub fn circle(&self) -> Result<Circle> {
        Ok(self.signed()?.circle)
    }

    pub fn signed(&self) -> Result<SignedCircle> {
        self.circle
            .read()
            .unwrap()
            .clone()
            .context("no circle yet: run `tearmesh circle apply` or `tearmesh join`")
    }

    /// Adopts a newer signed circle. The first circle a machine adopts must list it.
    pub fn adopt(&self, toml: &str, sig: &str) -> Result<u64> {
        let mut guard = self.circle.write().unwrap();
        let first = guard.is_none();
        let signed = SignedCircle::verify(toml, sig, guard.as_ref().map(|s| &s.circle))?;
        if first {
            ensure!(
                signed
                    .circle
                    .machine(&self.cfg.machine)
                    .is_some_and(|m| m.id == self.id()),
                "the circle doesn't list this machine ({}) with this node id ({})",
                self.cfg.machine,
                self.id()
            );
        }
        let dir = &self.cfg.state_dir;
        let stored = StoredCircle {
            toml: signed.toml.clone(),
            sig: signed.sig.clone(),
        };
        write_private(&dir.join("circle.json"), &serde_json::to_vec(&stored)?)?;
        let v = signed.circle.version;
        info!(version = v, "adopted circle");
        *guard = Some(signed);
        drop(guard);
        self.sync_now.notify_one();
        Ok(v)
    }

    pub fn learn_addr(&self, addr: EndpointAddr) {
        let member = self
            .circle
            .read()
            .unwrap()
            .as_ref()
            .is_some_and(|c| c.circle.machine_by_id(&addr.id).is_some());
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

    pub(crate) fn shared_with(&self, peer: &EndpointId) -> Vec<String> {
        match self.circle.read().unwrap().as_ref() {
            Some(c) => policy::shared_boundaries(&c.circle, &self.cfg.machine, peer),
            None => vec![],
        }
    }

    pub(crate) fn saw(&self, peer: &EndpointId) {
        if let Some(m) = self
            .circle
            .read()
            .unwrap()
            .as_ref()
            .and_then(|c| c.circle.machine_by_id(peer).map(|m| m.name.clone()))
        {
            self.last_seen.lock().unwrap().insert(m, now_ms());
        }
    }

    fn with_store<T>(&self, boundary: &str, f: impl FnOnce(&mut Store) -> Result<T>) -> Result<T> {
        let hosted = self
            .circle
            .read()
            .unwrap()
            .as_ref()
            .is_some_and(|c| c.circle.hosts(&self.cfg.machine, boundary));
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
        let circle = self.circle()?;
        ensure!(
            policy::may_sync(&circle, &self.cfg.machine, peer, boundary),
            "peer {} may not send boundary {boundary}",
            peer.fmt_short()
        );
        let mut new = vec![];
        self.with_store(boundary, |s| {
            for e in &entries {
                let env = match policy::check_entry(&circle, boundary, e) {
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
            self.announce(boundary, id, env);
        }
        Ok(new.len())
    }

    /// Tells the waker about mail for local mailboxes nobody holds.
    fn announce(&self, boundary: &str, id: &str, env: &Envelope) {
        for to in &env.to {
            let Some((mailbox, host)) = parse_address(to) else {
                continue;
            };
            if host != self.cfg.machine || env.from == *to || self.held(boundary, mailbox) {
                continue;
            }
            let _ = self.events.send(MailEvent {
                boundary: boundary.into(),
                mailbox: mailbox.into(),
                id: id.into(),
                from: env.from.clone(),
                subject: env.subject.clone(),
            });
        }
    }

    pub async fn sync_all(self: &Arc<Self>) {
        let peers: Vec<EndpointId> = match self.circle.read().unwrap().as_ref() {
            Some(c) => c
                .circle
                .machines
                .iter()
                .filter(|m| {
                    !policy::shared_boundaries(&c.circle, &self.cfg.machine, &m.id).is_empty()
                })
                .map(|m| m.id)
                .collect(),
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

    pub fn post(
        &self,
        boundary: &str,
        mailbox: &str,
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
        let circle = self.circle()?;
        policy::check_recipients(&circle, boundary, &to)?;
        let (id, env) = self.with_store(boundary, |s| {
            let thread = match thread {
                Some(t) => {
                    let root = s
                        .get(&t)?
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
                v: 1,
                circle: circle.id.clone(),
                boundary: boundary.into(),
                author: self.id(),
                seq,
                prev,
                ts: now_ms(),
                from: format!("{mailbox}@{}", self.cfg.machine),
                to,
                thread,
                subject,
                body_hash: hash_hex(body.as_bytes()),
                body_len: body.len() as u64,
                label: policy::post_label(boundary),
            };
            let entry = Entry::sign(&env, body, &self.key)?;
            let env = policy::check_entry(&circle, boundary, &entry)?;
            s.insert(&entry, &env)?;
            Ok((entry.id(), env))
        })?;
        self.announce(boundary, &id, &env);
        self.sync_now.notify_one();
        Ok(id)
    }

    pub fn inbox(&self, boundary: &str, mailbox: &str, all: bool) -> Result<Vec<Letter>> {
        let addr = format!("{mailbox}@{}", self.cfg.machine);
        self.with_store(boundary, |s| {
            Ok(s.mail_for(mailbox, &addr, Seen::Read)?
                .into_iter()
                .filter(|(_, read)| all || !read)
                .map(|(st, read)| letter(st, read, false))
                .collect())
        })
    }

    /// Any letter in the session's own boundary, by id or prefix. Marks it read for the mailbox.
    pub fn read(&self, boundary: &str, mailbox: &str, id: &str) -> Result<Letter> {
        self.with_store(boundary, |s| {
            let st = s
                .get(id)?
                .with_context(|| format!("no letter {id} in this boundary"))?;
            s.mark(mailbox, &st.id, Seen::Read)?;
            Ok(letter(st, true, true))
        })
    }

    /// Unread letters the mailbox hasn't been told about yet; marks them told.
    pub fn notify(&self, boundary: &str, mailbox: &str) -> Result<Vec<Letter>> {
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
                if notified || read.get(&st.id).copied().unwrap_or(false) {
                    continue;
                }
                s.mark(mailbox, &st.id, Seen::Notified)?;
                out.push(letter(st, false, false));
            }
            Ok(out)
        })
    }

    pub fn who(&self, boundary: &str, mailbox: &str) -> Result<Who> {
        let circle = self.circle()?;
        let seen = self.last_seen.lock().unwrap().clone();
        let machines = circle
            .machines
            .iter()
            .filter(|m| m.boundaries.iter().any(|b| b == boundary))
            .map(|m| PeerInfo {
                name: m.name.clone(),
                this_machine: m.name == self.cfg.machine,
                last_sync_ms: seen.get(&m.name).copied(),
            })
            .collect();
        let mut addresses = self.with_store(boundary, |s| s.senders())?;
        for (b, mb) in self.holders.lock().unwrap().keys() {
            let a = format!("{mb}@{}", self.cfg.machine);
            if b == boundary && !addresses.contains(&a) {
                addresses.push(a);
            }
        }
        addresses.sort();
        Ok(Who {
            you: format!("{mailbox}@{}", self.cfg.machine),
            boundary: boundary.into(),
            machines,
            addresses,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MailEvent> {
        self.events.subscribe()
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
        let guard = self.circle.read().unwrap().clone();
        let mut warnings = vec![];
        let seen = self.last_seen.lock().unwrap().clone();
        let (circle, peers, hosts) = match &guard {
            Some(c) => {
                let hosts = c
                    .circle
                    .machine(&self.cfg.machine)
                    .map(|m| m.boundaries.clone())
                    .unwrap_or_default();
                if hosts.is_empty() {
                    warnings.push("the adopted circle doesn't list this machine; it has been revoked or renamed".into());
                }
                let peers = c
                    .circle
                    .machines
                    .iter()
                    .filter(|m| m.name != self.cfg.machine)
                    .map(|m| PeerInfo {
                        name: m.name.clone(),
                        this_machine: false,
                        last_sync_ms: seen.get(&m.name).copied(),
                    })
                    .collect();
                let info = CircleInfo {
                    id: c.circle.id.clone(),
                    name: c.circle.name.clone(),
                    version: c.circle.version,
                    owners: c
                        .circle
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
                warnings.push("no circle yet".into());
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
            circle,
            entries,
            peers,
            warnings,
        }
    }

    pub fn invite(&self) -> Result<String> {
        let c = self.signed()?;
        let inv = Invite {
            v: 1,
            circle: c.toml,
            sig: c.sig,
            peer: self.endpoint.addr(),
        };
        Ok(format!(
            "tm1-{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&inv)?)
        ))
    }

    /// Joins with an invite: adopts its circle (which must list this machine) and learns one peer.
    pub fn join(&self, code: &str) -> Result<u64> {
        let raw = code
            .trim()
            .strip_prefix("tm1-")
            .context("not a tear-mesh invite")?;
        let inv: Invite =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(raw).context("invite encoding")?)?;
        ensure!(inv.v == 1, "unknown invite version");
        if let Some(cur) = self.circle.read().unwrap().as_ref() {
            let new = Circle::parse(&inv.circle)?;
            if new.id != cur.circle.id {
                bail!(
                    "this machine already belongs to circle {} ({})",
                    cur.circle.name,
                    cur.circle.id
                );
            }
        }
        let v = match self.adopt(&inv.circle, &inv.sig) {
            Ok(v) => v,
            // Already have this version or newer: still learn the peer.
            Err(e) if self.circle.read().unwrap().is_some() => {
                debug!("invite circle not adopted: {e:#}");
                self.circle()?.version
            }
            Err(e) => return Err(e),
        };
        self.learn_addr(inv.peer);
        self.sync_now.notify_one();
        Ok(v)
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
