//! Machines talking over real iroh connections on localhost (no relays, no DNS). The gates:
//! placement, membership, revocation, restart, relaying, wake events and the thread cap (0.1),
//! plus the 0.2 version chain, joins, converse, tool and shell grants.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use tearmesh::config::{Config, Network, Relay};
use tearmesh::envelope::{Entry, Envelope, Kind, Label, Trust, hash_hex};
use tearmesh::mesh::{Approval, Category, Machine, Mesh, SignedMesh, ssh_sign};
use tearmesh::node::{Event, Node, load_or_create_key};
use tearmesh::offer::Offer;
use tempfile::TempDir;

struct World {
    dir: TempDir,
    owner_key: PathBuf,
    backup_key: PathBuf,
    owners: Vec<String>,
}

fn keygen(dir: &Path, name: &str) -> (PathBuf, String) {
    let key = dir.join(name);
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", name, "-f"])
            .arg(&key)
            .status()
            .unwrap()
            .success()
    );
    let mut p = key.as_os_str().to_owned();
    p.push(".pub");
    (
        key.clone(),
        std::fs::read_to_string(PathBuf::from(p))
            .unwrap()
            .trim()
            .into(),
    )
}

type Signed = (String, String);

impl World {
    fn new() -> World {
        let dir = tempfile::tempdir().unwrap();
        let (owner_key, a) = keygen(dir.path(), "owner");
        let (backup_key, b) = keygen(dir.path(), "backup");
        World {
            dir,
            owner_key,
            backup_key,
            owners: vec![a, b],
        }
    }

    fn cfg(&self, name: &str) -> Config {
        let mut c = Config::new(name);
        c.state_dir = self.dir.path().join(name);
        c.socket = self.dir.path().join(format!("{name}.sock"));
        c.network = Network {
            relay: Some(Relay::Preset("none".into())),
            lookup: Some(vec![]),
            bind: Some("127.0.0.1:0".parse().unwrap()),
        };
        c.sync_interval_secs = 3600;
        c.max_thread_len = 5;
        c.max_log_mb = 64;
        c
    }

    fn id(&self, name: &str) -> iroh::EndpointId {
        load_or_create_key(&self.dir.path().join(name))
            .unwrap()
            .public()
    }

    fn mesh(&self, machines: &[(&str, &[&str])]) -> Mesh {
        let mut m = Mesh::new(
            "home",
            self.owners.clone(),
            vec!["work".into(), "vault".into()],
            None,
        )
        .unwrap();
        for (name, bs) in machines {
            m.add_machine(
                Machine {
                    name: (*name).into(),
                    id: self.id(name),
                    boundaries: bs.iter().map(|b| b.to_string()).collect(),
                },
                false,
            )
            .unwrap();
        }
        m
    }

    fn sign_with(&self, key: &Path, m: &Mesh) -> Signed {
        let toml = m.to_toml().unwrap();
        let p = self.dir.path().join("mesh.toml");
        std::fs::write(&p, &toml).unwrap();
        let _ = std::fs::remove_file(self.dir.path().join("mesh.toml.sig"));
        ssh_sign(key, &p).unwrap();
        (
            toml,
            std::fs::read_to_string(self.dir.path().join("mesh.toml.sig")).unwrap(),
        )
    }

    fn sign(&self, m: &Mesh) -> Signed {
        self.sign_with(&self.owner_key, m)
    }

    /// The version after `prev`, changed by `f`, signed with the owner key.
    fn next(&self, prev: &Signed, f: impl FnOnce(&mut Mesh)) -> Signed {
        let mut m = Mesh::parse(&prev.0).unwrap();
        f(&mut m);
        m.bump(&prev.0).unwrap();
        self.sign(&m)
    }

    async fn start_bare(&self, name: &str) -> Arc<Node> {
        Node::start(self.cfg(name)).await.unwrap()
    }

    async fn start(&self, name: &str, signed: &Signed) -> Arc<Node> {
        let n = self.start_bare(name).await;
        if n.mesh().is_err() {
            n.adopt_first(&signed.0, &signed.1).unwrap();
        }
        n
    }
}

fn version(s: &Signed) -> u64 {
    Mesh::parse(&s.0).unwrap().version
}

fn apply(n: &Arc<Node>, s: &Signed) -> anyhow::Result<u64> {
    n.adopt(&[(version(s), s.0.clone(), s.1.clone())])
}

/// Every node learns every other node's current address.
fn introduce(nodes: &[&Arc<Node>]) {
    for a in nodes {
        for b in nodes {
            a.learn_addr(b.endpoint.addr());
        }
    }
}

async fn sync(nodes: &[&Arc<Node>]) {
    for _ in 0..2 {
        for n in nodes {
            n.sync_all().await;
        }
    }
}

async fn stop(nodes: &[&Arc<Node>]) {
    for n in nodes {
        n.shutdown().await;
    }
}

fn subjects(n: &Arc<Node>, mailbox: &str) -> Vec<String> {
    n.inbox("work", mailbox, true)
        .unwrap()
        .into_iter()
        .map(|l| l.subject)
        .collect()
}

#[tokio::test]
async fn vault_mail_never_reaches_a_work_only_machine() {
    let w = World::new();
    let m = w.mesh(&[("ws", &["work", "vault"]), ("laptop", &["work"])]);
    let signed = w.sign(&m);
    let ws = w.start("ws", &signed).await;
    let laptop = w.start("laptop", &signed).await;
    introduce(&[&ws, &laptop]);

    ws.post(
        "work",
        "builder",
        vec!["admin@laptop".into()],
        "work note".into(),
        "hello".into(),
        None,
    )
    .unwrap();
    ws.post(
        "vault",
        "builder",
        vec!["*".into()],
        "vault secret".into(),
        "do not leak".into(),
        None,
    )
    .unwrap();
    assert!(
        ws.post(
            "vault",
            "builder",
            vec!["admin@laptop".into()],
            "x".into(),
            "x".into(),
            None
        )
        .is_err(),
        "addressing a machine outside the boundary"
    );
    sync(&[&ws, &laptop]).await;

    let inbox = laptop.inbox("work", "admin", false).unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].subject, "work note");

    assert!(!w.dir.path().join("laptop/boundaries/vault.db").exists());
    assert!(laptop.inbox("vault", "admin", true).is_err());
    assert!(!laptop.status().entries.contains_key("vault"));
    let laptop_db = std::fs::read(w.dir.path().join("laptop/boundaries/work.db")).unwrap();
    assert!(!String::from_utf8_lossy(&laptop_db).contains("vault secret"));

    // A (compromised) laptop pushing vault entries at ws is refused before anything is stored...
    let forged = forge(&laptop, &m, "vault", ["vault"]);
    assert_eq!(ws.status().entries["vault"], 1);
    let err = format!(
        "{:#}",
        ws.receive(&laptop.id(), "vault", forged).unwrap_err()
    );
    assert!(err.contains("may not send boundary vault"), "{err}");
    // ...and so is a work entry whose label claims more than work.
    let wide = forge(&laptop, &m, "work", ["work", "vault"]);
    ws.receive(&laptop.id(), "work", wide).unwrap();
    assert_eq!(
        ws.status().entries["work"],
        1,
        "wide-label entry was not stored"
    );
    stop(&[&ws, &laptop]).await;
}

fn forge<const N: usize>(
    from: &Arc<Node>,
    m: &Mesh,
    boundary: &str,
    label: [&str; N],
) -> Vec<Entry> {
    let key = load_or_create_key(&from.cfg.state_dir).unwrap();
    let body = "forged".to_string();
    let env = Envelope {
        v: 2,
        mesh: m.id.clone(),
        boundary: boundary.into(),
        author: key.public(),
        seq: 1_000,
        prev: Some("00".repeat(32)),
        ts: 0,
        from: format!("x@{}", from.cfg.machine),
        to: vec!["*".into()],
        thread: None,
        subject: "forged".into(),
        body_hash: hash_hex(body.as_bytes()),
        body_len: body.len() as u64,
        label: Label {
            boundaries: label.iter().map(|s| s.to_string()).collect(),
            trust: Trust::Member,
        },
        kind: Kind::Info,
    };
    vec![Entry::sign(&env, body, &key).unwrap()]
}

#[tokio::test]
async fn strangers_are_refused_at_the_handshake() {
    let w = World::new();
    let signed = w.sign(&w.mesh(&[("ws", &["work"]), ("laptop", &["work"])]));
    let ws = w.start("ws", &signed).await;

    // A stranger with its own mesh that (wrongly) lists ws.
    let s = World::new();
    let mut sm = Mesh::new("evil", s.owners.clone(), vec!["work".into()], None).unwrap();
    for (name, id) in [("stranger", s.id("stranger")), ("ws", ws.id())] {
        sm.add_machine(
            Machine {
                name: name.into(),
                id,
                boundaries: vec!["work".into()],
            },
            false,
        )
        .unwrap();
    }
    let stranger = s.start("stranger", &s.sign(&sm)).await;
    stranger.learn_addr(ws.endpoint.addr());
    stranger
        .post(
            "work",
            "x",
            vec!["*".into()],
            "hi".into(),
            "let me in".into(),
            None,
        )
        .unwrap();

    let err = format!(
        "{:#}",
        tearmesh::sync::initiate(&stranger, ws.id())
            .await
            .expect_err("got a session")
    );
    assert!(
        err.contains("not a mesh member") || err.contains("403"),
        "{err}"
    );
    assert_eq!(ws.status().entries["work"], 0);
    // With no invite open, the join protocol is closed to strangers too.
    let join = stranger
        .endpoint
        .connect(ws.endpoint.addr(), tearmesh::join::ALPN)
        .await;
    if let Ok(conn) = join {
        let err = conn
            .open_bi()
            .await
            .map(|_| ())
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        let closed = conn.closed().await.to_string();
        assert!(
            !err.is_empty() || closed.contains("member") || closed.contains("403"),
            "{closed}"
        );
    }
    stop(&[&ws, &stranger]).await;
}

#[tokio::test]
async fn revoked_machines_are_cut_off() {
    let w = World::new();
    let v1 = w.sign(&w.mesh(&[("ws", &["work"]), ("laptop", &["work"]), ("old", &["work"])]));
    let (ws, laptop, old) = (
        w.start("ws", &v1).await,
        w.start("laptop", &v1).await,
        w.start("old", &v1).await,
    );
    introduce(&[&ws, &laptop, &old]);
    old.post(
        "work",
        "a",
        vec!["*".into()],
        "before".into(),
        "x".into(),
        None,
    )
    .unwrap();
    sync(&[&ws, &laptop, &old]).await;
    assert_eq!(laptop.inbox("work", "admin", true).unwrap().len(), 1);

    let v2 = w.next(&v1, |m| m.remove_machine("old").unwrap());
    apply(&ws, &v2).unwrap();
    sync(&[&ws, &laptop]).await;
    assert_eq!(
        laptop.mesh().unwrap().version,
        version(&v2),
        "laptop learned v2 from ws"
    );

    old.post(
        "work",
        "a",
        vec!["*".into()],
        "after".into(),
        "x".into(),
        None,
    )
    .unwrap();
    sync(&[&old]).await;
    assert!(tearmesh::sync::initiate(&old, ws.id()).await.is_err());
    assert!(tearmesh::sync::initiate(&old, laptop.id()).await.is_err());
    for n in [&ws, &laptop] {
        // Revoking the machine also took away its grants, but the `* -> *` mail grant covers
        // only listed machines, so its old letters are no longer delivered either.
        assert!(
            subjects(n, "admin").is_empty(),
            "nothing from a revoked machine is shown"
        );
        assert_eq!(n.status().entries["work"], 1, "data already copied stays");
    }
    stop(&[&ws, &laptop, &old]).await;
}

#[tokio::test]
async fn logs_survive_restart_and_catch_up() {
    let w = World::new();
    let signed = w.sign(&w.mesh(&[("ws", &["work"]), ("laptop", &["work"])]));
    let ws = w.start("ws", &signed).await;
    let laptop = w.start("laptop", &signed).await;
    introduce(&[&ws, &laptop]);
    laptop
        .post(
            "work",
            "admin",
            vec!["builder@ws".into()],
            "from laptop".into(),
            "1".into(),
            None,
        )
        .unwrap();
    sync(&[&laptop]).await;
    laptop.shutdown().await;

    for i in 0..3 {
        ws.post(
            "work",
            "builder",
            vec!["admin@laptop".into()],
            format!("while away {i}"),
            "x".into(),
            None,
        )
        .unwrap();
    }
    ws.sync_all().await; // laptop is down; this must not wedge anything

    let laptop = w.start("laptop", &signed).await; // new port; ws only has the old one
    laptop.sync_all().await;
    let got: Vec<_> = laptop
        .inbox("work", "admin", false)
        .unwrap()
        .into_iter()
        .map(|l| l.subject)
        .collect();
    assert_eq!(got, vec!["while away 0", "while away 1", "while away 2"]);
    assert_eq!(
        ws.inbox("work", "builder", false).unwrap()[0].subject,
        "from laptop"
    );
    laptop
        .post(
            "work",
            "admin",
            vec!["builder@ws".into()],
            "back".into(),
            "2".into(),
            None,
        )
        .unwrap();
    laptop.sync_all().await;
    assert_eq!(ws.inbox("work", "builder", false).unwrap().len(), 2);
    stop(&[&ws, &laptop]).await;
}

#[tokio::test]
async fn mail_is_relayed_through_a_middle_machine() {
    let w = World::new();
    let signed = w.sign(&w.mesh(&[("a", &["work"]), ("b", &["work"]), ("c", &["work"])]));
    let (a, b, cc) = (
        w.start("a", &signed).await,
        w.start("b", &signed).await,
        w.start("c", &signed).await,
    );
    introduce(&[&a, &b]);
    introduce(&[&b, &cc]);
    a.post(
        "work",
        "x",
        vec!["y@c".into()],
        "via b".into(),
        "hop".into(),
        None,
    )
    .unwrap();
    sync(&[&a, &b, &cc]).await;
    assert_eq!(cc.inbox("work", "y", false).unwrap()[0].subject, "via b");
    stop(&[&a, &b, &cc]).await;
}

#[tokio::test]
async fn wake_events_and_thread_cap() {
    let w = World::new();
    let signed = w.sign(&w.mesh(&[("ws", &["work"]), ("laptop", &["work"])]));
    let ws = w.start("ws", &signed).await;
    let laptop = w.start("laptop", &signed).await;
    introduce(&[&ws, &laptop]);
    let mut events = laptop.subscribe();

    let root = ws
        .post(
            "work",
            "builder",
            vec!["helper@laptop".into()],
            "q".into(),
            "?".into(),
            None,
        )
        .unwrap();
    sync(&[&ws]).await;
    let Ok(Event::Mail(ev)) = events.try_recv() else {
        panic!("a wake event for an unheld mailbox")
    };
    assert_eq!(
        (ev.mailbox.as_str(), ev.id.as_str(), ev.trust),
        ("helper", root.as_str(), Trust::Member)
    );

    // While a session holds the mailbox, mail doesn't wake anyone.
    let hold = laptop.hold("work", "helper");
    ws.post(
        "work",
        "builder",
        vec!["helper@laptop".into()],
        "q2".into(),
        "?".into(),
        None,
    )
    .unwrap();
    sync(&[&ws]).await;
    assert!(events.try_recv().is_err());
    drop(hold);

    assert_eq!(laptop.notify("work", "helper").unwrap().len(), 2);
    assert!(laptop.notify("work", "helper").unwrap().is_empty());

    for i in 0..4 {
        let (n, from, to) = if i % 2 == 0 {
            (&laptop, "helper", "builder@ws")
        } else {
            (&ws, "builder", "helper@laptop")
        };
        n.post(
            "work",
            from,
            vec![to.into()],
            "re".into(),
            "x".into(),
            Some(root[..8].into()),
        )
        .unwrap();
        sync(&[&ws, &laptop]).await;
    }
    let err = ws.post(
        "work",
        "builder",
        vec!["helper@laptop".into()],
        "re".into(),
        "x".into(),
        Some(root.clone()),
    );
    assert!(format!("{:#}", err.unwrap_err()).contains("start a new thread"));
    stop(&[&ws, &laptop]).await;
}

#[tokio::test]
async fn a_machine_that_missed_an_owner_change_catches_up() {
    let w = World::new();
    let (new_key, new_pub) = keygen(w.dir.path(), "new-owner");
    let v1 = w.sign(&w.mesh(&[("ws", &["work"]), ("laptop", &["work"])]));
    let ws = w.start("ws", &v1).await;
    let laptop = w.start("laptop", &v1).await;
    introduce(&[&ws, &laptop]);

    // Promote a new key and drop the old one (signed by the old one), then a change signed by
    // the new key. laptop sees neither until it syncs.
    let v2 = w.next(&v1, |m| {
        m.owners = vec![new_pub.clone(), w.owners[1].clone()]
    });
    let mut m3 = Mesh::parse(&v2.0).unwrap();
    m3.grant("laptop", "ws", &[Category::Tools]);
    m3.bump(&v2.0).unwrap();
    let v3 = w.sign_with(&new_key, &m3);
    apply(&ws, &v2).unwrap();
    apply(&ws, &v3).unwrap();
    // The removed key can no longer sign what comes next.
    let stale = w.next(&v3, |_| {});
    assert!(apply(&ws, &stale).is_err(), "removed owner key");

    sync(&[&laptop, &ws]).await;
    assert_eq!(
        laptop.mesh().unwrap().version,
        3,
        "laptop took v2 and v3 in order"
    );
    assert!(
        laptop
            .mesh()
            .unwrap()
            .allows("laptop", "ws", Category::Tools)
    );

    // A restart reloads the whole chain from disk.
    laptop.shutdown().await;
    let laptop = w.start_bare("laptop").await;
    assert_eq!(laptop.mesh().unwrap().version, 3);
    stop(&[&ws, &laptop]).await;
}

#[tokio::test]
async fn a_split_heals_the_same_way_everywhere() {
    let w = World::new();
    let v1 = w.sign(&w.mesh(&[("ws", &["work"]), ("laptop", &["work"])]));
    let ws = w.start("ws", &v1).await;
    let laptop = w.start("laptop", &v1).await;
    introduce(&[&ws, &laptop]);
    // Two owners each sign a different version 2.
    let a = w.next(&v1, |m| m.grant("ws", "laptop", &[Category::Tools]));
    let mut mb = Mesh::parse(&v1.0).unwrap();
    mb.grant("laptop", "ws", &[Category::Tools]);
    mb.bump(&v1.0).unwrap();
    let b = w.sign_with(&w.backup_key, &mb);
    apply(&ws, &a).unwrap();
    apply(&laptop, &b).unwrap();
    sync(&[&ws, &laptop]).await;
    let (ha, hb) = (tearmesh::mesh::hash(&a.0), tearmesh::mesh::hash(&b.0));
    let winner = if ha < hb { &ha } else { &hb };
    assert_eq!(&ws.signed().unwrap().hash, winner);
    assert_eq!(&laptop.signed().unwrap().hash, winner);
    let loser = if ha < hb { &laptop } else { &ws };
    assert!(
        loser
            .status()
            .warnings
            .iter()
            .any(|x| x.contains("re-apply")),
        "the machine that lost says so"
    );
    stop(&[&ws, &laptop]).await;
}

#[tokio::test]
async fn joining_with_a_ticket() {
    let w = World::new();
    let v1 = w.sign(&w.mesh(&[("ws", &["work", "vault"])]));
    let ws = w.start("ws", &v1).await;
    let laptop = w.start_bare("laptop").await;
    assert!(
        ws.invite(
            "laptop",
            vec!["nope".into()],
            false,
            std::time::Duration::from_secs(60)
        )
        .is_err()
    );
    assert!(
        ws.invite(
            "ws",
            vec!["work".into()],
            false,
            std::time::Duration::from_secs(60)
        )
        .is_err(),
        "name in use"
    );
    let ticket = ws
        .invite(
            "laptop",
            vec!["work".into()],
            false,
            std::time::Duration::from_secs(600),
        )
        .unwrap();
    assert!(ticket.len() < 300, "{} chars", ticket.len());

    let joining = tearmesh::join::start(&laptop, &ticket).await.unwrap();
    let pending = ws.joins_pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        (pending[0].name.as_str(), pending[0].code.as_str()),
        ("laptop", joining.code.as_str())
    );
    assert_eq!(pending[0].node_id, laptop.id());

    // The ticket is single use: another machine with the same ticket gets nowhere.
    let thief_world = World::new();
    let mut tcfg = thief_world.cfg("laptop");
    tcfg.state_dir = w.dir.path().join("thief");
    let thief = Node::start(tcfg).await.unwrap();
    let err = tearmesh::join::start(&thief, &ticket)
        .await
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_default();
    assert!(
        err.contains("no open invite") || err.contains("not reachable") || err.contains("member"),
        "{err}"
    );

    // The person approves on the owner node: a version listing the machine.
    let v2 = w.next(&v1, |m| {
        let p = &pending[0];
        m.add_machine(
            Machine {
                name: p.name.clone(),
                id: p.node_id,
                boundaries: p.boundaries.clone(),
            },
            false,
        )
        .unwrap()
    });
    let handle = tokio::spawn({
        let laptop = laptop.clone();
        async move { joining.finish(&laptop).await }
    });
    apply(&ws, &v2).unwrap();
    assert_eq!(handle.await.unwrap().unwrap(), 2);
    assert_eq!(laptop.mesh().unwrap().version, 2);
    assert!(ws.joins_pending().is_empty());

    // Now they're members: mail flows.
    introduce(&[&ws, &laptop]);
    ws.post(
        "work",
        "builder",
        vec!["admin@laptop".into()],
        "welcome".into(),
        "hi".into(),
        None,
    )
    .unwrap();
    sync(&[&ws, &laptop]).await;
    assert_eq!(subjects(&laptop, "admin"), vec!["welcome"]);
    stop(&[&ws, &laptop, &thief]).await;
}

#[tokio::test]
async fn a_joiner_refuses_owners_the_ticket_didnt_name() {
    let w = World::new();
    let (other_key, other_pub) = keygen(w.dir.path(), "other");
    let v1 = w.sign(&w.mesh(&[("ws", &["work"])]));
    let ws = w.start("ws", &v1).await;
    let laptop = w.start_bare("laptop").await;
    let ticket = ws
        .invite(
            "laptop",
            vec!["work".into()],
            false,
            std::time::Duration::from_secs(600),
        )
        .unwrap();
    let joining = tearmesh::join::start(&laptop, &ticket).await.unwrap();
    let handle = tokio::spawn({
        let laptop = laptop.clone();
        async move { joining.finish(&laptop).await }
    });
    // The owner set changes before the approval.
    let v2 = w.next(&v1, |m| {
        m.owners = vec![other_pub.clone(), w.owners[1].clone()]
    });
    apply(&ws, &v2).unwrap();
    let mut m3 = Mesh::parse(&v2.0).unwrap();
    m3.add_machine(
        Machine {
            name: "laptop".into(),
            id: laptop.id(),
            boundaries: vec!["work".into()],
        },
        false,
    )
    .unwrap();
    m3.bump(&v2.0).unwrap();
    let v3 = w.sign_with(&other_key, &m3);
    apply(&ws, &v3).unwrap();
    let err = format!("{:#}", handle.await.unwrap().unwrap_err());
    assert!(
        err.contains("owner keys aren't the ones the ticket named"),
        "{err}"
    );
    assert!(laptop.mesh().is_err());
    stop(&[&ws, &laptop]).await;
}

#[tokio::test]
async fn converse_grants_decide_delivery() {
    let w = World::new();
    let mut m = w.mesh(&[("a", &["work"]), ("b", &["work"]), ("c", &["work"])]);
    m.grants.clear();
    m.grant("a", "b", &[Category::Converse]);
    m.grant("b", "a", &[Category::Converse]);
    m.grant("c", "a", &[Category::Converse]);
    let v1 = w.sign(&m);
    let (a, b, c) = (
        w.start("a", &v1).await,
        w.start("b", &v1).await,
        w.start("c", &v1).await,
    );
    introduce(&[&a, &b, &c]);

    let err = format!(
        "{:#}",
        c.post(
            "work",
            "x",
            vec!["y@b".into()],
            "no".into(),
            "x".into(),
            None
        )
        .unwrap_err()
    );
    assert!(err.contains("no converse grant"), "{err}");
    c.post(
        "work",
        "x",
        vec!["*".into()],
        "from c".into(),
        "x".into(),
        None,
    )
    .unwrap();
    sync(&[&a, &b, &c]).await;
    assert_eq!(subjects(&a, "y"), vec!["from c"]);
    assert!(
        subjects(&b, "y").is_empty(),
        "b stores it but doesn't deliver it"
    );
    assert_eq!(b.status().entries["work"], 1, "replication is unchanged");
    let id = a.inbox("work", "y", true).unwrap()[0].id.clone();
    assert!(b.read("work", "y", &id).is_err(), "not even by id");

    // Revoking the grant hides the author's earlier letters too.
    let v2 = w.next(&v1, |m| {
        m.revoke("c", "a", &[Category::Converse]).unwrap();
    });
    apply(&a, &v2).unwrap();
    assert!(subjects(&a, "y").is_empty());
    stop(&[&a, &b, &c]).await;
}

#[tokio::test]
async fn tool_calls_need_a_grant_an_approval_and_a_shared_boundary() {
    let w = World::new();
    let v1 = w.sign(&w.mesh(&[("ws", &["work", "vault"]), ("laptop", &["work"])]));
    let ws = w.start("ws", &v1).await;
    let laptop = w.start("laptop", &v1).await;
    introduce(&[&ws, &laptop]);
    let offer = Offer::new(
        "cad",
        "test".into(),
        None,
        None,
        vec![serde_json::json!({"name": "export_step", "inputSchema": {"type": "object"}})],
        None,
    )
    .unwrap();
    for b in ["work", "vault"] {
        ws.post_as(
            b,
            "admin",
            Trust::Member,
            Kind::Offer,
            vec!["*".into()],
            "cad".into(),
            serde_json::to_string(&offer).unwrap(),
            None,
        )
        .unwrap();
    }
    sync(&[&ws, &laptop]).await;
    assert_eq!(
        laptop
            .who("work", "admin")
            .unwrap()
            .machines
            .iter()
            .find(|m| m.name == "ws")
            .unwrap()
            .offers,
        vec!["cad"]
    );
    let err = |r: anyhow::Result<_>| r.err().map(|e| format!("{e:#}")).unwrap_or_default();

    let e = err(tearmesh::bridge::call(&laptop, "work", "ws", "cad")
        .await
        .map(|_| ()));
    assert!(e.contains("no tools grant"), "{e}");
    let v2 = w.next(&v1, |m| m.grant("laptop", "ws", &[Category::Tools]));
    apply(&ws, &v2).unwrap();
    apply(&laptop, &v2).unwrap();
    let e = err(tearmesh::bridge::call(&laptop, "work", "ws", "cad")
        .await
        .map(|_| ()));
    assert!(e.contains("hasn't approved"), "{e}");
    let e = err(tearmesh::bridge::call(&laptop, "vault", "ws", "cad")
        .await
        .map(|_| ()));
    assert!(e.contains("don't both host boundary vault"), "{e}");

    // An approval pinned to other tools is refused at the caller.
    let v3 = w.next(&v2, |m| {
        m.approvals.push(Approval {
            machine: "ws".into(),
            boundary: "work".into(),
            server: "cad".into(),
            pin: "0".repeat(64),
            tools: None,
        })
    });
    apply(&ws, &v3).unwrap();
    apply(&laptop, &v3).unwrap();
    let e = err(tearmesh::bridge::call(&laptop, "work", "ws", "cad")
        .await
        .map(|_| ()));
    assert!(e.contains("needs approving again"), "{e}");

    // With the right pin, both daemons agree; ws then needs a steward to run the server.
    let v4 = w.next(&v3, |m| m.approvals[0].pin = offer.pin.clone());
    apply(&ws, &v4).unwrap();
    apply(&laptop, &v4).unwrap();
    let e = err(tearmesh::bridge::call(&laptop, "work", "ws", "cad")
        .await
        .map(|_| ()));
    assert!(e.contains("no steward is serving boundary work"), "{e}");
    stop(&[&ws, &laptop]).await;
}

#[tokio::test]
async fn shell_streams_need_a_grant() {
    let w = World::new();
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut wr) = s.into_split();
                let _ = tokio::io::copy(&mut r, &mut wr).await;
            });
        }
    });
    let v1 = w.sign(&w.mesh(&[("ws", &["work"]), ("laptop", &["work"])]));
    let mut cfg = w.cfg("ws");
    cfg.shell_port = port;
    let ws = Node::start(cfg).await.unwrap();
    ws.adopt_first(&v1.0, &v1.1).unwrap();
    let laptop = w.start("laptop", &v1).await;
    introduce(&[&ws, &laptop]);

    assert!(
        tearmesh::shell::open(&laptop, "work", "ws").await.is_err(),
        "no grant"
    );
    let v2 = w.next(&v1, |m| m.grant("laptop", "ws", &[Category::Shell]));
    apply(&ws, &v2).unwrap();
    apply(&laptop, &v2).unwrap();
    assert!(
        tearmesh::shell::open(&ws, "work", "laptop").await.is_err(),
        "the grant is one way"
    );
    let (mut r, mut s, _conn) = tearmesh::shell::open(&laptop, "work", "ws").await.unwrap();
    s.write_all(b"SSH-2.0-test\r\n").await.unwrap();
    let mut buf = [0u8; 14];
    r.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"SSH-2.0-test\r\n");
    stop(&[&ws, &laptop]).await;
}

#[tokio::test]
async fn a_stored_0_1_circle_is_carried_over() {
    let w = World::new();
    // A 0.1.0 circle file, signed in 0.1's namespace, as a 0.1 daemon stored it.
    let v1 = format!(
        "id = \"abc123\"\nname = \"home\"\nversion = 3\nowners = [{:?}, {:?}]\nboundaries = [\"work\"]\n\n[[machine]]\nname = \"ws\"\nid = \"{}\"\nboundaries = [\"work\"]\n",
        w.owners[0],
        w.owners[1],
        w.id("ws")
    );
    let p = w.dir.path().join("circle.toml");
    std::fs::write(&p, &v1).unwrap();
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-Y", "sign", "-n", "tear-mesh-circle", "-f"])
            .arg(&w.owner_key)
            .arg(&p)
            .status()
            .unwrap()
            .success()
    );
    let sig = std::fs::read_to_string(w.dir.path().join("circle.toml.sig")).unwrap();
    std::fs::write(
        w.dir.path().join("ws/circle.json"),
        serde_json::to_vec(&serde_json::json!({ "toml": v1, "sig": sig })).unwrap(),
    )
    .unwrap();
    let ws = w.start_bare("ws").await;
    assert_eq!(ws.mesh().unwrap().version, 3);
    ws.post(
        "work",
        "a",
        vec!["*".into()],
        "kept".into(),
        "x".into(),
        None,
    )
    .unwrap();
    let v4 = w.next(&(v1.clone(), sig.clone()), |_| {});
    assert_eq!(apply(&ws, &v4).unwrap(), 4);
    assert_eq!(ws.mesh().unwrap().format, 2);
    assert_eq!(ws.status().entries["work"], 1);
    // The chain verifies from disk after a restart.
    ws.shutdown().await;
    let ws = w.start_bare("ws").await;
    assert_eq!(ws.mesh().unwrap().version, 4);
    let _ = SignedMesh::verify_first(&v4.0, &v4.1).unwrap();
    stop(&[&ws]).await;
}
