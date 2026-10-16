//! Machines talking over real iroh connections on localhost (no relays, no DNS). These are the
//! 0.1.0 gates: placement, membership, revocation, restart, relaying, wake events, thread cap.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use tearmesh::circle::{Circle, Machine, ssh_sign};
use tearmesh::config::{Config, Network, Relay};
use tearmesh::envelope::{Entry, Envelope, Label, Trust, hash_hex};
use tearmesh::node::{Node, load_or_create_key};
use tempfile::TempDir;

struct World {
    dir: TempDir,
    owner_key: PathBuf,
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
    (
        key.clone(),
        std::fs::read_to_string(key.with_extension("pub"))
            .unwrap()
            .trim()
            .into(),
    )
}

impl World {
    fn new() -> World {
        let dir = tempfile::tempdir().unwrap();
        let (owner_key, a) = keygen(dir.path(), "owner");
        let (_, b) = keygen(dir.path(), "backup");
        World {
            dir,
            owner_key,
            owners: vec![a, b],
        }
    }

    fn cfg(&self, name: &str) -> Config {
        Config {
            machine: name.into(),
            state_dir: self.dir.path().join(name),
            socket: self.dir.path().join(format!("{name}.sock")),
            users: Default::default(),
            network: Network {
                relay: Relay::Preset("none".into()),
                n0_dns: false,
                bind: Some("127.0.0.1:0".parse().unwrap()),
            },
            sync_interval_secs: 3600,
            max_thread_len: 5,
            max_posts_per_hour: 600,
            max_log_mb: 64,
        }
    }

    fn id(&self, name: &str) -> iroh::EndpointId {
        load_or_create_key(&self.dir.path().join(name))
            .unwrap()
            .public()
    }

    fn circle(&self, machines: &[(&str, &[&str])]) -> Circle {
        let mut c = Circle::new(
            "home",
            self.owners.clone(),
            vec!["work".into(), "vault".into()],
        )
        .unwrap();
        for (name, bs) in machines {
            c.set_machine(Machine {
                name: (*name).into(),
                id: self.id(name),
                boundaries: bs.iter().map(|b| b.to_string()).collect(),
            })
            .unwrap();
        }
        c
    }

    fn sign(&self, c: &Circle) -> (String, String) {
        let toml = c.to_toml().unwrap();
        let p = self.dir.path().join("circle.toml");
        std::fs::write(&p, &toml).unwrap();
        let _ = std::fs::remove_file(self.dir.path().join("circle.toml.sig"));
        ssh_sign(&self.owner_key, &p).unwrap();
        (
            toml,
            std::fs::read_to_string(self.dir.path().join("circle.toml.sig")).unwrap(),
        )
    }

    async fn start(&self, name: &str, signed: &(String, String)) -> Arc<Node> {
        let n = Node::start(self.cfg(name)).await.unwrap();
        if n.circle().is_err() {
            n.adopt(&signed.0, &signed.1).unwrap();
        }
        n
    }
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

#[tokio::test]
async fn vault_mail_never_reaches_a_work_only_machine() {
    let w = World::new();
    let c = w.circle(&[("ws", &["work", "vault"]), ("laptop", &["work"])]);
    let signed = w.sign(&c);
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
    // Addressing a machine outside the boundary is refused outright.
    assert!(
        ws.post(
            "vault",
            "builder",
            vec!["admin@laptop".into()],
            "x".into(),
            "x".into(),
            None
        )
        .is_err()
    );
    sync(&[&ws, &laptop]).await;

    let inbox = laptop.inbox("work", "admin", false).unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].subject, "work note");

    // Laptop has no vault store, no vault entries, and can't be made to accept or serve any.
    assert!(!w.dir.path().join("laptop/boundaries/vault.db").exists());
    assert!(laptop.inbox("vault", "admin", true).is_err());
    assert!(!laptop.status().entries.contains_key("vault"));
    let laptop_db = std::fs::read(w.dir.path().join("laptop/boundaries/work.db")).unwrap();
    assert!(!String::from_utf8_lossy(&laptop_db).contains("vault secret"));

    // A (compromised) laptop pushing vault entries at ws is refused before anything is stored...
    let forged = forge(&laptop, &c, "vault", ["vault"]);
    assert!(ws.status().entries["vault"] == 1);
    let err = format!(
        "{:#}",
        ws_receive(&ws, &laptop, "vault", forged).unwrap_err()
    );
    assert!(err.contains("may not send boundary vault"), "{err}");
    // ...and so is a work entry whose label claims more than work.
    let wide = forge(&laptop, &c, "work", ["work", "vault"]);
    ws_receive(&ws, &laptop, "work", wide).unwrap();
    assert_eq!(
        ws.status().entries["work"],
        1,
        "wide-label entry was not stored"
    );

    stop(&[&ws, &laptop]).await;
}

fn forge<const N: usize>(
    from: &Arc<Node>,
    c: &Circle,
    boundary: &str,
    label: [&str; N],
) -> Vec<Entry> {
    let key = load_or_create_key(&from.cfg.state_dir).unwrap();
    let body = "forged".to_string();
    let env = Envelope {
        v: 1,
        circle: c.id.clone(),
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
            trust: Trust::Circle,
        },
    };
    vec![Entry::sign(&env, body, &key).unwrap()]
}

fn ws_receive(
    ws: &Arc<Node>,
    from: &Arc<Node>,
    boundary: &str,
    entries: Vec<Entry>,
) -> anyhow::Result<usize> {
    ws.receive(&from.id(), boundary, entries)
}

#[tokio::test]
async fn strangers_are_refused_at_the_handshake() {
    let w = World::new();
    let c = w.circle(&[("ws", &["work"]), ("laptop", &["work"])]);
    let signed = w.sign(&c);
    let ws = w.start("ws", &signed).await;

    // A stranger with its own circle that (wrongly) lists ws.
    let s = World::new();
    let mut sc = Circle::new("evil", s.owners.clone(), vec!["work".into()]).unwrap();
    sc.set_machine(Machine {
        name: "stranger".into(),
        id: s.id("stranger"),
        boundaries: vec!["work".into()],
    })
    .unwrap();
    sc.set_machine(Machine {
        name: "ws".into(),
        id: ws.id(),
        boundaries: vec!["work".into()],
    })
    .unwrap();
    let stranger = s.start("stranger", &s.sign(&sc)).await;
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

    let res = tearmesh::sync::initiate(&stranger, ws.id()).await;
    let err = format!("{:#}", res.expect_err("stranger got a session"));
    assert!(
        err.contains("not a circle member") || err.contains("403"),
        "{err}"
    );
    assert_eq!(ws.status().entries["work"], 0);
    stop(&[&ws, &stranger]).await;
}

#[tokio::test]
async fn revoked_machines_are_cut_off() {
    let w = World::new();
    let mut c = w.circle(&[("ws", &["work"]), ("laptop", &["work"]), ("old", &["work"])]);
    let v1 = w.sign(&c);
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

    c.remove_machine("old").unwrap();
    let v2 = w.sign(&c);
    ws.adopt(&v2.0, &v2.1).unwrap();
    sync(&[&ws, &laptop]).await;
    assert_eq!(
        laptop.circle().unwrap().version,
        c.version,
        "laptop learned the new circle from ws"
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
        let subjects: Vec<_> = n
            .inbox("work", "admin", true)
            .unwrap()
            .into_iter()
            .map(|l| l.subject)
            .collect();
        assert_eq!(
            subjects,
            vec!["before"],
            "data already copied stays; nothing new arrives"
        );
    }
    stop(&[&ws, &laptop, &old]).await;
}

#[tokio::test]
async fn logs_survive_restart_and_catch_up() {
    let w = World::new();
    let c = w.circle(&[("ws", &["work"]), ("laptop", &["work"])]);
    let signed = w.sign(&c);
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
    // The restarted laptop keeps its chain going rather than starting over.
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
    let c = w.circle(&[("a", &["work"]), ("b", &["work"]), ("c", &["work"])]);
    let signed = w.sign(&c);
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
    let c = w.circle(&[("ws", &["work"]), ("laptop", &["work"])]);
    let signed = w.sign(&c);
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
    let ev = events
        .try_recv()
        .expect("a wake event for an unheld mailbox");
    assert_eq!(
        (ev.mailbox.as_str(), ev.id.as_str()),
        ("helper", root.as_str())
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
    assert!(!laptop.held("work", "helper"));

    // The hook path: notify reports each unread letter once.
    assert_eq!(laptop.notify("work", "helper").unwrap().len(), 2);
    assert!(laptop.notify("work", "helper").unwrap().is_empty());

    // max_thread_len = 5: the root plus four replies, then refused.
    for i in 0..4 {
        let (n, from) = if i % 2 == 0 {
            (&laptop, "helper")
        } else {
            (&ws, "builder")
        };
        let to = if i % 2 == 0 {
            "builder@ws"
        } else {
            "helper@laptop"
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
