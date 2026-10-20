//! The membership file: which machines belong, which boundaries each hosts, which machine may act
//! on which (grants), which shared tools the owner approved, and which owner keys may sign the
//! next version. It is TOML, signed with an ordinary SSH key (`ssh-keygen -Y sign`).
//!
//! Versions form a chain: each one names the hash of the one before and is exactly one higher,
//! signed by an owner of the one before. A machine that missed versions gets every one it lacks.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, PublicKey, SshSig};

use crate::config::Relay;
use crate::valid_name;

/// SSHSIG namespace for format 2, so a signature can't be replayed as any other SSH signature.
pub const SIG_NAMESPACE: &str = "tear-mesh-membership";
/// 0.1.0's namespace, checked only for a stored 0.1.0 circle being carried over.
const V1_NAMESPACE: &str = "tear-mesh-circle";
pub const MAX_FILE: usize = 64 * 1024;
const MAX_SIG: usize = 8 * 1024;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// Send letters the other machine will deliver.
    Converse,
    /// Call the MCP servers the other machine offers.
    Tools,
    /// Reach the other machine's sshd.
    Shell,
}

impl std::str::FromStr for Category {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "converse" => Category::Converse,
            "tools" => Category::Tools,
            "shell" => Category::Shell,
            _ => bail!("unknown category {s:?} (converse, tools, shell)"),
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Sharing {
    /// Each offer also needs an `[[approved]]` entry.
    #[default]
    Approval,
    /// Any published offer is callable by machines with a `tools` grant.
    Free,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// `"n0"`, `"none"`, or a list of relay URLs. A machine's own config can override it.
    #[serde(default)]
    pub relays: Relay,
    /// Address lookup: `"n0-dns"` and/or `"mdns"`. A machine's own config can override it.
    #[serde(default = "default_lookup")]
    pub lookup: Vec<String>,
    #[serde(default)]
    pub tools_sharing: Sharing,
}

pub fn default_lookup() -> Vec<String> {
    vec!["n0-dns".into(), "mdns".into()]
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            relays: Relay::default(),
            lookup: default_lookup(),
            tools_sharing: Sharing::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Machine {
    pub name: String,
    pub id: EndpointId,
    pub boundaries: Vec<String>,
}

/// `from` may act on `to` in each listed category. `*` matches any machine (not for shell).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub from: String,
    pub to: String,
    pub allow: Vec<Category>,
}

/// The owner's approval of one offered MCP server, pinned to its tool list.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub machine: String,
    pub boundary: String,
    pub server: String,
    /// `offer::pin` of the server's instructions and the approved tools.
    pub pin: String,
    /// Only these tools; absent means every tool in the offer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Mesh {
    pub format: u32,
    /// Random, fixed at creation. Entries and tickets carry it so two meshes never mix.
    pub id: String,
    pub name: String,
    pub version: u64,
    /// Hash of the previous version's exact signed bytes. Absent only at the start of a chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    /// OpenSSH public keys. Any one may sign the next version; at least two are required so
    /// losing one key doesn't lock the mesh forever.
    pub owners: Vec<String>,
    pub boundaries: Vec<String>,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default, rename = "machine")]
    pub machines: Vec<Machine>,
    #[serde(default, rename = "grant")]
    pub grants: Vec<Grant>,
    #[serde(default, rename = "approved")]
    pub approvals: Vec<Approval>,
}

/// 0.1.0's circle file, read only to carry a stored one over.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CircleV1 {
    id: String,
    name: String,
    version: u64,
    owners: Vec<String>,
    boundaries: Vec<String>,
    #[serde(default, rename = "machine")]
    machines: Vec<Machine>,
}

pub fn hash(toml: &str) -> String {
    blake3::hash(toml.as_bytes()).to_hex().to_string()
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// MCP tool names: 1-128 of letters, digits, `_`, `-`, `.`.
pub fn valid_tool_name(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

impl Mesh {
    /// Version 1 of a new mesh. It lets every member mail every other (`* → *` converse), as
    /// 0.1.0 did; revoke that grant for a stricter mesh.
    pub fn new(
        name: &str,
        owners: Vec<String>,
        boundaries: Vec<String>,
        id: Option<String>,
    ) -> Result<Self> {
        let id = match id {
            Some(id) => id,
            None => {
                let mut b = [0u8; 16];
                getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("random: {e}"))?;
                crate::envelope::hex(&b)
            }
        };
        let m = Mesh {
            format: 2,
            id,
            name: name.to_string(),
            version: 1,
            prev: None,
            owners,
            boundaries,
            settings: Settings::default(),
            machines: vec![],
            grants: vec![Grant {
                from: "*".into(),
                to: "*".into(),
                allow: vec![Category::Converse],
            }],
            approvals: vec![],
        };
        m.validate()?;
        Ok(m)
    }

    /// Parses format 2, or a 0.1.0 circle (no `format` key), which becomes format 1 with a
    /// `* → *` converse grant so mail keeps working.
    pub fn parse(toml_text: &str) -> Result<Self> {
        let table: toml::Table = toml::from_str(toml_text).context("membership file")?;
        let m = if table.contains_key("format") {
            let m: Mesh = toml::from_str(toml_text).context("membership file")?;
            ensure!(m.format == 2, "unknown membership format {}", m.format);
            m
        } else {
            let c: CircleV1 = toml::from_str(toml_text).context("0.1 circle file")?;
            Mesh {
                format: 1,
                id: c.id,
                name: c.name,
                version: c.version,
                prev: None,
                owners: c.owners,
                boundaries: c.boundaries,
                settings: Settings::default(),
                machines: c.machines,
                grants: vec![Grant {
                    from: "*".into(),
                    to: "*".into(),
                    allow: vec![Category::Converse],
                }],
                approvals: vec![],
            }
        };
        m.validate()?;
        Ok(m)
    }

    pub fn to_toml(&self) -> Result<String> {
        ensure!(self.format == 2, "only format 2 is written");
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.id.is_empty()
                && self.id.len() <= 64
                && self.id.bytes().all(|b| b.is_ascii_alphanumeric()),
            "mesh id must be 1-64 letters and digits"
        );
        ensure!(valid_name(&self.name), "bad mesh name {:?}", self.name);
        ensure!(self.version >= 1, "version starts at 1");
        ensure!(
            self.prev.as_deref().is_none_or(is_hex64),
            "prev must be a 64-character hash"
        );
        let keys = self.owner_keys()?;
        let distinct: BTreeSet<_> = keys.iter().map(|k| k.key_data().clone()).collect();
        ensure!(
            distinct.len() >= 2,
            "a mesh needs at least two distinct owner keys, so losing one doesn't lock it"
        );
        ensure!(
            !self.boundaries.is_empty(),
            "a mesh needs at least one boundary"
        );
        let mut seen = BTreeSet::new();
        for b in &self.boundaries {
            ensure!(valid_name(b), "bad boundary name {b:?}");
            ensure!(seen.insert(b), "boundary {b} listed twice");
        }
        if let Relay::Preset(p) = &self.settings.relays {
            ensure!(
                p == "n0" || p == "none",
                "settings.relays must be \"n0\", \"none\" or a list of URLs"
            );
        }
        for l in &self.settings.lookup {
            ensure!(
                l == "n0-dns" || l == "mdns",
                "settings.lookup: unknown method {l:?} (n0-dns, mdns)"
            );
        }
        let (mut names, mut ids) = (BTreeSet::new(), BTreeSet::new());
        for m in &self.machines {
            ensure!(valid_name(&m.name), "bad machine name {:?}", m.name);
            ensure!(names.insert(&m.name), "machine {} listed twice", m.name);
            ensure!(ids.insert(m.id), "machine id {} listed twice", m.id);
            ensure!(
                !m.boundaries.is_empty(),
                "machine {} hosts no boundary",
                m.name
            );
            let mut mb = BTreeSet::new();
            for b in &m.boundaries {
                ensure!(
                    self.boundaries.contains(b),
                    "machine {}: unknown boundary {b}",
                    m.name
                );
                ensure!(
                    mb.insert(b),
                    "machine {}: boundary {b} listed twice",
                    m.name
                );
            }
        }
        let known = |n: &str| n == "*" || names.contains(&n.to_string());
        for g in &self.grants {
            ensure!(
                known(&g.from) && known(&g.to),
                "grant {} -> {}: unknown machine",
                g.from,
                g.to
            );
            ensure!(
                !g.allow.is_empty(),
                "grant {} -> {} allows nothing",
                g.from,
                g.to
            );
            ensure!(
                !g.allow.contains(&Category::Shell) || (g.from != "*" && g.to != "*"),
                "a shell grant must name both machines, not *"
            );
        }
        let mut approved = BTreeSet::new();
        for a in &self.approvals {
            ensure!(
                self.hosts(&a.machine, &a.boundary),
                "approval for {}/{}: {} doesn't host {}",
                a.machine,
                a.server,
                a.machine,
                a.boundary
            );
            ensure!(valid_name(&a.server), "bad server name {:?}", a.server);
            ensure!(is_hex64(&a.pin), "approval pin must be a 64-character hash");
            ensure!(
                approved.insert((&a.machine, &a.boundary, &a.server)),
                "{}/{} in {} approved twice",
                a.machine,
                a.server,
                a.boundary
            );
            if let Some(t) = &a.tools {
                ensure!(
                    t.iter().all(|t| valid_tool_name(t)),
                    "approval for {}: bad tool name",
                    a.server
                );
            }
        }
        Ok(())
    }

    pub fn owner_keys(&self) -> Result<Vec<PublicKey>> {
        self.owners
            .iter()
            .map(|s| {
                let k = PublicKey::from_openssh(s).with_context(|| format!("owner key {s:?}"))?;
                ensure!(
                    matches!(k.algorithm(), Algorithm::Ed25519 | Algorithm::SkEd25519),
                    "owner keys must be ssh-ed25519 or sk-ssh-ed25519, got {}",
                    k.algorithm()
                );
                Ok(k)
            })
            .collect()
    }

    /// A short hash of the owner key set. A ticket carries it, so a joiner adopts only a file
    /// signed by the owners it was promised.
    pub fn owner_set_hash(&self) -> Result<[u8; 16]> {
        let mut fps: Vec<String> = self
            .owner_keys()?
            .iter()
            .map(|k| k.fingerprint(HashAlg::Sha256).to_string())
            .collect();
        fps.sort();
        fps.dedup();
        let h = blake3::hash(fps.join("\n").as_bytes());
        Ok(h.as_bytes()[..16].try_into().expect("16 bytes"))
    }

    pub fn machine(&self, name: &str) -> Option<&Machine> {
        self.machines.iter().find(|m| m.name == name)
    }

    pub fn machine_by_id(&self, id: &EndpointId) -> Option<&Machine> {
        self.machines.iter().find(|m| &m.id == id)
    }

    pub fn hosts(&self, machine: &str, boundary: &str) -> bool {
        self.machine(machine)
            .is_some_and(|m| m.boundaries.iter().any(|b| b == boundary))
    }

    /// May `from` act on `to` in `cat`? Mail within one machine is always allowed.
    pub fn allows(&self, from: &str, to: &str, cat: Category) -> bool {
        if from == to && cat == Category::Converse {
            return true;
        }
        self.grants.iter().any(|g| {
            (g.from == "*" || g.from == from)
                && (g.to == "*" || g.to == to)
                && g.allow.contains(&cat)
        })
    }

    /// Whether `key` is one of this version's owner keys.
    pub fn has_owner(&self, key: &KeyData) -> bool {
        self.owner_keys()
            .is_ok_and(|ks| ks.iter().any(|k| k.key_data() == key))
    }

    pub fn approval(&self, machine: &str, boundary: &str, server: &str) -> Option<&Approval> {
        self.approvals
            .iter()
            .find(|a| a.machine == machine && a.boundary == boundary && a.server == server)
    }

    /// Turns this into the next version after `prev_toml` (the exact bytes it was signed as).
    pub fn bump(&mut self, prev_toml: &str) -> Result<()> {
        self.version = self.version.checked_add(1).context("version overflow")?;
        self.prev = Some(hash(prev_toml));
        self.format = 2;
        self.validate()
    }

    /// Adds a machine. An existing name is refused unless `replace`: a new node id under an old
    /// name would otherwise inherit that machine's grants silently. Replacing keeps the grants
    /// (a reinstalled machine) and drops its tool approvals (its offers must be approved again).
    pub fn add_machine(&mut self, m: Machine, replace: bool) -> Result<()> {
        if self.machine(&m.name).is_some() {
            ensure!(
                replace,
                "machine {} is already in the mesh; pass --replace to give it a new node id",
                m.name
            );
            self.machines.retain(|x| x.name != m.name);
            self.approvals.retain(|a| a.machine != m.name);
        }
        self.machines.push(m);
        Ok(())
    }

    /// Removes a machine (revocation), with every grant and approval that names it.
    pub fn remove_machine(&mut self, name: &str) -> Result<()> {
        let before = self.machines.len();
        self.machines.retain(|x| x.name != name);
        ensure!(self.machines.len() < before, "no machine named {name}");
        self.grants.retain(|g| g.from != name && g.to != name);
        self.approvals.retain(|a| a.machine != name);
        Ok(())
    }

    pub fn grant(&mut self, from: &str, to: &str, cats: &[Category]) {
        match self
            .grants
            .iter_mut()
            .find(|g| g.from == from && g.to == to)
        {
            Some(g) => {
                for c in cats {
                    if !g.allow.contains(c) {
                        g.allow.push(*c);
                    }
                }
                g.allow.sort();
            }
            None => {
                let mut allow = cats.to_vec();
                allow.sort();
                allow.dedup();
                self.grants.push(Grant {
                    from: from.into(),
                    to: to.into(),
                    allow,
                })
            }
        }
    }

    /// Removes categories from the exact `from → to` grant. Returns the categories a wildcard
    /// grant still allows for the pair, so the caller can say so.
    pub fn revoke(&mut self, from: &str, to: &str, cats: &[Category]) -> Result<Vec<Category>> {
        let g = self
            .grants
            .iter_mut()
            .find(|g| g.from == from && g.to == to)
            .with_context(|| format!("no grant {from} -> {to}"))?;
        g.allow.retain(|c| !cats.contains(c));
        self.grants.retain(|g| !g.allow.is_empty());
        Ok(cats
            .iter()
            .copied()
            .filter(|c| self.allows(from, to, *c))
            .collect())
    }
}

/// One change to the membership file. A new version is any list of these under one signature.
#[derive(Clone, Debug, PartialEq)]
pub enum Change {
    AddMachine { machine: Machine, replace: bool },
    RemoveMachine(String),
    Grant(Grant),
    /// Takes `allow` away from the exact `from → to` grant.
    Revoke(Grant),
    AddBoundary(String),
    /// Replaces the boundaries `machine` hosts; drops its approvals in any it stops hosting.
    SetHosts { machine: String, boundaries: Vec<String> },
    /// An OpenSSH public key line.
    OwnerAdd(String),
    /// A SHA256 fingerprint.
    OwnerRemove(String),
    /// `tools-sharing`, `relays` or `lookup`, with `mesh set`'s values.
    Set { setting: String, value: String },
}

impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let cats = |g: &Grant| g.allow.iter().map(|c| format!("{c:?}").to_lowercase()).collect::<Vec<_>>().join(",");
        match self {
            Change::AddMachine { machine: m, replace } => write!(
                f,
                "{} machine {} hosting {}",
                if *replace { "replace" } else { "add" },
                m.name,
                m.boundaries.join(", ")
            ),
            Change::RemoveMachine(n) => write!(f, "remove machine {n}"),
            Change::Grant(g) => write!(f, "grant {} -> {}: {}", g.from, g.to, cats(g)),
            Change::Revoke(g) => write!(f, "revoke {} -> {}: {}", g.from, g.to, cats(g)),
            Change::AddBoundary(b) => write!(f, "add boundary {b}"),
            Change::SetHosts { machine, boundaries } => write!(f, "{machine} hosts {}", boundaries.join(", ")),
            Change::OwnerAdd(k) => write!(f, "add owner key {}", k.split_whitespace().take(2).last().unwrap_or(k)),
            Change::OwnerRemove(fp) => write!(f, "remove owner key {fp}"),
            Change::Set { setting, value } => write!(f, "set {setting} = {value}"),
        }
    }
}

/// `from:to:cat,cat`, e.g. `laptop:ws:tools,shell`.
impl std::str::FromStr for Grant {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let mut p = s.splitn(3, ':');
        let (Some(from), Some(to), Some(cats)) = (p.next(), p.next(), p.next()) else {
            bail!("a grant is from:to:categories, e.g. laptop:ws:tools,shell");
        };
        Ok(Grant {
            from: from.into(),
            to: to.into(),
            allow: cats.split(',').map(str::parse).collect::<Result<_>>()?,
        })
    }
}

impl Mesh {
    /// Makes one change. Returns a note worth telling the person, if any.
    pub fn change(&mut self, c: &Change) -> Result<Option<String>> {
        match c {
            Change::AddMachine { machine, replace } => self.add_machine(machine.clone(), *replace)?,
            Change::RemoveMachine(n) => self.remove_machine(n)?,
            Change::Grant(g) => self.grant(&g.from, &g.to, &g.allow),
            Change::Revoke(g) => {
                let still = self.revoke(&g.from, &g.to, &g.allow)?;
                if !still.is_empty() {
                    return Ok(Some(format!(
                        "a wildcard grant still allows {still:?} for {} -> {}; replace it with explicit grants to exclude this pair",
                        g.from, g.to
                    )));
                }
            }
            Change::AddBoundary(b) => {
                ensure!(valid_name(b), "bad boundary name {b:?}");
                ensure!(!self.boundaries.contains(b), "the mesh already has boundary {b}");
                self.boundaries.push(b.clone());
            }
            Change::SetHosts { machine, boundaries } => {
                let m = self
                    .machines
                    .iter_mut()
                    .find(|m| &m.name == machine)
                    .with_context(|| format!("no machine named {machine}"))?;
                m.boundaries = boundaries.clone();
                let n = self.approvals.len();
                self.approvals
                    .retain(|a| &a.machine != machine || boundaries.contains(&a.boundary));
                if self.approvals.len() < n {
                    return Ok(Some(format!(
                        "dropped {} approval(s) in boundaries {machine} no longer hosts",
                        n - self.approvals.len()
                    )));
                }
            }
            Change::OwnerAdd(k) => self.owners.push(k.trim().to_string()),
            Change::OwnerRemove(fp) => {
                let keys = self.owner_keys()?;
                let n = self.owners.len();
                let owners = std::mem::take(&mut self.owners);
                self.owners = owners
                    .into_iter()
                    .zip(keys)
                    .filter(|(_, k)| k.fingerprint(Default::default()).to_string() != *fp)
                    .map(|(s, _)| s)
                    .collect();
                ensure!(self.owners.len() < n, "no owner key with fingerprint {fp}");
            }
            Change::Set { setting, value } => match setting.as_str() {
                "tools-sharing" => {
                    self.settings.tools_sharing = match value.as_str() {
                        "approval" => Sharing::Approval,
                        "free" => Sharing::Free,
                        _ => bail!("tools-sharing is approval or free"),
                    }
                }
                "relays" => {
                    self.settings.relays = match value.as_str() {
                        "n0" | "none" => Relay::Preset(value.clone()),
                        urls => Relay::Urls(urls.split(',').map(String::from).collect()),
                    }
                }
                "lookup" => {
                    self.settings.lookup = value
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect()
                }
                _ => bail!("unknown setting {setting} (tools-sharing, relays, lookup)"),
            },
        }
        Ok(None)
    }
}

/// The version after `prev_toml` (the exact signed bytes of the current one) with `changes` made,
/// and any notes. The caller signs the returned text.
pub fn next_version(prev_toml: &str, changes: &[Change]) -> Result<(Mesh, String, Vec<String>)> {
    let mut m = Mesh::parse(prev_toml)?;
    let mut notes = vec![];
    for c in changes {
        notes.extend(m.change(c)?);
    }
    m.bump(prev_toml)?;
    let toml = m.to_toml()?;
    Ok((m, toml, notes))
}

/// A membership file plus the owner signature that was checked against it.
#[derive(Clone, Debug)]
pub struct SignedMesh {
    pub toml: String,
    pub sig: String,
    pub mesh: Mesh,
    /// `hash(toml)`.
    pub hash: String,
    /// The owner key that signed it.
    pub signer: KeyData,
}

impl SignedMesh {
    /// The first file a machine adopts (or the oldest stored one): trusted on its own owner keys.
    /// Where it comes from (`mesh apply`, a ticket, local state) is the anchor.
    pub fn verify_first(toml: &str, sig: &str) -> Result<Self> {
        let sshsig = parse_sig(toml, sig)?;
        let mesh = Mesh::parse(toml)?;
        let ns = if mesh.format == 1 {
            V1_NAMESPACE
        } else {
            SIG_NAMESPACE
        };
        check_sig(&mesh, ns, toml, &sshsig)?;
        Ok(SignedMesh {
            toml: toml.into(),
            sig: sig.into(),
            mesh,
            hash: hash(toml),
            signer: sshsig.public_key().clone(),
        })
    }

    /// The version right after `prev`: signed by one of *its* owners (checked before anything a
    /// peer sent is parsed), same id, version + 1, and naming `prev`'s hash.
    pub fn verify_next(toml: &str, sig: &str, prev: &SignedMesh) -> Result<Self> {
        let sshsig = parse_sig(toml, sig)?;
        check_sig(&prev.mesh, SIG_NAMESPACE, toml, &sshsig)?;
        let mesh = Mesh::parse(toml)?;
        ensure!(mesh.format == 2, "a new version must be format 2");
        ensure!(
            mesh.id == prev.mesh.id,
            "mesh id {} is not this mesh ({})",
            mesh.id,
            prev.mesh.id
        );
        ensure!(
            Some(mesh.version) == prev.mesh.version.checked_add(1),
            "version {} doesn't follow {}",
            mesh.version,
            prev.mesh.version
        );
        ensure!(
            mesh.prev.as_deref() == Some(prev.hash.as_str()),
            "version {} doesn't build on the version {} this machine has",
            mesh.version,
            prev.mesh.version
        );
        Ok(SignedMesh {
            toml: toml.into(),
            sig: sig.into(),
            mesh,
            hash: hash(toml),
            signer: sshsig.public_key().clone(),
        })
    }
}

fn parse_sig(toml: &str, sig: &str) -> Result<SshSig> {
    ensure!(
        toml.len() <= MAX_FILE && sig.len() <= MAX_SIG,
        "membership file too large"
    );
    SshSig::from_pem(sig.trim().as_bytes()).context("membership signature")
}

fn check_sig(anchor: &Mesh, ns: &str, toml: &str, sshsig: &SshSig) -> Result<()> {
    let signer = anchor
        .owner_keys()?
        .into_iter()
        .find(|k| k.key_data() == sshsig.public_key())
        .context("not signed by an owner key")?;
    signer
        .verify(ns, toml.as_bytes(), sshsig)
        .context("signature does not verify")?;
    ensure!(
        sk_flags_ok(sshsig),
        "security-key signature lacks user presence or user verification (create the key with \
         `-O verify-required`)"
    );
    Ok(())
}

/// Security-key signatures carry a flags byte; ssh-key verifies the signature but leaves the
/// flags to us. Both user presence (0x01, a touch) and user verification (0x04, the PIN) are
/// required, so a stolen key and its handle can't sign with a touch alone.
fn sk_flags_ok(sig: &SshSig) -> bool {
    match sig.algorithm() {
        Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256 => {
            let b = sig.signature_bytes();
            b.len() >= 5 && b[b.len() - 5] & 0x05 == 0x05
        }
        _ => true,
    }
}

/// Signs a membership file with `ssh-keygen -Y sign`, which also works with keys on a YubiKey.
pub fn ssh_sign(key: &std::path::Path, toml_path: &std::path::Path) -> Result<()> {
    let status = std::process::Command::new("ssh-keygen")
        .args(["-q", "-Y", "sign", "-n", SIG_NAMESPACE, "-f"])
        .arg(key)
        .arg(toml_path)
        .status()
        .context("running ssh-keygen")?;
    ensure!(status.success(), "ssh-keygen -Y sign failed");
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    pub fn keygen(dir: &Path, name: &str) -> (PathBuf, String) {
        let key = dir.join(name);
        let ok = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", name, "-f"])
            .arg(&key)
            .status()
            .unwrap()
            .success();
        assert!(ok);
        let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
        (key, public.trim().to_string())
    }

    pub fn sign_ns(dir: &Path, key: &Path, toml: &str, ns: &str) -> String {
        let p = dir.join("mesh.toml");
        std::fs::write(&p, toml).unwrap();
        let _ = std::fs::remove_file(dir.join("mesh.toml.sig"));
        let ok = Command::new("ssh-keygen")
            .args(["-q", "-Y", "sign", "-n", ns, "-f"])
            .arg(key)
            .arg(&p)
            .status()
            .unwrap()
            .success();
        assert!(ok);
        std::fs::read_to_string(dir.join("mesh.toml.sig")).unwrap()
    }

    pub fn sign(dir: &Path, key: &Path, toml: &str) -> String {
        sign_ns(dir, key, toml, SIG_NAMESPACE)
    }

    #[test]
    fn changes_batch_into_one_version() {
        let d = tempfile::tempdir().unwrap();
        let (_, a) = keygen(d.path(), "a");
        let (_, b) = keygen(d.path(), "b");
        let mut m = Mesh::new("home", vec![a, b.clone()], vec!["work".into()], None).unwrap();
        m.add_machine(machine("ws", &["work"]), false).unwrap();
        let v1 = m.to_toml().unwrap();
        let (n, toml, _) = next_version(
            &v1,
            &[
                Change::AddBoundary("lab".into()),
                Change::AddMachine { machine: machine("beta", &["lab"]), replace: false },
                "beta:ws:tools".parse::<Grant>().map(Change::Grant).unwrap(),
                Change::SetHosts { machine: "ws".into(), boundaries: vec!["work".into(), "lab".into()] },
            ],
        )
        .unwrap();
        assert_eq!((n.version, n.prev.as_deref()), (2, Some(hash(&v1).as_str())));
        assert!(n.allows("beta", "ws", Category::Tools) && n.hosts("ws", "lab"));
        assert_eq!(Mesh::parse(&toml).unwrap(), n);

        let no = |c: Change| next_version(&v1, &[c]).is_err();
        assert!(no(Change::AddMachine { machine: machine("beta", &["lab"]), replace: false }), "unknown boundary");
        assert!(no(Change::AddBoundary("work".into())));
        assert!(no(Change::Set { setting: "tools-sharing".into(), value: "x".into() }));
        let fp = PublicKey::from_openssh(&b).unwrap().fingerprint(Default::default()).to_string();
        assert!(no(Change::OwnerRemove(fp)), "keeps two owner keys");
        assert!("a:b".parse::<Grant>().is_err() && "a:b:fly".parse::<Grant>().is_err());
    }

    fn machine(name: &str, bs: &[&str]) -> Machine {
        Machine {
            name: name.into(),
            id: iroh::SecretKey::generate().public(),
            boundaries: bs.iter().map(|b| b.to_string()).collect(),
        }
    }

    #[test]
    fn chain_rules() {
        let d = tempfile::tempdir().unwrap();
        let (k1, p1) = keygen(d.path(), "one");
        let (_k2, p2) = keygen(d.path(), "two");
        let (k3, p3) = keygen(d.path(), "three");

        assert!(Mesh::new("home", vec![p1.clone()], vec!["work".into()], None).is_err());

        let m1 = Mesh::new(
            "home",
            vec![p1.clone(), p2.clone()],
            vec!["work".into()],
            None,
        )
        .unwrap();
        let t1 = m1.to_toml().unwrap();
        let v1 = SignedMesh::verify_first(&t1, &sign(d.path(), &k1, &t1)).unwrap();
        assert!(
            SignedMesh::verify_first(&t1.replace("home", "homf"), &v1.sig).is_err(),
            "tampered bytes"
        );
        assert!(
            SignedMesh::verify_first(&t1, &sign_ns(d.path(), &k1, &t1, "other")).is_err(),
            "wrong namespace"
        );

        let mut m2 = m1.clone();
        m2.add_machine(machine("ws", &["work"]), false).unwrap();
        m2.bump(&t1).unwrap();
        let t2 = m2.to_toml().unwrap();
        assert!(
            SignedMesh::verify_next(&t2, &sign(d.path(), &k3, &t2), &v1).is_err(),
            "non-owner"
        );
        let v2 = SignedMesh::verify_next(&t2, &sign(d.path(), &k1, &t2), &v1).unwrap();
        assert!(
            SignedMesh::verify_next(&t2, &v2.sig, &v2).is_err(),
            "replay of the same version"
        );
        assert!(
            SignedMesh::verify_next(&t1, &v1.sig, &v2).is_err(),
            "rollback"
        );

        // A jump (here to u64::MAX) can't freeze the mesh: only version + 1 follows.
        let mut jump = m2.clone();
        jump.version = u64::MAX - 1;
        jump.bump(&t2).unwrap();
        let tj = jump.to_toml().unwrap();
        assert!(SignedMesh::verify_next(&tj, &sign(d.path(), &k1, &tj), &v2).is_err());
        assert!(jump.clone().bump(&tj).is_err(), "overflow is an error");

        // The next version must name the hash of the one it follows.
        let mut stray = m2.clone();
        stray.bump(&t1).unwrap(); // built on v1's bytes, numbered 3
        let ts = stray.to_toml().unwrap();
        assert!(SignedMesh::verify_next(&ts, &sign(d.path(), &k1, &ts), &v2).is_err());

        // An owner change is checked against the current owners, and the next version after it
        // against the new ones.
        let mut m3 = m2.clone();
        m3.owners = vec![p1.clone(), p3.clone()];
        m3.bump(&t2).unwrap();
        let t3 = m3.to_toml().unwrap();
        assert!(SignedMesh::verify_next(&t3, &sign(d.path(), &k3, &t3), &v2).is_err());
        let v3 = SignedMesh::verify_next(&t3, &sign(d.path(), &k1, &t3), &v2).unwrap();
        let mut m4 = m3.clone();
        m4.bump(&t3).unwrap();
        let t4 = m4.to_toml().unwrap();
        SignedMesh::verify_next(&t4, &sign(d.path(), &k3, &t4), &v3).unwrap();
    }

    #[test]
    fn carries_a_v1_circle_over() {
        let d = tempfile::tempdir().unwrap();
        let (k1, p1) = keygen(d.path(), "one");
        let (_k2, p2) = keygen(d.path(), "two");
        let v1 = format!(
            "id = \"abc123\"\nname = \"home\"\nversion = 4\nowners = [{p1:?}, {p2:?}]\nboundaries = [\"work\"]\n"
        );
        let old =
            SignedMesh::verify_first(&v1, &sign_ns(d.path(), &k1, &v1, V1_NAMESPACE)).unwrap();
        assert_eq!(old.mesh.format, 1);
        assert!(
            old.mesh.allows("a", "b", Category::Converse),
            "0.1 mail still flows"
        );
        assert!(
            SignedMesh::verify_first(&v1, &sign(d.path(), &k1, &v1)).is_err(),
            "a v1 file isn't valid under the new namespace"
        );
        let mut next = old.mesh.clone();
        next.bump(&v1).unwrap();
        let t = next.to_toml().unwrap();
        let v = SignedMesh::verify_next(&t, &sign(d.path(), &k1, &t), &old).unwrap();
        assert_eq!((v.mesh.version, v.mesh.format), (5, 2));
    }

    #[test]
    fn grants_and_machines() {
        let d = tempfile::tempdir().unwrap();
        let (_k1, p1) = keygen(d.path(), "one");
        let (_k2, p2) = keygen(d.path(), "two");
        let mut m = Mesh::new(
            "home",
            vec![p1, p2],
            vec!["work".into(), "vault".into()],
            None,
        )
        .unwrap();
        m.add_machine(machine("a", &["work"]), false).unwrap();
        m.add_machine(machine("b", &["work", "vault"]), false)
            .unwrap();
        assert!(
            m.add_machine(machine("a", &["work"]), false).is_err(),
            "name reuse"
        );

        assert!(
            m.allows("a", "b", Category::Converse),
            "default * -> * mail"
        );
        assert!(!m.allows("a", "b", Category::Tools), "deny by default");
        m.grant("a", "b", &[Category::Tools, Category::Shell]);
        assert!(m.allows("a", "b", Category::Shell) && !m.allows("b", "a", Category::Shell));
        m.validate().unwrap();

        m.grant("*", "b", &[Category::Shell]);
        assert!(m.validate().is_err(), "wildcard shell");
        m.grants.retain(|g| g.from != "*" || g.to != "b");

        // Revoking a pair still covered by * says so.
        m.grant("a", "b", &[Category::Converse]);
        assert_eq!(
            m.revoke("a", "b", &[Category::Converse]).unwrap(),
            vec![Category::Converse]
        );

        m.approvals.push(Approval {
            machine: "a".into(),
            boundary: "vault".into(),
            server: "cad".into(),
            pin: "0".repeat(64),
            tools: None,
        });
        assert!(m.validate().is_err(), "a doesn't host vault");
        m.approvals[0].boundary = "work".into();
        m.validate().unwrap();

        // Removing a machine takes its grants and approvals with it, so the file stays valid.
        m.remove_machine("a").unwrap();
        assert!(m.grants.iter().all(|g| g.from != "a" && g.to != "a"));
        assert!(m.approvals.is_empty());
        m.validate().unwrap();
        // Replacing keeps grants and drops approvals.
        m.grant("b", "*", &[Category::Tools]);
        m.add_machine(machine("b", &["work"]), true).unwrap();
        assert!(m.allows("b", "x", Category::Tools));
    }

    #[test]
    fn owner_set_hash_ignores_order_and_comments() {
        let d = tempfile::tempdir().unwrap();
        let (_k1, p1) = keygen(d.path(), "one");
        let (_k2, p2) = keygen(d.path(), "two");
        let a = Mesh::new("home", vec![p1.clone(), p2.clone()], vec!["w".into()], None).unwrap();
        let mut b = a.clone();
        b.owners = vec![p2.replace(" two", " renamed"), p1];
        assert_eq!(a.owner_set_hash().unwrap(), b.owner_set_hash().unwrap());
    }
}
