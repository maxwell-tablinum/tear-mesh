//! The circle file: which machines belong, which boundaries each may host, and which owner keys
//! may sign the next version. It is TOML, signed with an ordinary SSH key (`ssh-keygen -Y sign`).

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, PublicKey, SshSig};

use crate::valid_name;

/// SSHSIG namespace, so a circle signature can't be replayed as any other kind of SSH signature.
pub const SIG_NAMESPACE: &str = "tear-mesh-circle";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Circle {
    /// Random, fixed at creation. Entries and invites carry it so two circles never mix.
    pub id: String,
    pub name: String,
    /// Goes up with every change. A daemon never adopts an older or equal version.
    pub version: u64,
    /// OpenSSH public keys. Any one may sign the next version; at least two are required so
    /// losing one key doesn't lock the circle forever.
    pub owners: Vec<String>,
    pub boundaries: Vec<String>,
    #[serde(default, rename = "machine")]
    pub machines: Vec<Machine>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Machine {
    pub name: String,
    pub id: EndpointId,
    pub boundaries: Vec<String>,
}

impl Circle {
    pub fn new(name: &str, owners: Vec<String>, boundaries: Vec<String>) -> Result<Self> {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).map_err(|e| anyhow::anyhow!("random: {e}"))?;
        let c = Circle {
            id: id.iter().map(|b| format!("{b:02x}")).collect(),
            name: name.to_string(),
            version: 1,
            owners,
            boundaries,
            machines: vec![],
        };
        c.validate()?;
        Ok(c)
    }

    pub fn parse(toml_text: &str) -> Result<Self> {
        let c: Circle = toml::from_str(toml_text).context("circle file")?;
        c.validate()?;
        Ok(c)
    }

    pub fn to_toml(&self) -> Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.id.is_empty() && self.id.len() <= 64,
            "circle id must be 1-64 chars"
        );
        ensure!(valid_name(&self.name), "bad circle name {:?}", self.name);
        ensure!(self.version >= 1, "version starts at 1");
        let keys = self.owner_keys()?;
        let distinct: BTreeSet<_> = keys.iter().map(|k| k.key_data().clone()).collect();
        ensure!(
            distinct.len() >= 2,
            "a circle needs at least two distinct owner keys, so losing one doesn't lock it"
        );
        ensure!(
            !self.boundaries.is_empty(),
            "a circle needs at least one boundary"
        );
        let mut seen = BTreeSet::new();
        for b in &self.boundaries {
            ensure!(valid_name(b), "bad boundary name {b:?}");
            ensure!(seen.insert(b), "boundary {b} listed twice");
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

    /// Adds or replaces a machine and bumps the version.
    pub fn set_machine(&mut self, m: Machine) -> Result<()> {
        self.machines.retain(|x| x.name != m.name);
        self.machines.push(m);
        self.version += 1;
        self.validate()
    }

    /// Removes a machine (revocation) and bumps the version.
    pub fn remove_machine(&mut self, name: &str) -> Result<()> {
        let before = self.machines.len();
        self.machines.retain(|x| x.name != name);
        ensure!(self.machines.len() < before, "no machine named {name}");
        self.version += 1;
        self.validate()
    }
}

/// A circle file plus the owner signature that was checked against it.
#[derive(Clone, Debug)]
pub struct SignedCircle {
    pub toml: String,
    pub sig: String,
    pub circle: Circle,
}

impl SignedCircle {
    /// Checks `sig` (an SSHSIG PEM) over the exact bytes of `toml`.
    ///
    /// With a `current` circle, the signer must be one of *its* owners, the id must match and the
    /// version must go up. Without one (the first circle a machine adopts, from `circle apply` or
    /// an invite handed over out of band), the file's own owners are the anchor.
    pub fn verify(toml: &str, sig: &str, current: Option<&Circle>) -> Result<Self> {
        ensure!(
            toml.len() <= 64 * 1024 && sig.len() <= 8 * 1024,
            "circle file too large"
        );
        let sshsig = SshSig::from_pem(sig.trim().as_bytes()).context("circle signature")?;
        // With a current circle, check the signature before parsing anything a peer sent.
        if let Some(cur) = current {
            check_sig(cur, toml, &sshsig)?;
        }
        let circle = Circle::parse(toml)?;
        if current.is_none() {
            check_sig(&circle, toml, &sshsig)?;
        }
        if let Some(cur) = current {
            ensure!(
                circle.id == cur.id,
                "circle id {} is not this circle ({})",
                circle.id,
                cur.id
            );
            if circle.version <= cur.version {
                bail!(
                    "circle version {} is not newer than {}",
                    circle.version,
                    cur.version
                );
            }
        }
        Ok(SignedCircle {
            toml: toml.to_string(),
            sig: sig.to_string(),
            circle,
        })
    }
}

fn check_sig(anchor: &Circle, toml: &str, sshsig: &SshSig) -> Result<()> {
    let signer = anchor
        .owner_keys()?
        .into_iter()
        .find(|k| k.key_data() == sshsig.public_key())
        .context("circle is not signed by an owner key")?;
    signer
        .verify(SIG_NAMESPACE, toml.as_bytes(), sshsig)
        .context("circle signature does not verify")?;
    ensure!(
        user_present(sshsig),
        "security-key signature lacks the user-presence flag"
    );
    Ok(())
}

/// Security-key signatures carry a flags byte; ssh-key verifies the signature but leaves the
/// user-presence bit (0x01, "someone touched the key") to us.
fn user_present(sig: &SshSig) -> bool {
    match sig.algorithm() {
        Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256 => {
            let b = sig.signature_bytes();
            b.len() >= 5 && b[b.len() - 5] & 0x01 != 0
        }
        _ => true,
    }
}

/// Signs a circle file with `ssh-keygen -Y sign`, which also works with keys on a YubiKey.
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

    pub fn sign(dir: &Path, key: &Path, toml: &str) -> String {
        let p = dir.join("circle.toml");
        std::fs::write(&p, toml).unwrap();
        let _ = std::fs::remove_file(dir.join("circle.toml.sig"));
        ssh_sign(key, &p).unwrap();
        std::fs::read_to_string(dir.join("circle.toml.sig")).unwrap()
    }

    #[test]
    fn verify_rules() {
        let d = tempfile::tempdir().unwrap();
        let (k1, p1) = keygen(d.path(), "one");
        let (_k2, p2) = keygen(d.path(), "two");
        let (k3, p3) = keygen(d.path(), "three");

        // One owner key is refused.
        assert!(Circle::new("home", vec![p1.clone()], vec!["work".into()]).is_err());

        let mut c = Circle::new("home", vec![p1.clone(), p2.clone()], vec!["work".into()]).unwrap();
        let v1 = c.to_toml().unwrap();
        let s1 = sign(d.path(), &k1, &v1);
        let first = SignedCircle::verify(&v1, &s1, None).unwrap();

        // Tampered bytes fail.
        assert!(SignedCircle::verify(&v1.replace("home", "homf"), &s1, None).is_err());

        // A non-owner can't sign the next version.
        c.set_machine(Machine {
            name: "ws".into(),
            id: iroh::SecretKey::generate().public(),
            boundaries: vec!["work".into()],
        })
        .unwrap();
        let v2 = c.to_toml().unwrap();
        let bad = sign(d.path(), &k3, &v2);
        assert!(SignedCircle::verify(&v2, &bad, Some(&first.circle)).is_err());

        // An owner can, and the version must go up.
        let s2 = sign(d.path(), &k1, &v2);
        let second = SignedCircle::verify(&v2, &s2, Some(&first.circle)).unwrap();
        assert!(
            SignedCircle::verify(&v1, &s1, Some(&second.circle)).is_err(),
            "rollback"
        );
        assert!(
            SignedCircle::verify(&v2, &s2, Some(&second.circle)).is_err(),
            "replay"
        );

        // A file listing a new owner set is still checked against the current owners.
        let mut takeover = c.clone();
        takeover.owners = vec![p3.clone(), p1.clone()];
        takeover.version += 1;
        let vt = takeover.to_toml().unwrap();
        let st = sign(d.path(), &k3, &vt);
        assert!(SignedCircle::verify(&vt, &st, Some(&second.circle)).is_err());

        // Unknown boundary on a machine is invalid.
        let mut broken = c.clone();
        broken.machines[0].boundaries = vec!["vault".into()];
        assert!(broken.validate().is_err());
    }
}
