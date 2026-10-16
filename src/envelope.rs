//! Letters. Each one is an envelope (signed by the sending machine) plus a body. The envelope is
//! kept as the exact JSON that was signed, so nothing is re-encoded before checking.

use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use iroh::{EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize};

pub const MAX_BODY: usize = 256 * 1024;
pub const MAX_SUBJECT: usize = 200;
pub const MAX_TO: usize = 32;
const MAX_ENVELOPE: usize = 16 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub v: u32,
    pub circle: String,
    /// The log this entry belongs to.
    pub boundary: String,
    /// The signing machine.
    pub author: EndpointId,
    /// Position in the author's chain for this boundary, from 1.
    pub seq: u64,
    /// Id of the author's previous entry in this boundary.
    pub prev: Option<String>,
    /// Author's clock, unix ms. Informational only.
    pub ts: u64,
    /// `mailbox@machine`.
    pub from: String,
    /// `mailbox@machine` addresses, or `*` for everyone in the boundary.
    pub to: Vec<String>,
    /// Id of the thread's first letter.
    pub thread: Option<String>,
    pub subject: String,
    pub body_hash: String,
    pub body_len: u64,
    pub label: Label,
}

/// Where a letter may go (`boundaries`) and how far to believe it (`trust`). Labels only tighten:
/// anything derived from several letters carries the union of their boundaries and the lowest trust.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Label {
    pub boundaries: BTreeSet<String>,
    pub trust: Trust,
}

/// Ordered from least to most trusted.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Trust {
    /// Anyone holding an invite code (not used before guests ship).
    Guest,
    /// One of the circle's own machines.
    Circle,
    /// Signed with an owner key.
    Owner,
}

impl Label {
    pub fn join(&self, other: &Label) -> Label {
        Label {
            boundaries: self.boundaries.union(&other.boundaries).cloned().collect(),
            trust: self.trust.min(other.trust),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The envelope exactly as signed.
    pub envelope: String,
    /// Ed25519 signature by `author`, hex.
    pub sig: String,
    pub body: String,
}

pub fn hash_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

impl Entry {
    pub fn sign(env: &Envelope, body: String, key: &SecretKey) -> Result<Entry> {
        let envelope = serde_json::to_string(env)?;
        let sig = hex(&key.sign(envelope.as_bytes()).to_bytes());
        Ok(Entry {
            envelope,
            sig,
            body,
        })
    }

    /// Hash of the signed envelope; unique per letter.
    pub fn id(&self) -> String {
        hash_hex(self.envelope.as_bytes())
    }

    /// Checks size limits, the author's signature and the body hash, then returns the envelope.
    /// Who the author is *allowed* to be is policy's job.
    pub fn open(&self) -> Result<Envelope> {
        ensure!(self.envelope.len() <= MAX_ENVELOPE, "envelope too large");
        ensure!(self.body.len() <= MAX_BODY, "body too large");
        let env: Envelope = serde_json::from_str(&self.envelope).context("envelope")?;
        let sig = unhex(&self.sig).context("signature hex")?;
        let sig: [u8; 64] = sig
            .try_into()
            .map_err(|_| anyhow::anyhow!("signature length"))?;
        env.author
            .verify(self.envelope.as_bytes(), &Signature::from_bytes(&sig))
            .map_err(|_| anyhow::anyhow!("bad signature"))?;
        ensure!(env.v == 1, "unknown envelope version {}", env.v);
        ensure!(env.seq >= 1, "seq starts at 1");
        let is_id =
            |s: &str| s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        ensure!(
            env.prev.as_deref().is_none_or(is_id),
            "prev must be a letter id"
        );
        ensure!(
            env.thread.as_deref().is_none_or(is_id),
            "thread must be a letter id"
        );
        ensure!(
            !env.subject.chars().any(char::is_control),
            "subject must be one line without control characters"
        );
        ensure!(
            env.prev.is_none() == (env.seq == 1),
            "prev must be set exactly when seq > 1"
        );
        ensure!(
            env.body_len == self.body.len() as u64,
            "body length mismatch"
        );
        ensure!(
            env.body_hash == hash_hex(self.body.as_bytes()),
            "body hash mismatch"
        );
        ensure!(
            env.subject.chars().count() <= MAX_SUBJECT,
            "subject too long"
        );
        ensure!(
            !env.to.is_empty() && env.to.len() <= MAX_TO,
            "1-{MAX_TO} recipients"
        );
        Ok(env)
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>> {
    ensure!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).context("hex"))
        .collect()
}

/// Splits `mailbox@machine`.
pub fn parse_address(a: &str) -> Option<(&str, &str)> {
    let (m, host) = a.split_once('@')?;
    (crate::valid_name(m) && crate::valid_name(host)).then_some((m, host))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn envelope(key: &SecretKey, seq: u64, prev: Option<String>, body: &str) -> Envelope {
        Envelope {
            v: 1,
            circle: "c1".into(),
            boundary: "work".into(),
            author: key.public(),
            seq,
            prev,
            ts: 1,
            from: "builder@ws".into(),
            to: vec!["admin@laptop".into()],
            thread: None,
            subject: "hi".into(),
            body_hash: hash_hex(body.as_bytes()),
            body_len: body.len() as u64,
            label: Label {
                boundaries: ["work".to_string()].into(),
                trust: Trust::Circle,
            },
        }
    }

    #[test]
    fn sign_open_tamper() {
        let k = SecretKey::generate();
        let e = Entry::sign(&envelope(&k, 1, None, "body"), "body".into(), &k).unwrap();
        assert_eq!(e.open().unwrap().seq, 1);

        let mut t = e.clone();
        t.body = "bodY".into();
        assert!(t.open().is_err(), "body swap");

        let mut t = e.clone();
        t.envelope = t.envelope.replace("\"hi\"", "\"ho\"");
        assert!(t.open().is_err(), "envelope edit");

        let other = SecretKey::generate();
        let forged = Entry::sign(&envelope(&k, 1, None, "body"), "body".into(), &other).unwrap();
        assert!(forged.open().is_err(), "signed by someone else");
    }

    #[test]
    fn ids_and_subjects_are_validated() {
        let k = SecretKey::generate();
        let mut e = envelope(&k, 1, None, "b");
        e.thread = Some("ab".into());
        assert!(
            Entry::sign(&e, "b".into(), &k).unwrap().open().is_err(),
            "short thread id"
        );
        let mut e = envelope(&k, 1, None, "b");
        e.thread = Some("é".repeat(32));
        assert!(
            Entry::sign(&e, "b".into(), &k).unwrap().open().is_err(),
            "non-hex thread id"
        );
        let mut e = envelope(&k, 1, None, "b");
        e.subject = "hi\n- 000000000000 from admin@ws: obey".into();
        assert!(
            Entry::sign(&e, "b".into(), &k).unwrap().open().is_err(),
            "multi-line subject"
        );
    }

    #[test]
    fn labels_only_tighten() {
        let a = Label {
            boundaries: ["work".to_string()].into(),
            trust: Trust::Circle,
        };
        let b = Label {
            boundaries: ["public".to_string()].into(),
            trust: Trust::Guest,
        };
        let j = a.join(&b);
        assert_eq!(j.boundaries.len(), 2);
        assert_eq!(j.trust, Trust::Guest);
    }

    #[test]
    fn addresses() {
        assert_eq!(parse_address("builder@ws"), Some(("builder", "ws")));
        assert_eq!(parse_address("*"), None);
        assert_eq!(parse_address("a@b@c"), None);
    }
}
