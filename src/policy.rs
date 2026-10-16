//! Every placement decision lives here: which boundaries a log may hold, which peers may receive a
//! boundary, and whether a received entry is acceptable. Nothing else decides where data goes.

use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use iroh::EndpointId;

use crate::circle::Circle;
use crate::envelope::{Entry, Envelope, Label, Trust, parse_address};

/// Boundaries whose content a log for `boundary` may hold.
/// 0.1.0 is same-boundary-only: each boundary is cleared for itself alone.
pub fn cleared(boundary: &str) -> BTreeSet<String> {
    [boundary.to_string()].into()
}

/// A label fits a boundary's log when it names that boundary and nothing the log isn't cleared for.
pub fn label_fits(label: &Label, boundary: &str) -> bool {
    label.boundaries.contains(boundary) && label.boundaries.is_subset(&cleared(boundary))
}

/// The label on anything a session in `boundary` writes.
pub fn post_label(boundary: &str) -> Label {
    Label {
        boundaries: [boundary.to_string()].into(),
        trust: Trust::Circle,
    }
}

/// Boundaries both this machine and `peer` host. Sync offers, and even mentions, only these.
pub fn shared_boundaries(circle: &Circle, me: &str, peer: &EndpointId) -> Vec<String> {
    let (Some(mine), Some(theirs)) = (circle.machine(me), circle.machine_by_id(peer)) else {
        return vec![];
    };
    if mine.name == theirs.name {
        return vec![];
    }
    mine.boundaries
        .iter()
        .filter(|b| theirs.boundaries.contains(b))
        .cloned()
        .collect()
}

pub fn may_sync(circle: &Circle, me: &str, peer: &EndpointId, boundary: &str) -> bool {
    shared_boundaries(circle, me, peer)
        .iter()
        .any(|b| b == boundary)
}

/// Recipients must be `*` or a mailbox on a machine that hosts the boundary, so a letter is never
/// addressed to someone who could not receive it.
pub fn check_recipients(circle: &Circle, boundary: &str, to: &[String]) -> Result<()> {
    for a in to {
        if a == "*" {
            continue;
        }
        let (_, host) = parse_address(a).ok_or_else(|| anyhow::anyhow!("bad address {a:?}"))?;
        ensure!(
            circle.hosts(host, boundary),
            "{host} is not in boundary {boundary}; can't address {a}"
        );
    }
    Ok(())
}

/// The one check every entry passes before it is stored, local or received.
pub fn check_entry(circle: &Circle, boundary: &str, entry: &Entry) -> Result<Envelope> {
    let env = entry.open()?;
    ensure!(env.circle == circle.id, "entry is from another circle");
    ensure!(
        env.boundary == boundary,
        "entry for {} offered as {boundary}",
        env.boundary
    );
    let author = circle
        .machine_by_id(&env.author)
        .ok_or_else(|| anyhow::anyhow!("author {} is not a member", env.author.fmt_short()))?;
    ensure!(
        circle.hosts(&author.name, boundary),
        "author {} is not in boundary {boundary}",
        author.name
    );
    ensure!(
        label_fits(&env.label, boundary),
        "label {:?} doesn't fit boundary {boundary}",
        env.label.boundaries
    );
    ensure!(
        env.label.trust == Trust::Circle,
        "only circle trust exists before guests ship"
    );
    let (_, from_host) = parse_address(&env.from).ok_or_else(|| anyhow::anyhow!("bad from"))?;
    ensure!(
        from_host == author.name,
        "from {} doesn't match author {}",
        env.from,
        author.name
    );
    check_recipients(circle, boundary, &env.to)?;
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circle::Machine;
    use crate::envelope::tests::envelope;
    use iroh::SecretKey;

    fn circle(ws: &SecretKey, laptop: &SecretKey) -> Circle {
        Circle {
            id: "c1".into(),
            name: "home".into(),
            version: 1,
            owners: vec![],
            boundaries: vec!["work".into(), "vault".into()],
            machines: vec![
                Machine {
                    name: "ws".into(),
                    id: ws.public(),
                    boundaries: vec!["work".into(), "vault".into()],
                },
                Machine {
                    name: "laptop".into(),
                    id: laptop.public(),
                    boundaries: vec!["work".into()],
                },
            ],
        }
    }

    #[test]
    fn same_boundary_only() {
        let (ws, laptop) = (SecretKey::generate(), SecretKey::generate());
        let c = circle(&ws, &laptop);
        assert_eq!(
            shared_boundaries(&c, "ws", &laptop.public()),
            vec!["work".to_string()]
        );
        assert!(!may_sync(&c, "ws", &laptop.public(), "vault"));
        assert!(shared_boundaries(&c, "ws", &SecretKey::generate().public()).is_empty());

        let mut wider = post_label("vault");
        wider.boundaries.insert("work".into());
        assert!(
            !label_fits(&wider, "vault"),
            "a vault+work label fits no single log yet"
        );
        assert!(check_recipients(&c, "vault", &["admin@laptop".into()]).is_err());
        assert!(check_recipients(&c, "work", &["admin@laptop".into(), "*".into()]).is_ok());
    }

    #[test]
    fn entry_checks() {
        let (ws, laptop) = (SecretKey::generate(), SecretKey::generate());
        let c = circle(&ws, &laptop);
        let ok = Entry::sign(&envelope(&ws, 1, None, "b"), "b".into(), &ws).unwrap();
        assert!(check_entry(&c, "work", &ok).is_ok());
        assert!(
            check_entry(&c, "vault", &ok).is_err(),
            "offered under another boundary"
        );

        // laptop isn't in vault, so it can't author vault entries.
        let mut e = envelope(&laptop, 1, None, "b");
        e.boundary = "vault".into();
        e.from = "x@laptop".into();
        e.to = vec!["*".into()];
        e.label = post_label("vault");
        let bad = Entry::sign(&e, "b".into(), &laptop).unwrap();
        assert!(check_entry(&c, "vault", &bad).is_err());

        // from must name the author's machine.
        let mut e = envelope(&laptop, 1, None, "b");
        e.from = "builder@ws".into();
        let spoof = Entry::sign(&e, "b".into(), &laptop).unwrap();
        assert!(check_entry(&c, "work", &spoof).is_err());

        // A stranger's key is refused.
        let s = SecretKey::generate();
        let mut e = envelope(&s, 1, None, "b");
        e.from = "x@ws".into();
        assert!(check_entry(&c, "work", &Entry::sign(&e, "b".into(), &s).unwrap()).is_err());
    }
}
