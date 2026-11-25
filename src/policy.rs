//! Every placement and permission decision lives here: which boundaries a log may hold, which peers
//! may receive a boundary, whether a received entry is acceptable, and which machines may address,
//! call or drive which. Nothing else decides where data goes.

use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use iroh::EndpointId;

use crate::envelope::{Entry, Envelope, Label, Trust, parse_address};
use crate::mesh::{Category, Mesh, Sharing};

/// Boundaries whose content a log for `boundary` may hold.
/// 0.1.0 is same-boundary-only: each boundary is cleared for itself alone.
pub fn cleared(boundary: &str) -> BTreeSet<String> {
    [boundary.to_string()].into()
}

/// A label fits a boundary's log when it names that boundary and nothing the log isn't cleared for.
pub fn label_fits(label: &Label, boundary: &str) -> bool {
    label.boundaries.contains(boundary) && label.boundaries.is_subset(&cleared(boundary))
}

/// The label on anything written in `boundary` with `trust`.
pub fn post_label(boundary: &str, trust: Trust) -> Label {
    Label {
        boundaries: [boundary.to_string()].into(),
        trust,
    }
}

/// Boundaries both this machine and `peer` host. Sync offers, and even mentions, only these.
pub fn shared_boundaries(mesh: &Mesh, me: &str, peer: &EndpointId) -> Vec<String> {
    let (Some(mine), Some(theirs)) = (mesh.machine(me), mesh.machine_by_id(peer)) else {
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

pub fn may_sync(mesh: &Mesh, me: &str, peer: &EndpointId, boundary: &str) -> bool {
    shared_boundaries(mesh, me, peer)
        .iter()
        .any(|b| b == boundary)
}

/// Recipients must be `*` or a mailbox on a machine that hosts the boundary, so a letter is never
/// addressed to someone who could not receive it.
pub fn check_recipients(mesh: &Mesh, boundary: &str, to: &[String]) -> Result<()> {
    for a in to {
        if a == "*" {
            continue;
        }
        let (_, host) = parse_address(a).ok_or_else(|| match crate::valid_name(a) {
            true => anyhow::anyhow!("bad address {a:?}: use mailbox@machine (for example admin@{a}), or * for everyone"),
            false => anyhow::anyhow!("bad address {a:?}: use mailbox@machine, or * for everyone"),
        })?;
        ensure!(
            mesh.hosts(host, boundary),
            "{host} is not in boundary {boundary}; can't address {a}"
        );
    }
    Ok(())
}

/// A local post: every named recipient's machine must accept mail from this one. `*` is always
/// allowed; each receiving machine shows it only if it accepts mail from the sender.
pub fn check_converse(mesh: &Mesh, me: &str, to: &[String]) -> Result<()> {
    for a in to {
        if let Some((_, host)) = parse_address(a) {
            ensure!(
                mesh.allows(me, host, Category::Converse),
                "{me} has no converse grant to {host}, so {host} won't deliver mail from it"
            );
        }
    }
    Ok(())
}

/// Whether this machine shows an entry to its sessions. Letters need a converse grant from the
/// author's machine to this one, checked against the current file, so revoking a grant also hides
/// earlier letters. Offers and bios are always visible: hiding them would quietly break tool
/// calls in the other direction.
pub fn visible(mesh: &Mesh, me: &str, env: &Envelope) -> bool {
    if !env.kind.is_letter() {
        return true;
    }
    mesh.machine_by_id(&env.author)
        .is_some_and(|m| mesh.allows(&m.name, me, Category::Converse))
}

/// Whether a session in `boundary` on `caller` may call `server` offered by `target`. Both
/// machines must host the boundary, the caller needs a tools grant, and, when the mesh requires
/// approval, the owner must have approved the offer. Returns the approval, if any, for its pin
/// and tool subset.
pub fn may_call<'a>(
    mesh: &'a Mesh,
    caller: &str,
    target: &str,
    boundary: &str,
    server: &str,
) -> Result<Option<&'a crate::mesh::Approval>> {
    ensure!(
        mesh.hosts(caller, boundary) && mesh.hosts(target, boundary),
        "{caller} and {target} don't both host boundary {boundary}"
    );
    ensure!(
        caller != target,
        "{server} is on this machine; use it directly"
    );
    ensure!(
        mesh.allows(caller, target, Category::Tools),
        "{caller} has no tools grant to {target}"
    );
    let approval = mesh.approval(target, boundary, server);
    if mesh.settings.tools_sharing == Sharing::Approval {
        ensure!(
            approval.is_some(),
            "the owner hasn't approved {target}/{server} in {boundary}"
        );
    }
    Ok(approval)
}

/// Whether `caller` may reach `target`'s sshd, for a session in `boundary`.
pub fn may_shell(mesh: &Mesh, caller: &str, target: &str, boundary: &str) -> Result<()> {
    ensure!(
        mesh.hosts(caller, boundary) && mesh.hosts(target, boundary),
        "{caller} and {target} don't both host boundary {boundary}"
    );
    ensure!(
        mesh.allows(caller, target, Category::Shell),
        "{caller} has no shell grant to {target}"
    );
    Ok(())
}

/// A status record's body: a JSON object of at most 4 KiB with only `about` (a string) and
/// `pending_questions` (a whole number), both optional.
pub fn check_status(body: &str) -> Result<()> {
    use crate::envelope::MAX_STATUS;
    ensure!(body.len() <= MAX_STATUS, "a status record is at most {MAX_STATUS} bytes");
    let m: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(body).map_err(|_| anyhow::anyhow!("a status record's body is a JSON object"))?;
    for (k, v) in &m {
        match k.as_str() {
            "about" => ensure!(v.is_string(), "about must be text"),
            "pending_questions" => ensure!(v.is_u64(), "pending_questions must be a whole number"),
            _ => anyhow::bail!("a status record has only about and pending_questions, not {k:?}"),
        }
    }
    Ok(())
}

/// The one check every entry passes before it is stored, local or received.
pub fn check_entry(mesh: &Mesh, boundary: &str, entry: &Entry) -> Result<Envelope> {
    let env = entry.open()?;
    ensure!(env.mesh == mesh.id, "entry is from another mesh");
    ensure!(
        env.boundary == boundary,
        "entry for {} offered as {boundary}",
        env.boundary
    );
    let author = mesh
        .machine_by_id(&env.author)
        .ok_or_else(|| anyhow::anyhow!("author {} is not a member", env.author.fmt_short()))?;
    ensure!(
        mesh.hosts(&author.name, boundary),
        "author {} is not in boundary {boundary}",
        author.name
    );
    ensure!(
        label_fits(&env.label, boundary),
        "label {:?} doesn't fit boundary {boundary}",
        env.label.boundaries
    );
    ensure!(
        env.kind.is_letter() || env.to == ["*"],
        "offers, bios and status records go to the whole boundary"
    );
    match env.kind {
        crate::envelope::Kind::Claim => {
            ensure!(env.thread.is_some(), "a claim answers a letter: it needs a thread");
            let b = entry.body.as_bytes();
            ensure!(
                b.len() <= 8 && b.iter().all(u8::is_ascii_digit),
                "a claim's body is empty or the seconds until the answer (1 to 8 digits)"
            );
        }
        crate::envelope::Kind::Status => check_status(&entry.body)?,
        crate::envelope::Kind::Bio => ensure!(
            entry.body.len() <= crate::envelope::MAX_BIO,
            "bio over {} bytes",
            crate::envelope::MAX_BIO
        ),
        crate::envelope::Kind::Offer => {
            let o = crate::offer::Offer::parse(&entry.body)?;
            ensure!(
                o.server == env.subject,
                "offer for {} filed as {}",
                o.server,
                env.subject
            );
        }
        _ => {}
    }
    let (_, from_host) = parse_address(&env.from).ok_or_else(|| anyhow::anyhow!("bad from"))?;
    ensure!(
        from_host == author.name,
        "from {} doesn't match author {}",
        env.from,
        author.name
    );
    check_recipients(mesh, boundary, &env.to)?;
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Kind;
    use crate::envelope::tests::envelope;
    use crate::mesh::{Grant, Machine, Settings};
    use iroh::SecretKey;

    fn circle(ws: &SecretKey, laptop: &SecretKey) -> Mesh {
        Mesh {
            format: 2,
            id: "c1".into(),
            name: "home".into(),
            version: 1,
            prev: None,
            closed: false,
            owners: vec![],
            boundaries: vec!["work".into(), "vault".into()],
            settings: Settings::default(),
            grants: vec![Grant {
                from: "*".into(),
                to: "*".into(),
                allow: vec![Category::Converse],
            }],
            approvals: vec![],
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

        let mut wider = post_label("vault", Trust::Member);
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
        e.label = post_label("vault", Trust::Member);
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

        // Any trust level is storable; an offer must go to the whole boundary.
        let mut e = envelope(&ws, 1, None, "b");
        e.label.trust = Trust::Guest;
        assert!(check_entry(&c, "work", &Entry::sign(&e, "b".into(), &ws).unwrap()).is_ok());
        e.kind = Kind::Offer;
        assert!(check_entry(&c, "work", &Entry::sign(&e, "b".into(), &ws).unwrap()).is_err());
    }

    #[test]
    fn converse_and_calls() {
        let (ws, laptop) = (SecretKey::generate(), SecretKey::generate());
        let mut c = circle(&ws, &laptop);
        c.grants.clear();
        let letter = envelope(&ws, 1, None, "b");
        assert!(!visible(&c, "laptop", &letter), "no grant, no delivery");
        assert!(visible(&c, "ws", &letter), "mail within one machine");
        assert!(check_converse(&c, "ws", &["admin@laptop".into()]).is_err());
        assert!(check_converse(&c, "ws", &["*".into(), "x@ws".into()]).is_ok());
        let mut offer = letter.clone();
        offer.kind = Kind::Offer;
        assert!(visible(&c, "laptop", &offer), "offers stay visible");
        c.grants.push(Grant {
            from: "ws".into(),
            to: "laptop".into(),
            allow: vec![Category::Converse],
        });
        assert!(visible(&c, "laptop", &letter));

        assert!(
            may_call(&c, "laptop", "ws", "work", "cad").is_err(),
            "no tools grant"
        );
        c.grant("laptop", "ws", &[Category::Tools]);
        assert!(
            may_call(&c, "laptop", "ws", "work", "cad").is_err(),
            "not approved"
        );
        assert!(
            may_call(&c, "laptop", "ws", "vault", "cad").is_err(),
            "laptop isn't in vault"
        );
        c.settings.tools_sharing = Sharing::Free;
        assert!(
            may_call(&c, "laptop", "ws", "work", "cad")
                .unwrap()
                .is_none()
        );
        assert!(may_shell(&c, "laptop", "ws", "work").is_err());
    }
}
