//! tear-mesh: a peer-to-peer mesh that connects apps and agents on your own machines. Agents
//! mail each other, call MCP servers other machines offer, and reach their shells, under
//! owner-signed grants. Each machine hosts one or more boundaries; the daemon and the OS keep
//! every boundary's data inside that boundary. No check depends on a model's judgment.

pub mod bridge;
pub mod config;
pub mod envelope;
#[cfg(target_os = "linux")]
pub mod gateway;
pub mod hook;
pub mod hub;
pub mod install;
pub mod ipc;
pub mod join;
pub mod keys;
pub mod mcp;
pub mod menu;
pub mod mesh;
pub mod node;
pub mod oauth;
pub mod offer;
pub mod os;
pub mod ping;
pub mod policy;
pub mod setup;
pub mod shell;
pub mod steward;
pub mod store;
pub mod sync;
pub mod talk;
pub mod tui;

/// Machine, boundary and mailbox names: 1–32 of `a-z`, `0-9`, `-`, not starting with `-`.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A valid machine name from a hostname: lowercase, up to the first `.`, anything else as `-`.
pub fn machine_name(raw: &str) -> String {
    let s: String = raw
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() { c } else { '-' })
        .collect();
    let s: String = s.trim_start_matches('-').chars().take(32).collect();
    if s.is_empty() { "machine".into() } else { s }
}

/// True if another event fits in an hourly budget; records it if so.
pub(crate) fn within_budget(
    log: &mut std::collections::VecDeque<std::time::Instant>,
    per_hour: u32,
    now: std::time::Instant,
) -> bool {
    while log
        .front()
        .is_some_and(|t| now.duration_since(*t) >= std::time::Duration::from_secs(3600))
    {
        log.pop_front();
    }
    if log.len() >= per_hour as usize {
        return false;
    }
    log.push_back(now);
    true
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn names() {
        assert!(super::valid_name("builder"));
        assert!(super::valid_name("box-1"));
        assert!(!super::valid_name(""));
        assert!(!super::valid_name("-x"));
        assert!(!super::valid_name("Builder"));
        assert!(!super::valid_name("a@b"));
        assert!(!super::valid_name(&"a".repeat(33)));
    }

    #[test]
    fn machine_names_from_hostnames() {
        use super::{machine_name, valid_name};
        assert_eq!(machine_name("mw-virtual-workstation\n".trim()), "mw-virtual-workstation");
        assert_eq!(machine_name("Laptop.local"), "laptop");
        assert_eq!(machine_name("DESKTOP-AB12_CD"), "desktop-ab12-cd");
        assert_eq!(machine_name("--x y"), "x-y");
        assert_eq!(machine_name(""), "machine");
        assert_eq!(machine_name(".lan"), "machine");
        assert_eq!(machine_name("Grüße"), "gr--e");
        let long = machine_name(&"a".repeat(40));
        assert_eq!(long.len(), 32);
        assert!(valid_name(&long));
    }
}
