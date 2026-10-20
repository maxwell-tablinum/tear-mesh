//! tear-mesh: a peer-to-peer mesh that connects apps and agents on your own machines. Agents
//! mail each other, call MCP servers other machines offer, and reach their shells, under
//! owner-signed grants. Each machine hosts one or more boundaries; the daemon and the OS keep
//! every boundary's data inside that boundary. No check depends on a model's judgment.

pub mod bridge;
pub mod config;
#[cfg(target_os = "linux")]
pub mod connector;
pub mod envelope;
pub mod hook;
pub mod hub;
pub mod ipc;
pub mod join;
pub mod keys;
pub mod mcp;
pub mod menu;
pub mod mesh;
pub mod node;
pub mod offer;
pub mod os;
pub mod ping;
pub mod policy;
pub mod setup;
pub mod shell;
pub mod steward;
pub mod store;
pub mod sync;
pub mod tui;

/// Machine, boundary and mailbox names: 1–32 of `a-z`, `0-9`, `-`, not starting with `-`.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
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
}
