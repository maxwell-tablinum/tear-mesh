//! The daemon's local config (`/etc/tearmesh/config.toml`, or
//! `C:\ProgramData\tearmesh\config.toml` on Windows). It holds no secrets.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::valid_name;

#[cfg(unix)]
pub const DEFAULT_CONFIG: &str = "/etc/tearmesh/config.toml";
#[cfg(unix)]
pub const DEFAULT_SOCKET: &str = "/run/tearmesh/tearmesh.sock";
#[cfg(unix)]
const DEFAULT_STATE: &str = "/var/lib/tearmesh";
#[cfg(windows)]
pub const DEFAULT_CONFIG: &str = r"C:\ProgramData\tearmesh\config.toml";
#[cfg(windows)]
pub const DEFAULT_SOCKET: &str = r"\\.\pipe\tearmesh";
#[cfg(windows)]
const DEFAULT_STATE: &str = r"C:\ProgramData\tearmesh\state";

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// This machine's name in the membership file.
    pub machine: String,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    /// The local socket (a named pipe on Windows).
    #[serde(default = "default_socket")]
    pub socket: PathBuf,
    /// OS user → boundary. A session's boundary is the user it runs as: the OS reports the user
    /// on the socket, so nothing a session says can change it.
    #[serde(default)]
    pub users: BTreeMap<String, String>,
    /// OS user → its fixed boundary and mailbox: sessions held to a guest's requests (the gateway's
    /// user, spec 18.4 point 1).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub guests: BTreeMap<String, Guest>,
    /// OS users, besides root/Administrators and the daemon's own user, that may run admin
    /// commands (status, invites, applying membership files).
    #[serde(default)]
    pub admins: Vec<String>,
    #[serde(default)]
    pub network: Network,
    #[serde(default = "default_sync_secs")]
    pub sync_interval_secs: u64,
    /// A thread stops accepting posts at this length, so two agents can't wake each other forever.
    #[serde(default = "default_max_thread")]
    pub max_thread_len: u64,
    /// Local posts per boundary per hour, so a runaway session can't flood its peers.
    #[serde(default = "default_max_posts")]
    pub max_posts_per_hour: u32,
    /// A boundary's log stops accepting entries at this size.
    #[serde(default = "default_max_log_mb")]
    pub max_log_mb: u64,
    /// Where shell streams go: this machine's sshd on 127.0.0.1.
    #[serde(default = "default_shell_port")]
    pub shell_port: u16,
    /// Boundaries whose inbound letters wait for the steward's screener before any session sees
    /// them. Here, root-owned, so a session in the boundary can't switch it off.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub screen: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Guest {
    pub boundary: String,
    pub mailbox: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Overrides the mesh's `settings.relays`: `"n0"`, `"none"`, or a list of relay URLs.
    #[serde(default)]
    pub relay: Option<Relay>,
    /// Overrides the mesh's `settings.lookup`: any of `"n0-dns"`, `"mdns"`; `[]` for none.
    #[serde(default)]
    pub lookup: Option<Vec<String>>,
    /// Local UDP socket, e.g. `"0.0.0.0:7777"`. Default: any free port.
    #[serde(default)]
    pub bind: Option<SocketAddr>,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum Relay {
    Preset(String),
    Urls(Vec<String>),
}

impl Default for Relay {
    fn default() -> Self {
        Relay::Preset("n0".into())
    }
}

fn default_state_dir() -> PathBuf {
    DEFAULT_STATE.into()
}
fn default_socket() -> PathBuf {
    DEFAULT_SOCKET.into()
}
fn default_sync_secs() -> u64 {
    30
}
fn default_max_thread() -> u64 {
    40
}
fn default_max_posts() -> u32 {
    600
}
fn default_max_log_mb() -> u64 {
    1024
}
fn default_shell_port() -> u16 {
    22
}

impl Config {
    /// A config with defaults for everything but the machine name.
    pub fn new(machine: &str) -> Config {
        Config {
            machine: machine.into(),
            state_dir: default_state_dir(),
            socket: default_socket(),
            users: BTreeMap::new(),
            guests: BTreeMap::new(),
            admins: vec![],
            network: Network::default(),
            sync_interval_secs: default_sync_secs(),
            max_thread_len: default_max_thread(),
            max_posts_per_hour: default_max_posts(),
            max_log_mb: default_max_log_mb(),
            shell_port: default_shell_port(),
            screen: vec![],
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let c: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            valid_name(&self.machine),
            "bad machine name {:?}",
            self.machine
        );
        for (user, b) in &self.users {
            ensure!(valid_name(b), "user {user}: bad boundary name {b:?}");
        }
        for (user, g) in &self.guests {
            ensure!(valid_name(&g.boundary), "guest {user}: bad boundary name {:?}", g.boundary);
            ensure!(valid_name(&g.mailbox), "guest {user}: bad mailbox name {:?}", g.mailbox);
            ensure!(g.mailbox != "admin", "guest {user}: the mailbox can't be admin, every session's default");
            ensure!(
                !self.users.contains_key(user) && !self.admins.contains(user) && user != "root",
                "{user} is under [guests], so it can't be root, under [users] or an admin"
            );
        }
        for b in &self.screen {
            ensure!(valid_name(b), "screen: bad boundary name {b:?}");
        }
        if let Some(Relay::Preset(p)) = &self.network.relay {
            ensure!(
                p == "n0" || p == "none",
                "network.relay must be \"n0\", \"none\" or a list of URLs"
            );
        }
        for l in self.network.lookup.iter().flatten() {
            ensure!(
                l == "n0-dns" || l == "mdns",
                "network.lookup: unknown method {l:?} (n0-dns, mdns)"
            );
        }
        #[cfg(unix)]
        ensure!(
            self.socket.as_os_str().len() < 108,
            "socket path must be under 108 bytes (a Unix socket limit)"
        );
        #[cfg(windows)]
        ensure!(
            self.socket
                .to_str()
                .and_then(|s| s.get(..9))
                .is_some_and(|p| p.eq_ignore_ascii_case(r"\\.\pipe\")),
            r"socket must be a named pipe, \\.\pipe\<name>"
        );
        ensure!(
            self.sync_interval_secs >= 1,
            "sync_interval_secs must be at least 1"
        );
        ensure!(self.max_thread_len >= 1, "max_thread_len must be at least 1");
        ensure!(self.max_posts_per_hour >= 1, "max_posts_per_hour must be at least 1");
        ensure!(self.max_log_mb >= 1, "max_log_mb must be at least 1");
        Ok(())
    }

    /// Resolves `users` to the OS's caller identities (uids, or SIDs on Windows). A missing user
    /// is an error, not a silent skip.
    pub fn identity_map(&self) -> Result<HashMap<String, String>> {
        let mut map = HashMap::new();
        for (user, boundary) in &self.users {
            let id = crate::os::user_identity(user)
                .with_context(|| format!("config maps unknown OS user {user}"))?;
            map.insert(id, boundary.clone());
        }
        Ok(map)
    }

    /// Resolves `guests` to the OS's caller identities, as `identity_map` does `users`.
    pub fn guest_map(&self) -> Result<HashMap<String, Guest>> {
        let mut map = HashMap::new();
        for (user, g) in &self.guests {
            let id = crate::os::user_identity(user)
                .with_context(|| format!("config maps unknown OS user {user}"))?;
            map.insert(id, g.clone());
        }
        Ok(map)
    }

    /// Identities of the configured `admins`.
    pub fn admin_identities(&self) -> Result<Vec<String>> {
        self.admins
            .iter()
            .map(|u| {
                crate::os::user_identity(u)
                    .with_context(|| format!("config lists unknown admin user {u}"))
            })
            .collect()
    }

    /// The OS user that runs as the boundary: `tm-<boundary>` when it is mapped there, since a
    /// person's own login can be mapped to the boundary too (`install --me`) and must not be
    /// picked for launches and services.
    pub fn boundary_user(&self, boundary: &str) -> Option<&str> {
        let own = format!("tm-{boundary}");
        match self.users.get_key_value(&own) {
            Some((u, b)) if b == boundary => Some(u.as_str()),
            _ => self.users.iter().find(|(_, b)| *b == boundary).map(|(u, _)| u.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_at_least_one() {
        assert!(Config::new("ws").validate().is_ok());
        for key in ["max_thread_len", "max_posts_per_hour", "max_log_mb"] {
            let mut c = Config::new("ws");
            match key {
                "max_thread_len" => c.max_thread_len = 0,
                "max_posts_per_hour" => c.max_posts_per_hour = 0,
                _ => c.max_log_mb = 0,
            }
            let e = c.validate().unwrap_err().to_string();
            assert_eq!(e, format!("{key} must be at least 1"));
        }
    }

    #[test]
    fn a_guest_user_is_nothing_else() {
        let base = "machine = \"ws\"\nadmins = [\"bob\"]\n[users]\nalice = \"work\"\n[guests]\n";
        let c: Config = toml::from_str(&format!("{base}tm-work-gw = {{ boundary = \"work\", mailbox = \"claude\" }}\n")).unwrap();
        c.validate().unwrap();
        assert_eq!(c.guests["tm-work-gw"], Guest { boundary: "work".into(), mailbox: "claude".into() });
        for (entry, why) in [
            ("alice = { boundary = \"work\", mailbox = \"claude\" }", "under [users]"),
            ("bob = { boundary = \"work\", mailbox = \"claude\" }", "an admin"),
            ("root = { boundary = \"work\", mailbox = \"claude\" }", "root"),
            ("gw = { boundary = \"Work\", mailbox = \"claude\" }", "bad boundary"),
            ("gw = { boundary = \"work\", mailbox = \"a b\" }", "bad mailbox"),
        ] {
            let c: Config = toml::from_str(&format!("{base}{entry}\n")).unwrap();
            assert!(c.validate().is_err(), "{why}");
        }
        assert!(toml::from_str::<Config>(&format!("{base}gw = {{ boundary = \"work\", mailbox = \"c\", trust = \"member\" }}\n")).is_err(), "unknown key");
        let c: Config = toml::from_str(&format!("{base}no-such-user-tm = {{ boundary = \"work\", mailbox = \"c\" }}\n")).unwrap();
        assert!(c.guest_map().unwrap_err().to_string().contains("config maps unknown OS user no-such-user-tm"));
    }

    #[test]
    fn a_boundary_runs_as_its_own_user_even_with_a_person_mapped() {
        let c: Config = toml::from_str("machine = \"ws\"\n[users]\nalice = \"work\"\ntm-work = \"work\"\nbob = \"lab\"\n").unwrap();
        assert_eq!(c.boundary_user("work"), Some("tm-work"));
        assert_eq!(c.boundary_user("lab"), Some("bob"), "no tm-lab: the one mapped");
        assert_eq!(c.boundary_user("vault"), None);
    }
}
