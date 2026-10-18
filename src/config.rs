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
            admins: vec![],
            network: Network::default(),
            sync_interval_secs: default_sync_secs(),
            max_thread_len: default_max_thread(),
            max_posts_per_hour: default_max_posts(),
            max_log_mb: default_max_log_mb(),
            shell_port: default_shell_port(),
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

    pub fn boundary_user(&self, boundary: &str) -> Option<&str> {
        self.users
            .iter()
            .find(|(_, b)| *b == boundary)
            .map(|(u, _)| u.as_str())
    }
}
