//! The daemon's local config (`/etc/tearmesh/config.toml`). It holds no secrets.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::valid_name;

pub const DEFAULT_CONFIG: &str = "/etc/tearmesh/config.toml";
pub const DEFAULT_SOCKET: &str = "/run/tearmesh/tearmesh.sock";

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// This machine's name in the circle file.
    pub machine: String,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default = "default_socket")]
    pub socket: PathBuf,
    /// OS user → boundary. A session's boundary is the user it runs as: the kernel reports the
    /// user on the socket, so nothing a session says can change it.
    #[serde(default)]
    pub users: BTreeMap<String, String>,
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
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// `"n0"` (n0's public relays, the default), `"none"`, or a list of your own relay URLs.
    #[serde(default)]
    pub relay: Relay,
    /// Publish and resolve addresses through n0's DNS server. Off: addresses come only from
    /// invites and from peers.
    #[serde(default = "yes")]
    pub n0_dns: bool,
    /// Local UDP socket, e.g. `"0.0.0.0:7777"`. Default: any free port.
    #[serde(default)]
    pub bind: Option<SocketAddr>,
}

impl Default for Network {
    fn default() -> Self {
        Network {
            relay: Relay::default(),
            n0_dns: true,
            bind: None,
        }
    }
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
    "/var/lib/tearmesh".into()
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
fn yes() -> bool {
    true
}

impl Config {
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
        if let Relay::Preset(p) = &self.network.relay {
            ensure!(
                p == "n0" || p == "none",
                "network.relay must be \"n0\", \"none\" or a list of URLs"
            );
        }
        ensure!(
            self.socket.as_os_str().len() < 108,
            "socket path must be under 108 bytes (a Unix socket limit)"
        );
        ensure!(
            self.sync_interval_secs >= 1,
            "sync_interval_secs must be at least 1"
        );
        Ok(())
    }

    /// Resolves `users` to uids. A missing user is an error, not a silent skip.
    pub fn uid_map(&self) -> Result<HashMap<u32, String>> {
        let mut map = HashMap::new();
        for (user, boundary) in &self.users {
            let u = nix::unistd::User::from_name(user)?
                .with_context(|| format!("config maps unknown OS user {user}"))?;
            map.insert(u.uid.as_raw(), boundary.clone());
        }
        Ok(map)
    }

    pub fn boundary_user(&self, boundary: &str) -> Option<&str> {
        self.users
            .iter()
            .find(|(_, b)| *b == boundary)
            .map(|(u, _)| u.as_str())
    }
}
