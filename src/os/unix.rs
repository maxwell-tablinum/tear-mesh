//! Linux and other Unixes: a Unix socket, with the kernel reporting the caller's uid
//! (`SO_PEERCRED`).

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::net::{UnixListener, UnixStream};

use super::{BoxRead, BoxWrite, Caller, Incoming};

pub struct Listener(UnixListener);

pub async fn listen(path: &Path) -> Result<Listener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    // Anyone may connect; the uid the kernel reports decides what they get.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(Listener(l))
}

impl Listener {
    pub async fn accept(&self) -> Result<Incoming> {
        let (s, _) = self.0.accept().await?;
        let uid = s.peer_cred()?.uid();
        let caller = Caller {
            id: uid.to_string(),
            admin: uid == 0 || uid == nix::unistd::geteuid().as_raw(),
        };
        let (r, w) = s.into_split();
        Ok(Incoming {
            read: Box::new(r),
            write: Box::new(w),
            caller: Box::new(move || Ok(caller.clone())),
        })
    }
}

pub async fn connect(path: &Path) -> Result<(BoxRead, BoxWrite)> {
    let s = UnixStream::connect(path)
        .await
        .with_context(|| format!("connecting to the tear-mesh daemon at {}", path.display()))?;
    let (r, w) = s.into_split();
    Ok((Box::new(r), Box::new(w)))
}

/// Connects to a socket of this user's own (the MCP hub's). Its directory is private to this
/// user, so nobody else can have put a socket there.
pub async fn connect_mine(path: &Path) -> Result<(BoxRead, BoxWrite)> {
    let s = UnixStream::connect(path)
        .await
        .with_context(|| format!("connecting to {}", path.display()))?;
    // The directory should already rule out a socket planted by someone else; check anyway.
    let uid = s.peer_cred()?.uid();
    anyhow::ensure!(
        uid == nix::unistd::geteuid().as_raw(),
        "{} belongs to uid {uid}, not to you",
        path.display()
    );
    let (r, w) = s.into_split();
    Ok((Box::new(r), Box::new(w)))
}

/// This process's identity, in the form `Caller::id` takes.
pub fn my_identity() -> Result<String> {
    Ok(nix::unistd::geteuid().as_raw().to_string())
}

pub fn user_identity(name: &str) -> Result<String> {
    let u = nix::unistd::User::from_name(name)?.context("no such user")?;
    Ok(u.uid.as_raw().to_string())
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// Write-then-rename with fsync, mode 0600, so a crash leaves the old file or the new one.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// The daemon's state directory: only its own user may enter.
pub fn secure_dir(dir: &Path) -> Result<()> {
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Replaces this process with `command` run as `user` (through sudo), with `env` set.
pub fn launch(user: &str, env: &[(String, String)], command: &[String]) -> Result<()> {
    let err = std::process::Command::new("sudo")
        .args(["-u", user, "-i", "env"])
        .args(env.iter().map(|(k, v)| format!("{k}={v}")))
        .args(command)
        .exec();
    Err(err).context("running sudo")
}

/// Resolves on SIGTERM or Ctrl-C.
pub async fn shutdown_signal() -> Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    Ok(())
}

/// Only Windows has a service manager mode.
pub fn run_service(_config: PathBuf) -> Result<()> {
    anyhow::bail!("--service is for Windows; on Linux run `tearmesh daemon` under systemd")
}
