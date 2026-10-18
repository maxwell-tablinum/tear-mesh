//! Windows: a named pipe, with the caller identified by impersonating the client's token.
//! shortcut: stubs until the Windows port lands; every call fails with a clear message.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use super::{BoxRead, BoxWrite, Incoming};

pub struct Listener;

pub async fn listen(_path: &Path) -> Result<Listener> {
    bail!("the Windows local socket isn't built yet")
}

impl Listener {
    pub async fn accept(&self) -> Result<Incoming> {
        bail!("the Windows local socket isn't built yet")
    }
}

pub async fn connect(_path: &Path) -> Result<(BoxRead, BoxWrite)> {
    bail!("the Windows local socket isn't built yet")
}

pub fn user_identity(_name: &str) -> Result<String> {
    bail!("Windows user lookup isn't built yet")
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_default()
}

pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn secure_dir(_dir: &Path) -> Result<()> {
    Ok(())
}

pub fn launch(_user: &str, _env: &[(String, String)], _command: &[String]) -> Result<()> {
    bail!("launch isn't built for Windows yet")
}

pub async fn shutdown_signal() -> Result<()> {
    tokio::signal::ctrl_c().await?;
    Ok(())
}

pub fn run_service(_config: PathBuf) -> Result<()> {
    bail!("the Windows service isn't built yet")
}
