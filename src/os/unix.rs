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

/// This machine's hostname, or "" if it can't be read.
pub fn hostname() -> String {
    ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
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

/// Replaces this process with `command` run as `user` (through sudo, else su as root), with `env` set.
pub fn launch(user: &str, env: &[(String, String)], command: &[String]) -> Result<()> {
    let have_sudo = std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("sudo").is_file()));
    let err = launch_command(user, env, command, have_sudo, nix::unistd::geteuid().is_root())?.exec();
    Err(err).context("running sudo or su")
}

fn launch_command(user: &str, env: &[(String, String)], command: &[String], have_sudo: bool, root: bool) -> Result<std::process::Command> {
    let kv = env.iter().map(|(k, v)| format!("{k}={v}"));
    let mut c;
    if have_sudo {
        c = std::process::Command::new("sudo");
        c.args(["-u", user, "-i", "env"]);
    } else if root {
        // The command rides in "$@", so it needs no quoting; `--` keeps su from reading its flags.
        c = std::process::Command::new("su");
        c.args(["-s", "/bin/sh", "-l", "-c", "exec env \"$@\"", "--", user, "sh"]);
    } else {
        anyhow::bail!("launch needs sudo, or run it as root");
    }
    c.args(kv).args(command);
    Ok(c)
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

#[cfg(test)]
mod tests {
    use super::launch_command;

    #[test]
    fn launch_uses_sudo_else_su_else_refuses() {
        let (env, cmd) = (vec![("A".to_string(), "1".to_string())], vec!["claude".to_string(), "--x".to_string()]);
        let args = |c: &std::process::Command| c.get_args().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>();
        let c = launch_command("tm-w", &env, &cmd, true, false).unwrap();
        assert_eq!((c.get_program().to_str(), args(&c)), (Some("sudo"), ["-u", "tm-w", "-i", "env", "A=1", "claude", "--x"].map(String::from).to_vec()));
        let c = launch_command("tm-w", &env, &cmd, false, true).unwrap();
        assert_eq!(c.get_program().to_str(), Some("su"));
        assert_eq!(args(&c)[6..], ["tm-w", "sh", "A=1", "claude", "--x"]);
        assert!(launch_command("tm-w", &env, &cmd, false, false).unwrap_err().to_string().contains("launch needs sudo, or run it as root"));
    }
}
