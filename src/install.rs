//! `tearmesh install` and `uninstall`: put tear-mesh on this machine from the binary alone, no
//! clone needed. They run the deploy script built into the binary (deploy/setup-linux.sh or
//! deploy/setup-windows.ps1, so a clone's copy does the same), after adding any new boundaries to
//! an existing config, and write the Claude Code plugin where every boundary user can read it.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};

use crate::config::Config;

/// The Claude Code plugin, laid out as in the repo, so `claude plugin marketplace add <dir>`
/// works on the installed copy as on a clone.
const PLUGIN: [(&str, &str); 4] = [
    (".claude-plugin/marketplace.json", include_str!("../.claude-plugin/marketplace.json")),
    ("adapters/claude-code/.claude-plugin/plugin.json", include_str!("../adapters/claude-code/.claude-plugin/plugin.json")),
    ("adapters/claude-code/.mcp.json", include_str!("../adapters/claude-code/.mcp.json")),
    ("adapters/claude-code/hooks/hooks.json", include_str!("../adapters/claude-code/hooks/hooks.json")),
];

/// The deploy script and the files it installs, as (path beside it, text).
#[cfg(not(windows))]
const SCRIPT: [(&str, &str); 4] = [
    ("setup-linux.sh", include_str!("../deploy/setup-linux.sh")),
    ("tearmesh.service", include_str!("../deploy/tearmesh.service")),
    ("tearmesh-steward@.service", include_str!("../deploy/tearmesh-steward@.service")),
    ("openrc/tearmesh", include_str!("../deploy/openrc/tearmesh")),
];
#[cfg(windows)]
const SCRIPT: [(&str, &str); 1] = [("setup-windows.ps1", include_str!("../deploy/setup-windows.ps1"))];

#[cfg(not(windows))]
const CONFIG: &str = "/etc/tearmesh/config.toml";
#[cfg(windows)]
const CONFIG: &str = r"C:\ProgramData\tearmesh\config.toml";

fn plugin_dir() -> PathBuf {
    #[cfg(windows)]
    return PathBuf::from(std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into())).join("tearmesh");
    #[cfg(not(windows))]
    PathBuf::from("/usr/local/share/tearmesh")
}

/// Adds `tm-<b> = "b"` for each boundary missing from an existing config's `[users]`, as text so
/// comments stay. None when nothing is missing.
pub fn add_users(text: &str, machine: &str, boundaries: &[String]) -> Result<Option<String>> {
    let cfg: Config = toml::from_str(text).context("the existing config")?;
    ensure!(
        cfg.machine == machine,
        "{CONFIG} names this machine {}; install doesn't rename machines (run it with {} as the name)",
        cfg.machine,
        cfg.machine
    );
    let new: Vec<String> = boundaries
        .iter()
        .filter(|b| !cfg.users.contains_key(&format!("tm-{b}")))
        .map(|b| format!("tm-{b} = \"{b}\""))
        .collect();
    if new.is_empty() {
        return Ok(None);
    }
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let at = lines.iter().position(|l| l.split('#').next().unwrap_or("").trim() == "[users]");
    match at {
        Some(i) => {
            for (n, l) in new.into_iter().enumerate() {
                lines.insert(i + 1 + n, l);
            }
        }
        None => {
            lines.push(String::new());
            lines.push("[users]".into());
            lines.extend(new);
        }
    }
    let out = lines.join("\n") + "\n";
    let check: Config = toml::from_str(&out).map_err(|_| {
        anyhow::anyhow!("couldn't add the new users to {CONFIG}; add them under [users] by hand")
    })?;
    ensure!(
        boundaries.iter().all(|b| check.users.contains_key(&format!("tm-{b}"))),
        "couldn't add the new users to {CONFIG}; add them under [users] by hand"
    );
    Ok(Some(out))
}

/// Writes the deploy script (and what it installs) to a private directory; returns the script.
fn unpack(dir: &Path) -> Result<PathBuf> {
    for (p, text) in SCRIPT {
        let f = dir.join(p);
        if let Some(d) = f.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(&f, text)?;
    }
    Ok(dir.join(SCRIPT[0].0))
}

fn run_script(args: &[String]) -> Result<()> {
    let dir = crate::setup::private_dir("tearmesh-install-")?;
    let r = (|| {
        let script = unpack(&dir)?;
        let exe = std::env::current_exe()?;
        #[cfg(not(windows))]
        let st = Command::new("sh").arg(&script).args(args).env("TEARMESH_BIN", &exe).status();
        #[cfg(windows)]
        let st = Command::new("powershell.exe")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(&script)
            .args(args)
            .args(if args.first().is_some_and(|a| a == "-Uninstall") { vec![] } else { vec!["-Exe".into(), exe.display().to_string()] })
            .status();
        let st = st.context("running the install script")?;
        ensure!(st.success(), "the install script stopped ({st})");
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    r
}

fn require_admin() -> Result<()> {
    #[cfg(unix)]
    ensure!(
        nix::unistd::geteuid().is_root(),
        "install needs root: sudo tearmesh install <machine> <boundary>..."
    );
    // On Windows the script checks for an elevated prompt.
    Ok(())
}

pub fn install(machine: &str, boundaries: &[String], stewards: bool) -> Result<()> {
    require_admin()?;
    ensure!(crate::valid_name(machine), "bad machine name {machine:?}: use a-z, 0-9 and -");
    for b in boundaries {
        ensure!(crate::valid_name(b), "bad boundary name {b:?}: use a-z, 0-9 and -");
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    anyhow::bail!("install runs on Linux and Windows");
    // The script leaves an existing config alone, so new users go in first.
    let mut added = false;
    if let Ok(text) = std::fs::read_to_string(CONFIG)
        && let Some(new) = add_users(&text, machine, boundaries)?
    {
        std::fs::write(CONFIG, new)?;
        added = true;
    }
    #[cfg(not(windows))]
    let args: Vec<String> = std::iter::once(machine.to_string()).chain(boundaries.iter().cloned()).collect();
    #[cfg(windows)]
    let args: Vec<String> = {
        let mut a = vec!["-Machine".into(), machine.into(), "-Boundaries".into(), boundaries.join(",")];
        if stewards {
            a.push("-Stewards".into());
        }
        a
    };
    run_script(&args)?;
    #[cfg(not(windows))]
    if stewards {
        ensure!(
            Path::new("/run/systemd/system").exists(),
            "--stewards needs systemd; run `tearmesh steward` as each boundary user yourself"
        );
        for b in boundaries {
            let st = Command::new("systemctl").args(["enable", "--now", &format!("tearmesh-steward@tm-{b}")]).status()?;
            ensure!(st.success(), "couldn't start the steward for tm-{b}");
        }
    }
    let dir = plugin_dir();
    for (p, text) in PLUGIN {
        let f = dir.join(p);
        std::fs::create_dir_all(f.parent().expect("has a parent"))?;
        std::fs::write(&f, text)?;
    }
    println!("Claude Code plugin, as each boundary user: claude plugin marketplace add \"{}\" && claude plugin install tearmesh@tear-mesh", dir.display());
    if added {
        println!("New boundaries are only local until an owner adds them to this machine in the mesh (tearmesh mesh hosts {machine} ...).");
    }
    #[cfg(windows)]
    println!("Next, in a new prompt (for PATH), as yourself: tearmesh menu");
    #[cfg(not(windows))]
    println!("Next, as yourself (not root): tearmesh menu");
    Ok(())
}

pub fn uninstall(boundaries: &[String]) -> Result<()> {
    require_admin()?;
    for b in boundaries {
        ensure!(crate::valid_name(b), "bad boundary name {b:?}");
    }
    #[cfg(not(windows))]
    let args: Vec<String> = std::iter::once("--uninstall".to_string()).chain(boundaries.iter().cloned()).collect();
    #[cfg(windows)]
    let args: Vec<String> = {
        let mut a = vec!["-Uninstall".to_string()];
        if !boundaries.is_empty() {
            a.extend(["-Boundaries".into(), boundaries.join(",")]);
        }
        a
    };
    run_script(&args)?;
    let _ = std::fs::remove_dir_all(plugin_dir());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_boundaries_join_an_existing_config() {
        let text = "machine = \"ws\"\nadmins = [\"me\"]\n\n[users]   # OS user -> boundary\ntm-work = \"work\"\n\n[network]\nrelay = \"n0\"\n";
        let b = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(add_users(text, "ws", &b(&["work"])).unwrap(), None);
        let out = add_users(text, "ws", &b(&["work", "lab"])).unwrap().unwrap();
        let c: Config = toml::from_str(&out).unwrap();
        assert_eq!(c.users.get("tm-lab").map(String::as_str), Some("lab"));
        assert!(out.contains("# OS user -> boundary") && out.contains("[network]"), "{out}");
        let out = add_users("machine = \"ws\"\n", "ws", &b(&["lab"])).unwrap().unwrap();
        assert!(out.ends_with("[users]\ntm-lab = \"lab\"\n"), "{out}");
        assert!(add_users(text, "other", &b(&["lab"])).unwrap_err().to_string().contains("doesn't rename"));
        assert!(add_users("machine = \"ws\"\nusers = { tm-work = \"work\" }\n", "ws", &b(&["lab"])).is_err());
    }

    #[test]
    fn the_plugin_matches_this_version() {
        let p: serde_json::Value = serde_json::from_str(PLUGIN[1].1).unwrap();
        assert_eq!(p["version"], env!("CARGO_PKG_VERSION"));
    }
}
