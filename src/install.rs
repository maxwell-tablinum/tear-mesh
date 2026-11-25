//! `tearmesh install` and `uninstall`: put tear-mesh on this machine from the binary alone, no
//! clone needed. They run the deploy script built into the binary (deploy/setup-linux.sh or
//! deploy/setup-windows.ps1, so a clone's copy does the same), after adding any new boundaries to
//! an existing config, and write the Claude Code plugin where every boundary user can read it.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};

use crate::config::{Config, Guest};

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
    let out = insert_into(text, "[users]", new);
    let check: Config = toml::from_str(&out).map_err(|_| {
        anyhow::anyhow!("couldn't add the new users to {CONFIG}; add them under [users] by hand")
    })?;
    ensure!(
        boundaries.iter().all(|b| check.users.contains_key(&format!("tm-{b}"))),
        "couldn't add the new users to {CONFIG}; add them under [users] by hand"
    );
    Ok(Some(out))
}

/// Puts `new` lines at the top of `table` (`[users]`), or adds the table.
fn insert_into(text: &str, table: &str, new: Vec<String>) -> String {
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let at = lines.iter().position(|l| l.split('#').next().unwrap_or("").trim() == table);
    match at {
        Some(i) => {
            for (n, l) in new.into_iter().enumerate() {
                lines.insert(i + 1 + n, l);
            }
        }
        None => {
            lines.push(String::new());
            lines.push(table.into());
            lines.extend(new);
        }
    }
    lines.join("\n") + "\n"
}

/// The person running install, for `--me`: the sudo invoker on Linux, the account of the
/// elevated prompt on Windows. None for root (and SYSTEM), who has no login to map.
fn invoker() -> Option<String> {
    #[cfg(not(windows))]
    return std::env::var("SUDO_USER").ok().filter(|u| !u.is_empty() && u != "root");
    #[cfg(windows)]
    {
        let u = std::env::var("USERNAME").ok().filter(|u| !u.is_empty() && !u.ends_with('$'))?;
        Some(match std::env::var("USERDOMAIN") {
            Ok(d) if !d.is_empty() => format!("{d}\\{u}"),
            _ => u,
        })
    }
}

/// Whether two config user names are one account: the same name, or the same uid or SID.
fn same_user(a: &str, b: &str) -> bool {
    a == b || matches!((crate::os::user_identity(a), crate::os::user_identity(b)), (Ok(x), Ok(y)) if x == y)
}

/// `--me`'s checks, before anything changes: `boundary` will have an OS user after this run
/// (`adding` are the boundaries it adds), and `user` is in no other boundary.
fn check_me(cfg: Option<&Config>, user: &str, boundary: &str, adding: &[String]) -> Result<()> {
    ensure!(crate::valid_name(boundary), "bad boundary name {boundary:?}: use a-z, 0-9 and -");
    ensure!(
        !user.rsplit('\\').next().unwrap_or(user).starts_with("tm-"),
        "{user} is a boundary's own user; --me is for a person's login"
    );
    ensure!(
        adding.iter().any(|b| b == boundary) || cfg.is_some_and(|c| c.users.values().any(|b| b == boundary)),
        "--me {boundary}: this machine has no OS user for boundary {boundary}; add it in the same run (install … {boundary} --me {boundary})"
    );
    for (u, b) in cfg.map(|c| &c.users).into_iter().flatten() {
        ensure!(
            b == boundary || !same_user(u, user),
            "{user} is already mapped to boundary {b}; a user is in one boundary"
        );
    }
    Ok(())
}

/// Adds `user = "boundary"` to the config text; None when it is there already.
fn map_user(text: &str, user: &str, boundary: &str) -> Result<Option<String>> {
    let cfg: Config = toml::from_str(text).context("the config")?;
    if cfg.users.iter().any(|(u, b)| b == boundary && same_user(u, user)) {
        return Ok(None);
    }
    // Quoted: a login may hold a dot, or a backslash on Windows.
    let out = insert_into(text, "[users]", vec![format!("{} = \"{boundary}\"", toml::Value::String(user.into()))]);
    let check: Config = toml::from_str(&out).map_err(|_| anyhow::anyhow!("couldn't add {user} to {CONFIG}; add it under [users] by hand"))?;
    ensure!(
        check.users.get(user).map(String::as_str) == Some(boundary),
        "couldn't add {user} to {CONFIG}; add it under [users] by hand"
    );
    Ok(Some(out))
}

/// Sets (Some) or removes (None) `user`'s line under `[guests]` in the config at `path`, which is
/// replaced in one step, and only by a config the daemon would accept. False when nothing changes.
pub fn set_guest(path: &Path, user: &str, entry: Option<&Guest>) -> Result<bool> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let Some(new) = guest_text(&text, user, entry)? else {
        return Ok(false);
    };
    replace_file(path, &new)?;
    Ok(true)
}

/// Replaces `path` with `text` in one step: a file beside it, with its mode and owner, renamed over it.
fn replace_file(path: &Path, text: &str) -> Result<()> {
    use std::io::Write;
    let meta = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    let name = path.file_name().context("a config path names a file")?.to_string_lossy();
    let tmp = path.with_file_name(format!(".{name}.tmp"));
    // Left by a run that stopped halfway.
    let _ = std::fs::remove_file(&tmp);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let r = o.open(&tmp).and_then(|mut f| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            std::os::unix::fs::fchown(&f, Some(meta.uid()), Some(meta.gid()))?;
        }
        f.set_permissions(meta.permissions())?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    });
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r.with_context(|| format!("writing {}", path.display()))
}

/// set_guest on the config's text, so comments stay; None when nothing changes.
fn guest_text(text: &str, user: &str, entry: Option<&Guest>) -> Result<Option<String>> {
    let cfg: Config = toml::from_str(text).context("the config")?;
    if cfg.guests.get(user) == entry {
        return Ok(None);
    }
    let mut table = String::new();
    let kept: Vec<&str> = text
        .lines()
        .filter(|l| {
            let code = l.split('#').next().unwrap_or("").trim();
            if code.starts_with('[') {
                table = code.to_string();
            }
            !(table == "[guests]" && code.split('=').next().unwrap_or("").trim().trim_matches('"') == user)
        })
        .collect();
    let mut out = kept.join("\n") + "\n";
    if let Some(g) = entry {
        let line = format!("{} = {{ boundary = \"{}\", mailbox = \"{}\" }}", toml::Value::String(user.into()), g.boundary, g.mailbox);
        out = insert_into(&out, "[guests]", vec![line]);
    }
    let by_hand = || anyhow::anyhow!("couldn't change {user} under [guests] in {CONFIG}; change it by hand");
    let check: Config = toml::from_str(&out).map_err(|_| by_hand())?;
    ensure!(check.guests.get(user) == entry, by_hand());
    check.validate()?;
    Ok(Some(out))
}

/// Restarts the daemon so it reads a changed config (only where install started it).
pub fn restart_service() -> Result<()> {
    #[cfg(not(windows))]
    let st = if Path::new("/run/systemd/system").exists() {
        // A restart we ask for must not count toward systemd's start limit (5 starts in 10 s).
        let _ = Command::new("systemctl").args(["reset-failed", "tearmesh"]).output();
        Command::new("systemctl").args(["restart", "tearmesh"]).status()
    } else if service_log().is_some() {
        Command::new("rc-service").args(["tearmesh", "restart"]).status()
    } else {
        return Ok(());
    };
    #[cfg(windows)]
    let st = Command::new("powershell.exe").args(["-NoProfile", "-Command", "Restart-Service tearmesh"]).status();
    ensure!(st.context("restarting the service")?.success(), "couldn't restart the tearmesh service");
    Ok(())
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

pub(crate) fn run_script(args: &[String]) -> Result<()> {
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

pub fn require_admin(usage: &str) -> Result<()> {
    #[cfg(unix)]
    ensure!(nix::unistd::geteuid().is_root(), "this needs root: sudo tearmesh {usage}");
    #[cfg(windows)]
    let _ = usage;
    // On Windows the script checks for an elevated prompt.
    Ok(())
}

/// Where the release binaries and install scripts are downloaded from.
pub const RELEASES: &str = "https://github.com/maxwell-tablinum/tear-mesh/releases/download";

/// The commands that install this version and join with `ticket`: [Linux, Windows PowerShell as
/// Administrator]. `name`: the machine name the ticket is for, so the joiner installs under it
/// (its hostname may differ). A dev build names its own, maybe unreleased, version.
/// With TEARMESH_RELEASE_URL set (see `release_url`), the commands fetch from that folder and pass it on.
pub fn one_liners(ticket: &str, name: Option<&str>) -> [String; 2] {
    one_liners_at(std::env::var("TEARMESH_RELEASE_URL").ok().as_deref(), ticket, name)
}

/// `over` as a folder URL, trailing slash trimmed: http(s) and only characters that need no
/// quoting in a shell or PowerShell. Anything else is None.
fn release_url(over: &str) -> Option<&str> {
    let ok = over.bytes().all(|c| c.is_ascii_alphanumeric() || b"._:/~%+-".contains(&c));
    let u = over.trim_end_matches('/');
    let host = u.strip_prefix("https://").or_else(|| u.strip_prefix("http://"))?;
    (ok && !host.is_empty()).then_some(u)
}

fn one_liners_at(over: Option<&str>, ticket: &str, name: Option<&str>) -> [String; 2] {
    let (sh, ps) = name.map_or_else(Default::default, |n| (format!("{n} "), format!("-Machine {n} ")));
    if let Some(u) = over.and_then(release_url) {
        return [
            format!("curl -fsSL {u}/install.sh | sudo TEARMESH_RELEASE_URL={u} sh -s -- {sh}--join {ticket}"),
            format!("$env:TEARMESH_RELEASE_URL='{u}'; & ([scriptblock]::Create((irm {u}/install.ps1))) {ps}-Join {ticket}"),
        ];
    }
    let base = format!("{RELEASES}/v{}", env!("CARGO_PKG_VERSION"));
    [
        format!("curl -fsSL {base}/install.sh | sudo sh -s -- {sh}--join {ticket}"),
        format!("& ([scriptblock]::Create((irm {base}/install.ps1))) {ps}-Join {ticket}"),
    ]
}

/// Linux user names are at most 32 characters, Windows local account names at most 20; the OS
/// user of a boundary is `tm-<boundary>`.
fn user_name_fits(b: &str) -> Result<()> {
    let limit = if cfg!(windows) { 20 } else { 32 };
    ensure!(
        3 + b.len() <= limit,
        "boundary {b:?} is too long: its OS user tm-{b} would be {} characters, and the limit is {limit}",
        3 + b.len()
    );
    Ok(())
}

/// Where the daemon's log is, when install started a service (systemd or OpenRC) it can check.
pub fn service_log() -> Option<&'static str> {
    #[cfg(not(windows))]
    {
        let rc = || std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("rc-service").is_file()));
        if Path::new("/run/systemd/system").exists() {
            Some("`journalctl -u tearmesh -n 20`")
        } else {
            rc().then_some("/var/log/tearmesh.log")
        }
    }
    #[cfg(windows)]
    None
}

/// The boundaries in `hosts` that no OS user maps to in `cfg`: the users a join still needs.
pub fn missing_users(cfg: &Config, hosts: &[String]) -> Vec<String> {
    hosts.iter().filter(|b| !cfg.users.values().any(|u| u == *b)).cloned().collect()
}

/// The installed config, if there is one.
pub fn installed() -> Option<Config> {
    toml::from_str(&std::fs::read_to_string(CONFIG).ok()?).ok()
}

/// The machine name install uses when none is given: the installed one, else the hostname.
pub fn default_machine() -> String {
    installed().map_or_else(|| crate::machine_name(&crate::os::hostname()), |c| c.machine)
}

/// Where the install script lists the users it created, one per line (on Windows, the user is
/// the first tab-separated field of each line of the passwords file).
#[cfg(not(windows))]
const CREATED: &str = "/etc/tearmesh/created-users";
#[cfg(windows)]
const CREATED: &str = r"C:\ProgramData\tearmesh\passwords.txt";

/// The users `CREATED` lists; empty when it can't be read.
pub fn created_record() -> String {
    std::fs::read_to_string(CREATED).unwrap_or_default()
}

/// The boundaries whose users install created (`tm-<b> = "b"`, and listed in `record`): the ones
/// uninstall deletes by default. Then the other mapped users, which it keeps: those mapped by
/// hand, like `alice = "work"`, and a `tm-<b>` that already existed when install ran.
pub fn created_users(cfg: &Config, record: &str) -> (Vec<String>, Vec<String>) {
    // Windows PowerShell's UTF8 starts the file with a BOM.
    let made: Vec<&str> = record.trim_start_matches('\u{feff}').lines().filter_map(|l| l.split('\t').next()).map(str::trim).collect();
    let (ours, kept): (Vec<_>, Vec<_>) =
        cfg.users.iter().partition(|(u, b)| **u == format!("tm-{b}") && made.contains(&u.as_str()));
    (ours.into_iter().map(|(_, b)| b.clone()).collect(), kept.into_iter().map(|(u, _)| u.clone()).collect())
}

/// The home of the person who ran the command: the sudo invoker's on unix, else this user's.
pub fn invoker_home() -> PathBuf {
    #[cfg(unix)]
    if let Some(home) = std::env::var("SUDO_USER")
        .ok()
        .and_then(|u| nix::unistd::User::from_name(&u).ok().flatten())
        .map(|u| u.dir)
    {
        return home;
    }
    crate::os::home_dir()
}

/// Arguments `elevated` may pass: nothing a shell or PowerShell would interpret.
fn plain_arg(a: &str) -> bool {
    !a.is_empty() && a.bytes().all(|c| c.is_ascii_alphanumeric() || b"._:/=+-".contains(&c))
}

/// Runs this binary again with admin rights: directly as root, else through sudo; on Windows
/// through a UAC prompt.
pub fn elevated(args: &[&str]) -> Result<()> {
    for a in args {
        ensure!(plain_arg(a), "refusing to pass {a:?} to an elevated command");
    }
    let exe = std::env::current_exe()?;
    #[cfg(unix)]
    let st = if nix::unistd::geteuid().is_root() {
        Command::new(&exe).args(args).status()
    } else {
        Command::new("sudo").arg(&exe).args(args).status()
    };
    // shortcut: the elevated window closes when done, so its output is lost; show it if needed
    #[cfg(windows)]
    let st = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            "$p = Start-Process -FilePath $env:TM_EXE -ArgumentList $env:TM_ARGS -Verb RunAs -Wait -PassThru; exit $p.ExitCode",
        ])
        .env("TM_EXE", &exe)
        .env("TM_ARGS", args.join(" "))
        .status();
    let st = st.context("running the elevated command")?;
    ensure!(st.success(), "`tearmesh {}` stopped ({st})", args.join(" "));
    Ok(())
}

/// What uninstall removes, besides users, for its confirmation.
#[cfg(not(windows))]
pub const REMOVES: &str = "the tearmesh service and its user, /usr/local/bin/tearmesh, the plugin (/usr/local/share/tearmesh), /etc/tearmesh, the state with every mail log (/var/lib/tearmesh), the gateway if there is one (its service, its user tm-<boundary>-gw and /var/lib/tearmesh-gateway)";
#[cfg(windows)]
pub const REMOVES: &str = r"the tearmesh service, the steward tasks, C:\Program Files\tearmesh, C:\ProgramData\tearmesh (the config and the state with every mail log)";

/// Returns whether it added users to an existing config. `me`: also map the person's own OS
/// user to that boundary.
pub fn install(machine: &str, boundaries: &[String], stewards: bool, me: Option<&str>) -> Result<bool> {
    require_admin("install [<machine> [<boundary>...]]")?;
    ensure!(crate::valid_name(machine), "bad machine name {machine:?}: use a-z, 0-9 and -");
    for b in boundaries {
        ensure!(crate::valid_name(b), "bad boundary name {b:?}: use a-z, 0-9 and -");
        user_name_fits(b)?;
    }
    let me = match me {
        Some(b) => {
            let user = invoker().context(
                "--me maps your own OS user, and root has none: run install through sudo from your own login",
            )?;
            check_me(installed().as_ref(), &user, b, boundaries)?;
            Some((user, b))
        }
        None => None,
    };
    #[cfg(not(any(target_os = "linux", windows)))]
    anyhow::bail!("install runs on Linux and Windows");
    // The script leaves an existing config alone, so new users go in first.
    let mut added = None;
    if let Ok(text) = std::fs::read_to_string(CONFIG)
        && let Some(new) = add_users(&text, machine, boundaries)?
    {
        std::fs::write(CONFIG, new)?;
        added = Some(text);
    }
    #[cfg(not(windows))]
    let args: Vec<String> = std::iter::once(machine.to_string()).chain(boundaries.iter().cloned()).collect();
    #[cfg(windows)]
    let args: Vec<String> = {
        let mut a = vec!["-Machine".into(), machine.into()];
        if !boundaries.is_empty() {
            a.extend(["-Boundaries".into(), boundaries.join(",")]);
        }
        if stewards {
            a.push("-Stewards".into());
        }
        a
    };
    if let Err(e) = run_script(&args) {
        // Users in the config that the script never made would stop the daemon at its next start.
        if let Some(old) = &added {
            let _ = std::fs::write(CONFIG, old);
        }
        return Err(e);
    }
    let dir = plugin_dir();
    for (p, text) in PLUGIN {
        let f = dir.join(p);
        std::fs::create_dir_all(f.parent().expect("has a parent"))?;
        std::fs::write(&f, text)?;
    }
    println!("Claude Code plugin, as each boundary user: claude plugin marketplace add \"{}\" && claude plugin install tearmesh@tear-mesh", dir.display());
    // After the script, which writes the config of a new install.
    if let Some((user, b)) = me
        && let Some(new) = map_user(&std::fs::read_to_string(CONFIG)?, &user, b)?
    {
        std::fs::write(CONFIG, new)?;
        restart_service()?;
        println!("{user} is now a session of boundary {b}: agents you run as yourself are in it.");
    }
    if boundaries.is_empty() && installed().is_none_or(|c| c.users.is_empty()) {
        println!("No boundaries yet: an owner picks them when this machine joins, or add one later with `sudo tearmesh install {machine} <boundary>`.");
    }
    #[cfg(windows)]
    println!("Next, in a new prompt (for PATH), as yourself: tearmesh menu");
    #[cfg(not(windows))]
    println!(
        "{}",
        if std::env::var("SUDO_USER").is_ok_and(|u| !u.is_empty() && u != "root") {
            "Next, as yourself (not root): tearmesh menu"
        } else {
            "Next: tearmesh menu"
        }
    );
    // Last, so a machine without systemd still gets the plugin files and the lines above.
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
    Ok(added.is_some())
}

pub fn uninstall(boundaries: &[String]) -> Result<()> {
    require_admin("uninstall")?;
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
    // First, while its boundary user still exists: the script deletes /etc/tearmesh and the users.
    #[cfg(target_os = "linux")]
    crate::gateway::remove_all()?;
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
    fn me_maps_a_person_once_and_only_to_a_boundary_with_a_user() {
        let c: Config = toml::from_str("machine = \"ws\"\n[users]\ntm-work = \"work\"\n").unwrap();
        let b = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(check_me(Some(&c), "alice", "work", &[]).is_ok());
        assert!(check_me(Some(&c), "alice", "lab", &b(&["lab"])).is_ok(), "made in this run");
        assert!(check_me(None, "alice", "lab", &b(&["lab"])).is_ok(), "a new install");
        assert!(check_me(Some(&c), "alice", "lab", &[]).unwrap_err().to_string().contains("no OS user for boundary lab"));
        assert!(check_me(Some(&c), "tm-work", "work", &[]).is_err(), "not a boundary's own user");
        let c2: Config = toml::from_str("machine = \"ws\"\n[users]\ntm-work = \"work\"\nalice = \"lab\"\ntm-lab = \"lab\"\n").unwrap();
        assert!(check_me(Some(&c2), "alice", "work", &[]).unwrap_err().to_string().contains("already mapped to boundary lab"));
        assert!(check_me(Some(&c2), "alice", "lab", &[]).is_ok(), "again: nothing to change");

        let text = "machine = \"ws\"\n[users]\ntm-work = \"work\"\n";
        let out = map_user(text, "john.doe", "work").unwrap().unwrap();
        let c: Config = toml::from_str(&out).unwrap();
        assert_eq!(c.users.get("john.doe").map(String::as_str), Some("work"));
        assert_eq!(c.boundary_user("work"), Some("tm-work"), "the boundary still runs as its own user");
        assert_eq!(map_user(&out, "john.doe", "work").unwrap(), None);
        let out = map_user(text, r"WS\alice", "work").unwrap().unwrap();
        assert!(toml::from_str::<Config>(&out).unwrap().users.contains_key(r"WS\alice"), "{out}");
        // Uninstall deletes only the users install made, never the person.
        assert!(created_users(&c, "tm-work\n").1.contains(&"john.doe".to_string()));
    }

    #[test]
    fn a_guest_line_comes_and_goes_and_comments_stay() {
        let text = "machine = \"ws\"   # this one\n[users]\ntm-work = \"work\"\n";
        let g = Guest { boundary: "work".into(), mailbox: "claude".into() };
        let out = guest_text(text, "tm-work-gw", Some(&g)).unwrap().unwrap();
        assert!(out.contains("# this one") && out.ends_with("[guests]\n\"tm-work-gw\" = { boundary = \"work\", mailbox = \"claude\" }\n"), "{out}");
        assert_eq!(guest_text(&out, "tm-work-gw", Some(&g)).unwrap(), None, "again: nothing to change");
        let other = Guest { mailbox: "voice".into(), ..g.clone() };
        let changed = guest_text(&out, "tm-work-gw", Some(&other)).unwrap().unwrap();
        assert_eq!(toml::from_str::<Config>(&changed).unwrap().guests["tm-work-gw"], other);
        let back = guest_text(&out, "tm-work-gw", None).unwrap().unwrap();
        assert!(toml::from_str::<Config>(&back).unwrap().guests.is_empty() && back.contains("tm-work = \"work\""), "{back}");
        assert_eq!(guest_text(&back, "tm-work-gw", None).unwrap(), None);
    }

    #[test]
    fn a_guest_line_is_refused_for_a_user_of_a_boundary_and_written_in_one_step() {
        let g = Guest { boundary: "work".into(), mailbox: "claude".into() };
        // Boundary work-gw's own user has the gateway's name: the daemon would refuse that config.
        for text in ["machine = \"ws\"\n[users]\ntm-work-gw = \"work-gw\"\n", "machine = \"ws\"\nadmins = [\"tm-work-gw\"]\n"] {
            let e = guest_text(text, "tm-work-gw", Some(&g)).unwrap_err().to_string();
            assert!(e.contains("under [guests], so it can't be root, under [users] or an admin"), "{e}");
        }
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.toml");
        std::fs::write(&p, "machine = \"ws\"\n[users]\ntm-work-gw = \"work-gw\"\n").unwrap();
        assert!(set_guest(&p, "tm-work-gw", Some(&g)).is_err());
        let text = "machine = \"ws\"  # mine\n[users]\ntm-work = \"work\"\n";
        std::fs::write(&p, text).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o640)).unwrap();
        assert!(set_guest(&p, "tm-work-gw", Some(&g)).unwrap());
        assert_eq!(Config::load(&p).unwrap().guests["tm-work-gw"], g);
        #[cfg(unix)]
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&p).unwrap().permissions()) & 0o777, 0o640);
        assert!(!set_guest(&p, "tm-work-gw", Some(&g)).unwrap(), "nothing to change");
        assert!(set_guest(&p, "tm-work-gw", None).unwrap());
        let back = std::fs::read_to_string(&p).unwrap();
        assert!(back.contains("# mine") && Config::load(&p).unwrap().guests.is_empty(), "{back}");
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1, "no file left beside it");
    }

    #[test]
    fn uninstall_deletes_only_the_users_install_made() {
        let c: Config = toml::from_str("machine = \"ws\"\n[users]\ntm-work = \"work\"\nalice = \"work\"\ntm-x = \"lab\"\ntm-lab = \"lab\"\ntm-vault = \"vault\"\n").unwrap();
        // tm-vault already existed when install ran, so the record doesn't list it.
        let (ours, kept) = created_users(&c, "tm-work\ntm-lab\ntm-x\n");
        assert_eq!(ours, ["lab", "work"]);
        assert_eq!(kept, ["alice", "tm-vault", "tm-x"]);
        // Windows: the passwords file, user then tab then password.
        assert_eq!(created_users(&c, "\u{feff}tm-vault\tTm1!abc\r\n").0, ["vault"]);
        assert!(created_users(&c, "").0.is_empty(), "no record: delete nothing");
    }

    #[test]
    fn elevated_passes_no_shell_text() {
        for a in ["$(x)", "a b", "`x`", "a;b", "", "x'y", "a|b", "%x%", "\"q\""] {
            assert!(!plain_arg(a), "{a:?}");
            assert!(elevated(&["uninstall", a]).is_err(), "{a:?}");
        }
        for a in ["uninstall", "--yes", "tm-work", "C:/x", "a=b+c.d"] {
            assert!(plain_arg(a), "{a:?}");
        }
    }

    #[test]
    fn one_liners_name_this_version_and_the_ticket() {
        let [sh, ps] = one_liners("tm2-abc", None);
        let base = format!("{RELEASES}/v{}", env!("CARGO_PKG_VERSION"));
        assert_eq!(sh, format!("curl -fsSL {base}/install.sh | sudo sh -s -- --join tm2-abc"));
        assert_eq!(ps, format!("& ([scriptblock]::Create((irm {base}/install.ps1))) -Join tm2-abc"));
        // A ticket for a named machine installs under that name, not the joiner's hostname.
        let [sh, ps] = one_liners("tm2-abc", Some("laptop"));
        assert_eq!(sh, format!("curl -fsSL {base}/install.sh | sudo sh -s -- laptop --join tm2-abc"));
        assert_eq!(ps, format!("& ([scriptblock]::Create((irm {base}/install.ps1))) -Machine laptop -Join tm2-abc"));
    }

    #[test]
    fn a_release_url_override_is_passed_on_or_ignored() {
        let [sh, ps] = one_liners_at(Some("http://10.0.0.5:8000/rel/"), "tm2-abc", Some("lap"));
        assert_eq!(sh, "curl -fsSL http://10.0.0.5:8000/rel/install.sh | sudo TEARMESH_RELEASE_URL=http://10.0.0.5:8000/rel sh -s -- lap --join tm2-abc");
        assert_eq!(ps, "$env:TEARMESH_RELEASE_URL='http://10.0.0.5:8000/rel'; & ([scriptblock]::Create((irm http://10.0.0.5:8000/rel/install.ps1))) -Machine lap -Join tm2-abc");
        for bad in ["ftp://x/y", "https://x/y z", "https://x/$(id)", "https://x/'y", "x/y", "https://", "https://;x", ""] {
            assert_eq!(one_liners_at(Some(bad), "t", None), one_liners_at(None, "t", None), "{bad:?}");
        }
    }

    #[test]
    fn a_boundary_must_fit_an_os_user_name() {
        assert!(user_name_fits(&"a".repeat(17)).is_ok());
        let e = user_name_fits(&"a".repeat(30)).unwrap_err().to_string();
        assert!(e.contains("tm-aaaa") && e.contains("33 characters"), "{e}");
        assert!(e.contains(if cfg!(windows) { "limit is 20" } else { "limit is 32" }), "{e}");
    }

    #[test]
    fn a_join_creates_users_only_for_unmapped_boundaries() {
        let c: Config = toml::from_str("machine = \"ws\"\n[users]\ntm-work = \"work\"\nalice = \"lab\"\n").unwrap();
        let h = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(missing_users(&c, &h(&["work", "lab", "vault"])), ["vault"]);
        assert!(missing_users(&c, &h(&["work"])).is_empty());
        assert!(missing_users(&c, &[]).is_empty());
    }

    #[test]
    fn the_plugin_matches_this_version() {
        let p: serde_json::Value = serde_json::from_str(PLUGIN[1].1).unwrap();
        assert_eq!(p["version"], env!("CARGO_PKG_VERSION"));
    }
}
