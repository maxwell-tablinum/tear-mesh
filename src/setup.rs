//! `tearmesh setup`: the first-run wizard, also reached from `tearmesh menu`. Every prompt
//! re-asks on bad input and takes `b` (back) and `q` (quit). Running it again on a machine that
//! is already set up changes nothing unless asked. Nothing is written until the last step: keys
//! are made in a private temporary directory, and a stop at any point (including Ctrl-C) leaves
//! the machine as it was.
//!
//! Keys: the owner keys sign every change to the mesh. Setup makes two plain key files, shows
//! each one and asks the person to copy it somewhere safe. The everyday key stays on this machine
//! under a passphrase; the recovery key is shown once and then deleted from this machine.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use crate::config::Config;
use crate::ipc::{Client, Request, socket_path};
use crate::mesh::{Machine, Mesh, ssh_sign};
use crate::valid_name;

const TMP_PREFIX: &str = "tearmesh-setup-";

/// What the person typed at a prompt.
#[derive(Debug, PartialEq)]
pub enum Answer {
    Back,
    Quit,
    Text(String),
}

pub fn parse_answer(line: Option<&str>) -> Answer {
    match line.map(str::trim) {
        // End of input (a closed pipe, Ctrl-D) quits rather than looping.
        None => Answer::Quit,
        Some("b") | Some("B") | Some("back") => Answer::Back,
        Some("q") | Some("Q") | Some("quit") => Answer::Quit,
        Some(s) => Answer::Text(s.to_string()),
    }
}

/// Why a ticket can't be right, before the daemon sees it.
pub fn check_ticket(t: &str) -> Result<()> {
    ensure!(
        t.starts_with("tm2-"),
        "a ticket starts with tm2- (copy the whole line `tearmesh mesh invite` printed)"
    );
    ensure!(
        !t.chars().any(char::is_whitespace),
        "the ticket has spaces or line breaks in it; paste it as one line"
    );
    ensure!(t.len() > 20, "that ticket is too short; it was probably cut off");
    Ok(())
}

pub fn check_mesh_name(n: &str) -> Result<()> {
    ensure!(
        valid_name(n),
        "use 1–32 characters: a-z, 0-9 and -, not starting with -"
    );
    ensure!(n.len() > 1, "use at least two characters (b and q mean back and quit)");
    Ok(())
}

/// Where setup keeps this mesh's everyday owner key.
pub fn owner_key_path(mesh: &str) -> PathBuf {
    crate::os::home_dir()
        .join(".ssh")
        .join(format!("tearmesh-owner-{mesh}"))
}

/// Private keys under ~/.ssh whose public half is one of `owners` (SHA256 fingerprints). The
/// menu calls this machine an owner node when it finds one.
pub fn find_owner_keys(owners: &[String]) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(crate::os::home_dir().join(".ssh")) else {
        return vec![];
    };
    let mut out: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_none_or(|x| x != "pub"))
        .filter(|p| {
            fingerprint_of(&pub_path(p)).is_some_and(|f| owners.iter().any(|o| *o == f))
        })
        .collect();
    out.sort();
    out
}

pub fn fingerprint_of(pub_file: &Path) -> Option<String> {
    let s = std::fs::read_to_string(pub_file).ok()?;
    let k = ssh_key::PublicKey::from_openssh(s.trim()).ok()?;
    Some(k.fingerprint(Default::default()).to_string())
}

fn sig_path(file: &Path) -> PathBuf {
    let mut s = file.as_os_str().to_owned();
    s.push(".sig");
    s.into()
}

pub fn pub_path(key: &Path) -> PathBuf {
    let mut s = key.as_os_str().to_owned();
    s.push(".pub");
    s.into()
}

/// A new directory only this user can enter, for files that get signed or hold keys: in a
/// shared temp directory another user could swap a file between writing and signing.
pub fn private_dir(prefix: &str) -> Result<PathBuf> {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).map_err(|e| anyhow::anyhow!("random: {e}"))?;
    let d = std::env::temp_dir().join(format!("{prefix}{}", crate::envelope::hex(&r)));
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700).create(&d)?;
    // Windows temp directories are already private to their user.
    #[cfg(not(unix))]
    std::fs::DirBuilder::new().create(&d)?;
    Ok(d)
}

/// Removes a directory holding key material, overwriting its files first.
fn shred_dir(d: &Path) {
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            if let Ok(m) = e.metadata() {
                let _ = std::fs::write(e.path(), vec![0u8; m.len() as usize]);
            }
        }
    }
    let _ = std::fs::remove_dir_all(d);
}

/// What a stop (Ctrl-C) must undo.
#[derive(Default)]
struct Undo {
    tmp: Option<PathBuf>,
    /// An owner key this run put in ~/.ssh before the mesh was applied.
    placed: Vec<PathBuf>,
    /// Files this run moved aside to `.old-*`, as (where it is now, where it was).
    renamed: Vec<(PathBuf, PathBuf)>,
}

impl Undo {
    fn run(&mut self) {
        if let Some(d) = self.tmp.take() {
            shred_dir(&d);
        }
        self.unplace();
    }

    fn unplace(&mut self) {
        for p in self.placed.drain(..) {
            let _ = std::fs::remove_file(pub_path(&p));
            let _ = std::fs::remove_file(&p);
        }
        for (now, was) in self.renamed.drain(..) {
            let _ = std::fs::rename(now, was);
        }
    }

    /// The mesh was applied: what this run put in place stays.
    fn keep(&mut self) {
        self.placed.clear();
        self.renamed.clear();
    }
}

struct Wizard {
    input: Box<dyn BufRead + Send>,
    undo: Arc<Mutex<Undo>>,
}

impl Wizard {
    fn ask(&mut self, q: &str) -> Result<Answer> {
        eprint!("{q}\n  [b back, q quit] > ");
        std::io::stderr().flush()?;
        // Bytes, not read_line: input that isn't UTF-8 is a bad answer to re-ask, not an error.
        let mut a = Vec::new();
        let n = self.input.read_until(b'\n', &mut a)?;
        let a = String::from_utf8_lossy(&a);
        Ok(parse_answer((n > 0).then_some(&*a)))
    }

    /// Asks until the answer is one of `keys`. Enter picks `default` when there is one.
    fn choose(&mut self, q: &str, keys: &[&str], default: Option<&str>) -> Result<Answer> {
        loop {
            match self.ask(q)? {
                Answer::Text(t) if keys.contains(&t.as_str()) => return Ok(Answer::Text(t)),
                Answer::Text(t) if t.is_empty() && default.is_some() => {
                    return Ok(Answer::Text(default.unwrap().into()));
                }
                Answer::Text(t) => eprintln!("  {t:?} isn't one of the choices: {}", keys.join(", ")),
                other => return Ok(other),
            }
        }
    }

    /// Asks until `check` accepts the answer.
    fn text(&mut self, q: &str, check: impl Fn(&str) -> Result<()>) -> Result<Answer> {
        loop {
            match self.ask(q)? {
                Answer::Text(t) => match check(&t) {
                    Ok(()) => return Ok(Answer::Text(t)),
                    Err(e) => eprintln!("  {e}"),
                },
                other => return Ok(other),
            }
        }
    }

    /// Waits for the word `saved`, then clears the key off a terminal's screen and scrollback.
    fn saved(&mut self) -> Result<Answer> {
        let a = self.text("Type `saved` once you have copied it.", |t| {
            ensure!(t.eq_ignore_ascii_case("saved"), "type the word saved (or b, q)");
            Ok(())
        })?;
        if matches!(a, Answer::Text(_)) && std::io::IsTerminal::is_terminal(&std::io::stderr()) {
            eprint!("\x1b[2J\x1b[3J\x1b[H");
            eprintln!("(Cleared the key from this screen. A terminal log or tmux history may still hold it.)");
        }
        Ok(a)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Step {
    Check,
    Choose,
    Join,
    Name,
    Keys,
    Confirm,
}

#[derive(Default)]
struct Plan {
    name: String,
    boundaries: Vec<String>,
    tmp: Option<PathBuf>,
    owner_src: Option<PathBuf>,
    /// Reusing a key already at the owner key path.
    reuse: bool,
    recovery_pub: Option<String>,
}

pub async fn run(config: &Path) -> Result<()> {
    clean_stale();
    let undo = Arc::new(Mutex::new(Undo::default()));
    let u = undo.clone();
    let stop = tokio::spawn(async move {
        if stopped().await {
            u.lock().unwrap().run();
            eprintln!("\nSetup stopped. Nothing was changed; run `tearmesh setup` again to start over.");
            std::process::exit(130);
        }
    });
    let mut w = Wizard {
        input: Box::new(std::io::BufReader::new(std::io::stdin())),
        undo: undo.clone(),
    };
    let r = wizard(&mut w, config).await;
    undo.lock().unwrap().run();
    stop.abort();
    match r {
        Ok(true) => Ok(()),
        Ok(false) => {
            eprintln!("Setup stopped. Nothing was changed.");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Ctrl-C, or (on Unix) the terminal closing or a plain kill.
async fn stopped() -> bool {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut term), Ok(mut hup)) = (signal(SignalKind::terminate()), signal(SignalKind::hangup())) else {
            return tokio::signal::ctrl_c().await.is_ok();
        };
        tokio::select! {
            r = tokio::signal::ctrl_c() => r.is_ok(),
            _ = term.recv() => true,
            _ = hup.recv() => true,
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.is_ok()
    }
}

/// Whether the setup that made a temp directory is still running (it wrote its pid there).
fn alive(dir: &Path) -> bool {
    let Some(pid) = std::fs::read_to_string(dir.join("pid")).ok().and_then(|s| s.trim().parse::<i32>().ok()) else {
        return false;
    };
    #[cfg(unix)]
    {
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok()
    }
    // shortcut: Windows can't cheaply ask whether a pid lives; treat a directory under an hour old
    // as in use. Upgrade to OpenProcess if two setups at once ever matter there.
    #[cfg(not(unix))]
    {
        let _ = pid;
        std::fs::metadata(dir)
            .and_then(|m| m.modified())
            .is_ok_and(|t| t.elapsed().is_ok_and(|e| e.as_secs() < 3600))
    }
}

/// Leftovers of a setup that was killed outright (signals are handled; SIGKILL isn't). A
/// setup still running (from another terminal, or the menu) keeps its directory.
fn clean_stale() {
    let Ok(rd) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for e in rd.flatten() {
        let mine = e.file_name().to_string_lossy().starts_with(TMP_PREFIX);
        // Only directories this user owns are ours to remove (Unix temp is shared).
        #[cfg(unix)]
        let mine = mine
            && e.metadata().is_ok_and(|m| {
                std::os::unix::fs::MetadataExt::uid(&m) == nix::unistd::geteuid().as_raw()
            });
        if mine && !alive(&e.path()) {
            shred_dir(&e.path());
        }
    }
}

async fn admin(req: Request) -> Result<Value> {
    Client::connect(&socket_path()).await?.call(&req).await
}

/// Ok(true) when setup finished, Ok(false) when the person quit.
async fn wizard(w: &mut Wizard, config: &Path) -> Result<bool> {
    let mut step = Step::Check;
    let mut plan = Plan::default();
    let mut cfg: Option<Config> = None;
    loop {
        step = match step {
            Step::Check => {
                let (c, status) = match preflight(w, config).await? {
                    Some(x) => x,
                    None => return Ok(false),
                };
                let next = existing(w, &c, &status).await?;
                cfg = Some(c);
                match next {
                    Some(s) => s,
                    None => return Ok(status["mesh"].is_object()),
                }
            }
            Step::Choose => {
                eprintln!("\nThis machine isn't in a mesh yet.");
                eprintln!("  1  Create a new mesh. This machine becomes its owner node: it holds the owner key and approves new machines.");
                eprintln!("  2  Join a mesh. You need a ticket from the owner node (`tearmesh mesh invite`).");
                match w.choose("Choose 1 or 2.", &["1", "2"], None)? {
                    Answer::Text(t) if t == "1" => Step::Name,
                    Answer::Text(_) => Step::Join,
                    Answer::Back => Step::Check,
                    Answer::Quit => return Ok(false),
                }
            }
            Step::Join => match join(w).await? {
                Some(true) => return Ok(true),
                Some(false) => Step::Choose,
                None => return Ok(false),
            },
            Step::Name => {
                let c = cfg.as_ref().expect("checked");
                let mut b: Vec<String> = c.users.values().cloned().collect();
                b.sort();
                b.dedup();
                if b.is_empty() {
                    eprintln!(
                        "\nThe config maps no OS users to boundaries, so a mesh would have nothing in it. \
                         Add users under [users] in the config (the install script does this), then run setup again."
                    );
                    return Ok(false);
                }
                plan.boundaries = b;
                match w.text("\nName for the new mesh (a-z, 0-9, -), e.g. home:", check_mesh_name)? {
                    Answer::Text(t) => {
                        plan.name = t;
                        Step::Keys
                    }
                    Answer::Back => Step::Choose,
                    Answer::Quit => return Ok(false),
                }
            }
            Step::Keys => match keys(w, &mut plan)? {
                Some(true) => Step::Confirm,
                Some(false) => Step::Name,
                None => return Ok(false),
            },
            Step::Confirm => {
                let c = cfg.as_ref().expect("checked");
                eprintln!("\nReady to create the mesh:");
                eprintln!("  mesh        {}", plan.name);
                eprintln!("  machine     {} (this one)", c.machine);
                eprintln!("  boundaries  {}", plan.boundaries.join(", "));
                eprintln!("  owner key   {}", owner_key_path(&plan.name).display());
                eprintln!("  recovery    the key you copied (deleted from this machine after this step)");
                match w.choose("Create it now? y to create.", &["y", "Y"], None)? {
                    Answer::Text(_) => match commit(w, c, &plan).await {
                        Ok(()) => return Ok(true),
                        Err(e) => {
                            w.undo.lock().unwrap().unplace();
                            eprintln!("\nThat didn't work: {e:#}\nNothing was changed. Try again, go back, or quit.");
                            Step::Confirm
                        }
                    },
                    Answer::Back => Step::Keys,
                    Answer::Quit => return Ok(false),
                }
            }
        };
    }
}

/// Loads the config and reaches the daemon, offering to retry. None when the person quits.
async fn preflight(w: &mut Wizard, config: &Path) -> Result<Option<(Config, Value)>> {
    loop {
        let problem = match Config::load(config) {
            Err(e) => format!(
                "{e:#}\n  Install tear-mesh on this machine first: `sudo deploy/setup-linux.sh <machine> <boundary>...` \
                 or deploy/setup-windows.ps1. It writes {}.",
                config.display()
            ),
            Ok(c) => match admin(Request::Status).await {
                Ok(s) => return Ok(Some((c, s))),
                Err(e) if format!("{e:#}").contains("admin only") => format!(
                    "{e:#}\n  Run setup as root/Administrator, or add your user to `admins` in {}.",
                    config.display()
                ),
                Err(e) => format!(
                    "{e:#}\n  The daemon isn't answering. Start it: `sudo systemctl start tearmesh` (Linux) or \
                     `Start-Service tearmesh` (Windows)."
                ),
            },
        };
        eprintln!("\n{problem}");
        match w.ask("Press Enter to check again.")? {
            Answer::Quit | Answer::Back => return Ok(None),
            Answer::Text(_) => continue,
        }
    }
}

/// When the machine is already in a mesh, says so and changes nothing unless asked. Returns the
/// next step, or None to stop.
async fn existing(w: &mut Wizard, c: &Config, status: &Value) -> Result<Option<Step>> {
    let Some(mesh) = status["mesh"].as_object() else {
        return Ok(Some(Step::Choose));
    };
    let name = mesh["name"].as_str().unwrap_or("?");
    let hosts: Vec<&str> = mesh["hosts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let owners: Vec<String> = serde_json::from_value(mesh["owners"].clone()).unwrap_or_default();
    let keys = find_owner_keys(&owners);
    if hosts.is_empty() {
        eprintln!(
            "\nThis machine ({}) has a copy of mesh {name}, but the mesh no longer lists it: it was removed or revoked.",
            c.machine
        );
    } else {
        eprintln!(
            "\nThis machine ({}) is already set up: mesh {name}, version {}, boundaries {}.",
            c.machine,
            mesh["version"],
            hosts.join(", ")
        );
        match keys.first() {
            Some(k) => eprintln!("It is an owner node (owner key {}).", k.display()),
            None => eprintln!("It is a member (no owner key on this machine)."),
        }
    }
    eprintln!("  1  Keep it as it is (nothing changes)");
    eprintln!("  2  Leave this mesh and set up again (the machine forgets the mesh; its mail logs stay)");
    match w.choose("Choose 1 or 2 (Enter keeps it).", &["1", "2"], Some("1"))? {
        Answer::Text(t) if t == "2" => {}
        Answer::Quit => return Ok(None),
        _ => {
            eprintln!("Nothing changed.");
            return Ok(None);
        }
    }
    let m = c.machine.clone();
    match w.text(
        &format!("To confirm, type this machine's name ({m}). Owners will still list it until they remove it."),
        |t| {
            ensure!(t == m, "type {m} exactly");
            Ok(())
        },
    )? {
        Answer::Text(_) => {
            admin(Request::Reset).await?;
            eprintln!("This machine left mesh {name}.");
            Ok(Some(Step::Choose))
        }
        Answer::Back => Ok(Some(Step::Check)),
        Answer::Quit => Ok(None),
    }
}

/// Some(true) joined, Some(false) back, None quit.
async fn join(w: &mut Wizard) -> Result<Option<bool>> {
    loop {
        let ticket = match w.text(
            "\nOn the owner node run `tearmesh mesh invite <name for this machine> --boundary <b>`, then paste the ticket here:",
            check_ticket,
        )? {
            Answer::Text(t) => t,
            Answer::Back => return Ok(Some(false)),
            Answer::Quit => return Ok(None),
        };
        let r = async {
            let mut c = Client::connect(&socket_path()).await?;
            c.call_each(&Request::Join { ticket }, |d| {
                eprintln!(
                    "\nCode {}. Check that the owner node shows the same code, then approve it there.\nWaiting for approval (Ctrl-C stops; nothing is changed until approval)...",
                    d["code"].as_str().unwrap_or_default()
                );
            })
            .await
        }
        .await;
        match r {
            Ok(v) => {
                eprintln!("\nJoined. Mesh version {}. `tearmesh menu` shows the other machines.", v["version"]);
                return Ok(Some(true));
            }
            Err(e) => eprintln!("\nThe join didn't go through: {e:#}\nAsk the owner node for a new ticket if this one expired."),
        }
    }
}

/// Makes (or reuses) the owner key and makes the recovery key, showing each one.
/// Some(true) done, Some(false) back, None quit.
fn keys(w: &mut Wizard, plan: &mut Plan) -> Result<Option<bool>> {
    if let Some(d) = plan.tmp.take() {
        shred_dir(&d);
    }
    let tmp = private_dir(TMP_PREFIX)?;
    std::fs::write(tmp.join("pid"), std::process::id().to_string())?;
    w.undo.lock().unwrap().tmp = Some(tmp.clone());
    plan.tmp = Some(tmp.clone());
    plan.reuse = false;
    let dest = owner_key_path(&plan.name);
    eprintln!(
        "\nOwner keys sign every change to the mesh: adding machines, grants, revoking a machine. \
         There are two, and you need either one to manage the mesh."
    );
    if dest.exists() {
        eprintln!(
            "\nThere is already an owner key for {} at {} (fingerprint {}).",
            plan.name,
            dest.display(),
            fingerprint_of(&pub_path(&dest)).unwrap_or_else(|| "unreadable".into())
        );
        match w.choose(
            "1 reuse it (you copied it earlier), 2 make a new one (the old file is kept as .old).",
            &["1", "2"],
            None,
        )? {
            Answer::Text(t) if t == "1" => {
                if !has_passphrase(&dest) {
                    eprintln!(
                        "  That key has no passphrase, so any program running as you could sign with it. \
                         Add one with `ssh-keygen -p -f {}` and run setup again, or make a new key.",
                        dest.display()
                    );
                    return Ok(Some(false));
                }
                plan.reuse = true
            }
            Answer::Text(_) => {}
            Answer::Back => return Ok(Some(false)),
            Answer::Quit => return Ok(None),
        }
    }
    if !plan.reuse {
        eprintln!(
            "\nKey 1 of 2, the everyday key. It stays on this machine. Choose a passphrase when asked: \
             without one, any program running as you could sign with it."
        );
        let k = tmp.join("owner");
        loop {
            keygen(&k, &format!("tearmesh owner {}", plan.name))?;
            if has_passphrase(&k) {
                break;
            }
            eprintln!("  That key has no passphrase. Making it again: enter a passphrase this time.");
            let _ = std::fs::remove_file(&k);
            let _ = std::fs::remove_file(pub_path(&k));
        }
        show_key(&k, "1 of 2: everyday owner key", &format!(
            "This machine keeps it at {}. The copy you save is your backup.",
            dest.display()
        ))?;
        match w.saved()? {
            Answer::Text(_) => {}
            Answer::Back => return Ok(Some(false)),
            Answer::Quit => return Ok(None),
        }
        plan.owner_src = Some(k);
    }
    eprintln!(
        "\nKey 2 of 2, the recovery key. It does not stay on this machine: it is your way back in if \
         this machine is lost, or if its key leaks and must be removed. A passphrase is optional; \
         if you set one, store it with the key."
    );
    let r = tmp.join("recovery");
    keygen(&r, &format!("tearmesh recovery {}", plan.name))?;
    show_key(&r, "2 of 2: recovery key", "This is the only copy. Setup deletes it from this machine when it finishes.")?;
    match w.saved()? {
        Answer::Text(_) => {}
        Answer::Back => return Ok(Some(false)),
        Answer::Quit => return Ok(None),
    }
    plan.recovery_pub = Some(std::fs::read_to_string(pub_path(&r))?.trim().to_string());
    Ok(Some(true))
}

fn show_key(path: &Path, title: &str, note: &str) -> Result<()> {
    let text = std::fs::read_to_string(path)?;
    let fp = fingerprint_of(&pub_path(path)).unwrap_or_default();
    eprintln!("\n──── Key {title} ({fp}) ────\n{}", text.trim_end());
    eprintln!("────────────────────────────────────────────");
    eprintln!("Copy this and put it somewhere safe.");
    eprintln!("{note} A password manager or a printed copy in a drawer works. Don't email it.");
    Ok(())
}

fn keygen(path: &Path, comment: &str) -> Result<()> {
    let ok = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-a", "100", "-C", comment, "-f"])
        .arg(path)
        .status()
        .context("running ssh-keygen (install OpenSSH: it makes and uses the owner keys)")?
        .success();
    ensure!(ok, "ssh-keygen didn't make the key");
    Ok(())
}

fn has_passphrase(key: &Path) -> bool {
    !std::process::Command::new("ssh-keygen")
        .args(["-y", "-P", ""])
        .arg("-f")
        .arg(key)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Builds, signs and applies the first membership file, then puts the owner key in place.
async fn commit(w: &mut Wizard, c: &Config, plan: &Plan) -> Result<()> {
    let tmp = plan.tmp.as_ref().context("keys first")?;
    let dest = owner_key_path(&plan.name);
    let owner_pub = match &plan.owner_src {
        Some(k) if !plan.reuse => std::fs::read_to_string(pub_path(k))?,
        _ => std::fs::read_to_string(pub_path(&dest))?,
    };
    let mut m = Mesh::new(
        &plan.name,
        vec![
            owner_pub.trim().to_string(),
            plan.recovery_pub.clone().context("recovery key")?,
        ],
        plan.boundaries.clone(),
        None,
    )?;
    let status = admin(Request::Status).await?;
    ensure!(
        status["mesh"].is_null(),
        "this machine joined a mesh while setup was running; run setup again"
    );
    let id = status["node_id"]
        .as_str()
        .context("the daemon didn't report its node id")?
        .parse()
        .map_err(|e| anyhow::anyhow!("node id: {e}"))?;
    m.add_machine(
        Machine {
            name: c.machine.clone(),
            id,
            boundaries: plan.boundaries.clone(),
        },
        false,
    )?;
    let file = tmp.join(format!("{}-mesh.toml", plan.name));
    let toml = m.to_toml()?;
    std::fs::write(&file, &toml)?;
    eprintln!("\nSigning the mesh with the everyday key (enter its passphrase):");
    let signer = if plan.reuse { dest.clone() } else { plan.owner_src.clone().context("owner key")? };
    ssh_sign(&signer, &file).context("signing (wrong passphrase?)")?;
    if !plan.reuse {
        place_key(w, plan.owner_src.as_ref().expect("made"), &dest)?;
    }
    let sig = std::fs::read_to_string(sig_path(&file))?;
    admin(Request::ApplyMesh { toml, sig }).await?;
    // Applied: the key in ~/.ssh is now the mesh's, not something to undo.
    w.undo.lock().unwrap().keep();
    eprintln!(
        "\nMesh {} is created, with this machine ({}) in it. This is its owner node.\n\
         The recovery key has been deleted from this machine; your saved copy is the only one.\n\
         Next: `tearmesh menu`, or add a machine with `tearmesh mesh invite <name> --boundary <b>`.",
        plan.name, c.machine
    );
    Ok(())
}

/// Copies the owner key into ~/.ssh, keeping any file already there as `.old`.
fn place_key(w: &mut Wizard, src: &Path, dest: &Path) -> Result<()> {
    if let Some(d) = dest.parent() {
        std::fs::create_dir_all(d)?;
    }
    if dest.exists() {
        let stamp = crate::now_ms();
        for p in [dest.to_path_buf(), pub_path(dest)] {
            if p.exists() {
                let mut old = p.as_os_str().to_owned();
                old.push(format!(".old-{stamp}"));
                let old = PathBuf::from(old);
                std::fs::rename(&p, &old)?;
                w.undo.lock().unwrap().renamed.push((old, p));
            }
        }
    }
    w.undo.lock().unwrap().placed.push(dest.to_path_buf());
    crate::os::write_private(dest, &std::fs::read(src)?)?;
    std::fs::write(pub_path(dest), std::fs::read(pub_path(src))?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers() {
        assert_eq!(parse_answer(None), Answer::Quit);
        assert_eq!(parse_answer(Some(" b\n")), Answer::Back);
        assert_eq!(parse_answer(Some("q\n")), Answer::Quit);
        assert_eq!(parse_answer(Some("\n")), Answer::Text(String::new()));
        assert_eq!(parse_answer(Some(" home \n")), Answer::Text("home".into()));
    }

    #[test]
    fn tickets_and_names() {
        assert!(check_ticket("hello").is_err());
        assert!(check_ticket("tm2-abc def-0000000000000000").is_err());
        assert!(check_ticket("tm2-short").is_err());
        assert!(check_ticket("tm2-abcdefghijklmnopqrstuvwxyz").is_ok());
        assert!(check_mesh_name("home").is_ok());
        assert!(check_mesh_name("b").is_err());
        assert!(check_mesh_name("Home").is_err());
        assert!(check_mesh_name("-x").is_err());
        assert!(check_mesh_name("").is_err());
    }

    fn wizard(input: &str) -> Wizard {
        Wizard {
            input: Box::new(std::io::Cursor::new(input.to_string())),
            undo: Arc::default(),
        }
    }

    #[test]
    fn prompts_re_ask_until_valid() {
        let mut w = wizard("x\n3\n2\n");
        assert_eq!(w.choose("?", &["1", "2"], None).unwrap(), Answer::Text("2".into()));
        let mut w = wizard("Bad Name\n-x\nhome\n");
        assert_eq!(w.text("?", check_mesh_name).unwrap(), Answer::Text("home".into()));
        let mut w = wizard("\n");
        assert_eq!(w.choose("?", &["1", "2"], Some("1")).unwrap(), Answer::Text("1".into()));
        let mut w = wizard("nope\nb\n");
        assert_eq!(w.saved().unwrap(), Answer::Back);
        let mut w = Wizard {
            input: Box::new(std::io::Cursor::new(b"\xff\xfe\n2\n".to_vec())),
            undo: Arc::default(),
        };
        assert_eq!(w.choose("?", &["1", "2"], None).unwrap(), Answer::Text("2".into()));
        // A closed input quits instead of spinning.
        let mut w = wizard("x\n");
        assert_eq!(w.choose("?", &["1"], None).unwrap(), Answer::Quit);
    }

    #[test]
    fn undo_removes_temp_and_placed_keys() {
        let d = tempfile::tempdir().unwrap();
        let tmp = d.path().join("t");
        std::fs::create_dir(&tmp).unwrap();
        std::fs::write(tmp.join("recovery"), "secret").unwrap();
        let placed = d.path().join("k");
        std::fs::write(&placed, "k").unwrap();
        std::fs::write(pub_path(&placed), "k").unwrap();
        let old = d.path().join("k.old-1");
        std::fs::write(&old, "previous").unwrap();
        let mut u = Undo {
            tmp: Some(tmp.clone()),
            placed: vec![placed.clone()],
            renamed: vec![(old.clone(), placed.clone())],
        };
        u.run();
        assert!(!tmp.exists() && !pub_path(&placed).exists());
        assert_eq!(std::fs::read_to_string(&placed).unwrap(), "previous", "the old key is back");
        assert!(!old.exists());
    }
}
