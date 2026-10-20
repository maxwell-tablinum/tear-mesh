//! `tearmesh setup`: the line-by-line first-run wizard (`tearmesh menu` does the same on one
//! screen). Every prompt re-asks on bad input and takes `b` (back) and `q` (quit). Running it
//! again on a machine that is already set up changes nothing unless asked. Keys and the signed
//! first version are made in memory, so a stop at any point before the last step (including
//! Ctrl-C) leaves the machine as it was.
//!
//! Keys: two owner keys sign every change to the mesh. The everyday key stays on this machine
//! under the person's passphrase. The recovery key is encrypted with a passphrase setup makes
//! (six random words), shown once with it, and never kept here.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, ensure};
use iroh::EndpointId;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::ipc::{Client, Request, socket_path};
use crate::keys::{self, NewKey};
use crate::mesh::{Machine, Mesh};
use crate::valid_name;

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

/// The one owner key of `m` in ~/.ssh, for commands that sign without `--key`.
pub fn owner_key(m: &Mesh) -> Result<PathBuf> {
    let owners: Vec<String> = m
        .owner_keys()?
        .iter()
        .map(|k| k.fingerprint(Default::default()).to_string())
        .collect();
    let mut found = find_owner_keys(&owners);
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => anyhow::bail!(
            "no owner key for mesh {} in ~/.ssh (looked for {}); pass --key PATH, or --no-sign",
            m.name,
            owners.join(", ")
        ),
        _ => anyhow::bail!(
            "several owner keys for mesh {} in ~/.ssh: {}; pick one with --key",
            m.name,
            found.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
        ),
    }
}

pub fn fingerprint_of(pub_file: &Path) -> Option<String> {
    let s = std::fs::read_to_string(pub_file).ok()?;
    let k = ssh_key::PublicKey::from_openssh(s.trim()).ok()?;
    Some(k.fingerprint(Default::default()).to_string())
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

/// Loads the config and reaches the daemon, offering to retry. None when the person quits.
async fn preflight(w: &mut Wizard, config: &Path) -> Result<Option<(Config, Value)>> {
    loop {
        let problem = match Config::load(config) {
            Err(e) => format!(
                "{e:#}\n  Install tear-mesh on this machine first: `sudo tearmesh install <machine> <boundary>...` \
                 (Windows: in an elevated prompt). It writes {}.",
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
            "\nOn the owner node run `tearmesh mesh invite` (or Owner → I in `tearmesh menu`), then paste the ticket here:",
            check_ticket,
        )? {
            Answer::Text(t) => t,
            Answer::Back => return Ok(Some(false)),
            Answer::Quit => return Ok(None),
        };
        JOINING.store(true, Ordering::SeqCst);
        let r = async {
            let mut c = Client::connect(&socket_path()).await?;
            c.call_each(&Request::Join { ticket }, |d| {
                eprintln!(
                    "\nCode {}. Check that the owner node shows the same code, then approve it there.\nWaiting for approval (Ctrl-C stops and cancels the request)...",
                    d["code"].as_str().unwrap_or_default()
                );
            })
            .await
        }
        .await;
        JOINING.store(false, Ordering::SeqCst);
        match r {
            Ok(v) => {
                eprintln!("\nJoined. Mesh version {}. `tearmesh menu` shows the other machines.", v["version"]);
                return Ok(Some(true));
            }
            Err(e) => eprintln!("\nThe join didn't go through: {e:#}\nAsk the owner node for a new ticket if this one expired."),
        }
    }
}

/// Version 1 of a new mesh with this machine in it, signed in memory with a new everyday key.
#[derive(Clone, Debug, PartialEq)]
pub struct NewMesh {
    pub name: String,
    pub machine: String,
    pub boundaries: Vec<String>,
    /// Encrypted with the person's passphrase; goes to ~/.ssh.
    pub owner: NewKey,
    /// Encrypted with `recovery_pass`; shown once, never kept here.
    pub recovery: NewKey,
    pub recovery_pass: Zeroizing<String>,
    pub toml: String,
    pub sig: String,
}

/// The boundaries a new mesh gets: the ones this machine's config maps users to.
pub fn boundaries(cfg: &Config) -> Result<Vec<String>> {
    let mut b: Vec<String> = cfg.users.values().cloned().collect();
    b.sort();
    b.dedup();
    ensure!(
        !b.is_empty(),
        "the config maps no OS users to boundaries, so a mesh would have nothing in it. \
         Add boundaries with `sudo tearmesh install {} <boundary>...`, then try again",
        cfg.machine
    );
    Ok(b)
}

pub fn check_passphrase(p: &str, again: &str) -> Result<()> {
    ensure!(p.chars().count() >= 8, "the passphrase needs at least 8 characters");
    ensure!(p == again, "the two passphrases differ");
    Ok(())
}

/// Makes both keys and signs version 1. Pure, and slow (bcrypt): run it off the UI thread.
pub fn version_one(
    name: &str,
    machine: &str,
    boundaries: Vec<String>,
    node_id: EndpointId,
    pass: &str,
) -> Result<NewMesh> {
    let (owner_key, owner) = keys::generate(&format!("tearmesh owner {name}"), pass)?;
    let recovery_pass = keys::passphrase();
    let (_, recovery) = keys::generate(&format!("tearmesh recovery {name}"), &recovery_pass)?;
    let mut m = Mesh::new(name, vec![owner.public.clone(), recovery.public.clone()], boundaries.clone(), None)?;
    m.add_machine(
        Machine {
            name: machine.into(),
            id: node_id,
            boundaries: boundaries.clone(),
        },
        false,
    )?;
    let toml = m.to_toml()?;
    let sig = keys::sign(&owner_key, &toml)?;
    Ok(NewMesh {
        name: name.into(),
        machine: machine.into(),
        boundaries,
        owner,
        recovery,
        recovery_pass,
        toml,
        sig,
    })
}

/// Checks this machine can start mesh `name`, then makes it in memory (nothing is written).
pub async fn new_mesh(name: &str, cfg: &Config, pass: &str) -> Result<NewMesh> {
    check_mesh_name(name)?;
    let b = boundaries(cfg)?;
    let status = admin(Request::Status).await?;
    ensure!(status["mesh"].is_null(), "this machine is already in a mesh");
    let id: EndpointId = status["node_id"]
        .as_str()
        .context("the daemon didn't report its node id")?
        .parse()
        .map_err(|e| anyhow::anyhow!("node id: {e}"))?;
    let (name, machine, pass) = (name.to_string(), cfg.machine.clone(), Zeroizing::new(pass.to_string()));
    tokio::task::spawn_blocking(move || version_one(&name, &machine, b, id, &pass)).await?
}

/// Puts the everyday key in ~/.ssh (an older file there is kept as `.old-<ms>`), then applies
/// version 1. If the daemon refuses, the key comes out again. Returns the key's path.
pub async fn commit(m: &NewMesh) -> Result<PathBuf> {
    let status = admin(Request::Status).await?;
    ensure!(
        status["mesh"].is_null(),
        "this machine joined a mesh in the meantime; nothing was changed"
    );
    let dest = owner_key_path(&m.name);
    let moved = place_key(&m.owner, &dest)?;
    let r = admin(Request::ApplyMesh {
        toml: m.toml.clone(),
        sig: m.sig.clone(),
    })
    .await;
    if let Err(e) = r {
        let _ = std::fs::remove_file(&dest);
        let _ = std::fs::remove_file(pub_path(&dest));
        for (now, was) in moved {
            let _ = std::fs::rename(now, was);
        }
        return Err(e);
    }
    Ok(dest)
}

/// Writes the key to `dest`, moving files already there aside. Returns the moves.
fn place_key(k: &NewKey, dest: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
    if let Some(d) = dest.parent() {
        std::fs::create_dir_all(d)?;
    }
    let stamp = crate::now_ms();
    let mut moved = vec![];
    for p in [dest.to_path_buf(), pub_path(dest)] {
        if p.exists() {
            let mut old = p.as_os_str().to_owned();
            old.push(format!(".old-{stamp}"));
            let old = PathBuf::from(old);
            std::fs::rename(&p, &old)?;
            moved.push((old, p));
        }
    }
    crate::os::write_private(dest, k.private.as_bytes())?;
    std::fs::write(pub_path(dest), format!("{}\n", k.public))?;
    Ok(moved)
}

struct Wizard {
    input: Box<dyn BufRead + Send>,
    /// Read passphrases without echo (a terminal), rather than as plain lines (a script).
    tty: bool,
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

    /// A passphrase: no echo on a terminal (Ctrl-C or an empty line quits), a line otherwise.
    fn secret(&mut self, q: &str) -> Result<Option<Zeroizing<String>>> {
        eprint!("{q} ");
        std::io::stderr().flush()?;
        if !self.tty {
            let mut a = Zeroizing::new(String::new());
            let n = self.input.read_line(&mut a)?;
            let t = Zeroizing::new(a.trim_end_matches(['\r', '\n']).to_string());
            return Ok((n > 0).then_some(t));
        }
        use ratatui::crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers, read};
        ratatui::crossterm::terminal::enable_raw_mode()?;
        let mut s = Zeroizing::new(String::with_capacity(256));
        let r = loop {
            match read() {
                Ok(Event::Key(k)) if k.kind != KeyEventKind::Release => match k.code {
                    KeyCode::Enter => break Ok(Some(())),
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => break Ok(None),
                    KeyCode::Backspace => {
                        s.pop();
                    }
                    KeyCode::Char(c) if s.len() < 128 => s.push(c),
                    _ => {}
                },
                Ok(_) => {}
                Err(e) => break Err(e),
            }
        };
        ratatui::crossterm::terminal::disable_raw_mode()?;
        eprintln!();
        Ok(r?.map(|_| s))
    }

    /// Waits for the word `saved`, then clears the key off a terminal's screen and scrollback.
    fn saved(&mut self) -> Result<Answer> {
        let a = self.text("Type `saved` once you have copied both.", |t| {
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
    Pass,
    Recovery,
    Confirm,
}

/// Set while a join is waiting, so a stop cancels it in the daemon too.
static JOINING: AtomicBool = AtomicBool::new(false);

pub async fn run(config: &Path) -> Result<()> {
    let stop = tokio::spawn(async {
        if stopped().await {
            if JOINING.load(Ordering::SeqCst) {
                let _ = admin(Request::JoinCancel).await;
            }
            eprintln!("\nSetup stopped. Nothing was changed; run `tearmesh setup` again to start over.");
            std::process::exit(130);
        }
    });
    let mut w = Wizard {
        input: Box::new(std::io::BufReader::new(std::io::stdin())),
        tty: std::io::IsTerminal::is_terminal(&std::io::stdin()),
    };
    let r = wizard(&mut w, config).await;
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

async fn admin(req: Request) -> Result<Value> {
    Client::connect(&socket_path()).await?.call(&req).await
}

/// Ok(true) when setup finished, Ok(false) when the person quit.
async fn wizard(w: &mut Wizard, config: &Path) -> Result<bool> {
    let mut step = Step::Check;
    let mut name = String::new();
    let mut made: Option<NewMesh> = None;
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
                if let Err(e) = boundaries(cfg.as_ref().expect("checked")) {
                    eprintln!("\n{e:#}");
                    return Ok(false);
                }
                match w.text("\nName for the new mesh (a-z, 0-9, -), e.g. home:", check_mesh_name)? {
                    Answer::Text(t) => {
                        name = t;
                        Step::Pass
                    }
                    Answer::Back => Step::Choose,
                    Answer::Quit => return Ok(false),
                }
            }
            Step::Pass => {
                eprintln!(
                    "\nThe owner key signs every change to the mesh. It stays on this machine, locked with a \
                     passphrase, so programs running as you can't sign with it. Choose one (8 or more characters)."
                );
                let Some(p) = w.secret("Passphrase:")? else { return Ok(false) };
                let Some(again) = w.secret("Same passphrase again:")? else { return Ok(false) };
                match check_passphrase(&p, &again) {
                    Err(e) => {
                        eprintln!("  {e}");
                        Step::Pass
                    }
                    Ok(()) => {
                        eprintln!("Making the owner keys…");
                        made = Some(new_mesh(&name, cfg.as_ref().expect("checked"), &p).await?);
                        Step::Recovery
                    }
                }
            }
            Step::Recovery => {
                let m = made.as_ref().expect("made");
                show_recovery(m);
                match w.saved()? {
                    Answer::Text(_) => Step::Confirm,
                    Answer::Back => Step::Pass,
                    Answer::Quit => return Ok(false),
                }
            }
            Step::Confirm => {
                let m = made.as_ref().expect("made");
                eprintln!("\nReady to create the mesh:");
                eprintln!("  mesh        {}", m.name);
                eprintln!("  machine     {} (this one, the owner node)", m.machine);
                eprintln!("  boundaries  {}", m.boundaries.join(", "));
                eprintln!("  owner key   {}", owner_key_path(&m.name).display());
                eprintln!("  recovery    the key and passphrase you saved (not kept here)");
                match w.choose("Create it now? y to create.", &["y", "Y"], None)? {
                    Answer::Text(_) => match commit(m).await {
                        Ok(_) => {
                            eprintln!(
                                "\nMesh {} is created, with this machine ({}) in it. This is its owner node.\n\
                                 Next: `tearmesh menu`, or add a machine with `tearmesh mesh invite`.",
                                m.name, m.machine
                            );
                            return Ok(true);
                        }
                        Err(e) => {
                            eprintln!("\nThat didn't work: {e:#}\nNothing was changed. Try again, go back, or quit.");
                            Step::Confirm
                        }
                    },
                    Answer::Back => Step::Recovery,
                    Answer::Quit => return Ok(false),
                }
            }
        };
    }
}

fn show_recovery(m: &NewMesh) {
    let fp = ssh_key::PublicKey::from_openssh(&m.recovery.public)
        .map(|k| k.fingerprint(Default::default()).to_string())
        .unwrap_or_default();
    eprintln!("\n──── Recovery key for mesh {} ({fp}) ────\n{}", m.name, m.recovery.private.trim_end());
    eprintln!("──── Its passphrase ────\n{}", *m.recovery_pass);
    eprintln!("────────────────────────────────────────────");
    eprintln!(
        "Save both somewhere off this machine: a password manager, or a printout in a drawer. Keep the \
         passphrase apart from the key file, or both in a password manager. This is your way back in if \
         this machine is lost or its key leaks. It isn't kept here. Don't email it."
    );
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
        assert!(check_passphrase("short", "short").is_err());
        assert!(check_passphrase("long enough", "long enougH").is_err());
        assert!(check_passphrase("long enough", "long enough").is_ok());
    }

    fn wizard(input: &str) -> Wizard {
        Wizard {
            input: Box::new(std::io::Cursor::new(input.to_string())),
            tty: false,
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
            tty: false,
        };
        assert_eq!(w.choose("?", &["1", "2"], None).unwrap(), Answer::Text("2".into()));
        // A closed input quits instead of spinning.
        let mut w = wizard("x\n");
        assert_eq!(w.choose("?", &["1"], None).unwrap(), Answer::Quit);
        let mut w = wizard("pass word\n");
        assert_eq!(w.secret("?").unwrap().as_deref().map(|s| s.as_str()), Some("pass word"));
        assert!(w.secret("?").unwrap().is_none());
    }

    #[test]
    fn version_one_is_signed_and_keys_open() {
        let id = iroh::SecretKey::generate().public();
        let m = version_one("home", "ws", vec!["work".into()], id, "everyday pass").unwrap();
        let s = crate::mesh::SignedMesh::verify_first(&m.toml, &m.sig).unwrap();
        assert_eq!(s.mesh.machine("ws").unwrap().id, id);
        let d = tempfile::tempdir().unwrap();
        let rec = d.path().join("rec");
        std::fs::write(&rec, m.recovery.private.as_bytes()).unwrap();
        assert!(keys::open(&rec, &m.recovery_pass).is_ok());
        assert!(keys::open(&rec, "everyday pass").is_err(), "the recovery key has its own passphrase");

        // Placing a key keeps the one already there.
        let dest = d.path().join("ssh/k");
        place_key(&m.owner, &dest).unwrap();
        let moved = place_key(&m.recovery, &dest).unwrap();
        assert_eq!(moved.len(), 2);
        assert!(keys::open(&moved[0].0, "everyday pass").is_ok());
    }
}
