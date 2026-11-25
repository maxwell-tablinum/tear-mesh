//! `tearmesh menu`: a full-screen terminal UI for running a machine in a mesh. Arrow keys (or
//! the keypad) move, Enter picks, Esc goes back, and a shortcut bar along the bottom shows the
//! keys for the current screen, like nano's.
//!
//! It shows live state (the daemon's status, which machines answer a ping, recent changes) and
//! acts directly, without leaving the screen: creating or joining a mesh, inviting, approving a
//! join (its code, boundaries and grants in one signature), and every change an owner signs. It
//! takes the owner key's passphrase itself and signs in this process; for a security key it takes
//! the PIN and ssh-keygen signs with the device. Only SSH and a security key whose file also has
//! a passphrase suspend the menu. It has three screens: Mesh (the map and the machines), Mail (the
//! mail client, in the menu) and Settings. The menu is an owner node's when an owner key for the
//! mesh is in ~/.ssh; only then does it offer the actions that sign.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::canvas::{Canvas, Line as CLine};
use ratatui::widgets::{Block, BorderType, Cell, Clear, Paragraph, Row, Table, Tabs, Wrap};

use zeroize::Zeroizing;

use crate::config::Config;
use crate::ipc::{Client, Request, socket_path};
use crate::join::{JoinProgress, PendingInfo};
use crate::keys::{self, Signer};
use crate::mesh::{Approval, Category, Change, Grant, Mesh};
use crate::node::Status;
use crate::ping::Ping;
use crate::setup::NewMesh;

const ACCENT: Color = Color::Cyan;
const TEAR: Color = Color::Magenta;
const OK: Color = Color::Green;
const BAD: Color = Color::Red;
const DIM: Color = Color::DarkGray;

/// The splash logo: a mesh beside the name, and the tear line torn along the bottom.
/// Every line has the same width so the logo stays square when centered.
pub const LOGO: [&str; 7] = [
    r"  o-----o-----o       _                                           _        ",
    r" / \   / \   / \     | |_ ___  __ _ _ __      _ __ ___   ___  ___| |__     ",
    r"o---o-o---o-o---o    | __/ _ \/ _` | '__|____| '_ ` _ \ / _ \/ __| '_ \    ",
    r" \ /   \ /   \ /     | ||  __/ (_| | | |_____| | | | | |  __/\__ \ | | |   ",
    r"  o-----o-----o       \__\___|\__,_|_|       |_| |_| |_|\___||___/_| |_|   ",
    r"                  a mesh for your machines and their agents                ",
    r"- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ✂ -",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Mesh,
    Mail,
    Settings,
}

const TABS: [Tab; 3] = [Tab::Mesh, Tab::Mail, Tab::Settings];

impl Tab {
    fn title(self) -> &'static str {
        match self {
            Tab::Mesh => "Mesh",
            Tab::Mail => "Mail",
            Tab::Settings => "Settings",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// No daemon answer, or no mesh yet.
    NotSetUp,
    /// An OS user mapped to a boundary: the daemon answers it mail, not the mesh's admin requests.
    BoundaryUser,
    Member,
    /// An owner key for this mesh is on this machine.
    Owner,
}

/// What the menu asks the runtime to do.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Suspend and SSH to a machine over the mesh.
    Ssh { machine: String, boundary: Option<String> },
    StartHub,
    Refresh,
    /// Start background work; its screen is already open.
    Job(Task),
    /// Stop watching the running job.
    Cancel,
    /// Put text on the clipboard (OSC 52).
    Copy(Zeroizing<String>),
    /// A security key whose file has a passphrase: sign with ssh-keygen in the plain terminal, then apply.
    SignOutside { key: PathBuf, changes: Vec<Change> },
    /// A key on the Mail tab that needs the daemon.
    Mail(crate::tui::Cmd),
    /// Run `tearmesh <args>` with admin rights (sudo or UAC) in the plain terminal.
    Elevated(Vec<String>),
}

/// Background work the runtime does while the menu stays on screen.
#[derive(Debug, Clone, PartialEq)]
pub enum Task {
    Invite { name: Option<String>, boundaries: Vec<String>, ttl_secs: u64 },
    Join { ticket: String },
    /// Make the owner keys and version 1 of a new mesh, in memory.
    NewMesh { name: String, pass: Zeroizing<String> },
    /// Put the everyday key in place and apply version 1.
    Create(Box<NewMesh>),
    Sign { key: PathBuf, pass: Zeroizing<String>, changes: Vec<Change> },
    Reject { name: String },
    JoinCancel,
    /// Tell the others this machine is leaving, then forget the mesh.
    Leave,
}

/// What background work reports back.
#[derive(Debug)]
pub enum Msg {
    Code(String),
    Ticket(String),
    Keys(Box<NewMesh>),
    Done(String),
    Failed(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum FormKind {
    Grant,
    Revoke,
    /// Offered servers waiting for the owner, as drawn: ticking one approves it at this pin.
    Offers(Vec<Approval>),
    /// The switches between this machine and another, as drawn: each one's grant, and whether
    /// it was on. One signature applies whatever changed.
    Permissions(Vec<(Grant, bool)>),
    Relays,
    OwnerAdd,
    Create,
    Join,
    /// A join request: add it, with any boundaries and grants ticked, in one signature. The
    /// boundaries and grants its boxes stand for, in order, as drawn.
    Approve(Box<PendingInfo>, Vec<String>, Vec<Grant>),
    /// Sign these changes.
    Sign(Vec<Change>),
    /// Install tear-mesh here: a machine name and boundaries.
    Install,
    /// Create OS users for boundaries this machine hosts or will.
    AddBoundaries,
    /// End the mesh: the person types its name.
    Dissolve,
}

/// One line of a form.
#[derive(Clone, Debug, PartialEq)]
pub enum Field {
    /// Text to read; focus skips it.
    Note(String),
    Text { label: String, value: String },
    /// Drawn as dots; wiped from memory when dropped.
    Secret { label: String, value: Zeroizing<String> },
    /// Space ticks it.
    Check { label: String, on: bool },
}

/// What a full screen shows for the person to keep.
#[derive(Clone, Debug, PartialEq)]
pub enum Keep {
    /// `invite` is `join::invite_id` of the ticket's secret: a join request with the same one
    /// replaces this screen.
    Ticket { ticket: String, invite: String },
    Recovery(Box<NewMesh>),
}

/// What the keep screen's input line is for.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Ask {
    Path,
    Word,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Modal {
    Form {
        kind: FormKind,
        title: String,
        fields: Vec<Field>,
        focus: usize,
        error: Option<String>,
    },
    Confirm {
        text: String,
        action: Action,
    },
    /// Text to read. ↑↓ scroll it; C copies `copy` when there is one.
    Info {
        title: String,
        text: String,
        scroll: u16,
        copy: Option<String>,
    },
    /// The keys and words, over the current screen.
    Help,
    /// Background work is running. `hold`: it can't be stopped (the last step of creating a
    /// mesh). `join`: Esc only hides it; the join keeps waiting in the daemon.
    Busy {
        title: String,
        text: String,
        hold: bool,
        join: bool,
    },
    /// Full screen, without borders, so a mouse selection copies only the text.
    Keep {
        what: Keep,
        ask: Option<(Ask, String)>,
        note: String,
    },
}

fn text(label: &str, value: &str) -> Field {
    Field::Text { label: label.into(), value: value.into() }
}

/// The secret field a security key's sign form asks for.
const PIN: &str = "PIN for the security key (then touch it)";

fn secret(label: &str) -> Field {
    // Reserved up front so typing never reallocates and leaves a copy behind.
    Field::Secret { label: label.into(), value: Zeroizing::new(String::with_capacity(256)) }
}

fn check(label: &str) -> Field {
    Field::Check { label: label.into(), on: false }
}

fn check_on(label: &str) -> Field {
    Field::Check { label: label.into(), on: true }
}

/// "123456" as "123 456".
fn spaced(code: &str) -> String {
    if code.len() == 6 { format!("{} {}", &code[..3], &code[3..]) } else { code.into() }
}

/// The screen a job shows while it runs.
fn busy(t: &Task) -> Modal {
    let (title, text, hold, join) = match t {
        Task::Invite { .. } => ("Invite", "Making a ticket…", false, false),
        Task::Join { .. } => ("Join a mesh", "Reaching the owner node…", false, true),
        Task::NewMesh { .. } => ("Create a mesh", "Making the owner keys…", false, false),
        Task::Create(_) => ("Create a mesh", "Creating the mesh…", true, false),
        Task::Sign { .. } => ("Sign", "Signing and applying… (a security key: touch it when it blinks)", false, false),
        Task::Reject { .. } => ("Refuse", "Refusing…", false, false),
        Task::JoinCancel => ("Join a mesh", "Cancelling the request…", false, false),
        Task::Leave => ("Leave the mesh", "Telling the others, then forgetting the mesh…", false, false),
    };
    Modal::Busy { title: title.into(), text: text.into(), hold, join }
}

fn info(title: impl Into<String>, text: impl Into<String>) -> Modal {
    Modal::Info { title: title.into(), text: text.into(), scroll: 0, copy: None }
}

/// The hub's settings and how to register it; C copies the `claude mcp add` line.
fn hub_panel(config: &std::path::Path, dir: &std::path::Path) -> Modal {
    match crate::hub::info_text(config, dir) {
        Ok(text) => {
            let copy = text.lines().map(str::trim).find(|l| l.starts_with("claude mcp add")).map(String::from);
            Modal::Info { title: "MCP hub".into(), text, scroll: 0, copy }
        }
        Err(e) => info("MCP hub", format!("{e:#}")),
    }
}

/// Everything the runtime fetched.
#[derive(Default, Clone)]
pub struct Data {
    pub status: Option<Status>,
    pub mesh: Option<Mesh>,
    pub pings: Vec<Ping>,
    pub pinged_at: Option<Instant>,
    /// Why the daemon couldn't be reached.
    pub error: Option<String>,
    /// Nothing listens on the daemon's socket (as opposed to it refusing this user).
    pub no_daemon: bool,
    pub owner_key: Option<PathBuf>,
    /// Set when the daemon refuses Status ("admin only") but answers Hello: this user's address and boundary.
    pub who: Option<(String, String)>,
    pub hub_running: bool,
    pub hub_url: String,
    pub journal: Vec<String>,
    /// On an owner node: offered servers no approval covers (new, or changed since).
    pub offers: Vec<Waiting>,
}

/// An offered MCP server waiting for the owner's approval.
#[derive(Clone, Debug, PartialEq)]
pub struct Waiting {
    /// What approving it signs: the whole tool list, at its current pin.
    pub approval: Approval,
    pub tools: Vec<String>,
    pub changed: bool,
}

pub struct App {
    pub tab: Tab,
    pub data: Data,
    /// Selected row: a join request or machine on Mesh, an owner key on Settings.
    pub sel: usize,
    pub modal: Option<Modal>,
    pub log: VecDeque<String>,
    pub note: String,
    pub quit: bool,
    pub mailbox: String,
    /// This machine's config, for the create and join screens.
    pub cfg: Option<Config>,
    /// The users install created (`install::created_record`), loaded with `cfg`.
    pub created: String,
    /// The config file exists, readable or not.
    pub config_file: bool,
    /// Said when the menu exits (after an uninstall removed it).
    pub bye: Option<String>,
    /// The Install form already opened by itself once.
    offered_install: bool,
    /// The Mail tab, once it reached the daemon.
    pub mail: Option<crate::tui::App>,
    /// Why the Mail tab couldn't connect.
    pub mail_error: Option<String>,
    /// Join requests that already got a popup.
    asked: Vec<iroh::EndpointId>,
    /// A boundary user's first screen (Mail) was chosen.
    placed: bool,
    /// The field the last failed form check was about.
    bad_field: Option<usize>,
    /// Machines that said they left and already got a popup.
    told: Vec<String>,
    /// The form to reopen, with the error, when its job fails.
    back: Option<Modal>,
    /// When the menu last opened a form by itself (not from a key): Enter waits `SETTLE` after it.
    pub(crate) auto_at: Option<Instant>,
}

/// How long a form the menu opened by itself ignores Enter, so a key meant for the screen it
/// replaced can't submit it (an unencrypted owner key would approve without comparing codes).
const SETTLE: Duration = Duration::from_millis(700);

impl App {
    pub fn new() -> App {
        App {
            tab: Tab::Mesh,
            data: Data::default(),
            sel: 0,
            modal: None,
            log: VecDeque::new(),
            note: String::new(),
            quit: false,
            mailbox: std::env::var("TEARMESH_MAILBOX").unwrap_or_else(|_| "admin".into()),
            cfg: None,
            created: String::new(),
            config_file: false,
            bye: None,
            offered_install: false,
            mail: None,
            mail_error: None,
            asked: vec![],
            placed: false,
            bad_field: None,
            told: vec![],
            back: None,
            auto_at: None,
        }
    }

    pub fn role(&self) -> Role {
        if self.data.who.is_some() {
            return Role::BoundaryUser;
        }
        match (&self.data.status, &self.data.mesh) {
            (Some(s), Some(_)) if s.mesh.is_some() => {
                if self.data.owner_key.is_some() {
                    Role::Owner
                } else {
                    Role::Member
                }
            }
            _ => Role::NotSetUp,
        }
    }

    /// No config file and nothing on the daemon's socket. A daemon that refuses this user
    /// ("admin only") is installed.
    pub fn not_installed(&self) -> bool {
        !self.config_file && self.data.no_daemon
    }

    /// Boundaries this machine hosts with no OS user here, else none when it has no users at all
    /// (Some(empty)); None when neither, and U isn't offered.
    fn boundaries_to_add(&self) -> Option<Vec<String>> {
        if self.role() == Role::BoundaryUser {
            return None;
        }
        let unmapped = self.data.status.as_ref().map(|s| s.unmapped.clone()).unwrap_or_default();
        if !unmapped.is_empty() {
            return Some(unmapped);
        }
        self.cfg.as_ref().filter(|c| c.users.is_empty()).map(|_| vec![])
    }

    fn say(&mut self, s: impl Into<String>) {
        let s = s.into();
        let stamp = clock();
        self.log.push_front(format!("{stamp}  {s}"));
        self.log.truncate(500);
    }

    /// Takes fresh data, noting what changed in the log.
    pub fn set_data(&mut self, mut d: Data) {
        let old = std::mem::take(&mut self.data);
        // One failed fetch of the membership file doesn't turn a member into a machine with no mesh.
        if d.mesh.is_none() && d.status.as_ref().and_then(|s| s.mesh.as_ref()).is_some_and(|i| old.mesh.as_ref().is_some_and(|m| m.id == i.id && m.version <= i.version)) {
            d.mesh = old.mesh.clone();
        }
        // A mesh the daemon no longer names (left, dissolved) takes its letters with it.
        if old.mesh.is_some() && d.status.as_ref().is_some_and(|s| s.mesh.is_none()) {
            self.mail = None;
        }
        match (&old.error, &d.error) {
            (None, Some(e)) => self.say(format!("daemon unreachable: {e}")),
            (Some(_), None) => self.say("daemon is answering again"),
            _ => {}
        }
        let ver = |d: &Data| d.mesh.as_ref().map(|m| m.version);
        if let (Some(a), Some(b)) = (ver(&old), ver(&d))
            && a != b
        {
            self.say(format!("mesh version {a} → {b}"));
        }
        if !d.pings.is_empty() {
            for p in &d.pings {
                let was = old.pings.iter().find(|o| o.name == p.name).map(|o| o.rtt_ms.is_some());
                let now = p.rtt_ms.is_some();
                if was != Some(now) && (was.is_some() || !now) {
                    self.say(format!(
                        "{} is {}",
                        p.name,
                        if now { "reachable" } else { "not answering" }
                    ));
                }
            }
        }
        let pend = |d: &Data| {
            d.status
                .as_ref()
                .map(|s| s.pending_joins.iter().map(|p| p.name.clone()).collect::<Vec<_>>())
                .unwrap_or_default()
        };
        for n in pend(&d) {
            if !pend(&old).contains(&n) {
                self.say(format!("join request from {n}: select it on the Mesh screen and press Enter"));
            }
        }
        if d.pings.is_empty() {
            d.pings = old.pings;
            d.pinged_at = old.pinged_at;
        }
        self.data = d;
        if self.data.who.is_some() && !self.placed {
            self.placed = true;
            self.tab = Tab::Mail;
        }
        if self.not_installed() && !self.offered_install && self.modal.is_none() {
            self.offered_install = true;
            self.install_form();
            self.auto_at = Some(Instant::now());
        }
        if self.role() != Role::Owner {
            return;
        }
        // A new join request opens its approval on an owner node, once: in place of the ticket
        // screen it was made from, otherwise when no other screen is open.
        let showing = match &self.modal {
            Some(Modal::Keep { what: Keep::Ticket { invite, .. }, .. }) if !invite.is_empty() => Some(invite.clone()),
            _ => None,
        };
        let new = self.data.status.as_ref().and_then(|s| {
            s.pending_joins
                .iter()
                .filter(|p| !self.asked.contains(&p.node_id))
                .find(|p| self.modal.is_none() || showing.as_ref() == Some(&p.invite))
                .cloned()
        });
        if let Some(p) = new {
            self.asked.push(p.node_id);
            self.approve(p);
            self.auto_at = Some(Instant::now());
        }
        // A machine that said it left (it left there, or was uninstalled): offer to remove it, once.
        if self.modal.is_none() {
            let me = self.this_machine();
            let left = self
                .data
                .status
                .as_ref()
                .and_then(|s| s.leaving.iter().find(|n| **n != me && !self.told.contains(n)).cloned());
            if let Some(n) = left {
                self.told.push(n.clone());
                self.sign(
                    "Remove a machine that left",
                    format!(
                        "{n} says it left the mesh (it left there, or tear-mesh was uninstalled).\n\
                         Remove it from the mesh, with its grants and approvals? Esc keeps it; D on the Mesh screen removes it later."
                    ),
                    vec![Change::RemoveMachine(n)],
                );
                self.auto_at = Some(Instant::now());
            }
        }
    }

    /// Machines that said they are leaving.
    fn leaving(&self) -> &[String] {
        self.data.status.as_ref().map_or(&[], |s| &s.leaving)
    }

    fn machines(&self) -> Vec<&crate::mesh::Machine> {
        self.data
            .mesh
            .as_ref()
            .map(|m| m.machines.iter().collect())
            .unwrap_or_default()
    }

    fn this_machine(&self) -> String {
        let who = self.data.who.as_ref().and_then(|(a, _)| a.split_once('@')).map(|(_, m)| m.to_string());
        self.data.status.as_ref().map(|s| s.machine.clone()).or(who).unwrap_or_default()
    }

    /// A boundary this machine and `other` both host, for a shell between them.
    fn shared_boundary(&self, other: &str) -> Option<String> {
        let mesh = self.data.mesh.as_ref()?;
        let theirs = &mesh.machine(other)?.boundaries;
        mesh.machine(&self.this_machine())?.boundaries.iter().find(|b| theirs.contains(b)).cloned()
    }

    /// Join requests, listed above the machines on an owner node's Mesh screen.
    fn pending(&self) -> Vec<PendingInfo> {
        match &self.data.status {
            Some(s) if self.role() == Role::Owner => s.pending_joins.clone(),
            _ => vec![],
        }
    }

    fn owners(&self) -> Vec<String> {
        self.data.status.as_ref().and_then(|s| s.mesh.as_ref()).map(|m| m.owners.clone()).unwrap_or_default()
    }

    fn rows(&self) -> usize {
        match self.tab {
            Tab::Mesh => self.pending().len() + self.machines().len(),
            Tab::Settings => self.owners().len(),
            Tab::Mail => 0,
        }
    }

    fn open(&mut self, kind: FormKind, title: &str, fields: Vec<Field>) {
        self.auto_at = None;
        let focus = fields.iter().position(|f| !matches!(f, Field::Note(_))).unwrap_or(0);
        self.modal = Some(Modal::Form { kind, title: title.into(), fields, focus, error: None });
    }

    /// Opens the screen that signs `changes` with this machine's owner key.
    fn sign(&mut self, title: &str, text: String, changes: Vec<Change>) -> Option<Action> {
        let key = self.data.owner_key.clone()?;
        let last = match keys::signer(&key) {
            Err(e) => {
                self.modal = Some(info(format!("Can't sign with {}", key.display()), format!("{e:#}")));
                return None;
            }
            Ok(Signer::Terminal) => {
                self.modal = Some(Modal::Confirm {
                    text: format!("{text}\n\nThis key signs with ssh-keygen in the plain terminal: touch it when it blinks."),
                    action: Action::SignOutside { key, changes },
                });
                return None;
            }
            Ok(Signer::Device) => secret(PIN),
            Ok(Signer::Here { encrypted: true }) => secret(&format!("Passphrase for {}", key.display())),
            Ok(Signer::Here { encrypted: false }) => Field::Note("Enter signs and applies it.".into()),
        };
        self.open(FormKind::Sign(changes), title, vec![Field::Note(text), last]);
        None
    }

    /// The boxes the approval offers: the boundaries the machine may host (the mesh's, then the
    /// new ones it asked for; label, boundary, pre-ticked), then the grants.
    #[allow(clippy::type_complexity)]
    fn approve_options(&self, p: &PendingInfo) -> (Vec<(String, String, bool)>, Vec<(String, Grant)>) {
        let Some(mesh) = &self.data.mesh else { return (vec![], vec![]) };
        let me = self.this_machine();
        let n = &p.name;
        let mut hosts: Vec<(String, String, bool)> =
            mesh.boundaries.iter().map(|b| (format!("{n} hosts {b}"), b.clone(), p.boundaries.contains(b))).collect();
        hosts.extend(
            p.boundaries
                .iter()
                .filter(|b| !mesh.boundaries.contains(b))
                .map(|b| (format!("{n} hosts {b} (new: adds it to the mesh)"), b.clone(), false)),
        );
        let mut v = vec![];
        let g = |from: &str, to: &str, c: Category| Grant { from: from.into(), to: to.into(), allow: vec![c] };
        if !mesh.allows(n, &me, Category::Converse) {
            v.push((format!("{n} may mail {me}"), g(n, &me, Category::Converse)));
            v.push((format!("{me} may mail {n}"), g(&me, n, Category::Converse)));
        }
        v.push((format!("{n} may use {me}'s tools"), g(n, &me, Category::Tools)));
        v.push((format!("{n} may open a shell on {me}"), g(n, &me, Category::Shell)));
        v.push((format!("{me} may use {n}'s tools"), g(&me, n, Category::Tools)));
        v.push((format!("{me} may open a shell on {n}"), g(&me, n, Category::Shell)));
        (hosts, v)
    }

    /// Opens the approval for a join request.
    fn approve(&mut self, p: PendingInfo) {
        let mut f = vec![
            Field::Note(if p.boundaries.is_empty() {
                format!("{} wants to join. It asked for no boundaries: you pick which ones it hosts (tick at least one).", p.name)
            } else {
                format!("{} wants to join with boundaries {}.", p.name, p.boundaries.join(", "))
            }),
            Field::Note(format!("Code {}: does {}'s own screen show the same code?", spaced(&p.code), p.name)),
        ];
        if p.contested {
            f.push(Field::Note(format!(
                "WARNING: another machine also tried this ticket. Approve only if the code matches on {}'s own screen.",
                p.name
            )));
        }
        if p.replace {
            f.push(Field::Note(format!("It replaces the machine already named {}, keeping its grants.", p.name)));
        }
        if !p.waiting {
            f.push(Field::Note(format!("{} is away; it gets the file when it comes back with the same ticket.", p.name)));
        }
        let (hosts, grants) = self.approve_options(&p);
        f.extend(hosts.iter().map(|(l, _, on)| if *on { check_on(l) } else { check(l) }));
        f.extend(grants.iter().map(|(l, _)| check(l)));
        let mail = self.data.mesh.as_ref().is_some_and(|m| m.allows(&p.name, &self.this_machine(), Category::Converse));
        if mail {
            f.push(Field::Note("Everyone may already mail everyone.".into()));
        }
        match self.data.owner_key.as_ref().map(|k| (k, keys::signer(k))) {
            Some((k, Ok(Signer::Here { encrypted: true }))) => f.push(secret(&format!("Passphrase for {}", k.display()))),
            Some((_, Ok(Signer::Device))) => f.push(secret(PIN)),
            Some((_, Ok(Signer::Terminal))) => f.push(Field::Note("This key signs with ssh-keygen in the plain terminal.".into())),
            Some((k, Err(e))) => f.push(Field::Note(format!("WARNING: can't sign with {}: {e:#}", k.display()))),
            _ => {}
        }
        let hosts = hosts.into_iter().map(|h| h.1).collect();
        let grants = grants.into_iter().map(|g| g.1).collect();
        self.open(FormKind::Approve(Box::new(p), hosts, grants), "Join request", f);
    }

    /// The offered servers waiting for approval, one box each. None is ticked: a machine signs
    /// its own offer, so the person decides what they expect it to share.
    fn review_offers(&mut self) {
        let mut f = vec![Field::Note(
            "Tick what you expect each machine to share. Machines it listens to for tools may then call these.".into(),
        )];
        for w in &self.data.offers {
            let a = &w.approval;
            let why = if w.changed { " (changed since you approved it)" } else { "" };
            let only = if a.tools.is_some() { " only, as before" } else { "" };
            f.push(check(&format!("{}/{} in {}{why}: {}{only}", a.machine, a.server, a.boundary, w.tools.join(", "))));
        }
        let offers = self.data.offers.iter().map(|w| w.approval.clone()).collect();
        self.open(FormKind::Offers(offers), "Offered MCP servers", f);
    }

    /// The six switches between this machine and `other`: each category, spoken and listened.
    /// One a `*` grant already allows is only a note: this form edits the pair's own grants.
    fn permissions(&mut self, other: &str) {
        let Some(mesh) = &self.data.mesh else { return };
        let me = self.this_machine();
        let mut f = vec![Field::Note(format!(
            "Speak: what {me} may do to {other}. Listen: what {me} accepts from {other}. Both ends check."
        ))];
        let mut switches = vec![];
        for c in [Category::Converse, Category::Tools, Category::Shell] {
            for (from, to) in [(me.as_str(), other), (other, me.as_str())] {
                let label = switch_label(c, from == me, &me, other);
                let has = |g: &&Grant, f: &str, t: &str| g.from == f && g.to == t && g.allow.contains(&c);
                if mesh.grants.iter().any(|g| has(&g, "*", to) || has(&g, from, "*") || has(&g, "*", "*")) {
                    f.push(Field::Note(format!("  [x] {label} · mesh-wide (V revokes it)")));
                } else {
                    let on = mesh.grants.iter().any(|g| has(&g, from, to));
                    f.push(Field::Check { label, on });
                    switches.push((Grant { from: from.into(), to: to.into(), allow: vec![c] }, on));
                }
            }
        }
        self.open(FormKind::Permissions(switches), &format!("Permissions: {me} and {other}"), f);
    }

    fn need_owner(&mut self) -> bool {
        if self.role() == Role::Owner {
            return true;
        }
        self.note = "only an owner node can do that (no owner key for this mesh in ~/.ssh)".into();
        false
    }

    /// The bindings shown in the bottom bar for the current screen.
    pub fn shortcuts(&self) -> Vec<(&'static str, &'static str)> {
        if let Some(m) = &self.modal {
            return match m {
                Modal::Form { kind: FormKind::Approve(..), .. } => {
                    vec![("Tab", "Next"), ("Space", "Tick"), ("Enter", "Approve"), ("Esc", "Later")]
                }
                Modal::Form { fields, .. } if fields.iter().any(|f| matches!(f, Field::Check { .. })) => {
                    vec![("Tab", "Next"), ("Space", "Tick"), ("Enter", "Submit"), ("Esc", "Cancel")]
                }
                Modal::Form { .. } => vec![("Tab", "Next field"), ("Enter", "Submit"), ("Esc", "Cancel")],
                Modal::Confirm { .. } => vec![("Y", "Yes"), ("N", "No"), ("Esc", "Cancel")],
                Modal::Info { text, copy, .. } => {
                    let mut v = vec![];
                    if text.lines().count() > 10 {
                        v.push(("↑↓", "Scroll"));
                    }
                    if copy.is_some() {
                        v.push(("C", "Copy command"));
                    }
                    v.extend([("Enter", "Close"), ("Esc", "Close")]);
                    v
                }
                Modal::Help => vec![("Esc", "Close")],
                Modal::Busy { hold: true, .. } => vec![],
                Modal::Busy { join: true, .. } => vec![("Esc", "Hide (keeps waiting)")],
                Modal::Busy { .. } => vec![("Esc", "Stop")],
                Modal::Keep { ask: Some(_), .. } => vec![("Enter", "OK"), ("Esc", "Back")],
                Modal::Keep { what: Keep::Ticket { .. }, .. } => vec![
                    ("C", "Copy Linux line"),
                    ("P", "Copy PowerShell line"),
                    ("T", "Copy ticket"),
                    ("W", "Save ticket to file"),
                    ("Esc", "Close"),
                ],
                Modal::Keep { what: Keep::Recovery(_), .. } => vec![
                    ("C", "Copy key"),
                    ("P", "Copy passphrase"),
                    ("W", "Save key to file"),
                    ("Y", "I've saved them"),
                    ("Esc", "Cancel"),
                ],
            };
        }
        self.tab_keys()
    }

    /// The current tab's keys, for the bar and the Help screen.
    fn tab_keys(&self) -> Vec<(&'static str, &'static str)> {
        let role = self.role();
        let mut v = vec![("←→", "Tabs")];
        let add = self.boundaries_to_add().is_some();
        match self.tab {
            Tab::Mesh if self.not_installed() => v.push(("I", "Install")),
            Tab::Mesh if role == Role::BoundaryUser => {}
            Tab::Mesh if role == Role::NotSetUp => {
                if add {
                    v.push(("U", "Add boundaries"));
                }
                v.extend([("C", "Create a mesh"), ("J", "Join a mesh")]);
                if self.joining() {
                    v.push(("X", "Cancel join"));
                }
            }
            Tab::Mesh => {
                let pend = self.selected_pending().is_some();
                v.extend([
                    ("↑↓", "Select"),
                    ("Enter", if pend { "Approve" } else { "Details" }),
                    ("X", "Shell"),
                    ("P", "Ping now"),
                    ("S", "Status JSON"),
                ]);
                if add {
                    v.push(("U", "Add boundaries"));
                }
                if role == Role::Owner {
                    v.extend([("A", "Add node"), ("D", if pend { "Refuse" } else { "Disconnect" }), ("G", "Permissions"), ("V", "Revoke grant")]);
                    if !self.data.offers.is_empty() {
                        v.push(("O", "Offers"));
                    }
                } else {
                    v.push(("Shift-L", "Leave mesh"));
                }
            }
            Tab::Mail => {
                // R, G and the rest belong to the mail client; its own footer lists them.
                if self.mail.as_ref().is_some_and(|m| m.compose.is_some()) {
                    return vec![("Tab", "Next field"), ("Ctrl-S", "Send"), ("Esc", "Discard")];
                }
                v.extend([("?", "Help"), ("Q", "Quit")]);
                return v;
            }
            Tab::Settings => {
                v.extend([("Shift-H", "Start MCP hub"), ("U", "Hub info"), ("E", "Clear events")]);
                if !self.not_installed() && role != Role::BoundaryUser {
                    v.push(("X", "Uninstall"));
                }
                if role == Role::Owner {
                    v.extend([
                        ("↑↓", "Select key"),
                        ("T", "Tools sharing"),
                        ("Y", "Relays"),
                        ("N", "Add owner key"),
                        ("Z", "Remove key"),
                        ("Shift-K", "Dissolve mesh"),
                    ]);
                }
            }
        }
        // On Mesh, P already refreshes (with a ping); R still works.
        if !(self.tab == Tab::Mesh && matches!(role, Role::Owner | Role::Member)) {
            v.push(("R", "Refresh"));
        }
        v.extend([("?", "Help"), ("Q", "Quit")]);
        v
    }

    /// This machine's own join is still running in the daemon.
    fn joining(&self) -> bool {
        matches!(
            self.data.status.as_ref().and_then(|s| s.joining.as_ref()),
            Some(JoinProgress::Dialing | JoinProgress::Waiting { .. })
        )
    }

    pub fn on_key(&mut self, k: KeyEvent) -> Option<Action> {
        let a = self.key(k);
        if let Some(Action::Job(t)) = &a {
            self.modal = Some(busy(t));
        }
        a
    }

    fn key(&mut self, k: KeyEvent) -> Option<Action> {
        // Windows terminals also report key releases.
        if k.kind != KeyEventKind::Press {
            return None;
        }
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            if matches!(self.modal, Some(Modal::Busy { hold: true, .. })) {
                self.note = "Almost done; one moment.".into();
            } else {
                self.quit = true;
            }
            return None;
        }
        if self.modal.is_some() {
            return self.modal_key(k);
        }
        self.note.clear();
        // While a letter is being written every key is text; otherwise the menu keeps only the
        // keys that move between tabs, Help and quit.
        if self.tab == Tab::Mail
            && let Some(m) = &mut self.mail
        {
            let menu = matches!(k.code, KeyCode::Left | KeyCode::Right | KeyCode::Tab)
                || matches!(k.code, KeyCode::Char('h' | 'l' | '4' | '6' | '?' | 'q' | 'Q'));
            if m.compose.is_some() || !menu {
                return m.on_key(k).map(Action::Mail);
            }
        }
        let at = TABS.iter().position(|t| *t == self.tab).unwrap_or(0);
        // The not-set-up Mesh screen has no rows, and J joins there.
        let rows = !(self.tab == Tab::Mesh && !matches!(self.role(), Role::Owner | Role::Member));
        let code = match k.code {
            // The keypad with Num Lock on sends digits.
            KeyCode::Char('4') | KeyCode::Char('h') => KeyCode::Left,
            KeyCode::Char('6') | KeyCode::Char('l') => KeyCode::Right,
            KeyCode::Char('8') => KeyCode::Up,
            KeyCode::Char('2') => KeyCode::Down,
            KeyCode::Char('k') if rows => KeyCode::Up,
            KeyCode::Char('j') if rows => KeyCode::Down,
            KeyCode::Char(c) => KeyCode::Char(c.to_ascii_lowercase()),
            c => c,
        };
        match code {
            KeyCode::Left => {
                self.tab = TABS[(at + TABS.len() - 1) % TABS.len()];
                self.sel = 0;
            }
            KeyCode::Right | KeyCode::Tab => {
                self.tab = TABS[(at + 1) % TABS.len()];
                self.sel = 0;
            }
            KeyCode::Up => self.sel = self.sel.saturating_sub(1),
            KeyCode::Down => {
                if self.sel + 1 < self.rows() {
                    self.sel += 1;
                }
            }
            KeyCode::Esc => {
                self.tab = Tab::Mesh;
                self.sel = 0;
            }
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') => self.modal = Some(Modal::Help),
            KeyCode::Char('r') => return Some(Action::Refresh),
            _ => return self.tab_key(code),
        }
        None
    }

    fn selected_machine(&self) -> Option<String> {
        let i = self.sel.checked_sub(self.pending().len())?;
        self.machines().get(i).map(|m| m.name.clone())
    }

    fn selected_pending(&self) -> Option<PendingInfo> {
        self.pending().into_iter().nth(self.sel)
    }

    fn tab_key(&mut self, code: KeyCode) -> Option<Action> {
        let role = self.role();
        match (self.tab, code) {
            (Tab::Mesh, KeyCode::Char('i')) if self.not_installed() => {
                self.install_form();
                None
            }
            (Tab::Mesh, _) if self.not_installed() || role == Role::BoundaryUser => None,
            (Tab::Mesh, KeyCode::Char('u')) => {
                let b = self.boundaries_to_add()?;
                self.add_boundaries_form(b);
                None
            }
            (Tab::Mesh, KeyCode::Char('c')) if role == Role::NotSetUp => {
                self.create_form();
                None
            }
            (Tab::Mesh, KeyCode::Char('j')) if role == Role::NotSetUp => {
                self.join_form();
                None
            }
            (Tab::Mesh, KeyCode::Char('x')) if role == Role::NotSetUp && self.joining() => {
                Some(Action::Job(Task::JoinCancel))
            }
            (Tab::Mesh, _) if role == Role::NotSetUp => None,
            (Tab::Mesh, KeyCode::Char('s')) => {
                let text = serde_json::to_string_pretty(self.data.status.as_ref()?).unwrap_or_default();
                self.modal = Some(info("Status", text));
                None
            }
            (Tab::Mesh, KeyCode::Char('p')) => Some(Action::Refresh),
            (Tab::Mesh, KeyCode::Enter) => {
                if let Some(p) = self.selected_pending() {
                    self.approve(p);
                    return None;
                }
                let name = self.selected_machine()?;
                self.modal = Some(info(name.clone(), self.details(&name)));
                None
            }
            (Tab::Mesh, KeyCode::Char('x')) => {
                let m = self.selected_machine()?;
                if m == self.this_machine() {
                    self.note = "that's this machine".into();
                    return None;
                }
                let boundary = self.shared_boundary(&m);
                Some(Action::Ssh { machine: m, boundary })
            }
            // The new machine proposes its name and boundaries; the approval picks.
            (Tab::Mesh, KeyCode::Char('a')) => {
                self.need_owner().then_some(Action::Job(Task::Invite { name: None, boundaries: vec![], ttl_secs: 3600 }))
            }
            (Tab::Mesh, KeyCode::Char('o')) if !self.data.offers.is_empty() => {
                if self.need_owner() {
                    self.review_offers();
                }
                None
            }
            (Tab::Mesh, KeyCode::Char('d')) => {
                if !self.need_owner() {
                    return None;
                }
                if let Some(p) = self.selected_pending() {
                    self.modal = Some(Modal::Confirm {
                        text: format!("Refuse {}'s request to join? Its ticket stops working.", p.name),
                        action: Action::Job(Task::Reject { name: p.name }),
                    });
                    return None;
                }
                let m = self.selected_machine()?;
                if m == self.this_machine() {
                    self.note = "an owner node can't remove itself here; use another owner key".into();
                    return None;
                }
                self.sign(
                    "Disconnect",
                    format!(
                        "Disconnect {m}: remove it from the mesh, with its grants and approvals.\n\
                         Use this when a machine is retired, lost, or its key may be stolen. Every member \
                         refuses it as soon as they sync the new version; it can come back only through a new invite."
                    ),
                    vec![Change::RemoveMachine(m)],
                )
            }
            (Tab::Mesh, KeyCode::Char('g')) => {
                if self.need_owner() {
                    // On another machine's row: the six switches. On this one's: any pair, or `*`.
                    match self.selected_machine().filter(|o| *o != self.this_machine()) {
                        Some(o) => self.permissions(&o),
                        None => self.form(FormKind::Grant),
                    }
                }
                None
            }
            (Tab::Mesh, KeyCode::Char('v')) => {
                if self.need_owner() {
                    self.form(FormKind::Revoke);
                }
                None
            }
            (Tab::Mesh, KeyCode::Char('l')) if role == Role::Member => {
                let name = self.data.mesh.as_ref().map(|m| m.name.clone()).unwrap_or_default();
                self.modal = Some(Modal::Confirm {
                    text: format!(
                        "Leave mesh {name}?\nThis machine tells the others it is leaving, then forgets the mesh (its \
                         logs are kept, moved aside). The owner node then removes it."
                    ),
                    action: Action::Job(Task::Leave),
                });
                None
            }
            (Tab::Settings, KeyCode::Char('e')) => {
                self.log.clear();
                None
            }
            (Tab::Settings, KeyCode::Char('h')) => Some(Action::StartHub),
            (Tab::Settings, KeyCode::Char('x')) if !self.not_installed() && role != Role::BoundaryUser => {
                self.modal = Some(Modal::Confirm {
                    text: self.uninstall_text(),
                    action: Action::Elevated(vec!["uninstall".into(), "--yes".into()]),
                });
                None
            }
            (Tab::Settings, KeyCode::Char('u')) => {
                self.modal = Some(hub_panel(&crate::hub::config_path(), &crate::hub::state_dir()));
                None
            }
            (Tab::Settings, KeyCode::Char('t')) => {
                if !self.need_owner() {
                    return None;
                }
                let free = self
                    .data
                    .mesh
                    .as_ref()
                    .is_some_and(|m| m.settings.tools_sharing == crate::mesh::Sharing::Free);
                let to = if free { "approval" } else { "free" };
                self.sign(
                    "Tools sharing",
                    format!(
                        "Set tools sharing to {to}? {}",
                        if to == "free" {
                            "Any offered server becomes callable by machines with a tools grant, without approval."
                        } else {
                            "Offered servers need your approval again before others can call them."
                        }
                    ),
                    vec![Change::Set { setting: "tools-sharing".into(), value: to.into() }],
                )
            }
            (Tab::Settings, KeyCode::Char('y')) => {
                if self.need_owner() {
                    self.form(FormKind::Relays);
                }
                None
            }
            (Tab::Settings, KeyCode::Char('n')) => {
                if self.need_owner() {
                    self.form(FormKind::OwnerAdd);
                }
                None
            }
            (Tab::Settings, KeyCode::Char('k')) => {
                if self.need_owner() {
                    self.form(FormKind::Dissolve);
                }
                None
            }
            (Tab::Settings, KeyCode::Char('z')) => {
                if !self.need_owner() {
                    return None;
                }
                let fp = self.owners().get(self.sel)?.clone();
                self.sign(
                    "Remove owner key",
                    format!(
                        "Remove owner key {fp}?\nDo this when a key leaked or was lost. The mesh keeps at \
                         least two owner keys, so add a replacement first (N)."
                    ),
                    vec![Change::OwnerRemove(fp)],
                )
            }
            _ => None,
        }
    }

    fn details(&self, name: &str) -> String {
        let Some(mesh) = &self.data.mesh else {
            return String::new();
        };
        let Some(m) = mesh.machine(name) else {
            return String::new();
        };
        let mut s = format!("node id     {}\nboundaries  {}\n", m.id, m.boundaries.join(", "));
        if let Some(p) = self.data.pings.iter().find(|p| p.name == name) {
            s += &match p.rtt_ms {
                Some(r) => format!("ping        {r} ms (dial {} ms)\n", p.dial_ms.unwrap_or(0)),
                None => format!("ping        no answer: {}\n", p.error.as_deref().unwrap_or("?")),
            };
        }
        let me = self.this_machine();
        if name != me {
            s += &format!("\n{me} speaks to it     {}\n", allowed(mesh, &me, name));
            s += &format!("{me} listens to it    {}\n", allowed(mesh, name, &me));
        }
        s += "\ngrants in the file\n";
        for g in &mesh.grants {
            if g.from == name || g.to == name || g.from == "*" || g.to == "*" {
                let cats: Vec<&str> = g.allow.iter().map(|c| cat(*c)).collect();
                s += &format!("  {} → {}: {}\n", g.from, g.to, cats.join(", "));
            }
        }
        for a in mesh.approvals.iter().filter(|a| a.machine == name) {
            s += &format!("approved    {}/{} in {}\n", a.machine, a.server, a.boundary);
        }
        s
    }

    fn local_boundaries(&self) -> String {
        self.cfg
            .as_ref()
            .and_then(|c| crate::setup::boundaries(c).ok())
            .map(|b| b.join(", "))
            .unwrap_or_else(|| "none yet".into())
    }

    fn create_form(&mut self) {
        let me = self.this_machine();
        let f = vec![
            Field::Note(format!("{me} becomes the owner node. Boundaries: {} (from its config).", self.local_boundaries())),
            text("Mesh name (a-z, 0-9, -), e.g. home", ""),
            Field::Note("The owner key signs every change to the mesh. It stays on this machine, locked with a passphrase.".into()),
            secret("Passphrase (8 or more characters)"),
            secret("Same passphrase again"),
        ];
        self.open(FormKind::Create, "Create a mesh", f);
    }

    fn install_form(&mut self) {
        let f = vec![
            Field::Note("tear-mesh isn't installed on this machine. Install puts in the daemon, its service and one OS user per boundary (tm-<boundary>); it asks for admin rights.".into()),
            text("Machine name (a-z, 0-9, -)", &crate::machine_name(&crate::os::hostname())),
            text("Boundaries (comma-separated; may be empty: the owner picks)", "work"),
        ];
        self.open(FormKind::Install, "Install tear-mesh", f);
    }

    fn add_boundaries_form(&mut self, unmapped: Vec<String>) {
        let note = if unmapped.is_empty() {
            "This machine hosts no boundaries yet. Each one gets an OS user, tm-<boundary>; it asks for admin rights.".to_string()
        } else {
            format!("The mesh has this machine host {}, with no OS user here yet. Each one gets tm-<boundary>; it asks for admin rights.", unmapped.join(", "))
        };
        let prefill = if unmapped.is_empty() { "work".to_string() } else { unmapped.join(",") };
        self.open(FormKind::AddBoundaries, "Add boundaries", vec![Field::Note(note), text("Boundaries (comma-separated)", &prefill)]);
    }

    /// What Settings → X says before it uninstalls.
    fn uninstall_text(&self) -> String {
        let (ours, kept) = self.cfg.as_ref().map(|c| crate::install::created_users(c, &self.created)).unwrap_or_default();
        let users: Vec<String> = ours.iter().map(|b| format!("tm-{b}")).collect();
        let mut t = format!(
            "Remove tear-mesh from this machine?\n\nIt removes {}{}, and stops running hubs and stewards. The menu closes afterwards, since its binary goes too.",
            crate::install::REMOVES,
            if users.is_empty() { String::new() } else { format!(", and users {} with their homes", users.join(", ")) }
        );
        if !kept.is_empty() {
            t += &format!("\nUsers kept (not created by install): {}.", kept.join(", "));
        }
        if self.data.owner_key.is_some() {
            let name = self.data.mesh.as_ref().map(|m| m.name.clone()).unwrap_or_default();
            t += &format!(
                "\n\nThis is an owner node of mesh {name}. Afterwards only the other owner keys (the recovery key) can sign for it. To end the mesh instead, dissolve it first: K on this screen (or `tearmesh mesh dissolve`)."
            );
        }
        t + "\n\nIf it is in a mesh, the other machines are told it is leaving. Owner keys in ~/.ssh stay."
    }

    fn join_form(&mut self) {
        let f = vec![
            Field::Note(format!("This machine: {} · boundaries {}", self.this_machine(), self.local_boundaries())),
            Field::Note("The owner node sees these and decides what to let in.".into()),
            text("Ticket from the owner node (paste it)", ""),
        ];
        self.open(FormKind::Join, "Join a mesh", f);
    }

    fn form(&mut self, kind: FormKind) {
        let sel = self.selected_machine().unwrap_or_default();
        let me = self.this_machine();
        let (title, fields) = match kind {
            FormKind::Grant => (
                "Grant",
                vec![
                    text("From machine", &me),
                    text("To machine", &sel),
                    text("Categories (converse,tools,shell)", "converse"),
                ],
            ),
            FormKind::Revoke => (
                "Revoke a grant",
                vec![
                    text("From machine", &me),
                    text("To machine", &sel),
                    text("Categories (converse,tools,shell)", "shell"),
                ],
            ),
            FormKind::Relays => ("Relays", vec![text("n0, none, or URL,URL", "n0")]),
            FormKind::OwnerAdd => ("Add an owner key", vec![text("Path to the new key's .pub file", "")]),
            FormKind::Dissolve => {
                let Some(m) = &self.data.mesh else { return };
                (
                    "Dissolve the mesh",
                    vec![
                        Field::Note(format!(
                            "Dissolving mesh {} removes all {} machines from it, for good. Each keeps its logs, moved aside, and can then create or join another mesh. No machine can rejoin it.",
                            m.name,
                            m.machines.len()
                        )),
                        text(&format!("Type the mesh name ({}) to dissolve it", m.name), ""),
                    ],
                )
            }
            _ => return,
        };
        self.open(kind, title, fields);
    }

    /// Pasted text goes into the focused field. A ticket loses any line breaks or spaces.
    pub fn on_paste(&mut self, s: &str) {
        let Some(Modal::Form { kind, fields, focus, .. }) = &mut self.modal else {
            if let Some(Modal::Keep { ask: Some((_, buf)), .. }) = &mut self.modal {
                buf.push_str(s.trim());
            }
            return;
        };
        let clean: String = if *kind == FormKind::Join {
            s.chars().filter(|c| !c.is_whitespace()).collect()
        } else {
            s.chars().filter(|c| *c != '\r' && *c != '\n').collect()
        };
        match fields.get_mut(*focus) {
            Some(Field::Text { value, .. }) => value.push_str(&clean),
            Some(Field::Secret { value, .. }) => {
                for c in clean.chars().take(128usize.saturating_sub(value.chars().count())) {
                    value.push(c);
                }
            }
            _ => {}
        }
    }

    fn modal_key(&mut self, k: KeyEvent) -> Option<Action> {
        let settling = self.auto_at.is_some_and(|t| t.elapsed() < SETTLE);
        let modal = self.modal.as_mut()?;
        match modal {
            Modal::Info { text, scroll, copy, .. } => {
                let last = text.lines().count().saturating_sub(1) as u16;
                match k.code {
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => self.modal = None,
                    KeyCode::Up => *scroll = scroll.saturating_sub(1),
                    KeyCode::Down => *scroll = (*scroll + 1).min(last),
                    KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
                    KeyCode::PageDown => *scroll = (*scroll + 10).min(last),
                    KeyCode::Char('c') | KeyCode::Char('C') => {
                        let c = copy.clone()?;
                        self.note = "Sent to the clipboard (under tmux: set -g set-clipboard on).".into();
                        return Some(Action::Copy(Zeroizing::new(c)));
                    }
                    _ => {}
                }
                None
            }
            Modal::Help => {
                if matches!(k.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('?')) {
                    self.modal = None;
                }
                None
            }
            Modal::Busy { hold, join, .. } => {
                if k.code != KeyCode::Esc {
                    return None;
                }
                if *hold {
                    self.note = "Almost done; one moment.".into();
                    return None;
                }
                self.note = if *join {
                    "Still waiting in the background: the Mesh screen shows the code, and X there cancels the request.".into()
                } else {
                    "Stopped.".into()
                };
                self.modal = None;
                self.back = None;
                Some(Action::Cancel)
            }
            Modal::Confirm { action, .. } => match k.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let a = action.clone();
                    self.modal = None;
                    Some(a)
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.modal = None;
                    self.note = "cancelled".into();
                    None
                }
                _ => None,
            },
            Modal::Keep { .. } => self.keep_key(k),
            Modal::Form { fields, focus, .. } => {
                let note: Vec<bool> = fields.iter().map(|f| matches!(f, Field::Note(_))).collect();
                let step = |from: usize, fwd: bool| {
                    let n = note.len();
                    let mut i = from;
                    for _ in 0..n {
                        i = if fwd { (i + 1) % n } else { (i + n - 1) % n };
                        if !note[i] {
                            return i;
                        }
                    }
                    from
                };
                let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
                match (k.code, &mut fields[*focus]) {
                    (KeyCode::Esc, _) => {
                        self.modal = None;
                        self.note = "cancelled".into();
                    }
                    (KeyCode::Tab | KeyCode::Down, _) => *focus = step(*focus, true),
                    (KeyCode::BackTab | KeyCode::Up, _) => *focus = step(*focus, false),
                    (KeyCode::Char(' '), Field::Check { on, .. }) => *on = !*on,
                    (KeyCode::Char('u'), Field::Text { value, .. }) if ctrl => value.clear(),
                    (KeyCode::Char('u'), Field::Secret { value, .. }) if ctrl => value.clear(),
                    (KeyCode::Backspace, Field::Text { value, .. }) => {
                        value.pop();
                    }
                    (KeyCode::Backspace, Field::Secret { value, .. }) => {
                        value.pop();
                    }
                    (KeyCode::Char(c), Field::Text { value, .. }) if !ctrl && value.len() < 512 => value.push(c),
                    (KeyCode::Char(c), Field::Secret { value, .. }) if !ctrl && value.chars().count() < 128 => value.push(c),
                    (KeyCode::Enter, _) if settling => {}
                    (KeyCode::Enter, _) => return self.submit_form(),
                    _ => {}
                }
                None
            }
        }
    }

    fn submit_form(&mut self) -> Option<Action> {
        let Some(Modal::Form { kind, title, fields, focus, .. }) = self.modal.take() else {
            return None;
        };
        match self.submit(&kind, &fields) {
            Ok(a) => {
                if let Some(Action::Job(_)) = a {
                    let fields = fields
                        .into_iter()
                        .map(|f| match f {
                            Field::Secret { label, .. } => secret(&label),
                            f => f,
                        })
                        .collect();
                    self.back = Some(Modal::Form { kind, title, fields, focus, error: None });
                }
                a
            }
            Err(e) => {
                let focus = self.bad_field.unwrap_or(focus);
                self.modal = Some(Modal::Form { kind, title, fields, focus, error: Some(e) });
                None
            }
        }
    }

    fn keep_key(&mut self, k: KeyEvent) -> Option<Action> {
        let Some(Modal::Keep { what, ask, note }) = &mut self.modal else { return None };
        if let Some((kind, buf)) = ask {
            match k.code {
                KeyCode::Esc => *ask = None,
                KeyCode::Backspace => {
                    buf.pop();
                }
                KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => buf.push(c),
                KeyCode::Enter => match (*kind, &*what) {
                    (Ask::Path, w) => {
                        let body = match w {
                            Keep::Ticket { ticket, .. } => format!("{ticket}\n"),
                            Keep::Recovery(m) => m.recovery.private.to_string(),
                        };
                        *note = match save_new(buf.trim(), &body) {
                            Ok(p) => format!("Saved to {} (only you can read it). Move it off this machine.", p.display()),
                            Err(e) => format!("{e}"),
                        };
                        *ask = None;
                    }
                    (Ask::Word, Keep::Recovery(m)) => {
                        let want = m.recovery_pass.split('-').nth(2).unwrap_or_default();
                        if buf.trim() != want {
                            *note = "That isn't word 3 of the passphrase. Check what you saved.".into();
                            // The key and passphrase are drawn again, so the person can look.
                            *ask = None;
                            return None;
                        }
                        let m = m.clone();
                        self.modal = Some(Modal::Confirm {
                            text: format!(
                                "Create mesh {} now?\n  machine     {} (the owner node)\n  boundaries  {}\n  owner key   {}\n  recovery    the copy you saved (not kept here)",
                                m.name,
                                m.machine,
                                m.boundaries.join(", "),
                                crate::setup::owner_key_path(&m.name).display()
                            ),
                            action: Action::Job(Task::Create(m)),
                        });
                    }
                    _ => *ask = None,
                },
                _ => {}
            }
            return None;
        }
        let recovery = matches!(what, Keep::Recovery(_));
        let sent = "Sent to the clipboard. If nothing arrived (tmux needs `set -g set-clipboard on`), press W to save it to a file, or select it with the mouse.";
        match (k.code, &*what) {
            (KeyCode::Char('c' | 'C'), Keep::Recovery(m)) => {
                *note = sent.into();
                return Some(Action::Copy(Zeroizing::new(m.recovery.private.to_string())));
            }
            (KeyCode::Char('p' | 'P'), Keep::Recovery(m)) => {
                *note = "Passphrase sent to the clipboard.".into();
                return Some(Action::Copy(m.recovery_pass.clone()));
            }
            (KeyCode::Char(c @ ('c' | 'C' | 'p' | 'P' | 't' | 'T')), Keep::Ticket { ticket, .. }) => {
                let [sh, ps] = crate::install::one_liners(ticket, None);
                let (what, line) = match c.to_ascii_lowercase() {
                    'c' => ("The Linux line", sh),
                    'p' => ("The PowerShell line", ps),
                    _ => ("The ticket", ticket.clone()),
                };
                *note = format!("{what}: {sent}");
                return Some(Action::Copy(Zeroizing::new(line)));
            }
            (KeyCode::Char('w' | 'W'), _) => {
                let name = match what {
                    Keep::Ticket { .. } => "~/tearmesh-ticket.txt".to_string(),
                    Keep::Recovery(m) => format!("~/tearmesh-recovery-{}.key", m.name),
                };
                *ask = Some((Ask::Path, name));
            }
            (KeyCode::Char('y' | 'Y'), _) if recovery => {
                *ask = Some((Ask::Word, String::new()));
                *note = String::new();
            }
            (KeyCode::Enter | KeyCode::Esc, _) if !recovery => {
                self.modal = None;
                self.note = "The ticket still works for its hour; the join request opens here when the machine asks.".into();
            }
            (KeyCode::Esc, _) => {
                self.modal = None;
                self.note = "Cancelled. Nothing was changed.".into();
            }
            _ => {}
        }
        None
    }

    /// Takes what a background job reports.
    pub fn on_msg(&mut self, m: Msg) {
        match m {
            Msg::Code(c) => {
                if let Some(Modal::Busy { text, .. }) = &mut self.modal {
                    *text = format!(
                        "Code  {}\n\nCheck that the owner node shows the same code, then approve it there.\nWaiting for approval (up to an hour)…",
                        spaced(&c)
                    );
                }
            }
            Msg::Ticket(ticket) => {
                self.back = None;
                let invite = crate::join::Ticket::decode(&ticket).map(|t| crate::join::invite_id(&t.secret)).unwrap_or_default();
                self.modal = Some(Modal::Keep { what: Keep::Ticket { ticket, invite }, ask: None, note: String::new() });
            }
            Msg::Keys(m) => {
                self.back = None;
                self.modal = Some(Modal::Keep { what: Keep::Recovery(m), ask: None, note: String::new() });
            }
            Msg::Done(text) => {
                self.back = None;
                self.say(text.lines().next().unwrap_or_default().to_string());
                self.modal = Some(info("Done", text));
            }
            Msg::Failed(e) => {
                self.say(format!("failed: {e}"));
                self.modal = match self.back.take() {
                    Some(Modal::Form { kind, title, fields, focus, .. }) => {
                        Some(Modal::Form { kind, title, fields, focus, error: Some(e) })
                    }
                    _ => Some(info("That didn't work", e)),
                };
            }
        }
    }

    /// Checks a form and turns it into what to do next (a job, or another screen it opens).
    /// Errors keep the form open; `bad_field` then says which field to put the cursor on.
    pub fn submit(&mut self, kind: &FormKind, f: &[Field]) -> Result<Option<Action>, String> {
        let bad = std::cell::Cell::new(None);
        let r = self.check_form(kind, f, &bad);
        self.bad_field = bad.get();
        r
    }

    /// `bad` is set to the position of the field a failed check is about.
    fn check_form(&mut self, kind: &FormKind, f: &[Field], bad: &std::cell::Cell<Option<usize>>) -> Result<Option<Action>, String> {
        // The n-th field that takes input (notes are skipped, as focus skips them).
        let slots: Vec<usize> = f.iter().enumerate().filter(|(_, x)| !matches!(x, Field::Note(_))).map(|(i, _)| i).collect();
        let at = |n: usize| bad.set(slots.get(n).copied());
        let v: Vec<String> = f
            .iter()
            .filter_map(|x| match x {
                Field::Text { value, .. } => Some(value.trim().to_string()),
                _ => None,
            })
            .collect();
        let pass: Vec<&Zeroizing<String>> = f
            .iter()
            .filter_map(|x| match x {
                Field::Secret { value, .. } => Some(value),
                _ => None,
            })
            .collect();
        let ticks: Vec<bool> = f
            .iter()
            .filter_map(|x| match x {
                Field::Check { on, .. } => Some(*on),
                _ => None,
            })
            .collect();
        let name = |s: &str, what: &str, n: usize| {
            if crate::valid_name(s) {
                Ok(s.to_string())
            } else {
                at(n);
                Err(format!("{what}: use a-z, 0-9 and -, 1–32 characters"))
            }
        };
        let list = |s: &str| -> Vec<String> {
            s.split([',', ' '])
                .filter(|x| !x.is_empty())
                .map(String::from)
                .collect()
        };
        let cats = |s: &str| -> Result<Vec<Category>, String> {
            let c: Result<Vec<Category>, _> = list(s).iter().map(|x| x.parse()).collect();
            match c {
                Ok(c) if !c.is_empty() => Ok(c),
                _ => {
                    at(2);
                    Err("categories: converse, tools and/or shell".into())
                }
            }
        };
        match kind {
            FormKind::Grant | FormKind::Revoke => {
                let from = if v[0] == "*" { "*".into() } else { name(&v[0], "from", 0)? };
                let to = if v[1] == "*" { "*".into() } else { name(&v[1], "to", 1)? };
                let c = cats(&v[2])?;
                if *kind == FormKind::Grant && c.contains(&Category::Shell) && (from == "*" || to == "*") {
                    at(if from == "*" { 0 } else { 1 });
                    return Err("shell grants name both machines (no *)".into());
                }
                let shown: Vec<&str> = c.iter().map(|x| cat(*x)).collect();
                let g = Grant { from: from.clone(), to: to.clone(), allow: c.clone() };
                let (verb, change) = if *kind == FormKind::Grant {
                    ("Grant", Change::Grant(g))
                } else {
                    ("Revoke", Change::Revoke(g))
                };
                Ok(self.sign(verb, format!("{verb} {from} → {to}: {}.", shown.join(", ")), vec![change]))
            }
            FormKind::Offers(offers) => {
                let picked: Vec<&Approval> = offers.iter().zip(&ticks).filter(|(_, on)| **on).map(|(a, _)| a).collect();
                if picked.is_empty() {
                    at(0);
                    return Err("nothing ticked: Space ticks an offer".into());
                }
                let text: Vec<String> = picked.iter().map(|a| format!("Approve {}/{} in {}.", a.machine, a.server, a.boundary)).collect();
                Ok(self.sign("Approve offers", text.join("\n"), picked.into_iter().cloned().map(Change::Approve).collect()))
            }
            FormKind::Permissions(switches) => {
                let me = self.this_machine();
                let (mut text, mut changes) = (String::new(), vec![]);
                for ((g, was), on) in switches.iter().zip(&ticks) {
                    if on == was {
                        continue;
                    }
                    text += &format!("{} {} → {}: {}\n", if *on { "Allow" } else { "Stop" }, g.from, g.to, cat(g.allow[0]));
                    if *on && g.allow[0] == Category::Shell && g.to == me {
                        text += &format!("  Careful: {} will be able to drive this machine, which holds an owner key.\n", g.from);
                    }
                    changes.push(if *on { Change::Grant(g.clone()) } else { Change::Revoke(g.clone()) });
                }
                if changes.is_empty() {
                    at(0);
                    return Err("nothing changed: Space ticks a switch".into());
                }
                Ok(self.sign("Permissions", text.trim_end().into(), changes))
            }
            FormKind::Relays => {
                let r = v[0].clone();
                if r != "n0" && r != "none" && !list(&r).iter().all(|u| u.starts_with("https://") || u.starts_with("http://")) {
                    at(0);
                    return Err("n0, none, or relay URLs separated by commas".into());
                }
                Ok(self.sign("Relays", format!("Set relays to {r}."), vec![Change::Set { setting: "relays".into(), value: r }]))
            }
            FormKind::OwnerAdd => {
                let p = std::path::Path::new(&v[0]);
                at(0);
                let fp = crate::setup::fingerprint_of(p).ok_or("that isn't a readable OpenSSH public key (.pub) file")?;
                let k = std::fs::read_to_string(p).map_err(|e| e.to_string())?;
                Ok(self.sign("Add an owner key", format!("Add owner key {fp}."), vec![Change::OwnerAdd(k)]))
            }
            FormKind::Create => {
                at(0);
                crate::setup::check_mesh_name(&v[0]).map_err(|e| format!("mesh name: {e}"))?;
                bad.set(None);
                let cfg = self.cfg.as_ref().ok_or("can't read this machine's config (install tear-mesh first, or set TEARMESH_CONFIG)")?;
                crate::setup::boundaries(cfg).map_err(|_| "this machine hosts no boundaries yet, so the mesh would have nothing in it: U on Mesh adds one first")?;
                at(if pass[0].chars().count() < 8 { 1 } else { 2 });
                crate::setup::check_passphrase(pass[0], pass[1]).map_err(|e| e.to_string())?;
                Ok(Some(Action::Job(Task::NewMesh { name: v[0].clone(), pass: pass[0].clone() })))
            }
            FormKind::Join => {
                at(0);
                let t: String = v[0].chars().filter(|c| !c.is_whitespace()).collect();
                crate::setup::check_ticket(&t).map_err(|e| e.to_string())?;
                let ticket = crate::join::Ticket::decode(&t).map_err(|_| "that ticket is incomplete; paste the whole thing")?;
                if ticket.expires + 3600 <= crate::now_ms() / 1000 {
                    return Err("that ticket expired; ask the owner node for a new one".into());
                }
                Ok(Some(Action::Job(Task::Join { ticket: t })))
            }
            FormKind::Approve(p, hosts, grants) => {
                let mesh = self.data.mesh.as_ref().ok_or("no mesh")?;
                // Paired with the options as drawn: a refresh since may have changed the live list.
                let (host_ticks, grant_ticks) = ticks.split_at(hosts.len().min(ticks.len()));
                let hosts: Vec<String> = hosts.iter().zip(host_ticks).filter(|(_, on)| **on).map(|(h, _)| h.clone()).collect();
                // An empty list would mean "what it asked for"; here the person ticks.
                if hosts.is_empty() {
                    at(0);
                    return Err(format!("tick at least one boundary for {} to host", p.name));
                }
                let grants: Vec<Grant> = grants.iter().zip(grant_ticks).filter(|(_, on)| **on).map(|(g, _)| g.clone()).collect();
                let changes = p.changes(mesh, &hosts, &grants).map_err(|e| format!("{e:#}"))?;
                let key = self.data.owner_key.clone().ok_or("no owner key on this machine")?;
                let how = keys::signer(&key).map_err(|e| format!("can't sign with {}: {e:#}", key.display()))?;
                Ok(Some(match how {
                    Signer::Terminal => Action::SignOutside { key, changes },
                    Signer::Here { .. } | Signer::Device => Action::Job(Task::Sign {
                        key,
                        pass: pass.first().map(|p| (*p).clone()).unwrap_or_default(),
                        changes,
                    }),
                }))
            }
            FormKind::Install => {
                let m = name(&v[0], "machine name", 0)?;
                let mut args = vec!["install".to_string(), m];
                for b in list(&v[1]) {
                    args.push(name(&b, "boundary", 1)?);
                }
                Ok(Some(Action::Elevated(args)))
            }
            FormKind::AddBoundaries => {
                let b = list(&v[0]);
                if b.is_empty() {
                    at(0);
                    return Err("name at least one boundary".into());
                }
                let m = self.cfg.as_ref().map_or_else(|| self.this_machine(), |c| c.machine.clone());
                let mut args = vec!["install".to_string(), m];
                for b in b {
                    args.push(name(&b, "boundary", 0)?);
                }
                Ok(Some(Action::Elevated(args)))
            }
            FormKind::Dissolve => {
                let m = self.data.mesh.as_ref().ok_or("no mesh")?;
                if v[0] != m.name {
                    at(0);
                    return Err(format!("type the mesh name exactly ({}) to dissolve it", m.name));
                }
                let text = format!(
                    "Dissolve mesh {}? Every machine leaves it and none can rejoin. This can't be undone.",
                    m.name
                );
                Ok(self.sign("Dissolve the mesh", text, vec![Change::Dissolve]))
            }
            FormKind::Sign(changes) => {
                let key = self.data.owner_key.clone().ok_or("no owner key on this machine")?;
                Ok(Some(Action::Job(Task::Sign {
                    key,
                    pass: pass.first().map(|p| (*p).clone()).unwrap_or_default(),
                    changes: changes.clone(),
                })))
            }
        }
    }

    pub fn draw(&self, f: &mut Frame) {
        if let Some(Modal::Keep { what, ask, note }) = &self.modal {
            draw_keep(f, what, ask.as_ref(), note, &self.shortcuts());
            return;
        }
        let [head, body, note, bar] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
            Constraint::Length(bar_rows(f.area(), &self.shortcuts())),
        ])
        .areas(f.area());
        self.draw_head(f, head);
        match self.tab {
            Tab::Mesh if self.role() == Role::BoundaryUser => self.draw_boundary_user(f, body),
            Tab::Mesh if self.role() == Role::NotSetUp => self.draw_not_set_up(f, body),
            Tab::Mesh => self.draw_mesh(f, body),
            Tab::Mail => self.draw_mail(f, body),
            Tab::Settings => self.draw_settings(f, body),
        }
        f.render_widget(Paragraph::new(self.note.as_str()).fg(Color::Yellow), note);
        draw_bar(f, bar, &self.shortcuts());
        if let Some(m) = &self.modal {
            draw_modal(f, m, &self.tab_keys());
        }
    }

    fn draw_head(&self, f: &mut Frame, area: Rect) {
        let at = TABS.iter().position(|t| *t == self.tab).unwrap_or(0);
        let (role, color) = match self.role() {
            Role::Owner => ("OWNER NODE", TEAR),
            Role::Member => ("MEMBER", ACCENT),
            Role::NotSetUp => ("NOT SET UP", Color::Yellow),
            Role::BoundaryUser => ("BOUNDARY USER", ACCENT),
        };
        let title = Line::from(vec![
            Span::styled(" o─o ", Style::new().fg(ACCENT).bold()),
            Span::styled("tear", Style::new().fg(ACCENT).bold()),
            Span::styled("-", Style::new().fg(TEAR).bold()),
            Span::styled("mesh ", Style::new().fg(ACCENT).bold()),
            Span::styled(format!(" {} ", self.this_machine()), Style::new().bold()),
            Span::styled(format!(" {role} "), Style::new().fg(Color::Black).bg(color).bold()),
        ]);
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(DIM))
            .title(title);
        let t = Tabs::new(TABS.iter().map(|t| t.title()))
            .select(at)
            .highlight_style(Style::new().fg(Color::Black).bg(ACCENT).bold())
            .divider(Span::styled("│", Style::new().fg(DIM)))
            .block(block);
        f.render_widget(t, area);
    }

    fn panel(&self, title: &str) -> Block<'static> {
        Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(DIM))
            .title(Span::styled(format!(" {title} "), Style::new().fg(ACCENT).bold()))
    }

    fn online(&self) -> (usize, usize) {
        let n = self.machines().len().saturating_sub(1);
        let up = self.data.pings.iter().filter(|p| p.rtt_ms.is_some()).count();
        (up, n)
    }

    /// A summary and warnings, the map, then the join requests and machines.
    fn draw_mesh(&self, f: &mut Frame, area: Rect) {
        let mut lines: Vec<Line> = vec![];
        if let (Some(s), Some(m)) = (&self.data.status, &self.data.mesh) {
            let (up, n) = self.online();
            lines.push(Line::from(vec![
                Span::styled(format!(" {}", m.name), Style::new().fg(ACCENT).bold()),
                Span::raw(format!(
                    " (version {}) · {up} of {n} other machines answer · boundaries {}",
                    m.version,
                    s.mesh.as_ref().map(|i| i.hosts.join(", ")).unwrap_or_default()
                )),
            ]));
            let pend = self.pending().len();
            if pend > 0 {
                lines.push(Line::styled(
                    format!(" {pend} join request(s) waiting: select one, Enter approves, D refuses"),
                    Style::new().fg(Color::Yellow).bold(),
                ));
            }
            if !self.data.offers.is_empty() {
                lines.push(Line::styled(
                    format!(" {} offered MCP server(s) waiting for your approval: O reviews them", self.data.offers.len()),
                    Style::new().fg(Color::Yellow).bold(),
                ));
            }
            for w in &s.warnings {
                lines.push(Line::styled(format!(" ! {w}"), Style::new().fg(Color::Yellow)));
            }
            if !s.unmapped.is_empty() {
                lines.push(Line::styled(
                    format!(" ! This machine hosts {} with no OS user here: U adds them", s.unmapped.join(", ")),
                    Style::new().fg(Color::Yellow),
                ));
            }
        }
        let top = (lines.len() as u16).clamp(1, (area.height / 4).max(1));
        let [sum, map, nodes] =
            Layout::vertical([Constraint::Length(top), Constraint::Percentage(45), Constraint::Min(4)]).areas(area);
        f.render_widget(Paragraph::new(lines), sum);
        self.draw_map(f, map);
        self.draw_nodes(f, nodes);
    }

    fn draw_boundary_user(&self, f: &mut Frame, area: Rect) {
        let (address, boundary) = self.data.who.clone().unwrap_or_default();
        let kv = |k: &str, v: String| Line::from(vec![Span::styled(format!("  {k:<14}"), Style::new().fg(DIM)), Span::raw(v)]);
        let lines = vec![
            Line::raw(""),
            kv("you are", address),
            kv("boundary", boundary),
            kv("machine", self.this_machine()),
            Line::raw(""),
            Line::raw("  Your mail is on the Mail tab."),
            Line::raw("  The mesh is managed by an admin of this machine: run `tearmesh menu` as that user."),
        ];
        f.render_widget(Paragraph::new(lines).block(self.panel("Mesh")).wrap(Wrap { trim: false }), area);
    }

    fn draw_not_set_up(&self, f: &mut Frame, area: Rect) {
        let [logo, rest] =
            Layout::vertical([Constraint::Length(LOGO.len() as u16 + 1), Constraint::Min(3)]).areas(area);
        f.render_widget(Paragraph::new(logo_text(LOGO[0].chars().count())).alignment(Alignment::Center), logo);
        let mut lines: Vec<Line> = vec![];
        if self.not_installed() {
            lines.push(Line::styled("  tear-mesh isn't installed on this machine.", Style::new().fg(Color::Yellow).bold()));
            lines.push(Line::raw("    I  Install it: a machine name and its boundaries (asks for admin rights)."));
        } else if let Some(e) = &self.data.error {
            lines.push(Line::styled(format!("  The daemon isn't answering: {e}"), Style::new().fg(BAD)));
            lines.push(Line::raw("  Install tear-mesh first (sudo tearmesh install <machine> <boundary>...), or start it"));
            lines.push(Line::raw("  (sudo systemctl start tearmesh, or Start-Service tearmesh)."));
        } else if let Some(s) = &self.data.status {
            lines.push(Line::from(vec![
                Span::styled(format!("  {:<14}", "machine"), Style::new().fg(DIM)),
                Span::raw(format!("{}  {}", s.machine, short(&s.node_id.to_string()))),
            ]));
            if let Some(name) = &s.dissolved {
                lines.push(Line::styled(
                    format!("  Mesh {name} was dissolved by its owner. Create a new one or join another."),
                    Style::new().fg(Color::Yellow),
                ));
            }
            match &s.joining {
                Some(JoinProgress::Dialing) => lines.push(Line::styled(
                    "  Joining: reaching the owner node…  (X cancels)",
                    Style::new().fg(Color::Yellow).bold(),
                )),
                Some(JoinProgress::Waiting { code }) => lines.push(Line::styled(
                    format!("  Waiting for approval: code {}  (X cancels)", spaced(code)),
                    Style::new().fg(Color::Yellow).bold(),
                )),
                j => {
                    if let Some(JoinProgress::Failed { reason }) = j {
                        lines.push(Line::styled(format!("  The last join didn't go through: {reason}"), Style::new().fg(BAD)));
                    }
                    lines.push(Line::styled(
                        format!("  This machine ({}) isn't in a mesh yet.", s.machine),
                        Style::new().fg(Color::Yellow).bold(),
                    ));
                    lines.push(Line::raw("    C  Create a mesh. This machine becomes its owner node: it approves new machines."));
                    lines.push(Line::raw("    J  Join a mesh. You need a ticket from its owner node."));
                    if self.boundaries_to_add().is_some() {
                        lines.push(Line::styled(
                            "    U  Add boundaries. This machine hosts none yet; creating a mesh needs one.",
                            Style::new().fg(Color::Yellow),
                        ));
                    }
                }
            }
            for w in &s.warnings {
                lines.push(Line::styled(format!("  ! {w}"), Style::new().fg(Color::Yellow)));
            }
        } else {
            lines.push(Line::raw("  Loading…"));
        }
        f.render_widget(Paragraph::new(lines).block(self.panel("Status")).wrap(Wrap { trim: false }), rest);
    }

    fn draw_map(&self, f: &mut Frame, area: Rect) {
        let me = self.this_machine();
        let peers: Vec<String> = self.machines().iter().map(|m| m.name.clone()).filter(|n| *n != me).collect();
        let pings = self.data.pings.clone();
        let st = move |n: &str| pings.iter().find(|p| p.name == n).map(|p| p.rtt_ms);
        let age = self
            .data
            .pinged_at
            .map(|t| format!("pinged {}s ago", t.elapsed().as_secs()))
            .unwrap_or_else(|| "pinging…".into());
        let canvas = Canvas::default()
            .block(self.panel(&format!("Map · {age}")))
            .marker(Marker::Braille)
            .x_bounds([-100.0, 100.0])
            .y_bounds([-60.0, 60.0])
            .paint(move |ctx| {
                let n = peers.len().max(1) as f64;
                let pos = |i: usize| {
                    let a = std::f64::consts::TAU * i as f64 / n + std::f64::consts::FRAC_PI_2;
                    (a.cos() * 70.0, a.sin() * 42.0)
                };
                for (i, p) in peers.iter().enumerate() {
                    let (x, y) = pos(i);
                    let c = match st(p) {
                        Some(Some(_)) => OK,
                        Some(None) => BAD,
                        None => DIM,
                    };
                    ctx.draw(&CLine { x1: 0.0, y1: 0.0, x2: x, y2: y, color: c });
                }
                ctx.layer();
                ctx.print(-(me.len() as f64) * 1.5, 0.0, Span::styled(format!("◉ {me}"), Style::new().fg(TEAR).bold()));
                for (i, p) in peers.iter().enumerate() {
                    let (x, y) = pos(i);
                    let (dot, c, info) = match st(p) {
                        Some(Some(ms)) => ("●", OK, format!(" {ms}ms")),
                        Some(None) => ("○", BAD, " down".into()),
                        None => ("◌", DIM, String::new()),
                    };
                    ctx.print(x - (p.len() as f64) * 1.5, y, Span::styled(format!("{dot} {p}{info}"), Style::new().fg(c).bold()));
                }
            });
        f.render_widget(canvas, area);
    }

    fn draw_nodes(&self, f: &mut Frame, area: Rect) {
        let me = self.this_machine();
        let seen = |n: &str| {
            self.data
                .status
                .as_ref()
                .and_then(|s| s.peers.iter().find(|p| p.name == n))
                .and_then(|p| p.last_sync_ms)
        };
        // What this machine may do to `n` (speaks), and what it accepts from `n` (listens).
        let grants = |n: &str, speak: bool| -> String {
            let Some(m) = &self.data.mesh else { return String::new() };
            if speak { allowed(m, &me, n) } else { allowed(m, n, &me) }
        };
        let mut rows: Vec<Row> = self
            .pending()
            .iter()
            .map(|p| {
                Row::new(vec![
                    Cell::from(p.name.clone()),
                    Cell::from(format!("join · {}", spaced(&p.code))).fg(Color::Yellow).bold(),
                    Cell::from(p.boundaries.join(",")),
                    Cell::from(short(&p.node_id.to_string())),
                    Cell::from(""),
                    Cell::from(""),
                ])
            })
            .collect();
        rows.extend(self.machines().iter().map(|m| {
            let (ping, c) = if m.name == me {
                ("this machine".to_string(), TEAR)
            } else {
                match self.data.pings.iter().find(|p| p.name == m.name) {
                    Some(Ping { rtt_ms: Some(ms), .. }) => (format!("● {ms} ms"), OK),
                    Some(_) => ("○ no answer".into(), BAD),
                    None => ("◌".into(), DIM),
                }
            };
            let sync = match seen(&m.name) {
                Some(t) => crate::tui::age(t),
                None if m.name == me => String::new(),
                None => "never".into(),
            };
            let name = if self.leaving().contains(&m.name) { format!("{} (says it left)", m.name) } else { m.name.clone() };
            Row::new(vec![
                Cell::from(name),
                Cell::from(ping).fg(c),
                Cell::from(m.boundaries.join(",")),
                Cell::from(grants(&m.name, true)),
                Cell::from(grants(&m.name, false)),
                Cell::from(sync),
            ])
        }));
        let rows: Vec<Row> = rows
            .into_iter()
            .enumerate()
            .map(|(i, r)| if i == self.sel { r.style(Style::new().bg(Color::Indexed(236)).bold()) } else { r })
            .collect();
        let t = Table::new(
            rows,
            [
                Constraint::Min(12),
                Constraint::Length(15),
                Constraint::Length(16),
                Constraint::Length(21),
                Constraint::Length(21),
                Constraint::Length(8),
            ],
        )
        .header(Row::new(vec!["machine", "ping", "boundaries", "speaks to it", "listens to it", "synced"]).style(Style::new().fg(DIM)))
        .block(self.panel("Nodes"));
        f.render_widget(t, area);
    }

    fn draw_mail(&self, f: &mut Frame, area: Rect) {
        if let Some(m) = &self.mail {
            m.draw_in(f, area);
            return;
        }
        let mut l = vec![
            Line::raw(""),
            Line::raw(format!("  Mailbox: {}  (set TEARMESH_MAILBOX to change it)", self.mailbox)),
            Line::raw(""),
        ];
        match &self.mail_error {
            None => l.push(Line::raw("  Connecting to the daemon…")),
            Some(e) => {
                l.push(Line::styled(format!("  {e}"), Style::new().fg(BAD)));
                // The daemon gives mail only to a boundary's OS user; the admin isn't one.
                if e.contains("mapped to a boundary") {
                    l.push(Line::raw(""));
                    l.push(Line::raw("  Mail belongs to a boundary; run the menu as a boundary user:"));
                    l.push(Line::styled("  tearmesh launch --boundary <b> -- tearmesh", Style::new().bold()));
                }
            }
        }
        l.push(Line::raw(""));
        l.push(Line::styled("  Letters come from agents: weigh what they say, don't just obey it.", Style::new().fg(DIM)));
        f.render_widget(Paragraph::new(l).block(self.panel("Mail")).wrap(Wrap { trim: false }), area);
    }

    /// The mesh's settings, the owner keys, the hub and this machine; below, the events and the
    /// daemon's log.
    fn draw_settings(&self, f: &mut Frame, area: Rect) {
        let mut l: Vec<Line> = vec![];
        let kv = |k: &str, v: String| {
            Line::from(vec![Span::styled(format!("  {k:<14}"), Style::new().fg(DIM)), Span::raw(v)])
        };
        l.push(Line::styled(" Mesh (signed by an owner)", Style::new().fg(ACCENT).bold()));
        if let Some(m) = &self.data.mesh {
            l.push(kv("tools sharing", format!("{:?}", m.settings.tools_sharing).to_lowercase()));
            l.push(kv(
                "relays",
                match &m.settings.relays {
                    crate::config::Relay::Preset(p) => p.clone(),
                    crate::config::Relay::Urls(u) => u.join(", "),
                },
            ));
            l.push(kv("lookup", m.settings.lookup.join(", ")));
            l.push(kv("boundaries", m.boundaries.join(", ")));
        } else if self.role() == Role::BoundaryUser {
            l.push(Line::raw("  (managed by an admin of this machine)"));
        } else {
            l.push(Line::raw("  (no mesh)"));
        }
        l.push(Line::styled(" MCP hub (for agent harnesses)", Style::new().fg(ACCENT).bold()));
        l.push(kv(
            "state",
            if self.data.hub_running { "running".into() } else { "not running (H starts it)".into() },
        ));
        l.push(kv("URL", self.data.hub_url.clone()));
        l.push(kv("stdio command", "tearmesh mcp connect".into()));
        l.push(Line::styled(" This machine", Style::new().fg(ACCENT).bold()));
        l.push(kv(
            "owner key",
            self.data.owner_key.as_ref().map_or("none here".into(), |k| k.display().to_string()),
        ));
        l.push(kv("config", crate::config::DEFAULT_CONFIG.into()));
        l.push(kv("socket", socket_path().display().to_string()));
        let high = (l.len() as u16 + 2).min(area.height.saturating_sub(6));
        let [top, logs] = Layout::vertical([Constraint::Length(high), Constraint::Min(3)]).areas(area);
        let [left, keys] = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(top);
        f.render_widget(Paragraph::new(l).block(self.panel("Settings")), left);

        let local = self.data.owner_key.as_ref().and_then(|k| crate::setup::fingerprint_of(&crate::setup::pub_path(k)));
        let rows: Vec<Row> = self
            .owners()
            .into_iter()
            .enumerate()
            .map(|(i, fp)| {
                let here = local.as_deref() == Some(fp.as_str());
                let r = Row::new(vec![
                    Cell::from(fp),
                    Cell::from(if here { "here" } else { "elsewhere" }).fg(if here { TEAR } else { DIM }),
                ]);
                if i == self.sel && self.role() == Role::Owner { r.style(Style::new().bg(Color::Indexed(236)).bold()) } else { r }
            })
            .collect();
        let title = if self.role() == Role::Owner {
            "Owner keys · N adds, Z removes the selected one (a leaked key: add a new one, then remove it)"
        } else {
            "Owner keys"
        };
        f.render_widget(Table::new(rows, [Constraint::Min(20), Constraint::Length(9)]).block(self.panel(title)), keys);

        let [mine, journal] = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(logs);
        let lines: Vec<Line> = if self.log.is_empty() {
            vec![Line::styled("  Nothing yet. Machines going up or down, joins and new versions show here.", Style::new().fg(DIM))]
        } else {
            self.log.iter().map(|s| Line::raw(format!(" {s}"))).collect()
        };
        f.render_widget(Paragraph::new(lines).block(self.panel("Mesh events (live) · E clears")).wrap(Wrap { trim: false }), mine);
        let j: Vec<Line> = self.data.journal.iter().rev().map(|s| Line::raw(s.clone())).collect();
        f.render_widget(
            Paragraph::new(if j.is_empty() { vec![Line::styled("  (the daemon's log isn't readable here)", Style::new().fg(DIM))] } else { j })
                .block(self.panel("Daemon log"))
                .wrap(Wrap { trim: false }),
            journal,
        );
    }
}

impl Default for App {
    fn default() -> Self {
        App::new()
    }
}

/// The categories `from` may use on `to`, e.g. "converse tools".
fn allowed(mesh: &Mesh, from: &str, to: &str) -> String {
    let c = [Category::Converse, Category::Tools, Category::Shell];
    c.into_iter().filter(|c| from != to && mesh.allows(from, to, *c)).map(cat).collect::<Vec<_>>().join(" ")
}

/// One switch, in the direction's word and in plain words, so "shell listen" can't read as harmless.
fn switch_label(c: Category, speak: bool, me: &str, o: &str) -> String {
    let what = match (c, speak) {
        (Category::Converse, true) => format!("{me} posts notes to {o}"),
        (Category::Converse, false) => format!("{me} accepts notes from {o}"),
        (Category::Tools, true) => format!("{me} calls the tools {o} offers"),
        (Category::Tools, false) => format!("{me} accepts tool calls from {o}"),
        (Category::Shell, true) => format!("{me} can drive {o}"),
        (Category::Shell, false) => format!("{me} can be driven by {o}"),
    };
    format!("{:<8} {:<6} {what}", cat(c), if speak { "speak" } else { "listen" })
}

fn cat(c: Category) -> &'static str {
    match c {
        Category::Converse => "converse",
        Category::Tools => "tools",
        Category::Shell => "shell",
    }
}

fn short(id: &str) -> String {
    id.chars().take(10).collect::<String>() + "…"
}

fn clock() -> String {
    let s = crate::now_ms() / 1000;
    format!("{:02}:{:02}:{:02}", (s / 3600) % 24, (s / 60) % 60, s % 60)
}

/// The logo, colored: the mesh in cyan, the lettering bright, the tear line in magenta.
pub fn logo_text(width: usize) -> Text<'static> {
    logo_frame(width, usize::MAX)
}

/// The logo with only the first `reveal` columns of the tear line drawn (for the splash).
fn logo_frame(_width: usize, reveal: usize) -> Text<'static> {
    let last = LOGO.len() - 1;
    let lines = LOGO
        .iter()
        .enumerate()
        .map(|(i, l)| {
            if i == last {
                let shown: String = l.chars().take(reveal).collect();
                let pad = " ".repeat(l.chars().count().saturating_sub(shown.chars().count()));
                return Line::from(vec![Span::styled(shown, Style::new().fg(TEAR).bold()), Span::raw(pad)]);
            }
            let (mesh, word): (String, String) = (l.chars().take(20).collect(), l.chars().skip(20).collect());
            Line::from(vec![
                Span::styled(mesh, Style::new().fg(ACCENT)),
                Span::styled(word, if i == 5 { Style::new().fg(DIM).italic() } else { Style::new().fg(Color::White).bold() }),
            ])
        })
        .collect::<Vec<_>>();
    Text::from(lines)
}

/// The Help screen: moving around, the words, what to do about a leak, and this screen's keys.
fn draw_help(f: &mut Frame, keys: &[(&str, &str)]) {
    let h = |k: &str, v: &str| Line::from(vec![Span::styled(format!("  {k:<14}"), Style::new().fg(ACCENT).bold()), Span::raw(v.to_string())]);
    let here: Vec<String> = keys.iter().map(|(k, l)| format!("{k} {l}")).collect();
    // This screen's keys come first, so a short terminal still shows them.
    let lines = vec![
        Line::styled(" Keys on this screen", Style::new().bold()),
        Line::raw(format!("  {}", here.join(" · "))),
        Line::raw(""),
        Line::styled(" Moving around", Style::new().bold()),
        h("← →  4 6", "switch screens: Mesh, Mail, Settings (also Tab, h, l)"),
        h("↑ ↓  8 2", "move the selection (also j, k)"),
        h("Enter / Esc", "pick or open / back (closes a dialog, or returns to Mesh)"),
        h("H  K  L", "need Shift: h and l switch screens, k moves up"),
        Line::raw(""),
        Line::styled(" Words", Style::new().bold()),
        h("mesh", "your machines, in a membership file the owner signs"),
        h("owner node", "holds an owner key: it invites, approves and revokes"),
        h("boundary", "an OS user per boundary; data never leaves its boundary"),
        h("speak / listen", "what a machine may do to another / what it accepts from it"),
        h("converse", "speak: post notes to it · listen: accept its notes"),
        h("tools", "speak: call the MCP servers it offers · listen: accept its calls"),
        h("shell", "speak: drive it through its sshd · listen: be driven by it"),
        h("MCP hub", "one MCP service per user for any agent harness"),
        Line::raw(""),
        Line::styled(" If a key leaks", Style::new().bold()),
        Line::raw("  A machine's: on the owner node, Mesh → select it → D; re-invite it."),
        Line::raw("  An owner key: Settings → N adds a new one, then Z removes the leaked one."),
        Line::raw(""),
        Line::styled(" On an owner node", Style::new().bold()),
        Line::raw("  Mesh → A shows a one-line install for a new machine; its join request opens by itself."),
        Line::raw("  Mesh → G on a machine's row: what it and this machine may do to each other."),
        Line::raw("  Mesh → O: MCP servers other machines offer, waiting for your approval."),
        Line::raw("  A machine that left (or was uninstalled) asks to be removed. Settings → Shift-K dissolves the mesh."),
    ];
    let a = centered(f.area(), 96, lines.len() as u16 + 4);
    f.render_widget(Clear, a);
    f.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().border_type(BorderType::Double).border_style(Style::new().fg(TEAR)).title(" Help "))
            .wrap(Wrap { trim: false }),
        a,
    );
}

/// nano-style: each binding is a highlighted key and a label, in columns over two rows.
/// Rows for the key bar: two, or three when two would cut a label and the screen can spare one.
fn bar_rows(screen: Rect, keys: &[(&str, &str)]) -> u16 {
    let col = screen.width as usize / keys.len().div_ceil(2).max(1);
    // A key takes its column (see key_width), then a space before and after its label.
    let kw = key_width(keys);
    let fits = keys.iter().all(|(_, l)| l.chars().count() + kw + 2 <= col);
    if fits || screen.height < 28 { 2 } else { 3 }
}

/// The key column: 5, or the widest key (`Shift-L`) when that is wider.
fn key_width(keys: &[(&str, &str)]) -> usize {
    keys.iter().map(|(k, _)| k.chars().count()).max().unwrap_or(0).max(5)
}

fn draw_bar(f: &mut Frame, area: Rect, keys: &[(&str, &str)]) {
    let n = area.height.max(1) as usize;
    let per_row = keys.len().div_ceil(n).max(1);
    let col = (area.width as usize / per_row).max(8);
    let kw = key_width(keys);
    let mut rows = vec![vec![]; n];
    for (i, (k, label)) in keys.iter().enumerate() {
        let row = &mut rows[i / per_row];
        let key = format!("{k:^kw$}");
        let rest = col.saturating_sub(key.chars().count() + 1);
        let label: String = format!(" {label}").chars().take(rest).collect();
        row.push(Span::styled(key, Style::new().fg(Color::Black).bg(ACCENT).bold()));
        row.push(Span::raw(format!("{label:<rest$} ")));
    }
    let lines: Vec<Line> = rows.into_iter().map(Line::from).collect();
    f.render_widget(Paragraph::new(lines), area);
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect::new(area.x + (area.width - w) / 2, area.y + (area.height - h) / 2, w, h)
}

fn draw_modal(f: &mut Frame, m: &Modal, keys: &[(&str, &str)]) {
    let block = |t: &str| {
        Block::bordered()
            .border_type(BorderType::Double)
            .border_style(Style::new().fg(TEAR))
            .title(Span::styled(format!(" {t} "), Style::new().bold()))
    };
    match m {
        Modal::Info { title, text, scroll, .. } => {
            let a = centered(f.area(), 90, text.lines().count() as u16 + 4);
            f.render_widget(Clear, a);
            f.render_widget(Paragraph::new(text.as_str()).block(block(title)).wrap(Wrap { trim: false }).scroll((*scroll, 0)), a);
        }
        Modal::Help => draw_help(f, keys),
        Modal::Busy { title, text, .. } => {
            let a = centered(f.area(), 76, text.lines().count() as u16 + 4);
            f.render_widget(Clear, a);
            f.render_widget(Paragraph::new(text.as_str()).block(block(title)).wrap(Wrap { trim: false }), a);
        }
        Modal::Confirm { text, .. } => {
            // Long texts (the uninstall list) grow the box; a short terminal still clips it.
            let a = centered(f.area(), 76, (wrap(text, 74).len() as u16 + 4).max(14));
            f.render_widget(Clear, a);
            f.render_widget(
                Paragraph::new(format!("{text}\n\n  [Y] yes    [N] no")).block(block("Confirm")).wrap(Wrap { trim: false }),
                a,
            );
        }
        Modal::Form { title, fields, focus, error, .. } => {
            const W: u16 = 80;
            let inner = W as usize - 2;
            let mut lines = vec![];
            for (i, field) in fields.iter().enumerate() {
                let on = i == *focus;
                let label = |l: &str| Line::styled(format!(" {l}"), Style::new().fg(if on { ACCENT } else { DIM }));
                let value = |v: String| {
                    // Long values show their end, where typing happens.
                    let room = inner.saturating_sub(5);
                    let n = v.chars().count();
                    let v = if n > room { format!("…{}", v.chars().skip(n - room + 1).collect::<String>()) } else { v };
                    Line::from(vec![
                        Span::raw(if on { " ▸ " } else { "   " }),
                        Span::styled(v, if on { Style::new().add_modifier(Modifier::UNDERLINED).bold() } else { Style::new() }),
                        Span::raw(if on { "▏" } else { "" }),
                    ])
                };
                match field {
                    Field::Note(t) => {
                        let style = if t.starts_with("WARNING") { Style::new().fg(BAD).bold() } else { Style::new() };
                        for l in wrap(t, inner - 1) {
                            lines.push(Line::styled(format!(" {l}"), style));
                        }
                    }
                    Field::Text { label: l, value: v } => {
                        lines.push(label(l));
                        lines.push(value(v.clone()));
                    }
                    Field::Secret { label: l, value: v } => {
                        lines.push(label(l));
                        lines.push(value("•".repeat(v.chars().count())));
                    }
                    Field::Check { label: l, on: c } => lines.push(Line::from(vec![
                        Span::raw(if on { " ▸ " } else { "   " }),
                        Span::styled(format!("[{}] {l}", if *c { "x" } else { " " }), if on { Style::new().fg(ACCENT).bold() } else { Style::new() }),
                    ])),
                }
            }
            if let Some(e) = error {
                for l in wrap(e, inner - 1) {
                    lines.push(Line::styled(format!(" {l}"), Style::new().fg(BAD).bold()));
                }
            }
            let a = centered(f.area(), W, lines.len() as u16 + 2);
            f.render_widget(Clear, a);
            f.render_widget(Paragraph::new(lines).block(block(title)), a);
        }
        Modal::Keep { .. } => {}
    }
}

/// Splits text into lines of at most `w` characters, at spaces where it can.
fn wrap(t: &str, w: usize) -> Vec<String> {
    let mut out = vec![];
    for para in t.lines() {
        let mut line = String::new();
        for word in para.split(' ') {
            if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > w {
                out.push(std::mem::take(&mut line));
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
        out.push(line);
    }
    out
}

/// The ticket or recovery key on a plain full screen: no borders inside the text, the key's
/// lines from column 0, so selecting it with the mouse copies it exactly.
fn draw_keep(f: &mut Frame, what: &Keep, ask: Option<&(Ask, String)>, note: &str, keys: &[(&str, &str)]) {
    let area = f.area();
    f.render_widget(Clear, area);
    let w = area.width.max(1) as usize;
    let mut lines: Vec<Line> = vec![];
    match what {
        Keep::Ticket { ticket, .. } => {
            let [sh, ps] = crate::install::one_liners(ticket, None);
            lines.push(Line::styled("Add a node: a ticket for a new machine", Style::new().fg(ACCENT).bold()));
            lines.push(Line::raw("Run one of these on the new machine: it installs tear-mesh and asks to join."));
            lines.push(Line::raw("The ticket admits one machine and works for an hour."));
            lines.push(Line::raw(""));
            // Each command starts at column 0 and wraps hard, so a mouse selection copies it whole.
            let mut long = |label: &str, t: &str| {
                lines.push(Line::styled(label.to_string(), Style::new().fg(DIM)));
                let chars: Vec<char> = t.chars().collect();
                for c in chars.chunks(w) {
                    lines.push(Line::raw(c.iter().collect::<String>()));
                }
                lines.push(Line::raw(""));
            };
            long("Linux (C copies it):", &sh);
            long("Windows, in PowerShell as Administrator (P copies it):", &ps);
            long("Already installed there? J in its menu, then paste the ticket (T copies it):", ticket);
            lines.push(Line::styled("Waiting for the new machine… its request opens here when it asks to join.", Style::new().fg(Color::Yellow).bold()));
        }
        Keep::Recovery(m) => {
            lines.push(Line::styled(format!("Recovery key for mesh {}", m.name), Style::new().fg(ACCENT).bold()));
            lines.push(Line::raw("Save the key and its passphrase somewhere off this machine: a password manager, or a"));
            lines.push(Line::raw("printout in a drawer. Keep the passphrase apart from the key file, or both in a password"));
            lines.push(Line::raw("manager. It's your way back in if this machine is lost or its key leaks. It isn't kept here."));
            if w < 70 {
                lines.push(Line::styled("Widen the window to select the whole key; C and W work at any size.", Style::new().fg(Color::Yellow)));
            }
            lines.push(Line::raw(""));
            // Hidden while the word is asked, so it comes from what was saved, not from the screen.
            if matches!(ask, Some((Ask::Word, _))) {
                lines.push(Line::styled("The key and passphrase are hidden. Esc brings them back.", Style::new().fg(DIM)));
            } else {
                for l in m.recovery.private.lines() {
                    lines.push(Line::raw(l.to_string()));
                }
                lines.push(Line::raw(""));
                lines.push(Line::from(vec![
                    Span::styled("Passphrase: ", Style::new().fg(DIM)),
                    Span::styled(m.recovery_pass.to_string(), Style::new().bold()),
                ]));
            }
        }
    }
    lines.push(Line::raw(""));
    match ask {
        Some((Ask::Path, b)) => lines.push(Line::raw(format!("Save to: {b}▏"))),
        Some((Ask::Word, b)) => lines.push(Line::raw(format!("To check you saved it, type word 3 of the passphrase: {b}▏"))),
        None => {}
    }
    if !note.is_empty() {
        lines.push(Line::styled(note.to_string(), Style::new().fg(Color::Yellow)));
    }
    let [body, bar] = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).areas(area);
    f.render_widget(Paragraph::new(lines), body);
    draw_bar(f, bar, keys);
}

/// Writes a new file only this user can read; never overwrites one.
fn save_new(path: &str, text: &str) -> std::io::Result<PathBuf> {
    let p = match path.strip_prefix("~/") {
        Some(rest) => crate::os::home_dir().join(rest),
        None => PathBuf::from(path),
    };
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(&p).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            std::io::Error::new(e.kind(), format!("{} exists; pick another name", p.display()))
        } else {
            std::io::Error::new(e.kind(), format!("{}: {e}", p.display()))
        }
    })?;
    std::io::Write::write_all(&mut f, text.as_bytes())?;
    Ok(std::path::absolute(&p).unwrap_or(p))
}

// ---- runtime ----

/// One row of the daemon's offers, if it waits for approval. The pin is worked out here, as
/// `mesh approve-offer` does, from the offer itself.
fn waiting(boundary: &str, o: &serde_json::Value) -> Option<Waiting> {
    let changed = o["state"] == "changed since approval";
    if !changed && o["state"] != "pending approval" {
        return None;
    }
    let full: crate::offer::Offer = serde_json::from_value(o["offer"].clone()).ok()?;
    let all = full.tool_names();
    // An approval limited to some tools stays limited to those: re-approving never widens it.
    let tools: Option<Vec<String>> = serde_json::from_value::<Option<Vec<String>>>(o["approved_tools"].clone())
        .ok()
        .flatten()
        .map(|t| t.into_iter().filter(|x| all.contains(x)).collect());
    // shortcut: when none of the allowed tools is still offered, the menu doesn't list it;
    // `mesh approve-offer --tools` decides anew. List it here if that turns out to be common.
    if tools.as_ref().is_some_and(|t| t.is_empty()) {
        return None;
    }
    Some(Waiting {
        approval: Approval {
            machine: o["machine"].as_str()?.into(),
            boundary: boundary.into(),
            server: full.server.clone(),
            pin: crate::offer::pin(full.instructions.as_deref(), &full.tools, tools.as_deref()),
            tools: tools.clone(),
        },
        tools: tools.unwrap_or(all),
        changed,
    })
}

async fn admin(req: Request) -> Result<serde_json::Value> {
    Client::connect(&socket_path()).await?.call(&req).await
}

async fn fetch(ping: bool) -> Data {
    let mut d = Data::default();
    let hub = crate::hub::load(&crate::hub::config_path()).unwrap_or_default();
    d.hub_url = crate::hub::url(&hub);
    d.hub_running = crate::os::connect_mine(&crate::hub::socket(&crate::hub::state_dir())).await.is_ok();
    d.journal = journal();
    let status = match Client::connect(&socket_path()).await {
        Ok(mut c) => c.call(&Request::Status).await,
        Err(e) => {
            d.no_daemon = true;
            Err(e)
        }
    };
    match status {
        Ok(v) => match serde_json::from_value::<Status>(v) {
            Ok(s) => d.status = Some(s),
            Err(e) => d.error = Some(format!("unexpected status: {e}")),
        },
        Err(e) => {
            let e = format!("{e:#}");
            // A boundary user is refused Status but has a session: not a daemon that is down.
            if e.contains("admin only")
                && let Ok(v) = admin(Request::Hello { mailbox: None, hold: false, trust: None }).await
            {
                let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
                d.who = Some((s("address"), s("boundary")));
            } else {
                d.error = Some(e);
            }
            return d;
        }
    }
    if d.status.as_ref().is_some_and(|s| s.mesh.is_some()) {
        if let Ok(v) = admin(Request::MeshCurrent).await {
            d.mesh = v["toml"].as_str().and_then(|t| Mesh::parse(t).ok());
        }
        let owners = d.status.as_ref().and_then(|s| s.mesh.as_ref()).map(|m| m.owners.clone()).unwrap_or_default();
        d.owner_key = crate::setup::find_owner_keys(&owners).into_iter().next();
        let hosts = d.status.as_ref().and_then(|s| s.mesh.as_ref()).map(|m| m.hosts.clone()).unwrap_or_default();
        for b in hosts.iter().filter(|_| d.owner_key.is_some()) {
            if let Ok(v) = admin(Request::Offers { boundary: Some(b.clone()) }).await {
                d.offers.extend(v.as_array().into_iter().flatten().filter_map(|o| waiting(b, o)));
            }
        }
        if ping && let Ok(v) = admin(Request::Ping).await {
            d.pings = serde_json::from_value(v).unwrap_or_default();
            d.pinged_at = Some(Instant::now());
        }
    }
    d
}

/// The last lines of the daemon's log, where this user may read it.
fn journal() -> Vec<String> {
    #[cfg(windows)]
    {
        let p = std::path::Path::new(r"C:\ProgramData\tearmesh\state\daemon.log");
        return std::fs::read_to_string(p)
            .map(|s| s.lines().rev().take(40).map(String::from).collect::<Vec<_>>().into_iter().rev().collect())
            .unwrap_or_default();
    }
    #[cfg(not(windows))]
    std::process::Command::new("journalctl")
        .args(["-u", "tearmesh", "-n", "40", "--no-pager", "-o", "short-iso", "-q"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().map(String::from).collect())
        .unwrap_or_default()
}

fn enter() -> ratatui::DefaultTerminal {
    let t = ratatui::init();
    // A legacy Windows console says Unsupported; pasting then arrives as key presses.
    let _ = ratatui::crossterm::execute!(std::io::stdout(), ratatui::crossterm::event::EnableBracketedPaste);
    t
}

fn leave() {
    let _ = ratatui::crossterm::execute!(std::io::stdout(), ratatui::crossterm::event::DisableBracketedPaste);
    ratatui::restore();
}

/// Ctrl-C in a program the menu runs (ssh, a "Press Enter" prompt) must stop that program, not
/// the menu. A handled signal goes back to its default in a child at exec, so the child still
/// gets Ctrl-C. While the menu is full-screen, Ctrl-C is a key and quits it.
fn survive_ctrl_c() -> Result<()> {
    #[cfg(unix)]
    let mut s = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    #[cfg(windows)]
    let mut s = tokio::signal::windows::ctrl_c()?;
    tokio::spawn(async move { while s.recv().await.is_some() {} });
    Ok(())
}

/// Leaves the full screen, runs `f` in the plain terminal, waits for Enter, comes back.
fn suspended(terminal: &mut ratatui::DefaultTerminal, f: impl FnOnce() -> Result<String>) -> Result<String> {
    leave();
    let r = f();
    match &r {
        Ok(s) if !s.is_empty() => eprintln!("\n{s}"),
        Err(e) => eprintln!("\nerror: {e:#}"),
        _ => {}
    }
    eprint!("\n[ Press Enter to return to the menu ]");
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    *terminal = enter();
    terminal.clear()?;
    r
}

/// The running background job: its messages, and its task to stop it.
struct Job {
    rx: tokio::sync::mpsc::UnboundedReceiver<Msg>,
    task: tokio::task::JoinHandle<()>,
}

/// Builds the next version from the daemon's current one, signs it here, applies it.
async fn sign_and_apply(key: PathBuf, pass: Zeroizing<String>, changes: Vec<Change>) -> Result<u64> {
    let cur = admin(Request::MeshCurrent).await?;
    let (_, toml, _) = crate::mesh::next_version(cur["toml"].as_str().unwrap_or_default(), &changes)?;
    let sig = match keys::signer(&key)? {
        Signer::Device => keys::sign_device(&key, &toml, &pass).await?,
        _ => {
            let t = toml.clone();
            tokio::task::spawn_blocking(move || keys::sign(&keys::open(&key, &pass)?, &t)).await??
        }
    };
    let v = admin(Request::ApplyMesh { toml, sig }).await?;
    Ok(v["version"].as_u64().unwrap_or_default())
}

/// After a Dissolve is applied: hands the closed version to the machines now, and says how many
/// it reached.
async fn dissolved(m: &Mesh) -> String {
    let me = admin(Request::Status).await.ok().and_then(|s| s["machine"].as_str().map(String::from)).unwrap_or_default();
    // Best effort: the rest fetch it on their next sync.
    let k = admin(Request::SyncNow).await.ok().and_then(|v| v["synced"].as_array().map(|a| a.len())).unwrap_or(0);
    let n = m.machines.iter().filter(|x| x.name != me).count();
    format!(
        "Dissolved mesh {}. It reached {k} of {n} machines; the rest get it on their next sync.\n\n\
         This machine is out of the mesh now: Settings → X uninstalls it, or Mesh → C creates a new mesh.",
        m.name
    )
}

async fn work(t: Task, config: PathBuf, tx: tokio::sync::mpsc::UnboundedSender<Msg>) {
    let tx2 = tx.clone();
    let r: Result<Msg> = async move {
        Ok(match t {
            Task::Invite { name, boundaries, ttl_secs } => {
                let v = admin(Request::Invite { name, boundaries, replace: false, ttl_secs: Some(ttl_secs) }).await?;
                Msg::Ticket(v["ticket"].as_str().unwrap_or_default().to_string())
            }
            Task::Join { ticket } => {
                let mut c = Client::connect(&socket_path()).await?;
                let v = c
                    .call_each(&Request::Join { ticket }, |d| {
                        let _ = tx2.send(Msg::Code(d["code"].as_str().unwrap_or_default().to_string()));
                    })
                    .await?;
                Msg::Done(format!("Joined. This machine is in the mesh now (version {}).", v["version"]))
            }
            Task::NewMesh { name, pass } => {
                let cfg = Config::load(&config)?;
                Msg::Keys(Box::new(crate::setup::new_mesh(&name, &cfg, &pass).await?))
            }
            Task::Create(m) => {
                crate::setup::commit(&m).await?;
                Msg::Done(format!(
                    "Mesh {} is ready, with {} in it as the owner node.\n\nNext: close this, then A adds a machine; you approve it here when it asks to join.",
                    m.name, m.machine
                ))
            }
            Task::Sign { key, pass, changes } => {
                // The machines as they were, to say how many the dissolve reached.
                let before = if changes == [Change::Dissolve] {
                    admin(Request::MeshCurrent).await?["toml"].as_str().and_then(|t| Mesh::parse(t).ok())
                } else {
                    None
                };
                let v = sign_and_apply(key, pass, changes).await?;
                match before {
                    Some(m) => Msg::Done(dissolved(&m).await),
                    None => Msg::Done(format!("Signed and applied mesh version {v}.")),
                }
            }
            Task::Reject { name } => {
                admin(Request::Reject { name: Some(name.clone()) }).await?;
                Msg::Done(format!("Refused {name}. Its ticket no longer works."))
            }
            Task::JoinCancel => {
                admin(Request::JoinCancel).await?;
                Msg::Done("Cancelled the join request.".into())
            }
            Task::Leave => {
                // Best effort: the others mark it as leaving.
                let heard: Vec<String> = admin(Request::Leave)
                    .await
                    .ok()
                    .and_then(|v| serde_json::from_value(v["heard"].clone()).ok())
                    .unwrap_or_default();
                admin(Request::LeaveMesh).await?;
                Msg::Done(if heard.is_empty() {
                    "Left the mesh. No other machine answered; the owner node can still remove this one.".into()
                } else {
                    format!("Left the mesh. Told {} that this machine is leaving.", heard.join(", "))
                })
            }
        })
    }
    .await;
    let _ = tx.send(r.unwrap_or_else(|e| Msg::Failed(format!("{e:#}"))));
}

async fn run_action(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    job: &mut Option<Job>,
    mail: &mut Option<Client>,
    config: &std::path::Path,
    a: Action,
) -> Result<()> {
    let exe = std::env::current_exe()?;
    match a {
        Action::Refresh => {}
        Action::Job(t) => {
            if let Some(j) = job.take() {
                j.task.abort();
            }
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            let task = tokio::spawn(work(t, config.to_path_buf(), tx));
            *job = Some(Job { rx, task });
        }
        Action::Cancel => {
            if let Some(j) = job.take() {
                j.task.abort();
            }
        }
        Action::Copy(t) => {
            use base64::Engine;
            let b = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(t.as_bytes()));
            let mut out = std::io::stdout();
            std::io::Write::write_all(&mut out, format!("\x1b]52;c;{}\x07", *b).as_bytes())?;
            std::io::Write::flush(&mut out)?;
        }
        Action::SignOutside { key, changes } => {
            let r = suspended(terminal, || {
                let cur = futures_block(admin(Request::MeshCurrent))?;
                let (_, toml, _) = crate::mesh::next_version(cur["toml"].as_str().unwrap_or_default(), &changes)?;
                let dir = crate::setup::private_dir("tearmesh-menu-")?;
                let file = dir.join("mesh-next.toml");
                std::fs::write(&file, &toml)?;
                eprintln!("Signing with {} (touch the key when it blinks)…", key.display());
                let r = crate::mesh::ssh_sign(&key, &file).and_then(|_| {
                    let sig = std::fs::read_to_string(dir.join("mesh-next.toml.sig"))?;
                    futures_block(admin(Request::ApplyMesh { toml, sig }))
                });
                let _ = std::fs::remove_dir_all(&dir);
                let r = r?;
                if changes == [Change::Dissolve]
                    && let Some(m) = cur["toml"].as_str().and_then(|t| Mesh::parse(t).ok())
                {
                    return futures_block(async { Ok(dissolved(&m).await) });
                }
                Ok(format!("applied mesh version {}", r["version"]))
            });
            app.say(r.map_or_else(|e| format!("signing: {e:#}"), |s| s.replace('\n', " ")));
        }
        Action::StartHub => {
            crate::hub::start_detached(&crate::hub::state_dir())?;
            app.say("started the MCP hub (Settings shows its URL; U shows how to register it)");
        }
        Action::Ssh { machine, boundary } => {
            // An OS user mapped to a boundary has a session in it and names none; an admin must.
            let mapped = match admin(Request::Hello { mailbox: None, hold: false, trust: None }).await {
                Ok(_) => true,
                Err(e) if format!("{e:#}").contains("mapped to a boundary") => false,
                Err(e) => {
                    app.note = format!("can't tell which boundary this user has: {e:#}");
                    return Ok(());
                }
            };
            let boundary = if mapped { None } else { boundary };
            if !mapped && boundary.is_none() {
                app.note = format!("no boundary in common with {machine}: a shell goes through a boundary both machines host");
                return Ok(());
            }
            let r = suspended(terminal, || {
                let user = std::env::var(if cfg!(windows) { "USERNAME" } else { "USER" }).unwrap_or_default();
                eprintln!("ssh {user}@{machine} over the mesh (needs a shell grant and an SSH login there)…\n");
                let via = boundary.map_or_else(String::new, |b| format!(" --boundary {b}"));
                let st = std::process::Command::new("ssh")
                    .args(["-o", &format!("ProxyCommand=\"{}\" shell-proxy %h{via}", exe.display()), "-l", &user, &machine])
                    .status()?;
                Ok(format!("ssh ended ({st})"))
            });
            app.say(format!("shell to {machine}: {}", r.map_or_else(|e| format!("{e:#}"), |s| s)));
        }
        Action::Mail(cmd) => mail_exec(app, mail, cmd).await,
        Action::Elevated(args) => {
            let r = suspended(terminal, || {
                eprintln!("Running tearmesh {} with admin rights…\n", args.join(" "));
                let a: Vec<&str> = args.iter().map(String::as_str).collect();
                crate::install::elevated(&a).map(|_| String::new())
            });
            if r.is_ok() && args[0] == "uninstall" {
                // The binary is gone; there is nothing to reconnect to.
                app.bye = Some(if cfg!(windows) {
                    "tear-mesh was removed from this machine. The exe this menu ran from may stay: delete it now that the menu has closed.".into()
                } else {
                    "tear-mesh was removed from this machine, this menu included.".into()
                });
                app.quit = true;
                return Ok(());
            }
            app.cfg = Config::load(config).ok();
            app.created = crate::install::created_record();
            app.config_file = config.exists();
            app.say(match r {
                Ok(_) => format!("tearmesh {}: done", args.join(" ")),
                Err(e) => format!("tearmesh {}: {e:#}", args.join(" ")),
            });
        }
    }
    Ok(())
}

/// The Mail tab's session: the mailbox, never held, so agents are still woken for its mail.
async fn mail_hello(mailbox: &str) -> Result<(Client, String, String)> {
    let mut c = Client::connect(&socket_path()).await?;
    let v = c.call(&Request::Hello { mailbox: Some(mailbox.into()), hold: false, trust: None }).await?;
    let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    Ok((c, s("address"), s("boundary")))
}

/// Connects the Mail tab if it isn't, then refreshes it.
async fn mail_tick(app: &mut App, c: &mut Option<Client>) {
    if c.is_none() {
        match mail_hello(&app.mailbox).await {
            Ok((client, address, boundary)) => {
                app.mail_error = None;
                // A reconnect keeps the open letter and any draft.
                let m = app.mail.get_or_insert_with(|| crate::tui::App::new(address.clone(), boundary.clone()));
                (m.address, m.boundary) = (address, boundary);
                m.status.clear();
                *c = Some(client);
            }
            Err(e) => {
                if let Some(m) = &mut app.mail {
                    m.status = format!("error: {e:#} (retrying)");
                }
                app.mail_error = Some(format!("{e:#}"));
                return;
            }
        }
    }
    mail_exec(app, c, crate::tui::Cmd::Refresh).await;
}

/// Runs a mail command; on an error drops the connection, so the next tick reconnects.
async fn mail_exec(app: &mut App, c: &mut Option<Client>, cmd: crate::tui::Cmd) {
    let Some(m) = &mut app.mail else { return };
    let Some(client) = c else {
        m.status = "not connected to the daemon; retrying".into();
        return;
    };
    if let Err(e) = crate::tui::exec(client, m, cmd).await {
        m.status = format!("error: {e:#}");
        *c = None;
    }
}

/// Runs a future to completion from blocking code on the menu's thread (inside `suspended`).
fn futures_block<T>(f: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
}

fn splash(terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
    let width = LOGO[0].chars().count();
    let start = Instant::now();
    let total = Duration::from_millis(1100);
    while start.elapsed() < total {
        let reveal = (start.elapsed().as_millis() as usize * width) / total.as_millis() as usize;
        terminal.draw(|f| {
            let a = centered(f.area(), width as u16 + 2, LOGO.len() as u16 + 2);
            f.render_widget(Paragraph::new(logo_frame(width, reveal)).alignment(Alignment::Center), a);
        })?;
        if event::poll(Duration::from_millis(30))? && matches!(event::read()?, Event::Key(_)) {
            break;
        }
    }
    Ok(())
}

pub async fn run(config: &std::path::Path) -> Result<()> {
    let mut app = App::new();
    app.cfg = Config::load(config).ok();
    app.created = crate::install::created_record();
    app.config_file = config.exists();
    survive_ctrl_c()?;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Data>(4);
    let poke = std::sync::Arc::new(tokio::sync::Notify::new());
    let p = poke.clone();
    // Status every 3 s, a ping round every 10 s (pings can take a few seconds when a machine
    // is down), sooner when the menu asks.
    tokio::spawn(async move {
        let mut last_ping: Option<Instant> = None;
        loop {
            let ping = last_ping.is_none_or(|t| t.elapsed() >= Duration::from_secs(10));
            let d = fetch(ping).await;
            if ping {
                last_ping = Some(Instant::now());
            }
            if tx.send(d).await.is_err() {
                return;
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(3)) => {}
                _ = p.notified() => last_ping = None,
            }
        }
    });
    let mut terminal = enter();
    let mut job: Option<Job> = None;
    let mut mail: Option<Client> = None;
    let mut mail_at: Option<Instant> = None;
    let res = async {
        splash(&mut terminal)?;
        app.say("menu started");
        while !app.quit {
            while let Ok(d) = rx.try_recv() {
                app.set_data(d);
            }
            if let Some(j) = &mut job {
                let mut finished = false;
                while let Ok(m) = j.rx.try_recv() {
                    finished |= !matches!(m, Msg::Code(_));
                    app.on_msg(m);
                }
                if finished {
                    job = None;
                    poke.notify_one();
                }
            }
            // Mail connects when its tab opens and refreshes every 3 s while it shows.
            if app.tab != Tab::Mail {
                mail_at = None;
            } else if mail_at.is_none_or(|t| t.elapsed() >= Duration::from_secs(3)) {
                mail_tick(&mut app, &mut mail).await;
                mail_at = Some(Instant::now());
            }
            terminal.draw(|f| app.draw(f))?;
            if !event::poll(Duration::from_millis(200))? {
                continue;
            }
            let a = match event::read()? {
                Event::Key(k) => app.on_key(k),
                Event::Paste(s) => {
                    app.on_paste(&s);
                    None
                }
                _ => None,
            };
            if let Some(a) = a {
                let refresh = matches!(a, Action::Ssh { .. } | Action::SignOutside { .. } | Action::Refresh | Action::Elevated(_));
                if let Err(e) = run_action(&mut terminal, &mut app, &mut job, &mut mail, config, a).await {
                    app.note = format!("{e:#}");
                }
                if refresh {
                    poke.notify_one();
                }
            }
        }
        anyhow::Ok(())
    }
    .await;
    if let Some(j) = job {
        j.task.abort();
    }
    leave();
    if let Some(b) = &app.bye {
        println!("{b}");
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::{Grant, Machine};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn screen(app: &App) -> String {
        sized(app, 120, 36)
    }

    fn sized(app: &App, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| app.draw(f)).unwrap();
        let buf = t.backend().buffer();
        buf.content()
            .chunks(buf.area.width as usize)
            .map(|row| row.iter().map(|c| c.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn data(owner: bool) -> Data {
        let k = iroh::SecretKey::generate();
        let id = k.public();
        let id2 = iroh::SecretKey::generate().public();
        let dir = tempfile::tempdir().unwrap();
        let mut mesh = Mesh::new(
            "home",
            vec![
                crate::mesh::tests::keygen(dir.path(), "a").1,
                crate::mesh::tests::keygen(dir.path(), "b").1,
            ],
            vec!["work".into()],
            None,
        )
        .unwrap();
        mesh.id = "x".into(); // the id the status below names
        mesh.machines = vec![
            Machine { name: "laptop".into(), id, boundaries: vec!["work".into()] },
            Machine { name: "beta".into(), id: id2, boundaries: vec!["work".into()] },
            Machine { name: "gamma".into(), id: id2, boundaries: vec!["work".into()] },
        ];
        mesh.grants = vec![Grant { from: "laptop".into(), to: "beta".into(), allow: vec![Category::Shell] }];
        let status: Status = serde_json::from_value(serde_json::json!({
            "machine": "laptop", "node_id": id, "entries": {}, "peers": [], "pending_joins": [], "warnings": [],
            "mesh": { "id": "x", "name": "home", "version": 3, "hash": "h", "owners": ["SHA256:a", "SHA256:b"], "hosts": ["work"] }
        }))
        .unwrap();
        Data {
            status: Some(status),
            mesh: Some(mesh),
            pings: vec![
                Ping { name: "beta".into(), node_id: id2.to_string(), rtt_ms: Some(12), dial_ms: Some(40), error: None },
                Ping { name: "gamma".into(), node_id: id2.to_string(), rtt_ms: None, dial_ms: None, error: Some("no answer".into()) },
            ],
            pinged_at: Some(Instant::now()),
            owner_key: owner.then(|| PathBuf::from("/home/u/.ssh/tearmesh-owner-home")),
            ..Default::default()
        }
    }

    #[test]
    fn every_role_has_the_same_three_tabs() {
        let mut a = App::new();
        assert_eq!(a.role(), Role::NotSetUp);
        assert!(screen(&a).contains("Mesh │ Mail │ Settings"), "{}", screen(&a));
        a.set_data(data(false));
        assert_eq!(a.role(), Role::Member);
        a.set_data(data(true));
        assert_eq!(a.role(), Role::Owner);
        let s = screen(&a);
        assert!(s.contains("OWNER NODE") && s.contains("Mesh │ Mail │ Settings"), "{s}");
        assert!(s.contains("1 of 2 other machines answer"), "{s}");
    }

    #[test]
    fn arrows_keypad_and_esc() {
        let mut a = App::new();
        a.set_data(data(false));
        a.on_key(key(KeyCode::Right));
        assert_eq!(a.tab, Tab::Mail);
        a.on_key(key(KeyCode::Char('6')));
        assert_eq!(a.tab, Tab::Settings);
        a.on_key(key(KeyCode::Right));
        assert_eq!(a.tab, Tab::Mesh, "wraps around");
        a.on_key(key(KeyCode::Down));
        a.on_key(key(KeyCode::Char('2')));
        a.on_key(key(KeyCode::Down));
        assert_eq!(a.sel, 2, "stops at the last row");
        a.on_key(key(KeyCode::Up));
        assert_eq!(a.sel, 1);
        a.on_key(key(KeyCode::Left));
        assert_eq!(a.tab, Tab::Settings);
        a.on_key(key(KeyCode::Esc));
        assert_eq!((a.tab, a.sel), (Tab::Mesh, 0));
        a.on_key(key(KeyCode::Char('Q')));
        assert!(a.quit);
    }

    #[test]
    fn the_mesh_screen_shows_the_map_and_who_answers() {
        let mut a = App::new();
        a.set_data(data(false));
        let s = screen(&a);
        assert!(s.contains("beta 12ms") && s.contains("gamma down"), "{s}");
        assert!(s.contains("● 12 ms") && s.contains("○ no answer") && s.contains("this machine"), "{s}");
    }

    #[test]
    fn at_80x24_the_map_sits_above_the_whole_node_table() {
        let mut a = App::new();
        a.set_data(data(true));
        let s = sized(&a, 80, 24);
        let rows: Vec<&str> = s.lines().collect();
        let row = |t: &str| rows.iter().position(|l| l.contains(t)).unwrap_or_else(|| panic!("no {t:?} in\n{s}"));
        let (map, nodes) = (row("Map · pinged"), row("Nodes"));
        assert!(map < row("beta 12ms") && row("beta 12ms") < nodes && map < row("gamma down") && row("gamma down") < nodes, "{s}");
        // The map's bottom border is above the table's top one, and every machine has a row.
        assert!(rows[nodes - 1].contains('╰') && rows[nodes].contains('╭'), "{s}");
        for m in ["laptop", "beta", "gamma"] {
            assert!(rows[nodes + 1..21].iter().any(|l| l.contains(m)), "{m} in\n{s}");
        }
        assert!(rows[nodes + 1..21].iter().any(|l| l.contains('╰')), "the table ends above the bar\n{s}");
    }

    #[test]
    fn shortcut_bar_follows_the_screen_and_role() {
        let mut a = App::new();
        a.set_data(data(false));
        let keys: Vec<&str> = a.shortcuts().iter().map(|k| k.1).collect();
        assert!(keys.contains(&"Leave mesh") && keys.contains(&"Status JSON") && !keys.contains(&"Disconnect"));
        a.set_data(data(true));
        let keys: Vec<&str> = a.shortcuts().iter().map(|k| k.1).collect();
        assert!(keys.contains(&"Add node") && keys.contains(&"Disconnect") && keys.contains(&"Permissions"));
        assert!(screen(&a).contains("Add node"));
        a.tab = Tab::Settings;
        let keys: Vec<&str> = a.shortcuts().iter().map(|k| k.1).collect();
        assert!(keys.contains(&"Hub info") && keys.contains(&"Remove key") && keys.contains(&"Clear events"));
        a.set_data(data(false));
        assert!(!a.shortcuts().iter().any(|k| k.1 == "Remove key"));
    }

    #[test]
    fn members_cant_sign() {
        let mut a = App::new();
        a.set_data(data(false));
        a.sel = 1;
        assert_eq!(a.on_key(key(KeyCode::Char('d'))), None);
        assert!(a.modal.is_none() && a.note.contains("only an owner node"));
        a.tab = Tab::Settings;
        assert_eq!(a.on_key(key(KeyCode::Char('z'))), None);
        assert!(a.modal.is_none() && a.note.contains("only an owner node"));
    }

    #[test]
    fn s_shows_the_status_json_and_scrolls() {
        let mut a = App::new();
        a.set_data(data(false));
        a.on_key(key(KeyCode::Char('s')));
        assert!(matches!(&a.modal, Some(Modal::Info { title, .. }) if title == "Status"));
        assert!(screen(&a).contains("\"node_id\""), "{}", screen(&a));
        let scroll = |a: &App| match &a.modal {
            Some(Modal::Info { scroll, .. }) => *scroll,
            _ => panic!(),
        };
        a.on_key(key(KeyCode::Down));
        a.on_key(key(KeyCode::Down));
        a.on_key(key(KeyCode::Up));
        assert_eq!(scroll(&a), 1);
        a.on_key(key(KeyCode::PageDown));
        assert_eq!(scroll(&a), 11);
        assert!(!screen(&a).contains("\"machine\": \"laptop\""), "scrolled past the first lines");
        for _ in 0..20 {
            a.on_key(key(KeyCode::PageDown));
        }
        let Some(Modal::Info { text, .. }) = &a.modal else { panic!() };
        assert_eq!(scroll(&a) as usize, text.lines().count() - 1, "stops at the last line");
        a.on_key(key(KeyCode::Esc));
        assert!(a.modal.is_none());
    }

    #[test]
    fn l_asks_then_leaves() {
        let mut a = App::new();
        a.set_data(data(false));
        a.on_key(key(KeyCode::Char('l')));
        assert_eq!(a.tab, Tab::Mail, "a plain l switches screens");
        a.on_key(key(KeyCode::Esc));
        a.on_key(key(KeyCode::Char('L')));
        assert!(matches!(&a.modal, Some(Modal::Confirm { text, .. }) if text.contains("Leave mesh home")));
        assert_eq!(a.on_key(key(KeyCode::Char('y'))), Some(Action::Job(Task::Leave)));
        assert!(matches!(a.modal, Some(Modal::Busy { .. })));
        // An owner node doesn't leave this way.
        let mut a = App::new();
        a.set_data(data(true));
        assert_eq!(a.on_key(key(KeyCode::Char('L'))), None);
        assert!(a.modal.is_none());
    }

    #[test]
    fn u_shows_the_hub_and_copies_the_claude_line_without_the_token() {
        let d = tempfile::tempdir().unwrap();
        let mut a = App::new();
        a.modal = Some(hub_panel(&d.path().join("hub.toml"), d.path()));
        let token = std::fs::read_to_string(d.path().join("token")).unwrap();
        assert!(screen(&a).contains("Copy command"));
        match a.on_key(key(KeyCode::Char('c'))) {
            Some(Action::Copy(line)) => {
                assert!(line.starts_with("claude mcp add --transport http tearmesh "), "{}", *line);
                assert!(line.contains("$(cat '") && !line.contains(token.trim()), "{}", *line);
            }
            other => panic!("{other:?}"),
        }
        assert!(a.note.contains("clipboard") && a.modal.is_some());
        // Settings → U opens it.
        a.modal = None;
        a.tab = Tab::Settings;
        a.on_key(key(KeyCode::Char('u')));
        assert!(matches!(&a.modal, Some(Modal::Info { title, .. }) if title == "MCP hub"));
    }

    #[test]
    fn question_mark_opens_and_closes_help() {
        let mut a = App::new();
        a.set_data(data(true));
        a.on_key(key(KeyCode::Char('?')));
        assert_eq!(a.modal, Some(Modal::Help));
        let s = screen(&a);
        assert!(s.contains("Keys on this screen") && s.contains("A Add node"), "{s}");
        a.on_key(key(KeyCode::Char('?')));
        assert!(a.modal.is_none());
        a.on_key(key(KeyCode::Char('?')));
        a.on_key(key(KeyCode::Esc));
        assert_eq!((a.modal.clone(), a.tab), (None, Tab::Mesh));
    }

    #[test]
    fn mail_keys_go_to_the_mail_client_and_h_types_while_composing() {
        let mut a = App::new();
        a.tab = Tab::Mail;
        a.mail = Some(crate::tui::App::new("admin@laptop".into(), "work".into()));
        assert!(screen(&a).contains("admin@laptop · boundary work"));
        assert_eq!(a.on_key(key(KeyCode::Char('g'))), Some(Action::Mail(crate::tui::Cmd::Refresh)));
        a.on_key(key(KeyCode::Char('n')));
        typed(&mut a, "h@ws");
        a.on_key(key(KeyCode::Tab));
        typed(&mut a, "hello ?q");
        assert_eq!(a.tab, Tab::Mail);
        assert!(!a.quit && a.modal.is_none());
        let c = a.mail.as_ref().unwrap().compose.clone().unwrap();
        assert_eq!((c.to.as_str(), c.subject.as_str()), ("h@ws", "hello ?q"));
        assert!(a.shortcuts().iter().any(|k| k.1 == "Send"));
        assert!(matches!(
            a.on_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL)),
            Some(Action::Mail(crate::tui::Cmd::Send { .. }))
        ));
        // Not composing, h moves to the screen on the left.
        a.on_key(key(KeyCode::Esc));
        a.on_key(key(KeyCode::Char('h')));
        assert_eq!(a.tab, Tab::Mesh);
    }

    #[test]
    fn mail_for_an_unmapped_user_says_how_to_get_it() {
        let mut a = App::new();
        a.tab = Tab::Mail;
        assert!(screen(&a).contains("Connecting"));
        a.mail_error = Some("this OS user isn't mapped to a boundary".into());
        let s = screen(&a);
        assert!(s.contains("run the menu as a boundary user") && s.contains("tearmesh launch --boundary <b> -- tearmesh"), "{s}");
    }

    #[test]
    fn a_dissolved_mesh_says_so() {
        let mut a = App::new();
        let mut d = data(false);
        let s = d.status.as_mut().unwrap();
        s.mesh = None;
        s.dissolved = Some("home".into());
        a.set_data(Data { status: d.status, ..Default::default() });
        assert_eq!(a.role(), Role::NotSetUp);
        let s = screen(&a);
        assert!(s.contains("Mesh home was dissolved by its owner") && s.contains("C  Create a mesh"), "{s}");
    }

    /// A real encrypted owner key, kept for the test run.
    fn owner_key(pass: &str) -> PathBuf {
        let d = tempfile::tempdir().unwrap().keep();
        let (_, k) = keys::generate("t", pass).unwrap();
        let p = d.join("owner");
        std::fs::write(&p, k.private.as_bytes()).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        p
    }

    fn typed(a: &mut App, s: &str) {
        for c in s.chars() {
            a.on_key(key(KeyCode::Char(c)));
        }
    }

    #[test]
    fn disconnect_is_signed_here_with_a_masked_passphrase() {
        let mut a = App::new();
        let mut d = data(true);
        d.owner_key = Some(owner_key("hunter22"));
        a.set_data(d);
        a.sel = 0;
        assert_eq!(a.on_key(key(KeyCode::Char('d'))), None);
        assert!(a.note.contains("can't remove itself"));
        a.sel = 1;
        a.on_key(key(KeyCode::Char('d')));
        assert!(matches!(&a.modal, Some(Modal::Form { kind: FormKind::Sign(_), .. })));
        typed(&mut a, "hunter22");
        let s = screen(&a);
        assert!(!s.contains("hunter22") && s.contains("••••••••"), "{s}");
        match a.on_key(key(KeyCode::Enter)) {
            Some(Action::Job(Task::Sign { pass, changes, .. })) => {
                assert_eq!(pass.as_str(), "hunter22");
                assert_eq!(changes, vec![Change::RemoveMachine("beta".into())]);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(a.modal, Some(Modal::Busy { .. })));
        // A wrong passphrase reopens the form with the reason, the passphrase cleared.
        a.on_msg(Msg::Failed("that passphrase doesn't open it".into()));
        match &a.modal {
            Some(Modal::Form { error: Some(e), fields, .. }) => {
                assert!(e.contains("doesn't open"));
                assert!(fields.iter().all(|f| !matches!(f, Field::Secret { value, .. } if !value.is_empty())));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_unreadable_owner_key_says_why() {
        let mut a = App::new();
        a.set_data(data(true));
        a.sel = 1;
        a.on_key(key(KeyCode::Char('d')));
        match &a.modal {
            Some(Modal::Info { title, text, .. }) => {
                assert!(title.starts_with("Can't sign with") && text.contains("reading"), "{title}: {text}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_security_key_asks_for_its_pin_here() {
        let mut a = App::new();
        let mut d = data(true);
        d.owner_key = Some(keys::tests::sk_file(&tempfile::tempdir().unwrap().keep(), 0x05));
        a.set_data(d);
        a.sel = 1;
        a.on_key(key(KeyCode::Char('d')));
        assert!(screen(&a).contains("PIN for the security key"), "{}", screen(&a));
        typed(&mut a, "123456");
        match a.on_key(key(KeyCode::Enter)) {
            Some(Action::Job(Task::Sign { pass, .. })) => assert_eq!(pass.as_str(), "123456"),
            other => panic!("{other:?}"),
        }
        assert!(screen(&a).contains("touch it when it blinks"));
    }

    #[test]
    fn permissions_are_six_switches_and_one_signature() {
        let mut a = App::new();
        let mut d = data(true);
        d.owner_key = Some(owner_key("hunter22"));
        a.set_data(d);
        // On this machine's own row G is still the any-pair form.
        a.sel = 0;
        a.on_key(key(KeyCode::Char('g')));
        assert!(matches!(&a.modal, Some(Modal::Form { kind: FormKind::Grant, .. })));
        a.on_key(key(KeyCode::Esc));
        a.sel = 1;
        a.on_key(key(KeyCode::Char('g')));
        let s = screen(&a);
        assert!(s.contains("Permissions: laptop and beta"), "{s}");
        assert!(s.contains("[x] shell    speak  laptop can drive beta"), "the grant in the file is ticked\n{s}");
        assert!(s.contains("[ ] shell    listen laptop can be driven by beta"), "{s}");
        assert!(s.contains("[ ] converse listen laptop accepts notes from beta"), "{s}");
        // Nothing ticked or unticked: nothing to sign.
        a.on_key(key(KeyCode::Enter));
        assert!(screen(&a).contains("nothing changed"), "{}", screen(&a));
        let Some(Modal::Form { fields, .. }) = &mut a.modal else { panic!() };
        // Drawn order: converse, tools, shell; speak then listen. Turn tools speak on, shell
        // speak off and shell listen on.
        for (i, f) in fields.iter_mut().filter(|f| matches!(f, Field::Check { .. })).enumerate() {
            if let Field::Check { on, .. } = f {
                *on = matches!(i, 2 | 5);
            }
        }
        a.on_key(key(KeyCode::Enter));
        let g = |f: &str, t: &str, c| Grant { from: f.into(), to: t.into(), allow: vec![c] };
        match &a.modal {
            Some(Modal::Form { kind: FormKind::Sign(c), .. }) => assert_eq!(
                *c,
                [
                    Change::Grant(g("laptop", "beta", Category::Tools)),
                    Change::Revoke(g("laptop", "beta", Category::Shell)),
                    Change::Grant(g("beta", "laptop", Category::Shell)),
                ]
            ),
            other => panic!("{other:?}"),
        }
        let s = screen(&a);
        assert!(s.contains("Stop laptop → beta: shell") && s.contains("Careful: beta will be able to drive this machine"), "{s}");
        // A switch a `*` grant already allows is shown, not offered: unticking it couldn't revoke it.
        a.modal = None;
        a.data.mesh.as_mut().unwrap().grant("*", "*", &[Category::Converse]);
        a.on_key(key(KeyCode::Char('g')));
        let s = screen(&a);
        assert!(s.contains("[x] converse speak  laptop posts notes to beta · mesh-wide"), "{s}");
        assert!(matches!(&a.modal, Some(Modal::Form { kind: FormKind::Permissions(sw), .. }) if sw.len() == 4));
        // The table says both directions.
        a.modal = None;
        let s = screen(&a);
        assert!(s.contains("speaks to it") && s.contains("listens to it"), "{s}");
    }

    #[test]
    fn waiting_offers_show_on_mesh_and_o_approves_the_ticked_ones() {
        let mut a = App::new();
        let mut d = data(true);
        d.owner_key = Some(owner_key("hunter22"));
        a.set_data(d.clone());
        assert!(!screen(&a).contains("waiting for your approval") && !a.shortcuts().iter().any(|k| k.0 == "O"));
        a.on_key(key(KeyCode::Char('o')));
        assert!(a.modal.is_none(), "nothing waits, so O does nothing");
        let offer = crate::offer::Offer::new("cad", "CAD".into(), None, None, vec![serde_json::json!({"name": "export_step", "inputSchema": {"type": "object"}})], None).unwrap();
        let row = |state: &str| serde_json::json!({ "machine": "beta", "state": state, "offer": offer });
        assert_eq!(waiting("work", &row("approved")), None);
        assert_eq!(waiting("work", &row("free")), None);
        let w = waiting("work", &row("pending approval")).unwrap();
        assert_eq!((w.approval.pin.as_str(), w.approval.tools.as_ref(), w.changed), (offer.pin.as_str(), None, false));
        assert!(waiting("work", &row("changed since approval")).unwrap().changed);
        // An approval that was limited to some tools is re-approved for those, not for all.
        let two = crate::offer::Offer::new("cad", "CAD".into(), None, None, ["export_step", "run_script"].map(|n| serde_json::json!({"name": n, "inputSchema": {"type": "object"}})).to_vec(), None).unwrap();
        let limited = |t: &[&str]| serde_json::json!({ "machine": "beta", "state": "changed since approval", "offer": two, "approved_tools": t });
        let l = waiting("work", &limited(&["export_step", "gone"])).unwrap();
        let only = vec!["export_step".to_string()];
        assert_eq!((l.approval.tools.as_ref(), &l.tools), (Some(&only), &only));
        assert_eq!(l.approval.pin, crate::offer::pin(None, &two.tools, Some(&only)));
        assert_eq!(waiting("work", &limited(&["gone"])), None);
        d.offers = vec![w.clone()];
        a.set_data(d);
        assert!(screen(&a).contains("1 offered MCP server(s) waiting for your approval: O reviews them"), "{}", screen(&a));
        a.on_key(key(KeyCode::Char('o')));
        let s = screen(&a);
        assert!(s.contains("[ ] beta/cad in work: export_step"), "unticked until the person ticks\n{s}");
        a.on_key(key(KeyCode::Enter));
        assert!(screen(&a).contains("nothing ticked"), "{}", screen(&a));
        a.on_key(key(KeyCode::Char(' ')));
        a.on_key(key(KeyCode::Enter));
        match &a.modal {
            Some(Modal::Form { kind: FormKind::Sign(c), .. }) => assert_eq!(*c, [Change::Approve(w.approval)]),
            other => panic!("{other:?}"),
        }
        assert!(screen(&a).contains("Approve beta/cad in work."), "{}", screen(&a));
    }

    #[test]
    fn the_key_bar_takes_a_third_row_before_it_cuts_a_label() {
        let mut a = App::new();
        a.set_data(data(true));
        a.tab = Tab::Settings;
        let s = sized(&a, 110, 34);
        assert!(s.contains("Uninstall") && s.contains("Start MCP hub"), "{s}");
        // A short screen keeps two rows: the map and the table need theirs.
        assert_eq!(bar_rows(Rect::new(0, 0, 80, 24), &a.shortcuts()), 2);
    }

    #[test]
    fn forms_check_their_input() {
        let mut a = App::new();
        a.set_data(data(true));
        let t = |s: &[&str]| s.iter().map(|x| text("", x)).collect::<Vec<_>>();
        assert!(a.submit(&FormKind::Grant, &t(&["*", "beta", "shell"])).is_err());
        assert!(a.submit(&FormKind::Grant, &t(&["laptop", "beta", "telepathy"])).is_err());
        assert!(a.submit(&FormKind::Grant, &t(&["laptop", "beta", "tools,shell"])).is_ok());
        assert!(a.submit(&FormKind::Relays, &t(&["ftp://x"])).is_err());
        assert!(a.submit(&FormKind::OwnerAdd, &t(&["/nonexistent.pub"])).is_err());
        assert!(a.submit(&FormKind::Join, &t(&["tm2-abc"])).is_err());
        // Typing into a form and pressing Enter with an error keeps it open.
        a.modal = None;
        a.tab = Tab::Settings;
        a.on_key(key(KeyCode::Char('y')));
        assert!(matches!(&a.modal, Some(Modal::Form { kind: FormKind::Relays, .. })));
        a.on_key(key(KeyCode::Char('Z')));
        assert_eq!(a.on_key(key(KeyCode::Enter)), None);
        assert!(matches!(&a.modal, Some(Modal::Form { error: Some(_), .. })));
        a.on_key(key(KeyCode::Esc));
        assert!(a.modal.is_none());
    }

    #[test]
    fn a_pasted_ticket_loses_its_line_breaks_and_long_values_show_their_end() {
        let mut a = App::new();
        a.set_data(Data { status: data(false).status.map(|mut s| { s.mesh = None; s }), ..Default::default() });
        assert_eq!(a.role(), Role::NotSetUp);
        a.on_key(key(KeyCode::Char('j')));
        assert!(matches!(&a.modal, Some(Modal::Form { kind: FormKind::Join, .. })));
        a.on_paste("tm2-ab\n cd\r\n");
        let Some(Modal::Form { fields, .. }) = &a.modal else { panic!() };
        assert!(fields.contains(&text("Ticket from the owner node (paste it)", "tm2-abcd")));
        a.on_paste(&"x".repeat(300));
        assert!(screen(&a).contains("…xxxx"));
        // An incomplete ticket keeps the form open, so the rest can still be pasted.
        assert_eq!(a.on_key(key(KeyCode::Enter)), None);
        assert!(matches!(&a.modal, Some(Modal::Form { error: Some(_), .. })));
    }

    #[test]
    fn a_join_request_pops_up_once_and_approves_in_one_signature() {
        let mut a = App::new();
        let mut d = data(true);
        d.owner_key = Some(owner_key("pw-pw-pw-pw"));
        let id = iroh::SecretKey::generate().public();
        let p = PendingInfo {
            name: "delta".into(),
            node_id: id,
            boundaries: vec!["lab".into(), "work".into()],
            replace: false,
            code: "123456".into(),
            expires_ms: 0,
            waiting: true,
            contested: true,
            invite: String::new(),
        };
        d.status.as_mut().unwrap().pending_joins = vec![p];
        a.set_data(d.clone());
        let s = screen(&a);
        assert!(s.contains("delta wants to join") && s.contains("123 456") && s.contains("WARNING"), "{s}");
        a.on_key(key(KeyCode::Esc));
        a.set_data(d);
        assert!(a.modal.is_none(), "the same request doesn't pop up again");
        // It is the first row on the Mesh screen: D refuses it, Enter approves it.
        assert!(screen(&a).contains("join · 123 456"), "{}", screen(&a));
        a.on_key(key(KeyCode::Char('d')));
        assert!(matches!(&a.modal, Some(Modal::Confirm { action: Action::Job(Task::Reject { name }), .. }) if name == "delta"));
        a.on_key(key(KeyCode::Char('n')));
        a.on_key(key(KeyCode::Enter));
        // The boundary ticks come first: "delta hosts work" (asked for, so ticked) and "delta hosts
        // lab (new…)". Tick lab, then the second grant (this mesh has no mail-for-all grant).
        let s = screen(&a);
        assert!(s.contains("[x] delta hosts work") && s.contains("[ ] delta hosts lab (new: adds it to the mesh)"), "{s}");
        a.on_key(key(KeyCode::Tab));
        a.on_key(key(KeyCode::Char(' ')));
        a.on_key(key(KeyCode::Tab));
        a.on_key(key(KeyCode::Tab));
        a.on_key(key(KeyCode::Char(' ')));
        while !matches!(&a.modal, Some(Modal::Form { fields, focus, .. }) if matches!(fields[*focus], Field::Secret { .. })) {
            a.on_key(key(KeyCode::Tab));
        }
        typed(&mut a, "pw-pw-pw-pw");
        match a.on_key(key(KeyCode::Enter)) {
            Some(Action::Job(Task::Sign { changes, .. })) => {
                let shown: Vec<String> = changes.iter().map(|c| c.to_string()).collect();
                assert_eq!(
                    shown,
                    ["add boundary lab", "add machine delta hosting work, lab", "grant laptop -> delta: converse"],
                    "{shown:?}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_approval_signs_the_ticks_as_drawn_even_if_the_mesh_changes_meanwhile() {
        let mut a = App::new();
        let mut d = data(true);
        d.owner_key = Some(owner_key("pw-pw-pw-pw"));
        d.status.as_mut().unwrap().pending_joins = vec![pending("delta", &["work"], "")];
        a.set_data(d.clone());
        a.on_key(key(KeyCode::Esc));
        a.on_key(key(KeyCode::Enter));
        // "delta hosts work" (ticked), then the first grant: "delta may mail laptop".
        a.on_key(key(KeyCode::Tab));
        assert!(screen(&a).contains("[ ] delta may mail laptop"));
        a.on_key(key(KeyCode::Char(' ')));
        // A refresh adds mail for everyone, so a list made now would have no mail lines.
        d.mesh.as_mut().unwrap().grants.push(Grant { from: "*".into(), to: "*".into(), allow: vec![Category::Converse] });
        a.set_data(d);
        while !matches!(&a.modal, Some(Modal::Form { fields, focus, .. }) if matches!(fields[*focus], Field::Secret { .. })) {
            a.on_key(key(KeyCode::Tab));
        }
        typed(&mut a, "pw-pw-pw-pw");
        match a.on_key(key(KeyCode::Enter)) {
            Some(Action::Job(Task::Sign { changes, .. })) => {
                let shown: Vec<String> = changes.iter().map(|c| c.to_string()).collect();
                assert_eq!(shown, ["add machine delta hosting work", "grant delta -> laptop: converse"], "{shown:?}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_enter_already_on_its_way_doesnt_approve_a_form_that_just_popped_up() {
        let mut a = App::new();
        let mut d = data(true);
        let p = tempfile::tempdir().unwrap().keep().join("owner");
        let k = keys::generate("t", "x").unwrap().0;
        std::fs::write(&p, k.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes()).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        d.owner_key = Some(p);
        assert!(matches!(keys::signer(d.owner_key.as_ref().unwrap()), Ok(Signer::Here { encrypted: false })));
        d.status.as_mut().unwrap().pending_joins = vec![pending("delta", &["work"], "")];
        a.set_data(d);
        assert_eq!(approving(&a).as_deref(), Some("delta"));
        assert_eq!(a.on_key(key(KeyCode::Enter)), None);
        assert_eq!(approving(&a).as_deref(), Some("delta"), "still open, nothing signed");
        a.auto_at = a.auto_at.map(|t| t - SETTLE);
        assert!(matches!(a.on_key(key(KeyCode::Enter)), Some(Action::Job(Task::Sign { .. }))));
    }

    #[test]
    fn creating_a_mesh_shows_the_recovery_key_and_checks_it_was_saved() {
        let mut a = App::new();
        a.set_data(Data { status: data(false).status.map(|mut s| { s.mesh = None; s }), ..Default::default() });
        let mut cfg = Config::new("laptop");
        cfg.users.insert("tm-work".into(), "work".into());
        a.cfg = Some(cfg);
        a.on_key(key(KeyCode::Char('c')));
        typed(&mut a, "home");
        a.on_key(key(KeyCode::Tab));
        typed(&mut a, "short");
        a.on_key(key(KeyCode::Tab));
        typed(&mut a, "short");
        a.on_key(key(KeyCode::Enter));
        assert!(matches!(&a.modal, Some(Modal::Form { error: Some(e), focus: 3, .. }) if e.contains("8 characters")), "the cursor goes to the passphrase: {:?}", a.modal);
        a.on_key(key(KeyCode::Char('u')));
        let ctrl_u = KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL);
        a.on_key(ctrl_u);
        typed(&mut a, "long enough");
        a.on_key(key(KeyCode::Tab));
        a.on_key(ctrl_u);
        typed(&mut a, "long enough");
        assert!(matches!(a.on_key(key(KeyCode::Enter)), Some(Action::Job(Task::NewMesh { .. }))));

        let m = crate::setup::version_one("home", "laptop", vec!["work".into()], iroh::SecretKey::generate().public(), "long enough").unwrap();
        let word3 = m.recovery_pass.split('-').nth(2).unwrap().to_string();
        let a_pass = m.recovery_pass.clone();
        a.on_msg(Msg::Keys(Box::new(m)));
        let s = screen(&a);
        assert!(s.lines().any(|l| l.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")), "{s}");
        assert!(!s.contains('│') && !s.contains('║') && !s.contains('╭'), "no borders on the key screen");
        assert!(matches!(a.on_key(key(KeyCode::Char('c'))), Some(Action::Copy(_))));
        // W saves a new file, only for this user, and never over another.
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("rec.key").display().to_string();
        for _ in 0..2 {
            a.on_key(key(KeyCode::Char('w')));
            if let Some(Modal::Keep { ask: Some((_, b)), .. }) = &mut a.modal {
                *b = path.clone();
            }
            a.on_key(key(KeyCode::Enter));
        }
        assert!(matches!(&a.modal, Some(Modal::Keep { note, .. }) if note.contains("exists")));
        #[cfg(unix)]
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&path).unwrap().permissions()) & 0o777, 0o600);
        a.on_key(key(KeyCode::Char('y')));
        let s = screen(&a);
        assert!(!s.contains("BEGIN OPENSSH") && !s.contains(&*a_pass) && s.contains("word 3"), "hidden while asking: {s}");
        typed(&mut a, "wrong");
        a.on_key(key(KeyCode::Enter));
        assert!(matches!(&a.modal, Some(Modal::Keep { note, .. }) if note.contains("isn't word 3")));
        assert!(screen(&a).contains(&*a_pass), "a wrong word shows them again");
        a.on_key(key(KeyCode::Char('y')));
        typed(&mut a, &word3);
        a.on_key(key(KeyCode::Enter));
        assert!(matches!(&a.modal, Some(Modal::Confirm { .. })));
        assert!(matches!(a.on_key(key(KeyCode::Char('y'))), Some(Action::Job(Task::Create(_)))));
        assert!(matches!(a.modal, Some(Modal::Busy { hold: true, .. })));
        a.on_key(key(KeyCode::Char('q')));
        a.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(!a.quit, "the last step can't be quit halfway");
        a.on_msg(Msg::Done("Mesh home is ready".into()));
        assert!(a.log.iter().any(|l| l.contains("Mesh home is ready")));
        assert!(matches!(&a.modal, Some(Modal::Info { .. })));
    }

    #[test]
    fn a_join_shows_its_code_and_esc_leaves_it_waiting() {
        let mut a = App::new();
        a.modal = Some(busy(&Task::Join { ticket: "t".into() }));
        a.on_msg(Msg::Code("123456".into()));
        assert!(screen(&a).contains("Code  123 456"));
        assert_eq!(a.on_key(key(KeyCode::Esc)), Some(Action::Cancel));
        assert!(a.note.contains("X there cancels"));
    }

    #[test]
    fn log_notes_changes() {
        let mut a = App::new();
        a.set_data(data(true));
        let mut d = data(true);
        d.pings[0].rtt_ms = None;
        a.set_data(d);
        assert!(a.log.iter().any(|l| l.contains("beta is not answering")), "{:?}", a.log);
        let d = Data { error: Some("connection refused".into()), ..Default::default() };
        a.set_data(d);
        assert!(a.log.iter().any(|l| l.contains("daemon unreachable")));
        assert_eq!(a.role(), Role::NotSetUp);
        assert!(screen(&a).contains("isn't answering"));
    }

    fn field_values(a: &App) -> Vec<String> {
        let Some(Modal::Form { fields, .. }) = &a.modal else { panic!("no form: {:?}", a.modal) };
        fields.iter().filter_map(|f| if let Field::Text { value, .. } = f { Some(value.clone()) } else { None }).collect()
    }

    fn args(s: &[&str]) -> Option<Action> {
        Some(Action::Elevated(s.iter().map(|x| x.to_string()).collect()))
    }

    #[test]
    fn not_installed_means_no_config_and_no_daemon_never_admin_only() {
        let gone = || Data { error: Some("connecting: No such file".into()), no_daemon: true, ..Default::default() };
        // The daemon refuses this user: installed.
        let mut a = App::new();
        a.set_data(Data { error: Some("admin only (root or an Administrator…)".into()), ..Default::default() });
        assert!(!a.not_installed() && a.modal.is_none());
        assert!(!screen(&a).contains("isn't installed"));
        // A config file but a stopped daemon: installed.
        let mut a = App::new();
        a.config_file = true;
        a.set_data(gone());
        assert!(!a.not_installed() && a.modal.is_none());
        // Neither: the Install form opens by itself, once.
        let mut a = App::new();
        a.set_data(gone());
        assert!(a.not_installed());
        assert!(matches!(&a.modal, Some(Modal::Form { kind: FormKind::Install, .. })));
        a.on_key(key(KeyCode::Esc));
        a.set_data(gone());
        assert!(a.modal.is_none(), "only on the first screen");
        let s = screen(&a);
        assert!(s.contains("isn't installed") && s.contains("Install"), "{s}");
        assert_eq!(a.on_key(key(KeyCode::Char('c'))), None);
        assert!(a.modal.is_none(), "no Create before Install");
        a.on_key(key(KeyCode::Char('i')));
        assert!(matches!(&a.modal, Some(Modal::Form { kind: FormKind::Install, .. })));
    }

    #[test]
    fn the_install_form_defaults_to_the_hostname_and_work() {
        let mut a = App::new();
        a.set_data(Data { no_daemon: true, ..Default::default() });
        let host = crate::machine_name(&crate::os::hostname());
        assert_eq!(field_values(&a), [host.clone(), "work".to_string()]);
        a.auto_at = a.auto_at.map(|t| t - SETTLE);
        assert_eq!(a.on_key(key(KeyCode::Enter)), args(&["install", &host, "work"]));
        let t = |s: &[&str]| s.iter().map(|x| text("", x)).collect::<Vec<_>>();
        assert!(a.submit(&FormKind::Install, &t(&["Bad Name", "work"])).unwrap_err().contains("machine name"));
        assert!(a.submit(&FormKind::Install, &t(&["ws", "work,$(x)"])).unwrap_err().contains("boundary"));
        assert_eq!(a.submit(&FormKind::Install, &t(&["ws", "work, lab"])).unwrap(), args(&["install", "ws", "work", "lab"]));
        assert_eq!(a.submit(&FormKind::Install, &t(&["ws", ""])).unwrap(), args(&["install", "ws"]), "the owner picks");
    }

    #[test]
    fn u_adds_unmapped_boundaries_or_a_first_one() {
        let mut cfg = Config::new("laptop");
        cfg.users.insert("tm-work".into(), "work".into());
        // In a mesh, every hosted boundary mapped: no U.
        let mut a = App::new();
        a.config_file = true;
        a.cfg = Some(cfg.clone());
        a.set_data(data(false));
        assert!(!a.shortcuts().iter().any(|k| k.0 == "U"));
        assert_eq!(a.on_key(key(KeyCode::Char('u'))), None);
        assert!(a.modal.is_none());
        // The mesh has it host lab, with no user here: a yellow line and U.
        let mut d = data(false);
        d.status.as_mut().unwrap().unmapped = vec!["lab".into()];
        a.set_data(d);
        assert!(a.shortcuts().contains(&("U", "Add boundaries")));
        assert!(screen(&a).contains("hosts lab with no OS user here: U adds them"), "{}", screen(&a));
        a.on_key(key(KeyCode::Char('u')));
        assert!(matches!(&a.modal, Some(Modal::Form { kind: FormKind::AddBoundaries, .. })));
        assert_eq!(field_values(&a), ["lab"]);
        assert_eq!(a.on_key(key(KeyCode::Enter)), args(&["install", "laptop", "lab"]));
        let t = |s: &[&str]| s.iter().map(|x| text("", x)).collect::<Vec<_>>();
        assert!(a.submit(&FormKind::AddBoundaries, &t(&[""])).is_err());
        assert!(a.submit(&FormKind::AddBoundaries, &t(&["Lab"])).is_err());
        // Not in a mesh and no users at all: U, prefilled work, and Create points at it.
        let mut a = App::new();
        a.config_file = true;
        a.cfg = Some(Config::new("ws"));
        a.set_data(Data { status: data(false).status.map(|mut s| { s.mesh = None; s }), ..Default::default() });
        assert!(a.shortcuts().contains(&("U", "Add boundaries")));
        assert!(screen(&a).contains("U  Add boundaries"), "{}", screen(&a));
        let e = a.submit(&FormKind::Create, &[text("", "home"), secret("a"), secret("b")]).unwrap_err();
        assert!(e.contains("U on Mesh adds one first"), "{e}");
        a.on_key(key(KeyCode::Char('u')));
        assert_eq!(field_values(&a), ["work"]);
        assert_eq!(a.on_key(key(KeyCode::Enter)), args(&["install", "ws", "work"]));
    }

    #[test]
    fn a_failed_fetch_keeps_the_file_of_the_same_mesh_only() {
        let mut d = data(true);
        d.mesh.as_mut().unwrap().id = "x".into();
        let mut a = App::new();
        a.set_data(d.clone());
        a.set_data(Data { mesh: None, ..d.clone() });
        assert!(a.data.mesh.is_some());
        let mut other = d.clone();
        other.status.as_mut().unwrap().mesh.as_mut().unwrap().id = "y".into();
        a.set_data(Data { mesh: None, ..other });
        assert!(a.data.mesh.is_none());
        // Left: the mail of the old mesh goes too.
        a.mail = Some(crate::tui::App::new("a@b".into(), "work".into()));
        a.set_data(d.clone());
        a.set_data(Data { mesh: None, status: data(false).status.map(|mut s| { s.mesh = None; s }), ..Default::default() });
        assert!(a.mail.is_none());
    }

    #[test]
    fn the_key_column_fits_the_widest_key() {
        assert_eq!(key_width(&[("A", "Add"), ("Shift-L", "Leave")]), 7);
        assert_eq!(key_width(&[("A", "Add")]), 5);
    }

    #[test]
    fn x_on_settings_confirms_the_uninstall() {
        let mut cfg = Config::new("laptop");
        cfg.users.insert("tm-work".into(), "work".into());
        cfg.users.insert("alice".into(), "work".into());
        let mut a = App::new();
        cfg.users.insert("tm-lab".into(), "lab".into());
        a.config_file = true;
        a.cfg = Some(cfg);
        a.created = "tm-work\n".into();
        a.set_data(data(true));
        a.tab = Tab::Settings;
        assert!(a.shortcuts().contains(&("X", "Uninstall")));
        a.on_key(key(KeyCode::Char('x')));
        let Some(Modal::Confirm { text, action }) = &a.modal else { panic!("{:?}", a.modal) };
        assert_eq!(Some(action.clone()), args(&["uninstall", "--yes"]));
        for want in ["users tm-work with their homes", "mail log", "plugin", "hubs and stewards", "owner node of mesh home", "K on this screen", "tearmesh mesh dissolve", "menu closes"] {
            assert!(text.contains(want), "{want:?} in {text}");
        }
        assert!(text.contains("Users kept (not created by install): alice, tm-lab."), "{text}");
        assert!(screen(&a).contains("tearmesh mesh dissolve"), "fits the box\n{}", screen(&a));
        assert_eq!(a.on_key(key(KeyCode::Char('y'))), args(&["uninstall", "--yes"]));
        // A member gets no owner-key warning.
        a.set_data(data(false));
        a.on_key(key(KeyCode::Char('x')));
        let Some(Modal::Confirm { text, .. }) = &a.modal else { panic!() };
        assert!(!text.contains("owner node"), "{text}");
    }

    /// A real ticket and its invite id.
    fn ticket() -> (String, String) {
        let t = crate::join::Ticket {
            mesh: "x".into(),
            owners: [1; 16],
            secret: [7; 16],
            expires: 0,
            owner_node: iroh::EndpointAddr::new(iroh::SecretKey::generate().public()),
        };
        (t.encode(), crate::join::invite_id(&[7; 16]))
    }

    fn pending(name: &str, boundaries: &[&str], invite: &str) -> PendingInfo {
        PendingInfo {
            name: name.into(),
            node_id: iroh::SecretKey::generate().public(),
            boundaries: boundaries.iter().map(|b| b.to_string()).collect(),
            replace: false,
            code: "123456".into(),
            expires_ms: 0,
            waiting: true,
            contested: false,
            invite: invite.into(),
        }
    }

    fn approving(a: &App) -> Option<String> {
        match &a.modal {
            Some(Modal::Form { kind: FormKind::Approve(p, ..), .. }) => Some(p.name.clone()),
            _ => None,
        }
    }

    #[test]
    fn a_makes_the_ticket_at_once_and_shows_both_one_liners() {
        let mut a = App::new();
        a.set_data(data(true));
        assert_eq!(
            a.on_key(key(KeyCode::Char('a'))),
            Some(Action::Job(Task::Invite { name: None, boundaries: vec![], ttl_secs: 3600 }))
        );
        assert!(matches!(a.modal, Some(Modal::Busy { .. })));
        let (t, inv) = ticket();
        a.on_msg(Msg::Ticket(t.clone()));
        assert!(matches!(&a.modal, Some(Modal::Keep { what: Keep::Ticket { invite, .. }, .. }) if *invite == inv));
        let [sh, ps] = crate::install::one_liners(&t, None);
        // Wide enough, each command is one row of its own, from column 0.
        let s = sized(&a, 400, 40);
        let rows: Vec<&str> = s.lines().map(str::trim_end).collect();
        for l in [&sh, &ps, &t] {
            assert!(rows.contains(&l.as_str()), "{l} in\n{s}");
        }
        assert!(s.contains("Waiting for the new machine…"), "{s}");
        // Narrower, they wrap, still starting at column 0 and with no borders.
        let s = screen(&a);
        for start in ["curl -fsSL ", "& ([scriptblock]", "tm2-"] {
            assert!(s.lines().any(|l| l.starts_with(start)), "{start} in\n{s}");
        }
        assert!(!s.contains('│') && !s.contains('╭'), "{s}");
        for (k, want) in [('c', &sh), ('P', &ps), ('t', &t)] {
            assert_eq!(a.on_key(key(KeyCode::Char(k))), Some(Action::Copy(Zeroizing::new(want.clone()))), "{k}");
        }
        a.on_key(key(KeyCode::Char('w')));
        assert!(matches!(&a.modal, Some(Modal::Keep { ask: Some((Ask::Path, p)), .. }) if p == "~/tearmesh-ticket.txt"));
        a.on_key(key(KeyCode::Esc));
        assert!(matches!(&a.modal, Some(Modal::Keep { ask: None, .. })), "Esc leaves the save prompt first");
        a.on_key(key(KeyCode::Esc));
        assert!(a.modal.is_none() && a.note.contains("still works"), "{}", a.note);
        // A member can't make one.
        let mut a = App::new();
        a.set_data(data(false));
        assert_eq!(a.on_key(key(KeyCode::Char('a'))), None);
        assert!(a.modal.is_none() && a.note.contains("only an owner node"));
    }

    #[test]
    fn a_matching_request_replaces_the_ticket_screen_once_and_others_wait() {
        let mut a = App::new();
        let mut d = data(true);
        a.set_data(d.clone());
        let (t, inv) = ticket();
        a.on_msg(Msg::Ticket(t));
        let other = pending("omega", &["work"], "ffffffffffff");
        d.status.as_mut().unwrap().pending_joins = vec![other.clone()];
        a.set_data(d.clone());
        assert!(matches!(a.modal, Some(Modal::Keep { .. })), "a request on another ticket waits");
        d.status.as_mut().unwrap().pending_joins = vec![other, pending("delta", &["work"], &inv)];
        a.set_data(d.clone());
        assert_eq!(approving(&a).as_deref(), Some("delta"), "{:?}", a.modal);
        a.on_key(key(KeyCode::Esc));
        // With nothing open, the waiting one pops up; then neither again.
        a.set_data(d.clone());
        assert_eq!(approving(&a).as_deref(), Some("omega"));
        a.on_key(key(KeyCode::Esc));
        a.set_data(d.clone());
        assert!(a.modal.is_none(), "{:?}", a.modal);
        // A new ticket screen isn't replaced by a request already asked about.
        a.on_msg(Msg::Ticket(ticket().0));
        a.set_data(d);
        assert!(matches!(a.modal, Some(Modal::Keep { .. })));
    }

    #[test]
    fn an_empty_proposal_needs_a_tick() {
        let mut a = App::new();
        let mut d = data(true);
        d.owner_key = Some(owner_key("pw-pw-pw-pw"));
        d.status.as_mut().unwrap().pending_joins = vec![pending("delta", &[], "")];
        a.set_data(d);
        let s = screen(&a);
        assert!(s.contains("asked for no boundaries: you pick") && s.contains("[ ] delta hosts work"), "{s}");
        a.auto_at = a.auto_at.map(|t| t - SETTLE);
        assert_eq!(a.on_key(key(KeyCode::Enter)), None);
        assert!(matches!(&a.modal, Some(Modal::Form { error: Some(e), .. }) if e.contains("tick at least one")), "{:?}", a.modal);
        a.on_key(key(KeyCode::Char(' ')));
        match a.on_key(key(KeyCode::Enter)) {
            Some(Action::Job(Task::Sign { changes, .. })) => {
                let shown: Vec<String> = changes.iter().map(|c| c.to_string()).collect();
                assert_eq!(shown, ["add machine delta hosting work"]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_machine_that_left_pops_up_once_on_an_owner_node() {
        let mut a = App::new();
        let mut d = data(true);
        d.owner_key = Some(owner_key("pw-pw-pw-pw"));
        d.status.as_mut().unwrap().leaving = vec!["beta".into()];
        a.set_data(d.clone());
        match &a.modal {
            Some(Modal::Form { kind: FormKind::Sign(c), title, .. }) => {
                assert_eq!((title.as_str(), c.as_slice()), ("Remove a machine that left", [Change::RemoveMachine("beta".into())].as_slice()));
            }
            other => panic!("{other:?}"),
        }
        assert!(screen(&a).contains("beta says it left"), "{}", screen(&a));
        a.on_key(key(KeyCode::Esc));
        a.set_data(d.clone());
        assert!(a.modal.is_none(), "once");
        assert!(screen(&a).contains("beta (says it left)"), "{}", screen(&a));
        // A member only sees the row.
        let mut a = App::new();
        let mut d = data(false);
        d.status.as_mut().unwrap().leaving = vec!["beta".into()];
        a.set_data(d);
        assert!(a.modal.is_none());
    }

    #[test]
    fn dissolve_needs_the_exact_mesh_name() {
        let mut a = App::new();
        let mut d = data(true);
        d.owner_key = Some(owner_key("pw-pw-pw-pw"));
        a.set_data(d);
        a.tab = Tab::Settings;
        assert!(a.shortcuts().contains(&("Shift-K", "Dissolve mesh")));
        a.on_key(key(KeyCode::Char('k')));
        assert!(a.modal.is_none(), "a plain k moves the selection");
        a.on_key(key(KeyCode::Char('K')));
        assert!(matches!(&a.modal, Some(Modal::Form { kind: FormKind::Dissolve, .. })));
        assert!(screen(&a).contains("removes all 3 machines"), "{}", screen(&a));
        typed(&mut a, "Home");
        assert_eq!(a.on_key(key(KeyCode::Enter)), None);
        assert!(matches!(&a.modal, Some(Modal::Form { error: Some(e), .. }) if e.contains("exactly (home)")));
        a.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        typed(&mut a, "home");
        a.on_key(key(KeyCode::Enter));
        assert!(matches!(&a.modal, Some(Modal::Form { kind: FormKind::Sign(c), .. }) if *c == [Change::Dissolve]), "{:?}", a.modal);
        typed(&mut a, "pw-pw-pw-pw");
        assert!(matches!(a.on_key(key(KeyCode::Enter)), Some(Action::Job(Task::Sign { changes, .. })) if changes == [Change::Dissolve]));
        // Not for a member.
        let mut a = App::new();
        a.set_data(data(false));
        a.tab = Tab::Settings;
        a.on_key(key(KeyCode::Char('K')));
        assert!(a.modal.is_none() && a.note.contains("only an owner node"));
    }

    #[test]
    fn a_boundary_user_sees_who_they_are_and_starts_on_mail() {
        let mut a = App::new();
        a.set_data(Data { who: Some(("admin@laptop".into(), "work".into())), ..Default::default() });
        assert_eq!(a.role(), Role::BoundaryUser);
        assert_eq!(a.tab, Tab::Mail);
        assert!(screen(&a).contains("BOUNDARY USER"), "{}", screen(&a));
        a.on_key(key(KeyCode::Esc));
        let s = screen(&a);
        assert!(s.contains("admin@laptop") && s.contains("boundary") && s.contains("Mail tab") && s.contains("admin of this machine"), "{s}");
        assert!(!s.contains("NOT SET UP") && !s.contains("isn't answering"), "{s}");
        assert!(!a.shortcuts().iter().any(|(k, _)| matches!(*k, "C" | "J" | "I")));
        a.on_key(key(KeyCode::Char('c')));
        assert!(a.modal.is_none(), "no Create for a boundary user");
        a.on_key(key(KeyCode::Right));
        a.on_key(key(KeyCode::Right));
        assert_eq!(a.tab, Tab::Settings);
        assert!(a.shortcuts().contains(&("Shift-H", "Start MCP hub")));
        assert!(!a.shortcuts().iter().any(|(_, l)| *l == "Uninstall"));
        a.on_key(key(KeyCode::Char('x')));
        assert!(a.modal.is_none(), "uninstall needs an admin");
    }

    #[test]
    fn a_failed_fetch_of_the_membership_file_keeps_the_last_one() {
        let mut a = App::new();
        a.set_data(data(false));
        assert_eq!(a.role(), Role::Member);
        let mut d = data(false);
        d.mesh = None;
        a.set_data(d);
        assert_eq!(a.role(), Role::Member);
        assert!(a.data.mesh.is_some());
    }

    #[test]
    fn a_shell_names_a_boundary_both_machines_host() {
        let mut a = App::new();
        a.set_data(data(false));
        assert_eq!(a.shared_boundary("beta").as_deref(), Some("work"));
        assert_eq!(a.shared_boundary("nobody"), None);
        a.sel = 1;
        assert_eq!(a.selected_machine().as_deref(), Some("beta"));
        a.on_key(key(KeyCode::Char('x')));
        // (the Action carries it; run_action decides by Hello whether the daemon maps this user)
        assert_eq!(a.key(key(KeyCode::Char('x'))), Some(Action::Ssh { machine: "beta".into(), boundary: Some("work".into()) }));
    }

    #[test]
    fn a_form_error_puts_the_cursor_on_its_field() {
        let mut a = App::new();
        a.set_data(data(true));
        a.form(FormKind::Grant);
        a.on_key(key(KeyCode::Tab));
        a.on_key(key(KeyCode::Tab));
        a.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        typed(&mut a, "telepathy");
        a.on_key(key(KeyCode::Up));
        a.on_key(key(KeyCode::Up));
        a.on_key(key(KeyCode::Enter));
        assert!(matches!(&a.modal, Some(Modal::Form { error: Some(e), focus, fields, .. })
            if e.contains("categories") && matches!(&fields[*focus], Field::Text { label, .. } if label.starts_with("Categories"))), "{:?}", a.modal);
    }
}
