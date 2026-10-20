//! `tearmesh menu`: a full-screen terminal UI for running a machine in a mesh. Arrow keys (or
//! the keypad) move, Enter picks, Esc goes back, and a shortcut bar along the bottom shows the
//! keys for the current screen, like nano's.
//!
//! It shows live state (the daemon's status, which machines answer a ping, recent changes) and
//! acts directly, without leaving the screen: creating or joining a mesh, inviting, approving a
//! join (its code, boundaries and grants in one signature), and every change an owner signs. It
//! takes the owner key's passphrase itself and signs in this process. Only plain programs (SSH,
//! the mail client) and security keys, which sign with ssh-keygen, suspend the menu. The menu is
//! an owner node's when an owner key for the mesh is in ~/.ssh; only then does it show the Owner
//! screen and the actions that sign.

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
use crate::mesh::{Category, Change, Grant, Mesh};
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
    Overview,
    Map,
    Nodes,
    Mail,
    Logs,
    Settings,
    Owner,
    Help,
}

const TABS: [Tab; 8] = [
    Tab::Overview,
    Tab::Map,
    Tab::Nodes,
    Tab::Mail,
    Tab::Logs,
    Tab::Settings,
    Tab::Owner,
    Tab::Help,
];

impl Tab {
    fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Map => "Map",
            Tab::Nodes => "Nodes",
            Tab::Mail => "Mail",
            Tab::Logs => "Logs",
            Tab::Settings => "Settings",
            Tab::Owner => "Owner",
            Tab::Help => "Help",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// No daemon answer, or no mesh yet.
    NotSetUp,
    Member,
    /// An owner key for this mesh is on this machine.
    Owner,
}

/// What the menu asks the runtime to do.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Suspend the menu and run `tearmesh <args>` in the terminal.
    Run { args: Vec<String> },
    /// Suspend and SSH to a machine over the mesh.
    Ssh { machine: String },
    StartHub,
    Refresh,
    /// Start background work; its screen is already open.
    Job(Task),
    /// Stop watching the running job.
    Cancel,
    /// Put text on the clipboard (OSC 52).
    Copy(Zeroizing<String>),
    /// A security key: sign with ssh-keygen in the plain terminal, then apply.
    SignOutside { key: PathBuf, changes: Vec<Change> },
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
    Invite,
    Grant,
    Revoke,
    Relays,
    OwnerAdd,
    Create,
    Join,
    /// A join request: add it, with any boundaries and grants ticked, in one signature.
    Approve(Box<PendingInfo>),
    /// Sign these changes.
    Sign(Vec<Change>),
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
    Ticket(String),
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
    Info {
        title: String,
        text: String,
    },
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

fn secret(label: &str) -> Field {
    // Reserved up front so typing never reallocates and leaves a copy behind.
    Field::Secret { label: label.into(), value: Zeroizing::new(String::with_capacity(256)) }
}

fn check(label: &str) -> Field {
    Field::Check { label: label.into(), on: false }
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
        Task::Sign { .. } => ("Sign", "Signing and applying…", false, false),
        Task::Reject { .. } => ("Refuse", "Refusing…", false, false),
        Task::JoinCancel => ("Join a mesh", "Cancelling the request…", false, false),
    };
    Modal::Busy { title: title.into(), text: text.into(), hold, join }
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
    pub owner_key: Option<PathBuf>,
    pub hub_running: bool,
    pub hub_url: String,
    pub journal: Vec<String>,
}

pub struct App {
    pub tab: Tab,
    pub data: Data,
    /// Selected row on the Nodes and Owner screens.
    pub sel: usize,
    pub modal: Option<Modal>,
    pub log: VecDeque<String>,
    pub note: String,
    pub quit: bool,
    pub mailbox: String,
    /// This machine's config, for the create and join screens.
    pub cfg: Option<Config>,
    /// Join requests that already got a popup.
    asked: Vec<iroh::EndpointId>,
    /// The form to reopen, with the error, when its job fails.
    back: Option<Modal>,
}

impl App {
    pub fn new() -> App {
        App {
            tab: Tab::Overview,
            data: Data::default(),
            sel: 0,
            modal: None,
            log: VecDeque::new(),
            note: String::new(),
            quit: false,
            mailbox: std::env::var("TEARMESH_MAILBOX").unwrap_or_else(|_| "admin".into()),
            cfg: None,
            asked: vec![],
            back: None,
        }
    }

    pub fn role(&self) -> Role {
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

    pub fn tabs(&self) -> Vec<Tab> {
        TABS.iter()
            .copied()
            .filter(|t| *t != Tab::Owner || self.role() == Role::Owner)
            .collect()
    }

    fn say(&mut self, s: impl Into<String>) {
        let s = s.into();
        let stamp = clock();
        self.log.push_front(format!("{stamp}  {s}"));
        self.log.truncate(500);
    }

    /// Takes fresh data, noting what changed in the log.
    pub fn set_data(&mut self, d: Data) {
        let old = std::mem::take(&mut self.data);
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
                self.say(format!("join request from {n}: approve it on the Owner screen"));
            }
        }
        let mut d = d;
        if d.pings.is_empty() {
            d.pings = old.pings;
            d.pinged_at = old.pinged_at;
        }
        self.data = d;
        if !self.tabs().contains(&self.tab) {
            self.tab = Tab::Overview;
        }
        // A new join request opens its approval on an owner node, once.
        if self.role() == Role::Owner && self.modal.is_none() {
            let new = self
                .data
                .status
                .as_ref()
                .and_then(|s| s.pending_joins.iter().find(|p| !self.asked.contains(&p.node_id)).cloned());
            if let Some(p) = new {
                self.asked.push(p.node_id);
                self.approve(p);
            }
        }
    }

    fn machines(&self) -> Vec<&crate::mesh::Machine> {
        self.data
            .mesh
            .as_ref()
            .map(|m| m.machines.iter().collect())
            .unwrap_or_default()
    }

    fn this_machine(&self) -> String {
        self.data
            .status
            .as_ref()
            .map(|s| s.machine.clone())
            .unwrap_or_default()
    }

    fn rows(&self) -> usize {
        match self.tab {
            Tab::Nodes => self.machines().len(),
            Tab::Owner => {
                let p = self.data.status.as_ref().map_or(0, |s| s.pending_joins.len());
                let k = self.data.mesh.as_ref().map_or(0, |m| m.owners.len());
                p + k
            }
            _ => 0,
        }
    }

    fn open(&mut self, kind: FormKind, title: &str, fields: Vec<Field>) {
        let focus = fields.iter().position(|f| !matches!(f, Field::Note(_))).unwrap_or(0);
        self.modal = Some(Modal::Form { kind, title: title.into(), fields, focus, error: None });
    }

    /// Opens the screen that signs `changes` with this machine's owner key.
    fn sign(&mut self, title: &str, text: String, changes: Vec<Change>) -> Option<Action> {
        let key = self.data.owner_key.clone()?;
        match keys::signer(&key) {
            Signer::Outside => {
                self.modal = Some(Modal::Confirm {
                    text: format!("{text}\n\nThis key signs with ssh-keygen in the plain terminal: touch it when it blinks."),
                    action: Action::SignOutside { key, changes },
                });
            }
            Signer::Here { encrypted } => {
                let mut f = vec![Field::Note(text)];
                f.push(if encrypted {
                    secret(&format!("Passphrase for {}", key.display()))
                } else {
                    Field::Note("Enter signs and applies it.".into())
                });
                self.open(FormKind::Sign(changes), title, f);
            }
        }
        None
    }

    /// The boxes the approval offers: boundaries to add, then grants.
    fn approve_options(&self, p: &PendingInfo) -> Vec<(String, Change)> {
        let Some(mesh) = &self.data.mesh else { return vec![] };
        let me = self.this_machine();
        let n = &p.name;
        let mut v: Vec<(String, Change)> = p
            .boundaries
            .iter()
            .filter(|b| !mesh.boundaries.contains(b))
            .map(|b| (format!("Add boundary {b} to the mesh"), Change::AddBoundary(b.clone())))
            .collect();
        let g = |from: &str, to: &str, c: Category| {
            Change::Grant(Grant { from: from.into(), to: to.into(), allow: vec![c] })
        };
        if !mesh.allows(n, &me, Category::Converse) {
            v.push((format!("{n} may mail {me}"), g(n, &me, Category::Converse)));
            v.push((format!("{me} may mail {n}"), g(&me, n, Category::Converse)));
        }
        v.push((format!("{n} may use {me}'s tools"), g(n, &me, Category::Tools)));
        v.push((format!("{n} may open a shell on {me}"), g(n, &me, Category::Shell)));
        v.push((format!("{me} may use {n}'s tools"), g(&me, n, Category::Tools)));
        v.push((format!("{me} may open a shell on {n}"), g(&me, n, Category::Shell)));
        v
    }

    /// Opens the approval for a join request.
    fn approve(&mut self, p: PendingInfo) {
        let mut f = vec![
            Field::Note(format!("{} wants to join with boundaries {}.", p.name, p.boundaries.join(", "))),
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
        f.extend(self.approve_options(&p).into_iter().map(|(l, _)| check(&l)));
        let mail = self.data.mesh.as_ref().is_some_and(|m| m.allows(&p.name, &self.this_machine(), Category::Converse));
        if mail {
            f.push(Field::Note("Everyone may already mail everyone.".into()));
        }
        match self.data.owner_key.as_ref().map(|k| (k, keys::signer(k))) {
            Some((k, Signer::Here { encrypted: true })) => f.push(secret(&format!("Passphrase for {}", k.display()))),
            Some((_, Signer::Outside)) => f.push(Field::Note("This key signs with ssh-keygen in the plain terminal.".into())),
            _ => {}
        }
        self.open(FormKind::Approve(Box::new(p)), "Join request", f);
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
                Modal::Form { kind: FormKind::Approve(_), .. } => {
                    vec![("Tab", "Next"), ("Space", "Tick"), ("Enter", "Approve"), ("Esc", "Later")]
                }
                Modal::Form { fields, .. } if fields.iter().any(|f| matches!(f, Field::Check { .. })) => {
                    vec![("Tab", "Next"), ("Space", "Tick"), ("Enter", "Submit"), ("Esc", "Cancel")]
                }
                Modal::Form { .. } => vec![("Tab", "Next field"), ("Enter", "Submit"), ("Esc", "Cancel")],
                Modal::Confirm { .. } => vec![("Y", "Yes"), ("N", "No"), ("Esc", "Cancel")],
                Modal::Info { .. } => vec![("Enter", "Close"), ("Esc", "Close")],
                Modal::Busy { hold: true, .. } => vec![],
                Modal::Busy { join: true, .. } => vec![("Esc", "Hide (keeps waiting)")],
                Modal::Busy { .. } => vec![("Esc", "Stop")],
                Modal::Keep { ask: Some(_), .. } => vec![("Enter", "OK"), ("Esc", "Back")],
                Modal::Keep { what: Keep::Ticket(_), .. } => vec![("C", "Copy"), ("W", "Save to file"), ("Enter", "Close")],
                Modal::Keep { what: Keep::Recovery(_), .. } => vec![
                    ("C", "Copy key"),
                    ("P", "Copy passphrase"),
                    ("W", "Save key to file"),
                    ("Y", "I've saved them"),
                    ("Esc", "Cancel"),
                ],
            };
        }
        let owner = self.role() == Role::Owner;
        let mut v = vec![("←→", "Tabs")];
        match self.tab {
            Tab::Overview => {
                if self.role() == Role::NotSetUp {
                    v.extend([("C", "Create a mesh"), ("J", "Join a mesh")]);
                    if self.joining() {
                        v.push(("X", "Cancel join"));
                    }
                } else {
                    v.push(("S", "Status JSON"));
                }
            }
            Tab::Map => v.push(("P", "Ping now")),
            Tab::Nodes => {
                v.push(("↑↓", "Select"));
                v.push(("Enter", "Details"));
                v.push(("X", "Shell"));
                if owner {
                    v.extend([("C", "Connect new"), ("D", "Disconnect"), ("G", "Grant"), ("V", "Revoke grant")]);
                } else if self.role() == Role::Member {
                    v.push(("L", "Leave mesh"));
                }
            }
            Tab::Mail => v.push(("Enter", "Open mail")),
            Tab::Logs => v.push(("E", "Clear")),
            Tab::Settings => {
                v.push(("H", "Start MCP hub"));
                v.push(("U", "Hub info"));
                if owner {
                    v.extend([("T", "Tools sharing"), ("Y", "Relays")]);
                }
            }
            Tab::Owner => v.extend([
                ("↑↓", "Select"),
                ("A", "Approve"),
                ("X", "Refuse"),
                ("I", "Invite"),
                ("K", "Revoke machine"),
                ("N", "Add owner key"),
                ("Z", "Remove key"),
            ]),
            Tab::Help => {}
        }
        v.extend([("R", "Refresh"), ("?", "Help"), ("Q", "Quit")]);
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
        let tabs = self.tabs();
        let at = tabs.iter().position(|t| *t == self.tab).unwrap_or(0);
        let rows = self.tab != Tab::Overview;
        let code = match k.code {
            // The keypad with Num Lock on sends digits.
            KeyCode::Char('4') | KeyCode::Char('h') => KeyCode::Left,
            KeyCode::Char('6') | KeyCode::Char('l') => KeyCode::Right,
            KeyCode::Char('8') => KeyCode::Up,
            KeyCode::Char('2') => KeyCode::Down,
            // The Overview has no rows, and J joins there.
            KeyCode::Char('k') if rows => KeyCode::Up,
            KeyCode::Char('j') if rows => KeyCode::Down,
            KeyCode::Char(c) => KeyCode::Char(c.to_ascii_lowercase()),
            c => c,
        };
        match code {
            KeyCode::Left => {
                self.tab = tabs[(at + tabs.len() - 1) % tabs.len()];
                self.sel = 0;
            }
            KeyCode::Right | KeyCode::Tab => {
                self.tab = tabs[(at + 1) % tabs.len()];
                self.sel = 0;
            }
            KeyCode::Up => self.sel = self.sel.saturating_sub(1),
            KeyCode::Down => {
                if self.sel + 1 < self.rows() {
                    self.sel += 1;
                }
            }
            KeyCode::Esc => {
                self.tab = Tab::Overview;
                self.sel = 0;
            }
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') => self.tab = Tab::Help,
            KeyCode::Char('r') => return Some(Action::Refresh),
            _ => return self.tab_key(code),
        }
        None
    }

    fn selected_machine(&self) -> Option<String> {
        self.machines().get(self.sel).map(|m| m.name.clone())
    }

    fn selected_pending(&self) -> Option<PendingInfo> {
        self.data.status.as_ref()?.pending_joins.get(self.sel).cloned()
    }

    fn tab_key(&mut self, code: KeyCode) -> Option<Action> {
        let run = |a: &[&str]| Action::Run {
            args: a.iter().map(|s| s.to_string()).collect(),
        };
        let not_set_up = self.role() == Role::NotSetUp;
        match (self.tab, code) {
            (Tab::Overview, KeyCode::Char('c')) if not_set_up => {
                self.create_form();
                None
            }
            (Tab::Overview, KeyCode::Char('j')) if not_set_up => {
                self.join_form();
                None
            }
            (Tab::Overview, KeyCode::Char('x')) if self.joining() => Some(Action::Job(Task::JoinCancel)),
            (Tab::Overview, KeyCode::Char('s')) if !not_set_up => Some(run(&["status"])),
            (Tab::Map, KeyCode::Char('p')) => Some(Action::Refresh),
            (Tab::Nodes, KeyCode::Enter) => {
                let name = self.selected_machine()?;
                self.modal = Some(Modal::Info {
                    title: name.clone(),
                    text: self.details(&name),
                });
                None
            }
            (Tab::Nodes, KeyCode::Char('x')) => {
                let m = self.selected_machine()?;
                if m == self.this_machine() {
                    self.note = "that's this machine".into();
                    return None;
                }
                Some(Action::Ssh { machine: m })
            }
            (Tab::Nodes, KeyCode::Char('c')) | (Tab::Owner, KeyCode::Char('i')) => {
                if self.need_owner() {
                    self.form(FormKind::Invite);
                }
                None
            }
            (Tab::Nodes, KeyCode::Char('d')) | (Tab::Owner, KeyCode::Char('k')) => {
                if !self.need_owner() {
                    return None;
                }
                if self.tab == Tab::Owner {
                    self.note = "pick the machine here and press D to revoke it".into();
                    self.tab = Tab::Nodes;
                    self.sel = 0;
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
            (Tab::Nodes, KeyCode::Char('g')) => {
                if self.need_owner() {
                    self.form(FormKind::Grant);
                }
                None
            }
            (Tab::Nodes, KeyCode::Char('v')) => {
                if self.need_owner() {
                    self.form(FormKind::Revoke);
                }
                None
            }
            (Tab::Nodes, KeyCode::Char('l')) if self.role() == Role::Member => Some(run(&["mesh", "reset"])),
            (Tab::Mail, KeyCode::Enter) => Some(Action::Run {
                args: vec!["tui".into(), "--mailbox".into(), self.mailbox.clone()],
            }),
            (Tab::Logs, KeyCode::Char('e')) => {
                self.log.clear();
                None
            }
            (Tab::Settings, KeyCode::Char('h')) => Some(Action::StartHub),
            (Tab::Settings, KeyCode::Char('u')) => Some(run(&["mcp", "info"])),
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
            (Tab::Owner, KeyCode::Char('a')) => {
                let p = self.selected_pending()?;
                self.approve(p);
                None
            }
            (Tab::Owner, KeyCode::Char('x')) => {
                let p = self.selected_pending()?;
                self.modal = Some(Modal::Confirm {
                    text: format!("Refuse {}'s request to join? Its ticket stops working.", p.name),
                    action: Action::Job(Task::Reject { name: p.name }),
                });
                None
            }
            (Tab::Owner, KeyCode::Char('n')) => {
                self.form(FormKind::OwnerAdd);
                None
            }
            (Tab::Owner, KeyCode::Char('z')) => {
                let pend = self.data.status.as_ref().map_or(0, |s| s.pending_joins.len());
                let i = self.sel.checked_sub(pend)?;
                let fp = self.data.status.as_ref()?.mesh.as_ref()?.owners.get(i)?.clone();
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
        s += "\ngrants\n";
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
            FormKind::Invite => (
                "Invite a machine",
                vec![
                    Field::Note("Everything is optional: the new machine proposes its name and boundaries, and you approve them.".into()),
                    text("Name (optional)", ""),
                    text("Boundaries (optional, e.g. work,vault)", ""),
                    text("Ticket works for", "1h"),
                ],
            ),
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
        let modal = self.modal.as_mut()?;
        match modal {
            Modal::Info { .. } => {
                if matches!(k.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
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
                    "Still waiting in the background: the Overview shows the code, and X there cancels the request.".into()
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
                            Keep::Ticket(t) => format!("{t}\n"),
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
                            buf.clear();
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
        match k.code {
            KeyCode::Char('c') | KeyCode::Char('C') => {
                *note = "Sent to the clipboard. If nothing arrived (tmux needs `set -g set-clipboard on`), press W to save it to a file.".into();
                return Some(Action::Copy(Zeroizing::new(match what {
                    Keep::Ticket(t) => t.clone(),
                    Keep::Recovery(m) => m.recovery.private.to_string(),
                })));
            }
            KeyCode::Char('p') | KeyCode::Char('P') if recovery => {
                let Keep::Recovery(m) = what else { return None };
                *note = "Passphrase sent to the clipboard.".into();
                return Some(Action::Copy(m.recovery_pass.clone()));
            }
            KeyCode::Char('w') | KeyCode::Char('W') => {
                let name = match what {
                    Keep::Ticket(_) => "~/tearmesh-ticket.txt".to_string(),
                    Keep::Recovery(m) => format!("~/tearmesh-recovery-{}.key", m.name),
                };
                *ask = Some((Ask::Path, name));
            }
            KeyCode::Char('y') | KeyCode::Char('Y') if recovery => *ask = Some((Ask::Word, String::new())),
            KeyCode::Enter if !recovery => self.modal = None,
            KeyCode::Esc => {
                self.modal = None;
                if recovery {
                    self.note = "Cancelled. Nothing was changed.".into();
                }
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
            Msg::Ticket(t) => {
                self.back = None;
                self.modal = Some(Modal::Keep { what: Keep::Ticket(t), ask: None, note: String::new() });
            }
            Msg::Keys(m) => {
                self.back = None;
                self.modal = Some(Modal::Keep { what: Keep::Recovery(m), ask: None, note: String::new() });
            }
            Msg::Done(text) => {
                self.back = None;
                self.say(text.lines().next().unwrap_or_default().to_string());
                self.modal = Some(Modal::Info { title: "Done".into(), text });
            }
            Msg::Failed(e) => {
                self.say(format!("failed: {e}"));
                self.modal = match self.back.take() {
                    Some(Modal::Form { kind, title, fields, focus, .. }) => {
                        Some(Modal::Form { kind, title, fields, focus, error: Some(e) })
                    }
                    _ => Some(Modal::Info { title: "That didn't work".into(), text: e }),
                };
            }
        }
    }

    /// Checks a form and turns it into what to do next (a job, or another screen it opens).
    /// Errors keep the form open.
    pub fn submit(&mut self, kind: &FormKind, f: &[Field]) -> Result<Option<Action>, String> {
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
        let name = |s: &str, what: &str| {
            if crate::valid_name(s) {
                Ok(s.to_string())
            } else {
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
                _ => Err("categories: converse, tools and/or shell".into()),
            }
        };
        let known = self.data.mesh.as_ref().map(|m| m.boundaries.clone()).unwrap_or_default();
        match kind {
            FormKind::Invite => {
                let n = if v[0].is_empty() { None } else { Some(name(&v[0], "name")?) };
                if let Some(n) = &n
                    && self.machines().iter().any(|m| &m.name == n)
                {
                    return Err(format!("{n} is already in the mesh; disconnect it first or pick another name"));
                }
                let b = list(&v[1]);
                if let Some(x) = b.iter().find(|x| !known.contains(x)) {
                    return Err(format!("the mesh has no boundary {x} (it has {})", known.join(", ")));
                }
                let ttl = parse_ttl(&v[2]).ok_or("ticket works for: like 30m, 2h or 1d")?;
                Ok(Some(Action::Job(Task::Invite { name: n, boundaries: b, ttl_secs: ttl })))
            }
            FormKind::Grant | FormKind::Revoke => {
                let from = if v[0] == "*" { "*".into() } else { name(&v[0], "from")? };
                let to = if v[1] == "*" { "*".into() } else { name(&v[1], "to")? };
                let c = cats(&v[2])?;
                if *kind == FormKind::Grant && c.contains(&Category::Shell) && (from == "*" || to == "*") {
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
            FormKind::Relays => {
                let r = v[0].clone();
                if r != "n0" && r != "none" && !list(&r).iter().all(|u| u.starts_with("https://") || u.starts_with("http://")) {
                    return Err("n0, none, or relay URLs separated by commas".into());
                }
                Ok(self.sign("Relays", format!("Set relays to {r}."), vec![Change::Set { setting: "relays".into(), value: r }]))
            }
            FormKind::OwnerAdd => {
                let p = std::path::Path::new(&v[0]);
                let fp = crate::setup::fingerprint_of(p).ok_or("that isn't a readable OpenSSH public key (.pub) file")?;
                let k = std::fs::read_to_string(p).map_err(|e| e.to_string())?;
                Ok(self.sign("Add an owner key", format!("Add owner key {fp}."), vec![Change::OwnerAdd(k)]))
            }
            FormKind::Create => {
                crate::setup::check_mesh_name(&v[0]).map_err(|e| e.to_string())?;
                let cfg = self.cfg.as_ref().ok_or("can't read this machine's config (install tear-mesh first, or set TEARMESH_CONFIG)")?;
                crate::setup::boundaries(cfg).map_err(|e| e.to_string())?;
                crate::setup::check_passphrase(pass[0], pass[1]).map_err(|e| e.to_string())?;
                Ok(Some(Action::Job(Task::NewMesh { name: v[0].clone(), pass: pass[0].clone() })))
            }
            FormKind::Join => {
                let t: String = v[0].chars().filter(|c| !c.is_whitespace()).collect();
                crate::setup::check_ticket(&t).map_err(|e| e.to_string())?;
                let ticket = crate::join::Ticket::decode(&t).map_err(|_| "that ticket is incomplete; paste the whole thing")?;
                if ticket.expires + 3600 <= crate::now_ms() / 1000 {
                    return Err("that ticket expired; ask the owner node for a new one".into());
                }
                Ok(Some(Action::Job(Task::Join { ticket: t })))
            }
            FormKind::Approve(p) => {
                let mesh = self.data.mesh.as_ref().ok_or("no mesh")?;
                let (mut add, mut grants) = (vec![], vec![]);
                for ((_, c), on) in self.approve_options(p).into_iter().zip(ticks) {
                    match (c, on) {
                        (Change::AddBoundary(b), true) => add.push(b),
                        (Change::Grant(g), true) => grants.push(g),
                        _ => {}
                    }
                }
                let changes = p.changes(mesh, &add, &grants).map_err(|e| format!("{e:#}"))?;
                let key = self.data.owner_key.clone().ok_or("no owner key on this machine")?;
                Ok(Some(match keys::signer(&key) {
                    Signer::Outside => Action::SignOutside { key, changes },
                    Signer::Here { .. } => Action::Job(Task::Sign {
                        key,
                        pass: pass.first().map(|p| (*p).clone()).unwrap_or_default(),
                        changes,
                    }),
                }))
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
            Constraint::Length(2),
        ])
        .areas(f.area());
        self.draw_head(f, head);
        match self.tab {
            Tab::Overview => self.draw_overview(f, body),
            Tab::Map => self.draw_map(f, body),
            Tab::Nodes => self.draw_nodes(f, body),
            Tab::Mail => self.draw_mail(f, body),
            Tab::Logs => self.draw_logs(f, body),
            Tab::Settings => self.draw_settings(f, body),
            Tab::Owner => self.draw_owner(f, body),
            Tab::Help => draw_help(f, body),
        }
        f.render_widget(Paragraph::new(self.note.as_str()).fg(Color::Yellow), note);
        draw_bar(f, bar, &self.shortcuts());
        if let Some(m) = &self.modal {
            draw_modal(f, m);
        }
    }

    fn draw_head(&self, f: &mut Frame, area: Rect) {
        let tabs = self.tabs();
        let at = tabs.iter().position(|t| *t == self.tab).unwrap_or(0);
        let (role, color) = match self.role() {
            Role::Owner => ("OWNER NODE", TEAR),
            Role::Member => ("MEMBER", ACCENT),
            Role::NotSetUp => ("NOT SET UP", Color::Yellow),
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
        let t = Tabs::new(tabs.iter().map(|t| t.title()))
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

    fn draw_overview(&self, f: &mut Frame, area: Rect) {
        let [logo, rest] =
            Layout::vertical([Constraint::Length(LOGO.len() as u16 + 1), Constraint::Min(3)]).areas(area);
        f.render_widget(Paragraph::new(logo_text(LOGO[0].chars().count())).alignment(Alignment::Center), logo);
        let mut lines: Vec<Line> = vec![];
        let kv = |k: &str, v: String| {
            Line::from(vec![Span::styled(format!("  {k:<14}"), Style::new().fg(DIM)), Span::raw(v)])
        };
        if let Some(e) = &self.data.error {
            lines.push(Line::styled(format!("  The daemon isn't answering: {e}"), Style::new().fg(BAD)));
            lines.push(Line::raw("  Install tear-mesh first (sudo tearmesh install <machine> <boundary>...), or start it"));
            lines.push(Line::raw("  (sudo systemctl start tearmesh, or Start-Service tearmesh)."));
        } else if let Some(s) = &self.data.status {
            match &s.mesh {
                Some(m) => {
                    let (up, n) = self.online();
                    lines.push(kv("mesh", format!("{} (version {})", m.name, m.version)));
                    lines.push(kv("machine", format!("{}  {}", s.machine, short(&s.node_id.to_string()))));
                    lines.push(kv("boundaries", m.hosts.join(", ")));
                    lines.push(kv("reachable", format!("{up} of {n} other machines")));
                    lines.push(kv(
                        "role",
                        match &self.data.owner_key {
                            Some(k) => format!("owner node (key {})", k.display()),
                            None => "member (no owner key here)".into(),
                        },
                    ));
                    lines.push(kv("owner keys", m.owners.len().to_string()));
                    if !s.pending_joins.is_empty() {
                        lines.push(Line::styled(
                            format!("  {} join request(s) waiting: see the Owner screen", s.pending_joins.len()),
                            Style::new().fg(Color::Yellow).bold(),
                        ));
                    }
                }
                None => {
                    lines.push(kv("machine", format!("{}  {}", s.machine, short(&s.node_id.to_string()))));
                    lines.push(Line::raw(""));
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
                        }
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
        let [map, side] = Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)]).areas(area);
        let me = self.this_machine();
        let peers: Vec<String> = self.machines().iter().map(|m| m.name.clone()).filter(|n| *n != me).collect();
        let pings = self.data.pings.clone();
        let state = move |n: &str| pings.iter().find(|p| p.name == n).map(|p| p.rtt_ms);
        let st = state.clone();
        let me2 = me.clone();
        let peers2 = peers.clone();
        let canvas = Canvas::default()
            .block(self.panel("Map"))
            .marker(Marker::Braille)
            .x_bounds([-100.0, 100.0])
            .y_bounds([-60.0, 60.0])
            .paint(move |ctx| {
                let n = peers2.len().max(1) as f64;
                let pos = |i: usize| {
                    let a = std::f64::consts::TAU * i as f64 / n + std::f64::consts::FRAC_PI_2;
                    (a.cos() * 70.0, a.sin() * 42.0)
                };
                for (i, p) in peers2.iter().enumerate() {
                    let (x, y) = pos(i);
                    let c = match st(p) {
                        Some(Some(_)) => OK,
                        Some(None) => BAD,
                        None => DIM,
                    };
                    ctx.draw(&CLine { x1: 0.0, y1: 0.0, x2: x, y2: y, color: c });
                }
                ctx.layer();
                ctx.print(-(me2.len() as f64) * 1.5, 0.0, Span::styled(format!("◉ {me2}"), Style::new().fg(TEAR).bold()));
                for (i, p) in peers2.iter().enumerate() {
                    let (x, y) = pos(i);
                    let (dot, c, info) = match st(p) {
                        Some(Some(ms)) => ("●", OK, format!(" {ms}ms")),
                        Some(None) => ("○", BAD, " down".into()),
                        None => ("◌", DIM, String::new()),
                    };
                    ctx.print(x - (p.len() as f64) * 1.5, y, Span::styled(format!("{dot} {p}{info}"), Style::new().fg(c).bold()));
                }
            });
        f.render_widget(canvas, map);
        let mut rows = vec![];
        for p in &peers {
            let (s, c) = match state(p) {
                Some(Some(ms)) => (format!("● {ms} ms"), OK),
                Some(None) => ("○ no answer".into(), BAD),
                None => ("◌ not pinged".into(), DIM),
            };
            rows.push(Row::new(vec![Cell::from(p.clone()), Cell::from(s).fg(c)]));
        }
        let age = self
            .data
            .pinged_at
            .map(|t| format!("pinged {}s ago", t.elapsed().as_secs()))
            .unwrap_or_else(|| "pinging…".into());
        let t = Table::new(rows, [Constraint::Min(10), Constraint::Length(16)])
            .header(Row::new(vec!["machine", "ping"]).style(Style::new().fg(DIM)))
            .block(self.panel(&format!("Devices · {age}")));
        f.render_widget(t, side);
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
        let grants = |n: &str| -> String {
            let Some(m) = &self.data.mesh else { return String::new() };
            let to: Vec<&str> = [Category::Converse, Category::Tools, Category::Shell]
                .into_iter()
                .filter(|c| n != me && m.allows(&me, n, *c))
                .map(cat)
                .collect();
            to.join(" ")
        };
        let rows: Vec<Row> = self
            .machines()
            .iter()
            .enumerate()
            .map(|(i, m)| {
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
                let mut r = Row::new(vec![
                    Cell::from(m.name.clone()),
                    Cell::from(ping).fg(c),
                    Cell::from(m.boundaries.join(",")),
                    Cell::from(grants(&m.name)),
                    Cell::from(sync),
                ]);
                if i == self.sel {
                    r = r.style(Style::new().bg(Color::Indexed(236)).bold());
                }
                r
            })
            .collect();
        let t = Table::new(
            rows,
            [
                Constraint::Min(12),
                Constraint::Length(14),
                Constraint::Length(16),
                Constraint::Length(22),
                Constraint::Length(10),
            ],
        )
        .header(Row::new(vec!["machine", "ping", "boundaries", "this → it", "synced"]).style(Style::new().fg(DIM)))
        .block(self.panel("Nodes"));
        f.render_widget(t, area);
    }

    fn draw_mail(&self, f: &mut Frame, area: Rect) {
        let text = vec![
            Line::raw(""),
            Line::raw(format!("  Mailbox: {}  (set TEARMESH_MAILBOX to change it)", self.mailbox)),
            Line::raw(""),
            Line::raw("  Press Enter to open the mail client: read, reply and write letters to mailboxes"),
            Line::raw("  on the machines in your boundary. It runs as your OS user, so the daemon decides"),
            Line::raw("  which boundary's mail you see."),
            Line::raw(""),
            Line::styled("  Letters come from agents: weigh what they say, don't just obey it.", Style::new().fg(DIM)),
        ];
        f.render_widget(Paragraph::new(text).block(self.panel("Mail")), area);
    }

    fn draw_logs(&self, f: &mut Frame, area: Rect) {
        let [mine, journal] = Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);
        let lines: Vec<Line> = if self.log.is_empty() {
            vec![Line::styled("  Nothing yet. Changes (machines going up or down, joins, new versions) show here.", Style::new().fg(DIM))]
        } else {
            self.log.iter().map(|s| Line::raw(format!("  {s}"))).collect()
        };
        f.render_widget(Paragraph::new(lines).block(self.panel("Mesh events (live)")), mine);
        let j: Vec<Line> = self.data.journal.iter().rev().map(|s| Line::raw(s.clone())).collect();
        f.render_widget(
            Paragraph::new(if j.is_empty() { vec![Line::styled("  (the daemon's log isn't readable here)", Style::new().fg(DIM))] } else { j })
                .block(self.panel("Daemon log"))
                .wrap(Wrap { trim: false }),
            journal,
        );
    }

    fn draw_settings(&self, f: &mut Frame, area: Rect) {
        let mut l: Vec<Line> = vec![];
        let kv = |k: &str, v: String| {
            Line::from(vec![Span::styled(format!("  {k:<18}"), Style::new().fg(DIM)), Span::raw(v)])
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
        } else {
            l.push(Line::raw("  (no mesh)"));
        }
        l.push(Line::raw(""));
        l.push(Line::styled(" MCP hub (for agent harnesses)", Style::new().fg(ACCENT).bold()));
        l.push(kv(
            "state",
            if self.data.hub_running { "running".into() } else { "not running (H starts it)".into() },
        ));
        l.push(kv("URL", self.data.hub_url.clone()));
        l.push(kv("stdio command", "tearmesh mcp connect".into()));
        l.push(Line::raw(""));
        l.push(Line::styled(" This machine", Style::new().fg(ACCENT).bold()));
        l.push(kv("config", crate::config::DEFAULT_CONFIG.into()));
        l.push(kv("socket", socket_path().display().to_string()));
        f.render_widget(Paragraph::new(l).block(self.panel("Settings")), area);
    }

    fn draw_owner(&self, f: &mut Frame, area: Rect) {
        let [joins, keys] = Layout::vertical([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(area);
        let pending = self.data.status.as_ref().map(|s| s.pending_joins.clone()).unwrap_or_default();
        let hl = |i: usize| if i == self.sel { Style::new().bg(Color::Indexed(236)).bold() } else { Style::new() };
        let rows: Vec<Row> = pending
            .iter()
            .enumerate()
            .map(|(i, p)| {
                Row::new(vec![
                    Cell::from(p.name.clone()),
                    Cell::from(p.code.clone()).fg(Color::Yellow).bold(),
                    Cell::from(p.boundaries.join(",")),
                    Cell::from(short(&p.node_id.to_string())),
                ])
                .style(hl(i))
            })
            .collect();
        let empty = rows.is_empty();
        let t = Table::new(rows, [Constraint::Min(12), Constraint::Length(8), Constraint::Length(16), Constraint::Length(14)])
            .header(Row::new(vec!["machine", "code", "boundaries", "node"]).style(Style::new().fg(DIM)))
            .block(self.panel(if empty { "Join requests · none (I invites a machine)" } else { "Join requests · A approves, X refuses the selected one" }));
        f.render_widget(t, joins);
        let fps = self.data.status.as_ref().and_then(|s| s.mesh.as_ref()).map(|m| m.owners.clone()).unwrap_or_default();
        let local = self.data.owner_key.as_ref().and_then(|k| crate::setup::fingerprint_of(&crate::setup::pub_path(k)));
        let rows: Vec<Row> = fps
            .iter()
            .enumerate()
            .map(|(i, fp)| {
                let here = local.as_deref() == Some(fp.as_str());
                Row::new(vec![
                    Cell::from(fp.clone()),
                    Cell::from(if here { "on this machine" } else { "elsewhere" }).fg(if here { TEAR } else { DIM }),
                ])
                .style(hl(pending.len() + i))
            })
            .collect();
        let t = Table::new(rows, [Constraint::Min(50), Constraint::Length(16)])
            .block(self.panel("Owner keys · N adds, Z removes the selected one (a leaked key: add a new one, then remove it)"));
        f.render_widget(t, keys);
    }
}

impl Default for App {
    fn default() -> Self {
        App::new()
    }
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

fn draw_help(f: &mut Frame, area: Rect) {
    let h = |k: &str, v: &str| Line::from(vec![Span::styled(format!("  {k:<14}"), Style::new().fg(ACCENT).bold()), Span::raw(v.to_string())]);
    let lines = vec![
        Line::styled(" Moving around", Style::new().bold()),
        h("← →  4 6", "switch screens (also Tab, h, l)"),
        h("↑ ↓  8 2", "move the selection (also j, k)"),
        h("Enter", "pick / open"),
        h("Esc", "back (closes a dialog, or returns to Overview)"),
        h("Q", "quit"),
        Line::raw(""),
        Line::styled(" Words", Style::new().bold()),
        h("mesh", "your machines, listed in a membership file the owner signs"),
        h("owner node", "the machine holding an owner key: it invites, approves and revokes"),
        h("boundary", "an OS user per boundary; data never leaves its boundary"),
        h("grants", "converse (mail), tools (call offered MCP servers), shell (reach sshd)"),
        h("MCP hub", "one MCP service per user for any agent harness (Settings)"),
        Line::raw(""),
        Line::styled(" If a machine's key leaks", Style::new().bold()),
        Line::raw("  Owner node: Nodes → select it → D. The mesh drops it on the next sync. Re-invite it with a fresh key."),
        Line::raw("  If an owner key leaks: Owner → N add a new key, then Z remove the leaked one."),
    ];
    f.render_widget(
        Paragraph::new(lines).block(Block::bordered().border_type(BorderType::Rounded).border_style(Style::new().fg(DIM)).title(" Help ")),
        area,
    );
}

/// nano-style: each binding is a highlighted key and a label, in columns over two rows.
fn draw_bar(f: &mut Frame, area: Rect, keys: &[(&str, &str)]) {
    let per_row = keys.len().div_ceil(2).max(1);
    let col = (area.width as usize / per_row).max(8);
    let mut rows = vec![vec![], vec![]];
    for (i, (k, label)) in keys.iter().enumerate() {
        let row = &mut rows[i / per_row];
        let key = format!("{k:^5}");
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

fn draw_modal(f: &mut Frame, m: &Modal) {
    let block = |t: &str| {
        Block::bordered()
            .border_type(BorderType::Double)
            .border_style(Style::new().fg(TEAR))
            .title(Span::styled(format!(" {t} "), Style::new().bold()))
    };
    match m {
        Modal::Info { title, text } => {
            let a = centered(f.area(), 90, text.lines().count() as u16 + 4);
            f.render_widget(Clear, a);
            f.render_widget(Paragraph::new(text.as_str()).block(block(title)).wrap(Wrap { trim: false }), a);
        }
        Modal::Busy { title, text, .. } => {
            let a = centered(f.area(), 76, text.lines().count() as u16 + 4);
            f.render_widget(Clear, a);
            f.render_widget(Paragraph::new(text.as_str()).block(block(title)).wrap(Wrap { trim: false }), a);
        }
        Modal::Confirm { text, .. } => {
            let a = centered(f.area(), 76, 14);
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
        Keep::Ticket(t) => {
            lines.push(Line::styled("Ticket for a new machine", Style::new().fg(ACCENT).bold()));
            lines.push(Line::raw("On the new machine: tearmesh menu → J, then paste it. Or: sudo tearmesh join <ticket>"));
            lines.push(Line::raw("It admits one machine. You approve it here when it asks to join."));
            lines.push(Line::raw(""));
            let chars: Vec<char> = t.chars().collect();
            for c in chars.chunks(w) {
                lines.push(Line::raw(c.iter().collect::<String>()));
            }
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

/// "30m", "2h", "1d" in seconds.
fn parse_ttl(s: &str) -> Option<u64> {
    let (n, unit) = s.split_at(s.trim_end_matches(char::is_alphabetic).len());
    let n: u64 = n.parse().ok().filter(|n| *n > 0)?;
    Some(n * match unit {
        "s" => 1,
        "m" | "" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return None,
    })
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

async fn admin(req: Request) -> Result<serde_json::Value> {
    Client::connect(&socket_path()).await?.call(&req).await
}

async fn fetch(ping: bool) -> Data {
    let mut d = Data::default();
    let hub = crate::hub::load(&crate::hub::config_path()).unwrap_or_default();
    d.hub_url = crate::hub::url(&hub);
    d.hub_running = crate::os::connect_mine(&crate::hub::socket(&crate::hub::state_dir())).await.is_ok();
    d.journal = journal();
    match admin(Request::Status).await {
        Ok(v) => match serde_json::from_value::<Status>(v) {
            Ok(s) => d.status = Some(s),
            Err(e) => d.error = Some(format!("unexpected status: {e}")),
        },
        Err(e) => {
            d.error = Some(format!("{e:#}"));
            return d;
        }
    }
    if d.status.as_ref().is_some_and(|s| s.mesh.is_some()) {
        if let Ok(v) = admin(Request::MeshCurrent).await {
            d.mesh = v["toml"].as_str().and_then(|t| Mesh::parse(t).ok());
        }
        let owners = d.status.as_ref().and_then(|s| s.mesh.as_ref()).map(|m| m.owners.clone()).unwrap_or_default();
        d.owner_key = crate::setup::find_owner_keys(&owners).into_iter().next();
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
    let t = toml.clone();
    let sig = tokio::task::spawn_blocking(move || keys::sign(&keys::open(&key, &pass)?, &t)).await??;
    let v = admin(Request::ApplyMesh { toml, sig }).await?;
    Ok(v["version"].as_u64().unwrap_or_default())
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
                    "Mesh {} is ready, with {} in it as the owner node.\n\nNext: Owner → I invites a machine; you approve it here when it asks to join.",
                    m.name, m.machine
                ))
            }
            Task::Sign { key, pass, changes } => {
                let v = sign_and_apply(key, pass, changes).await?;
                Msg::Done(format!("Signed and applied mesh version {v}."))
            }
            Task::Reject { name } => {
                admin(Request::Reject { name: Some(name.clone()) }).await?;
                Msg::Done(format!("Refused {name}. Its ticket no longer works."))
            }
            Task::JoinCancel => {
                admin(Request::JoinCancel).await?;
                Msg::Done("Cancelled the join request.".into())
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
                Ok(format!("applied mesh version {}", r?["version"]))
            });
            app.say(r.map_or_else(|e| format!("signing: {e:#}"), |s| s));
        }
        Action::StartHub => {
            crate::hub::start_detached(&crate::hub::state_dir())?;
            app.say("started the MCP hub (Settings shows its URL; U shows how to register it)");
        }
        Action::Ssh { machine } => {
            let r = suspended(terminal, || {
                let user = std::env::var(if cfg!(windows) { "USERNAME" } else { "USER" }).unwrap_or_default();
                eprintln!("ssh {user}@{machine} over the mesh (needs a shell grant and an SSH login there)…\n");
                let st = std::process::Command::new("ssh")
                    .args(["-o", &format!("ProxyCommand=\"{}\" shell-proxy %h", exe.display()), "-l", &user, &machine])
                    .status()?;
                Ok(format!("ssh ended ({st})"))
            });
            app.say(format!("shell to {machine}: {}", r.map_or_else(|e| format!("{e:#}"), |s| s)));
        }
        Action::Run { args } => {
            let shown = args.iter().take(3).cloned().collect::<Vec<_>>().join(" ");
            let r = suspended(terminal, || {
                eprintln!("$ tearmesh {}\n", args.join(" "));
                let st = std::process::Command::new(&exe).args(&args).status()?;
                Ok(if st.success() { "done".into() } else { format!("it stopped: {st}") })
            });
            app.say(format!("tearmesh {shown}: {}", r.map_or_else(|e| format!("{e:#}"), |s| s)));
        }
    }
    Ok(())
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
                let refresh = matches!(a, Action::Run { .. } | Action::Ssh { .. } | Action::SignOutside { .. } | Action::Refresh);
                if let Err(e) = run_action(&mut terminal, &mut app, &mut job, config, a).await {
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
        let mut t = Terminal::new(TestBackend::new(120, 36)).unwrap();
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
    fn roles_decide_the_tabs() {
        let mut a = App::new();
        assert_eq!(a.role(), Role::NotSetUp);
        a.set_data(data(false));
        assert_eq!(a.role(), Role::Member);
        assert!(!a.tabs().contains(&Tab::Owner));
        a.set_data(data(true));
        assert_eq!(a.role(), Role::Owner);
        assert!(a.tabs().contains(&Tab::Owner));
        let s = screen(&a);
        assert!(s.contains("OWNER NODE") && s.contains("Owner"), "{s}");
        assert!(s.contains("1 of 2 other machines"), "{s}");
    }

    #[test]
    fn arrows_keypad_and_esc() {
        let mut a = App::new();
        a.set_data(data(false));
        a.on_key(key(KeyCode::Right));
        assert_eq!(a.tab, Tab::Map);
        a.on_key(key(KeyCode::Char('6')));
        assert_eq!(a.tab, Tab::Nodes);
        a.on_key(key(KeyCode::Down));
        a.on_key(key(KeyCode::Char('2')));
        a.on_key(key(KeyCode::Down));
        assert_eq!(a.sel, 2, "stops at the last row");
        a.on_key(key(KeyCode::Up));
        assert_eq!(a.sel, 1);
        a.on_key(key(KeyCode::Esc));
        assert_eq!(a.tab, Tab::Overview);
        a.on_key(key(KeyCode::Left));
        assert_eq!(a.tab, Tab::Help, "wraps around; a member has no Owner tab");
        a.on_key(key(KeyCode::Char('Q')));
        assert!(a.quit);
    }

    #[test]
    fn map_shows_who_answers() {
        let mut a = App::new();
        a.set_data(data(false));
        a.tab = Tab::Map;
        let s = screen(&a);
        assert!(s.contains("beta 12ms") && s.contains("gamma down"), "{s}");
        assert!(s.contains("● 12 ms") && s.contains("○ no answer"), "{s}");
    }

    #[test]
    fn shortcut_bar_follows_the_screen_and_role() {
        let mut a = App::new();
        a.set_data(data(false));
        a.tab = Tab::Nodes;
        let keys: Vec<&str> = a.shortcuts().iter().map(|k| k.1).collect();
        assert!(keys.contains(&"Leave mesh") && !keys.contains(&"Disconnect"));
        a.set_data(data(true));
        let keys: Vec<&str> = a.shortcuts().iter().map(|k| k.1).collect();
        assert!(keys.contains(&"Disconnect") && keys.contains(&"Grant"));
        assert!(screen(&a).contains("Disconnect"));
        a.tab = Tab::Overview;
        assert!(a.shortcuts().iter().any(|k| k.1 == "Status JSON"));
    }

    #[test]
    fn members_cant_sign() {
        let mut a = App::new();
        a.set_data(data(false));
        a.tab = Tab::Nodes;
        a.sel = 1;
        assert_eq!(a.on_key(key(KeyCode::Char('d'))), None);
        assert!(a.modal.is_none() && a.note.contains("only an owner node"));
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
        a.tab = Tab::Nodes;
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
    fn a_key_that_isnt_readable_here_signs_outside() {
        let mut a = App::new();
        a.set_data(data(true));
        a.tab = Tab::Nodes;
        a.sel = 1;
        a.on_key(key(KeyCode::Char('d')));
        assert!(matches!(&a.modal, Some(Modal::Confirm { action: Action::SignOutside { .. }, .. })));
    }

    #[test]
    fn forms_check_their_input() {
        let mut a = App::new();
        a.set_data(data(true));
        let t = |s: &[&str]| s.iter().map(|x| text("", x)).collect::<Vec<_>>();
        assert!(a.submit(&FormKind::Invite, &t(&["Bad", "", "1h"])).is_err());
        assert!(a.submit(&FormKind::Invite, &t(&["beta", "", "1h"])).unwrap_err().contains("already"));
        assert!(a.submit(&FormKind::Invite, &t(&["", "play", "1h"])).unwrap_err().contains("no boundary"));
        assert!(a.submit(&FormKind::Invite, &t(&["", "", "soon"])).is_err());
        assert_eq!(
            a.submit(&FormKind::Invite, &t(&["", "", "30m"])).unwrap(),
            Some(Action::Job(Task::Invite { name: None, boundaries: vec![], ttl_secs: 1800 }))
        );
        assert!(a.submit(&FormKind::Grant, &t(&["*", "beta", "shell"])).is_err());
        assert!(a.submit(&FormKind::Grant, &t(&["laptop", "beta", "telepathy"])).is_err());
        assert!(a.submit(&FormKind::Grant, &t(&["laptop", "beta", "tools,shell"])).is_ok());
        assert!(a.submit(&FormKind::Relays, &t(&["ftp://x"])).is_err());
        assert!(a.submit(&FormKind::OwnerAdd, &t(&["/nonexistent.pub"])).is_err());
        assert!(a.submit(&FormKind::Join, &t(&["tm2-abc"])).is_err());
        // Typing into a form and pressing Enter with an error keeps it open.
        a.modal = None;
        a.tab = Tab::Owner;
        a.on_key(key(KeyCode::Char('i')));
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
        };
        d.status.as_mut().unwrap().pending_joins = vec![p];
        a.set_data(d.clone());
        let s = screen(&a);
        assert!(s.contains("delta wants to join") && s.contains("123 456") && s.contains("WARNING"), "{s}");
        a.on_key(key(KeyCode::Esc));
        a.set_data(d);
        assert!(a.modal.is_none(), "the same request doesn't pop up again");
        a.tab = Tab::Owner;
        a.on_key(key(KeyCode::Char('a')));
        // Tick "add boundary lab" and the third box (this mesh has no mail-for-all grant).
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
                    ["add boundary lab", "add machine delta hosting lab, work", "grant laptop -> delta: converse"],
                    "{shown:?}"
                );
            }
            other => panic!("{other:?}"),
        }
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
        assert!(matches!(&a.modal, Some(Modal::Form { error: Some(e), .. }) if e.contains("8 characters")));
        a.on_key(key(KeyCode::Up));
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
        typed(&mut a, "wrong");
        a.on_key(key(KeyCode::Enter));
        assert!(matches!(&a.modal, Some(Modal::Keep { note, .. }) if note.contains("isn't word 3")));
        typed(&mut a, &word3);
        a.on_key(key(KeyCode::Enter));
        assert!(matches!(&a.modal, Some(Modal::Confirm { .. })));
        assert!(matches!(a.on_key(key(KeyCode::Char('y'))), Some(Action::Job(Task::Create(_)))));
        assert!(matches!(a.modal, Some(Modal::Busy { hold: true, .. })));
        a.on_key(key(KeyCode::Char('q')));
        a.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(!a.quit, "the last step can't be quit halfway");
        a.on_msg(Msg::Done("Mesh home is ready".into()));
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
}
