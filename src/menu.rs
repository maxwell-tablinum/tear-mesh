//! `tearmesh menu`: a full-screen terminal UI for running a machine in a mesh. Arrow keys (or
//! the keypad) move, Enter picks, Esc goes back, and a shortcut bar along the bottom shows the
//! keys for the current screen, like nano's.
//!
//! It shows live state (the daemon's status, which machines answer a ping, recent changes) and
//! acts directly. Actions that need a person at the keyboard (setup, signing with the owner key's
//! passphrase, comparing a join code, SSH) suspend the menu, run the matching `tearmesh` command
//! in the terminal, and come back. The menu is an owner node's when an owner key for the mesh is
//! in ~/.ssh; only then does it show the Owner screen and the actions that sign.

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

use crate::ipc::{Client, Request, socket_path};
use crate::mesh::{Category, Mesh};
use crate::node::Status;
use crate::ping::Ping;

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
    /// Suspend the menu and run `tearmesh <args>` in the terminal. `sign` adds `--out` in a
    /// private directory, so signed files don't land in the working directory.
    Run {
        args: Vec<String>,
        sign: bool,
    },
    /// Suspend and SSH to a machine over the mesh.
    Ssh { machine: String },
    StartHub,
    Refresh,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FormKind {
    Invite,
    Grant,
    Revoke,
    Relays,
    OwnerAdd,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Modal {
    Form {
        kind: FormKind,
        title: String,
        fields: Vec<(String, String)>,
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

    fn key_arg(&self) -> Option<String> {
        self.data.owner_key.as_ref().map(|k| k.display().to_string())
    }

    fn signed(&self, mut args: Vec<String>) -> Option<Action> {
        args.push("--key".into());
        args.push(self.key_arg()?);
        Some(Action::Run { args, sign: true })
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
                Modal::Form { .. } => vec![("Tab", "Next field"), ("Enter", "Submit"), ("Esc", "Cancel")],
                Modal::Confirm { .. } => vec![("Y", "Yes"), ("N", "No"), ("Esc", "Cancel")],
                Modal::Info { .. } => vec![("Enter", "Close"), ("Esc", "Close")],
            };
        }
        let owner = self.role() == Role::Owner;
        let mut v = vec![("←→", "Tabs")];
        match self.tab {
            Tab::Overview => {
                v.push(("S", "Setup"));
                if self.role() == Role::NotSetUp {
                    v.push(("C", "Create/join"));
                } else {
                    v.push(("J", "Status JSON"));
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

    pub fn on_key(&mut self, k: KeyEvent) -> Option<Action> {
        // Windows terminals also report key releases.
        if k.kind != KeyEventKind::Press {
            return None;
        }
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            self.quit = true;
            return None;
        }
        if self.modal.is_some() {
            return self.modal_key(k);
        }
        self.note.clear();
        let tabs = self.tabs();
        let at = tabs.iter().position(|t| *t == self.tab).unwrap_or(0);
        let code = match k.code {
            // The keypad with Num Lock on sends digits.
            KeyCode::Char('4') | KeyCode::Char('h') => KeyCode::Left,
            KeyCode::Char('6') | KeyCode::Char('l') => KeyCode::Right,
            KeyCode::Char('8') | KeyCode::Char('k') => KeyCode::Up,
            KeyCode::Char('2') | KeyCode::Char('j') => KeyCode::Down,
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

    fn tab_key(&mut self, code: KeyCode) -> Option<Action> {
        let run = |a: &[&str]| Action::Run {
            args: a.iter().map(|s| s.to_string()).collect(),
            sign: false,
        };
        match (self.tab, code) {
            (Tab::Overview, KeyCode::Char('s') | KeyCode::Char('c') | KeyCode::Enter) => {
                Some(run(&["setup"]))
            }
            (Tab::Overview, KeyCode::Char('j')) => Some(run(&["status"])),
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
                self.modal = Some(Modal::Confirm {
                    text: format!(
                        "Disconnect {m}: remove it from the mesh, with its grants and approvals.\n\n\
                         Use this when a machine is retired, lost, or its key may be stolen. Every \
                         member refuses it as soon as they sync the new version; it can come back \
                         only through a new invite.\n\nSign and apply now?"
                    ),
                    action: self.signed(vec!["mesh".into(), "remove".into(), m])?,
                });
                None
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
            (Tab::Nodes, KeyCode::Char('l')) if self.role() == Role::Member => {
                Some(run(&["mesh", "reset"]))
            }
            (Tab::Mail, KeyCode::Enter) => Some(Action::Run {
                args: vec!["tui".into(), "--mailbox".into(), self.mailbox.clone()],
                sign: false,
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
                self.modal = Some(Modal::Confirm {
                    text: format!(
                        "Set tools sharing to {to}? {}",
                        if to == "free" {
                            "Any offered server becomes callable by machines with a tools grant, without approval."
                        } else {
                            "Offered servers need your approval again before others can call them."
                        }
                    ),
                    action: self.signed(vec!["mesh".into(), "set".into(), "tools-sharing".into(), to.into()])?,
                });
                None
            }
            (Tab::Settings, KeyCode::Char('y')) => {
                if self.need_owner() {
                    self.form(FormKind::Relays);
                }
                None
            }
            (Tab::Owner, KeyCode::Char('a')) => {
                let pending = self.data.status.as_ref()?.pending_joins.get(self.sel)?.name.clone();
                self.signed(vec!["mesh".into(), "approve".into(), pending])
                    .map(|a| match a {
                        // approve writes its file in its own private directory.
                        Action::Run { args, .. } => Action::Run { args, sign: false },
                        a => a,
                    })
            }
            (Tab::Owner, KeyCode::Char('n')) => {
                self.form(FormKind::OwnerAdd);
                None
            }
            (Tab::Owner, KeyCode::Char('z')) => {
                let pend = self.data.status.as_ref().map_or(0, |s| s.pending_joins.len());
                let i = self.sel.checked_sub(pend)?;
                let fp = self.data.status.as_ref()?.mesh.as_ref()?.owners.get(i)?.clone();
                self.modal = Some(Modal::Confirm {
                    text: format!(
                        "Remove owner key {fp}?\n\nDo this when a key leaked or was lost. The mesh keeps at \
                         least two owner keys, so add a replacement first (N)."
                    ),
                    action: self.signed(vec!["mesh".into(), "owner-remove".into(), fp])?,
                });
                None
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

    fn form(&mut self, kind: FormKind) {
        let sel = self.selected_machine().unwrap_or_default();
        let me = self.this_machine();
        let bounds = self
            .data
            .mesh
            .as_ref()
            .map(|m| m.boundaries.join(","))
            .unwrap_or_default();
        let f = |l: &str, v: &str| (l.to_string(), v.to_string());
        let (title, fields) = match kind {
            FormKind::Invite => (
                "Connect a new machine (invite)",
                vec![f("Name for it", ""), f("Boundaries", &bounds), f("Ticket expires in", "1h")],
            ),
            FormKind::Grant => (
                "Grant",
                vec![
                    f("From machine", &me),
                    f("To machine", &sel),
                    f("Categories (converse,tools,shell)", "converse"),
                ],
            ),
            FormKind::Revoke => (
                "Revoke a grant",
                vec![
                    f("From machine", &me),
                    f("To machine", &sel),
                    f("Categories (converse,tools,shell)", "shell"),
                ],
            ),
            FormKind::Relays => ("Relays", vec![f("n0, none, or URL,URL", "n0")]),
            FormKind::OwnerAdd => (
                "Add an owner key",
                vec![f("Path to the new key's .pub file", "")],
            ),
        };
        self.modal = Some(Modal::Form {
            kind,
            title: title.into(),
            fields,
            focus: 0,
            error: None,
        });
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
            Modal::Form {
                fields, focus, kind, ..
            } => {
                match k.code {
                    KeyCode::Esc => {
                        self.modal = None;
                        self.note = "cancelled".into();
                    }
                    KeyCode::Tab | KeyCode::Down => *focus = (*focus + 1) % fields.len(),
                    KeyCode::BackTab | KeyCode::Up => *focus = (*focus + fields.len() - 1) % fields.len(),
                    KeyCode::Backspace => {
                        fields[*focus].1.pop();
                    }
                    KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => {
                        if fields[*focus].1.len() < 512 {
                            fields[*focus].1.push(c)
                        }
                    }
                    KeyCode::Enter => {
                        let (kind, vals) = (*kind, fields.iter().map(|f| f.1.trim().to_string()).collect::<Vec<_>>());
                        match self.submit(kind, &vals) {
                            Ok(a) => {
                                self.modal = None;
                                return Some(a);
                            }
                            Err(e) => {
                                if let Some(Modal::Form { error, .. }) = &mut self.modal {
                                    *error = Some(e);
                                }
                            }
                        }
                        return None;
                    }
                    _ => {}
                }
                None
            }
        }
    }

    /// Checks a form and turns it into the command to run. Errors keep the form open.
    pub fn submit(&self, kind: FormKind, v: &[String]) -> Result<Action, String> {
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
        let cats = |s: &str| -> Result<Vec<String>, String> {
            let c = list(s);
            if c.is_empty() || c.iter().any(|x| !["converse", "tools", "shell"].contains(&x.as_str())) {
                return Err("categories: converse, tools and/or shell".into());
            }
            Ok(c)
        };
        let owner = |args: Vec<String>| self.signed(args).ok_or_else(|| "no owner key on this machine".to_string());
        match kind {
            FormKind::Invite => {
                let n = name(&v[0], "name")?;
                if self.machines().iter().any(|m| m.name == n) {
                    return Err(format!("{n} is already in the mesh; disconnect it first or pick another name"));
                }
                let b = list(&v[1]);
                if b.is_empty() {
                    return Err("boundaries: at least one".into());
                }
                let known = self.data.mesh.as_ref().map(|m| m.boundaries.clone()).unwrap_or_default();
                if let Some(x) = b.iter().find(|x| !known.contains(x)) {
                    return Err(format!("the mesh has no boundary {x} (it has {})", known.join(", ")));
                }
                let exp = v[2].clone();
                if !exp.chars().next().is_some_and(|c| c.is_ascii_digit())
                    || !exp.trim_start_matches(|c: char| c.is_ascii_digit()).chars().all(|c| "smhd".contains(c))
                {
                    return Err("expires: like 30m, 2h or 1d".into());
                }
                let mut args = vec!["mesh".to_string(), "invite".into(), n];
                for x in b {
                    args.extend(["--boundary".into(), x]);
                }
                args.extend(["--expires".into(), exp]);
                Ok(Action::Run { args, sign: false })
            }
            FormKind::Grant | FormKind::Revoke => {
                let from = if v[0] == "*" { "*".into() } else { name(&v[0], "from")? };
                let to = if v[1] == "*" { "*".into() } else { name(&v[1], "to")? };
                let c = cats(&v[2])?;
                if kind == FormKind::Grant && c.iter().any(|x| x == "shell") && (from == "*" || to == "*") {
                    return Err("shell grants name both machines (no *)".into());
                }
                let verb = if kind == FormKind::Grant { "grant" } else { "revoke" };
                let mut args = vec!["mesh".to_string(), verb.into(), from, to];
                args.extend(c);
                owner(args)
            }
            FormKind::Relays => {
                let r = v[0].clone();
                if r != "n0" && r != "none" && !list(&r).iter().all(|u| u.starts_with("https://") || u.starts_with("http://")) {
                    return Err("n0, none, or relay URLs separated by commas".into());
                }
                owner(vec!["mesh".into(), "set".into(), "relays".into(), r])
            }
            FormKind::OwnerAdd => {
                let p = v[0].clone();
                let fp = crate::setup::fingerprint_of(std::path::Path::new(&p));
                if fp.is_none() {
                    return Err("that isn't a readable OpenSSH public key (.pub) file".into());
                }
                owner(vec!["mesh".into(), "owner-add".into(), p])
            }
        }
    }

    pub fn draw(&self, f: &mut Frame) {
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
            lines.push(Line::raw("  Start it (sudo systemctl start tearmesh, or Start-Service tearmesh), or press S to run setup."));
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
                    lines.push(Line::styled(
                        "  This machine isn't in a mesh yet. Press C to create one or join one.",
                        Style::new().fg(Color::Yellow).bold(),
                    ));
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
            .block(self.panel(if empty { "Join requests · none (I invites a machine)" } else { "Join requests · A approves the selected one" }));
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
        Modal::Confirm { text, .. } => {
            let a = centered(f.area(), 76, 14);
            f.render_widget(Clear, a);
            f.render_widget(
                Paragraph::new(format!("{text}\n\n  [Y] yes    [N] no")).block(block("Confirm")).wrap(Wrap { trim: false }),
                a,
            );
        }
        Modal::Form { title, fields, focus, error, .. } => {
            let a = centered(f.area(), 76, fields.len() as u16 * 2 + 6);
            f.render_widget(Clear, a);
            let mut lines = vec![];
            for (i, (label, value)) in fields.iter().enumerate() {
                let on = i == *focus;
                lines.push(Line::styled(format!(" {label}"), Style::new().fg(if on { ACCENT } else { DIM })));
                lines.push(Line::from(vec![
                    Span::raw(if on { " ▸ " } else { "   " }),
                    Span::styled(value.clone(), if on { Style::new().add_modifier(Modifier::UNDERLINED).bold() } else { Style::new() }),
                    Span::raw(if on { "▏" } else { "" }),
                ]));
            }
            if let Some(e) = error {
                lines.push(Line::styled(format!(" {e}"), Style::new().fg(BAD).bold()));
            }
            f.render_widget(Paragraph::new(lines).block(block(title)), a);
        }
    }
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

/// Leaves the full screen, runs `f` in the plain terminal, waits for Enter, comes back.
fn suspended(terminal: &mut ratatui::DefaultTerminal, f: impl FnOnce() -> Result<String>) -> Result<String> {
    ratatui::restore();
    let r = f();
    match &r {
        Ok(s) if !s.is_empty() => eprintln!("\n{s}"),
        Err(e) => eprintln!("\nerror: {e:#}"),
        _ => {}
    }
    eprint!("\n[ Press Enter to return to the menu ]");
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    *terminal = ratatui::init();
    terminal.clear()?;
    r
}

fn run_action(terminal: &mut ratatui::DefaultTerminal, app: &mut App, a: Action) -> Result<()> {
    let exe = std::env::current_exe()?;
    match a {
        Action::Refresh => {}
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
        Action::Run { mut args, sign } => {
            let dir = if sign { Some(crate::setup::private_dir("tearmesh-menu-")?) } else { None };
            if let Some(d) = &dir {
                args.extend(["--out".into(), d.join("mesh-next.toml").display().to_string()]);
            }
            let shown = args.iter().take(3).cloned().collect::<Vec<_>>().join(" ");
            let r = suspended(terminal, || {
                eprintln!("$ tearmesh {}\n", args.join(" "));
                let st = std::process::Command::new(&exe).args(&args).status()?;
                Ok(if st.success() { "done".into() } else { format!("it stopped: {st}") })
            });
            if let Some(d) = dir {
                let _ = std::fs::remove_dir_all(d);
            }
            app.say(format!("tearmesh {shown}: {}", r.map_or_else(|e| format!("{e:#}"), |s| s)));
        }
    }
    Ok(())
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

pub async fn run() -> Result<()> {
    let mut app = App::new();
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
    let mut terminal = ratatui::init();
    let res = async {
        splash(&mut terminal)?;
        app.say("menu started");
        while !app.quit {
            while let Ok(d) = rx.try_recv() {
                app.set_data(d);
            }
            terminal.draw(|f| app.draw(f))?;
            if event::poll(Duration::from_millis(200))?
                && let Event::Key(k) = event::read()?
                && let Some(a) = app.on_key(k)
            {
                let refresh = !matches!(a, Action::Refresh);
                if let Err(e) = run_action(&mut terminal, &mut app, a) {
                    app.note = format!("{e:#}");
                }
                if refresh {
                    app.say("refreshing");
                }
                poke.notify_one();
            }
        }
        anyhow::Ok(())
    }
    .await;
    ratatui::restore();
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

    #[test]
    fn disconnect_is_confirmed_and_signed() {
        let mut a = App::new();
        a.set_data(data(true));
        a.tab = Tab::Nodes;
        a.sel = 0;
        assert_eq!(a.on_key(key(KeyCode::Char('d'))), None);
        assert!(a.note.contains("can't remove itself"));
        a.sel = 1;
        a.on_key(key(KeyCode::Char('d')));
        assert!(matches!(a.modal, Some(Modal::Confirm { .. })));
        assert_eq!(a.on_key(key(KeyCode::Char('n'))), None);
        a.on_key(key(KeyCode::Char('d')));
        let act = a.on_key(key(KeyCode::Char('y'))).unwrap();
        assert_eq!(
            act,
            Action::Run {
                args: ["mesh", "remove", "beta", "--key", "/home/u/.ssh/tearmesh-owner-home"].map(String::from).to_vec(),
                sign: true
            }
        );
    }

    #[test]
    fn forms_check_their_input() {
        let mut a = App::new();
        a.set_data(data(true));
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(a.submit(FormKind::Invite, &v(&["Bad", "work", "1h"])).is_err());
        assert!(a.submit(FormKind::Invite, &v(&["beta", "work", "1h"])).unwrap_err().contains("already"));
        assert!(a.submit(FormKind::Invite, &v(&["delta", "play", "1h"])).unwrap_err().contains("no boundary"));
        assert!(a.submit(FormKind::Invite, &v(&["delta", "work", "soon"])).is_err());
        assert_eq!(
            a.submit(FormKind::Invite, &v(&["delta", "work", "30m"])).unwrap(),
            Action::Run { args: v(&["mesh", "invite", "delta", "--boundary", "work", "--expires", "30m"]), sign: false }
        );
        assert!(a.submit(FormKind::Grant, &v(&["*", "beta", "shell"])).is_err());
        assert!(a.submit(FormKind::Grant, &v(&["laptop", "beta", "telepathy"])).is_err());
        assert!(a.submit(FormKind::Grant, &v(&["laptop", "beta", "tools,shell"])).is_ok());
        assert!(a.submit(FormKind::Relays, &v(&["ftp://x"])).is_err());
        assert!(a.submit(FormKind::OwnerAdd, &v(&["/nonexistent.pub"])).is_err());
        // Typing into a form and pressing Enter with an error keeps it open.
        a.tab = Tab::Owner;
        a.on_key(key(KeyCode::Char('i')));
        a.on_key(key(KeyCode::Char('Z')));
        assert_eq!(a.on_key(key(KeyCode::Enter)), None);
        assert!(matches!(&a.modal, Some(Modal::Form { error: Some(_), .. })));
        a.on_key(key(KeyCode::Esc));
        assert!(a.modal.is_none());
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
