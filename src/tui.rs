//! `tearmesh tui`: a terminal mail client for one mailbox. It connects like any session, as the
//! OS user it runs as, so the daemon decides its boundary. It doesn't hold the mailbox, so agents
//! are still woken for mail; opening a letter marks it read for the mailbox.

use std::time::{Duration, Instant};

use anyhow::Result;
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph, Wrap};

use crate::envelope::MAX_SUBJECT;
use crate::ipc::{Client, Request, socket_path};
use crate::node::{Letter, Who};

/// Work the UI asks the runtime to do against the daemon.
#[derive(Debug, PartialEq)]
pub enum Cmd {
    Refresh,
    Open(String),
    Send {
        to: Vec<String>,
        subject: String,
        body: String,
        thread: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Field {
    To,
    Subject,
    Body,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Compose {
    pub to: String,
    pub subject: String,
    pub body: String,
    pub thread: Option<String>,
    pub field: Field,
}

pub struct App {
    pub address: String,
    pub boundary: String,
    pub who: Option<Who>,
    /// Newest first.
    pub letters: Vec<Letter>,
    /// Show read letters too.
    pub all: bool,
    pub selected: usize,
    pub open: Option<Letter>,
    pub scroll: u16,
    pub compose: Option<Compose>,
    pub status: String,
    pub quit: bool,
}

impl App {
    pub fn new(address: String, boundary: String) -> App {
        App {
            address,
            boundary,
            who: None,
            letters: vec![],
            all: true,
            selected: 0,
            open: None,
            scroll: 0,
            compose: None,
            status: String::new(),
            quit: false,
        }
    }

    /// Takes the daemon's list (oldest first) and keeps the selection on the same letter.
    pub fn set_letters(&mut self, mut letters: Vec<Letter>) {
        letters.reverse();
        let keep = self.letters.get(self.selected).map(|l| l.id.clone());
        self.letters = letters;
        self.selected = keep
            .and_then(|id| self.letters.iter().position(|l| l.id == id))
            .unwrap_or(self.selected)
            .min(self.letters.len().saturating_sub(1));
    }

    pub fn on_key(&mut self, k: KeyEvent) -> Option<Cmd> {
        // Windows terminals also report key releases.
        if k.kind != KeyEventKind::Press {
            return None;
        }
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && k.code == KeyCode::Char('c') {
            self.quit = true;
            return None;
        }
        if let Some(c) = &mut self.compose {
            match k.code {
                KeyCode::Esc => {
                    self.compose = None;
                    self.status = "draft discarded".into();
                }
                KeyCode::Char('s') if ctrl => return self.send(),
                KeyCode::Tab => c.field = next(c.field),
                KeyCode::BackTab => c.field = prev(c.field),
                KeyCode::Enter if c.field == Field::Body => c.body.push('\n'),
                KeyCode::Enter => c.field = next(c.field),
                KeyCode::Backspace => {
                    field_mut(c).pop();
                }
                KeyCode::Char(ch) if !ctrl => field_mut(c).push(ch),
                _ => {}
            }
            return None;
        }
        match k.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Esc => self.open = None,
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected + 1 < self.letters.len() {
                    self.selected += 1;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.saturating_sub(1),
            KeyCode::Enter => {
                return self
                    .letters
                    .get(self.selected)
                    .map(|l| Cmd::Open(l.id.clone()));
            }
            KeyCode::PageDown | KeyCode::Char(' ') => self.scroll = self.scroll.saturating_add(10),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
            KeyCode::Char('n') => {
                self.compose = Some(Compose {
                    to: String::new(),
                    subject: String::new(),
                    body: String::new(),
                    thread: None,
                    field: Field::To,
                })
            }
            KeyCode::Char('r') => self.reply(),
            KeyCode::Char('a') => {
                self.all = !self.all;
                return Some(Cmd::Refresh);
            }
            KeyCode::Char('g') | KeyCode::F(5) => return Some(Cmd::Refresh),
            _ => {}
        }
        None
    }

    /// Replies to the open letter, or else the selected one.
    fn reply(&mut self) {
        let Some(l) = self.open.as_ref().or(self.letters.get(self.selected)) else {
            self.status = "no letter to reply to".into();
            return;
        };
        let subject = if l.subject.to_lowercase().starts_with("re:") {
            l.subject.clone()
        } else {
            format!("Re: {}", l.subject)
        };
        self.compose = Some(Compose {
            to: l.from.clone(),
            subject: subject.chars().take(MAX_SUBJECT).collect(),
            body: String::new(),
            thread: Some(l.id.clone()),
            field: Field::Body,
        });
    }

    fn send(&mut self) -> Option<Cmd> {
        let c = self.compose.as_ref()?;
        let to: Vec<String> =
            c.to.split(|ch: char| ch == ',' || ch.is_whitespace())
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
        if to.is_empty() {
            self.status = "add a recipient: mailbox@machine, or * for everyone".into();
            return None;
        }
        if c.subject.trim().is_empty() {
            self.status = "add a subject".into();
            return None;
        }
        Some(Cmd::Send {
            to,
            subject: c.subject.trim().into(),
            body: c.body.clone(),
            thread: c.thread.clone(),
        })
    }

    pub fn draw(&self, f: &mut Frame) {
        let [head, main, foot] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .areas(f.area());
        let mut spans = vec![
            Span::styled(
                " tear-mesh ",
                Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("{} · boundary {}", self.address, self.boundary)),
        ];
        if let Some(w) = &self.who {
            for m in w.machines.iter().filter(|m| !m.this_machine) {
                let seen = match m.last_sync_ms.map(age).as_deref() {
                    Some("now") => "synced just now".to_string(),
                    Some(a) => format!("synced {a} ago"),
                    None => "not synced".into(),
                };
                spans.push(Span::styled(
                    format!(" · {} {seen}", m.name),
                    Style::new().fg(Color::DarkGray),
                ));
            }
        }
        f.render_widget(Paragraph::new(Line::from(spans)), head);

        let [left, right] =
            Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)])
                .areas(main);
        self.draw_list(f, left);
        match &self.compose {
            Some(c) => draw_compose(f, right, c),
            None => draw_letter(f, right, self.open.as_ref(), self.scroll),
        }

        let keys = if self.compose.is_some() {
            "tab next field · enter newline (body) · ctrl+s send · esc discard"
        } else {
            "↑↓ move · enter open · r reply · n new · a all/unread · g refresh · q quit"
        };
        let mut footer = vec![Span::styled(
            format!(" {keys}"),
            Style::new().fg(Color::DarkGray),
        )];
        if !self.status.is_empty() {
            footer.push(Span::styled(
                format!("   {}", self.status),
                Style::new().fg(Color::Yellow),
            ));
        }
        f.render_widget(Paragraph::new(Line::from(footer)), foot);
    }

    fn draw_list(&self, f: &mut Frame, area: Rect) {
        let title = format!(
            " Inbox: {} ({}) ",
            if self.all { "all" } else { "unread" },
            self.letters.len()
        );
        let block = Block::bordered().title(title);
        if self.letters.is_empty() {
            let hint = if self.all {
                "No mail yet. Press n to write a letter."
            } else {
                "No unread mail."
            };
            f.render_widget(Paragraph::new(hint).block(block), area);
            return;
        }
        let items: Vec<ListItem> = self
            .letters
            .iter()
            .map(|l| {
                let mark = if l.read {
                    Span::raw("  ")
                } else {
                    Span::styled("● ", Style::new().fg(Color::Green))
                };
                ListItem::new(Line::from(vec![
                    mark,
                    Span::styled(
                        format!("{:>4} ", age(l.ts)),
                        Style::new().fg(Color::DarkGray),
                    ),
                    Span::raw(format!("{:<20} ", clip(&l.from, 20))),
                    Span::raw(l.subject.clone()),
                ]))
            })
            .collect();
        let list = List::new(items)
            .block(block)
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .highlight_symbol("▶");
        let mut state = ListState::default().with_selected(Some(self.selected));
        f.render_stateful_widget(list, area, &mut state);
    }
}

fn draw_letter(f: &mut Frame, area: Rect, open: Option<&Letter>, scroll: u16) {
    let block = Block::bordered().title(" Letter ");
    let Some(l) = open else {
        f.render_widget(
            Paragraph::new("Select a letter and press enter.").block(block),
            area,
        );
        return;
    };
    let label = Style::new().fg(Color::DarkGray);
    let mut lines = vec![
        Line::from(vec![
            Span::styled("From     ", label),
            Span::raw(l.from.clone()),
        ]),
        Line::from(vec![
            Span::styled("To       ", label),
            Span::raw(l.to.join(", ")),
        ]),
        Line::from(vec![
            Span::styled("Subject  ", label),
            Span::styled(l.subject.clone(), Style::new().add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Id       ", label),
            Span::raw(l.id[..12].to_string()),
        ]),
    ];
    if let Some(t) = &l.thread {
        lines.push(Line::from(vec![
            Span::styled("Thread   ", label),
            Span::raw(t.get(..12).unwrap_or(t).to_string()),
        ]));
    }
    lines.push(Line::raw(""));
    lines.extend(
        l.body
            .as_deref()
            .unwrap_or_default()
            .lines()
            .map(|s| Line::raw(s.to_string())),
    );
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0))
            .block(block),
        area,
    );
}

fn draw_compose(f: &mut Frame, area: Rect, c: &Compose) {
    let [to, subject, body] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(3),
    ])
    .areas(area);
    let field = |text: &str, title: &str, which: Field| {
        let active = c.field == which;
        // A block cursor at the end of the field being edited.
        let shown = if active {
            format!("{text}█")
        } else {
            text.to_string()
        };
        let style = if active {
            Style::new().fg(Color::Yellow)
        } else {
            Style::new()
        };
        Paragraph::new(shown).wrap(Wrap { trim: false }).block(
            Block::bordered()
                .title(title.to_string())
                .border_style(style),
        )
    };
    let kind = if c.thread.is_some() {
        "Reply"
    } else {
        "New letter"
    };
    f.render_widget(
        field(
            &c.to,
            &format!(" {kind} · To (mailbox@machine, or *) "),
            Field::To,
        ),
        to,
    );
    f.render_widget(field(&c.subject, " Subject ", Field::Subject), subject);
    f.render_widget(field(&c.body, " Body ", Field::Body), body);
}

fn next(f: Field) -> Field {
    match f {
        Field::To => Field::Subject,
        Field::Subject => Field::Body,
        Field::Body => Field::To,
    }
}

fn prev(f: Field) -> Field {
    match f {
        Field::To => Field::Body,
        Field::Subject => Field::To,
        Field::Body => Field::Subject,
    }
}

fn field_mut(c: &mut Compose) -> &mut String {
    match c.field {
        Field::To => &mut c.to,
        Field::Subject => &mut c.subject,
        Field::Body => &mut c.body,
    }
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n - 1).chain(['…']).collect()
    }
}

/// "now", "45s", "12m", "3h", "5d" since a unix-ms timestamp.
fn age(ts: u64) -> String {
    let s = crate::now_ms().saturating_sub(ts) / 1000;
    match s {
        0..=4 => "now".into(),
        5..=59 => format!("{s}s"),
        60..=3599 => format!("{}m", s / 60),
        3600..=86399 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86400),
    }
}

pub async fn run(mailbox: Option<String>) -> Result<()> {
    let mut c = Client::connect(&socket_path()).await?;
    let mailbox = mailbox.or_else(|| std::env::var("TEARMESH_MAILBOX").ok());
    let hello = c
        .call(&Request::Hello {
            mailbox,
            hold: false,
        })
        .await?;
    let mut app = App::new(
        hello["address"].as_str().unwrap_or_default().into(),
        hello["boundary"].as_str().unwrap_or_default().into(),
    );
    exec(&mut c, &mut app, Cmd::Refresh).await;
    let mut terminal = ratatui::init();
    let res = async {
        let mut refreshed = Instant::now();
        while !app.quit {
            terminal.draw(|f| app.draw(f))?;
            if event::poll(Duration::from_millis(200))? {
                if let Event::Key(k) = event::read()?
                    && let Some(cmd) = app.on_key(k)
                {
                    exec(&mut c, &mut app, cmd).await;
                }
            } else if refreshed.elapsed() >= Duration::from_secs(3) {
                exec(&mut c, &mut app, Cmd::Refresh).await;
                refreshed = Instant::now();
            }
        }
        anyhow::Ok(())
    }
    .await;
    ratatui::restore();
    res
}

async fn exec(c: &mut Client, app: &mut App, cmd: Cmd) {
    let r: Result<()> = async {
        match cmd {
            Cmd::Refresh => {
                app.who = serde_json::from_value(c.call(&Request::Who).await?).ok();
                let letters: Vec<Letter> =
                    serde_json::from_value(c.call(&Request::Inbox { all: app.all }).await?)?;
                app.set_letters(letters);
            }
            Cmd::Open(id) => {
                let l: Letter = serde_json::from_value(c.call(&Request::Read { id }).await?)?;
                if let Some(x) = app.letters.iter_mut().find(|x| x.id == l.id) {
                    x.read = true;
                }
                app.scroll = 0;
                app.open = Some(l);
            }
            Cmd::Send {
                to,
                subject,
                body,
                thread,
            } => {
                let v = c
                    .call(&Request::Post {
                        to,
                        subject,
                        body,
                        thread,
                    })
                    .await?;
                app.compose = None;
                app.status = format!(
                    "sent {}",
                    v["id"]
                        .as_str()
                        .and_then(|s| s.get(..12))
                        .unwrap_or_default()
                );
            }
        }
        Ok(())
    }
    .await;
    if let Err(e) = r {
        // shortcut: no reconnect; if the daemon restarts, quit and start the TUI again.
        app.status = format!("error: {e:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::PeerInfo;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn letter(c: char, from: &str, subject: &str, read: bool) -> Letter {
        Letter {
            id: c.to_string().repeat(64),
            from: from.into(),
            to: vec!["admin@laptop".into()],
            subject: subject.into(),
            thread: None,
            ts: crate::now_ms() - 120_000,
            read,
            body: None,
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn typed(app: &mut App, s: &str) {
        for ch in s.chars() {
            assert_eq!(app.on_key(key(KeyCode::Char(ch))), None);
        }
    }

    fn screen(app: &App) -> String {
        let mut t = Terminal::new(TestBackend::new(110, 16)).unwrap();
        t.draw(|f| app.draw(f)).unwrap();
        let buf = t.backend().buffer();
        buf.content()
            .chunks(buf.area.width as usize)
            .map(|row| row.iter().map(|c| c.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn app() -> App {
        let mut a = App::new("admin@laptop".into(), "work".into());
        // The daemon lists oldest first.
        a.set_letters(vec![
            letter('a', "builder@ws", "older one", true),
            letter('b', "helper@ws", "newer one", false),
        ]);
        a
    }

    #[test]
    fn renders_header_inbox_and_letter() {
        let mut a = app();
        a.who = Some(Who {
            you: "admin@laptop".into(),
            boundary: "work".into(),
            machines: vec![PeerInfo {
                name: "ws".into(),
                this_machine: false,
                last_sync_ms: Some(crate::now_ms() - 7_000),
            }],
            addresses: vec![],
        });
        let s = screen(&a);
        assert!(s.contains("admin@laptop · boundary work"), "{s}");
        assert!(s.contains("ws synced 7s ago"), "{s}");
        assert!(s.contains("Inbox: all (2)"), "{s}");
        let newer = s.find("newer one").unwrap();
        assert!(newer < s.find("older one").unwrap(), "newest first");
        assert!(s.contains("Select a letter"), "{s}");

        let mut l = letter('b', "helper@ws", "newer one", true);
        l.body = Some("line one\nline two".into());
        a.open = Some(l);
        let s = screen(&a);
        assert!(
            s.contains("From     helper@ws") && s.contains("line two"),
            "{s}"
        );
    }

    #[test]
    fn empty_inbox_has_a_hint() {
        let a = App::new("admin@laptop".into(), "work".into());
        assert!(screen(&a).contains("No mail yet. Press n"));
    }

    #[test]
    fn move_open_and_keep_selection_across_refresh() {
        let mut a = app();
        assert_eq!(
            a.on_key(key(KeyCode::Enter)),
            Some(Cmd::Open("b".repeat(64)))
        );
        a.on_key(key(KeyCode::Char('j')));
        a.on_key(key(KeyCode::Down)); // already at the bottom
        assert_eq!(
            a.on_key(key(KeyCode::Enter)),
            Some(Cmd::Open("a".repeat(64)))
        );
        // A new letter arrives; the selection stays on the same letter.
        a.set_letters(vec![
            letter('a', "builder@ws", "older one", true),
            letter('b', "helper@ws", "newer one", false),
            letter('c', "builder@ws", "newest", false),
        ]);
        assert_eq!(a.letters[a.selected].id, "a".repeat(64));
    }

    #[test]
    fn reply_flow() {
        let mut a = app();
        a.open = Some(letter('a', "builder@ws", "older one", true));
        a.on_key(key(KeyCode::Char('r')));
        let c = a.compose.clone().unwrap();
        assert_eq!(
            (c.to.as_str(), c.subject.as_str(), c.field),
            ("builder@ws", "Re: older one", Field::Body)
        );
        typed(&mut a, "ok, q is just a letter");
        a.on_key(key(KeyCode::Enter));
        typed(&mut a, "bye");
        assert!(!a.quit, "q in a draft is text");
        assert!(screen(&a).contains("Reply · To"));
        assert_eq!(
            a.on_key(ctrl('s')),
            Some(Cmd::Send {
                to: vec!["builder@ws".into()],
                subject: "Re: older one".into(),
                body: "ok, q is just a letter\nbye".into(),
                thread: Some("a".repeat(64)),
            })
        );
        // Replying to a reply doesn't stack "Re:".
        a.compose = None;
        a.open = Some(letter('c', "x@ws", "RE: thing", true));
        a.on_key(key(KeyCode::Char('r')));
        assert_eq!(a.compose.unwrap().subject, "RE: thing");
    }

    #[test]
    fn new_letter_validation_and_discard() {
        let mut a = app();
        a.on_key(key(KeyCode::Char('n')));
        assert_eq!(a.on_key(ctrl('s')), None);
        assert!(a.status.contains("add a recipient"));
        typed(&mut a, "x@ws, y@ws");
        a.on_key(key(KeyCode::Tab));
        assert_eq!(a.on_key(ctrl('s')), None);
        assert!(a.status.contains("add a subject"));
        typed(&mut a, "hi");
        a.on_key(key(KeyCode::Backspace));
        typed(&mut a, "ello");
        let Some(Cmd::Send {
            to,
            subject,
            thread,
            ..
        }) = a.on_key(ctrl('s'))
        else {
            panic!()
        };
        assert_eq!(
            (to, subject.as_str(), thread),
            (vec!["x@ws".to_string(), "y@ws".to_string()], "hello", None)
        );
        a.on_key(key(KeyCode::Esc));
        assert!(a.compose.is_none());
    }

    #[test]
    fn list_keys() {
        let mut a = app();
        assert_eq!(a.on_key(key(KeyCode::Char('a'))), Some(Cmd::Refresh));
        assert!(!a.all);
        assert_eq!(a.on_key(key(KeyCode::Char('g'))), Some(Cmd::Refresh));
        let mut release = key(KeyCode::Char('q'));
        release.kind = KeyEventKind::Release;
        a.on_key(release);
        assert!(!a.quit, "key releases are ignored");
        a.on_key(key(KeyCode::Char('q')));
        assert!(a.quit);
    }
}
