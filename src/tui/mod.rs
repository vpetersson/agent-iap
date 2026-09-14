//! The interactive console.
//!
//! Little Snitch for agents: when a rule says `ask`, the request stops here and
//! a human answers it. A live tail of the audit log sits under every pane, so
//! the operator can see what the agent has been doing while deciding what to
//! allow next.
//!
//! It is also where the policy is kept. Everything `agent-iap agent add`,
//! `upstream add`, `mcp-server add`, `acl add` and `profile add` do from a
//! shell is a form here, over the same `enroll` functions — because the answer
//! to "this agent needs GitHub" arrives while you are sitting in front of the
//! queue, and a console you have to quit to act on it is a console you quit.
//! Rules and agents take effect in this process the moment they are written;
//! services need a restart, and the console says so rather than pretending.
//!
//! No credential value is ever displayed. References are, and whether each one
//! still resolves — which is the question the file cannot answer.

mod actions;
mod approve;
mod form;
mod views;

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::approval::{PendingView, Verdict};
use crate::audit::AuditEvent;
use crate::profiles::Profile;
use crate::state::AppState;

use actions::Policy;
use approve::{Answer, Dialogue};
use form::{Field, Form, Intent, Outcome};

const FEED_CAPACITY: usize = 200;
const TICK: Duration = Duration::from_millis(120);
/// How long a result stays on the footer before the key hints come back.
const FLASH_TTL: Duration = Duration::from_secs(8);

/// What `run` does with the terminal it was started in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Console {
    /// Draw the approval console. The terminal is the console's, so the
    /// diagnostic log goes to a file beside the audit log instead.
    Draw,
    /// Stream the log to stderr. Nobody is at a keyboard, so an `ask` is
    /// answered over the control plane or not at all.
    Headless,
}

impl Console {
    pub fn draws(self) -> bool {
        matches!(self, Console::Draw)
    }
}

/// Which of the two `run` is.
///
/// `run` is the console: an `ask` rule parks a request until a human answers,
/// and the one thing it must not do is park it in a queue nobody is looking
/// at. Where there is no terminal to draw on — a unit file, a container, a
/// pipe into `tee` — that is already the answer, and no flag should be needed
/// to say so. `--no-tui` is for a terminal you want the log stream on anyway;
/// `--tui` is for a terminal we failed to recognise as one.
pub fn choose(tui: bool, no_tui: bool, terminal: bool) -> Console {
    if tui || (terminal && !no_tui) {
        Console::Draw
    } else {
        Console::Headless
    }
}

/// Is a human at the other end of this process?
///
/// The console draws on stdout, and stdin being redirected is how a supervisor
/// says that nobody is going to type. Either one missing means the log stream.
pub fn at_a_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal() && std::io::stdin().is_terminal()
}

pub fn run(state: Arc<AppState>, config_path: &Path) -> Result<()> {
    let mut app = App::new(state, config_path)?;
    // `try_init` rather than `init`: now that the console is what `run` does by
    // default, a terminal it cannot drive has to name the flag that runs the
    // proxy anyway, not panic through a half-configured terminal.
    let mut terminal = ratatui::try_init().context(
        "opening the approval console — `agent-iap run --no-tui` runs the proxy without it",
    )?;
    let result = app.event_loop(&mut terminal);
    ratatui::restore();
    result
}

/// The panes, in the order the number keys select them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Approvals,
    Agents,
    Upstreams,
    Mcp,
    Acl,
    Credentials,
    Profiles,
}

impl Tab {
    const ALL: [Tab; 7] = [
        Tab::Approvals,
        Tab::Agents,
        Tab::Upstreams,
        Tab::Mcp,
        Tab::Acl,
        Tab::Credentials,
        Tab::Profiles,
    ];

    fn label(self) -> &'static str {
        match self {
            Tab::Approvals => "approvals",
            Tab::Agents => "agents",
            Tab::Upstreams => "upstreams",
            Tab::Mcp => "mcp",
            Tab::Acl => "acl",
            Tab::Credentials => "credentials",
            Tab::Profiles => "profiles",
        }
    }

    fn index(self) -> usize {
        Tab::ALL.iter().position(|tab| *tab == self).unwrap_or(0)
    }

    /// The keys this pane answers to, beyond the ones every pane answers to.
    fn keys(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Tab::Approvals => &[
                ("enter", "answer"),
                ("a", "allow once"),
                ("d", "deny once"),
                ("f", "forget"),
            ],
            Tab::Agents => &[("n", "enrol"), ("t", "new token"), ("x", "revoke")],
            Tab::Upstreams | Tab::Mcp => &[("n", "add"), ("x", "remove")],
            Tab::Acl => &[("n", "add rule"), ("x", "remove rule")],
            Tab::Credentials => &[("c", "re-check")],
            Tab::Profiles => &[("enter", "add")],
        }
    }
}

/// A result worth leaving on screen for a moment.
struct Flash {
    message: String,
    failed: bool,
    at: Instant,
}

enum Modal {
    /// The Little Snitch dialogue.
    Approve(Box<Dialogue>),
    Form(Box<Form>),
    Confirm(Confirm),
    /// Something to read and dismiss: a minted token, a dry run.
    Show {
        title: String,
        body: String,
        /// Rendered as a warning — a token is on screen and will not be again.
        secret: bool,
    },
    Help,
}

struct Confirm {
    question: String,
    detail: String,
    /// Offer `--prune`, and whether it is on.
    prune: Option<bool>,
    intent: Destructive,
}

#[derive(Clone)]
enum Destructive {
    RemoveAgent(String),
    RotateAgent(String),
    RemoveUpstream(String),
    RemoveMcpServer(String),
    RemoveRule(usize),
}

struct App {
    state: Arc<AppState>,
    policy: Policy,
    profiles: Vec<Profile>,
    tab: Tab,
    cursor: Vec<ListState>,
    feed: std::collections::VecDeque<AuditEvent>,
    pending: Vec<PendingView>,
    modal: Option<Modal>,
    flash: Option<Flash>,
    /// Requests the operator has looked at and left waiting, so the dialogue
    /// does not spring back the instant it is dismissed.
    dismissed: HashSet<String>,
}

impl App {
    fn new(state: Arc<AppState>, config_path: &Path) -> Result<Self> {
        let policy = Policy::load(config_path, &state)?;
        Ok(App {
            state,
            policy,
            profiles: crate::profiles::catalog(),
            tab: Tab::Approvals,
            cursor: Tab::ALL.iter().map(|_| ListState::default()).collect(),
            feed: std::collections::VecDeque::with_capacity(FEED_CAPACITY),
            pending: Vec::new(),
            modal: None,
            flash: None,
            dismissed: HashSet::new(),
        })
    }

    fn event_loop(&mut self, terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
        let mut feed_rx = self.state.audit.subscribe();

        loop {
            while let Ok(event) = feed_rx.try_recv() {
                if self.feed.len() == FEED_CAPACITY {
                    self.feed.pop_front();
                }
                self.feed.push_back(event);
            }

            self.pending = self.state.broker.list();
            self.dismissed
                .retain(|id| self.pending.iter().any(|view| view.id == *id));
            self.raise_dialogue();
            self.clamp_cursors();
            if self
                .flash
                .as_ref()
                .is_some_and(|f| f.at.elapsed() > FLASH_TTL)
            {
                self.flash = None;
            }

            terminal.draw(|frame| self.draw(frame))?;

            if !event::poll(TICK)? {
                continue;
            }
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if self.handle(key)? {
                return Ok(());
            }
        }
    }

    /// Put the oldest unanswered request in front of the operator.
    ///
    /// Unprompted, because that is the behaviour being copied: a request parked
    /// behind a pane nobody happens to be looking at will time out, and a
    /// timeout denies. Never over a modal — interrupting someone mid-form with
    /// a dialogue whose first key is "allow" is how the wrong thing gets
    /// allowed.
    fn raise_dialogue(&mut self) {
        if self.modal.is_some() {
            return;
        }
        let Some(view) = self
            .pending
            .iter()
            .find(|view| !self.dismissed.contains(&view.id))
        else {
            return;
        };
        self.tab = Tab::Approvals;
        self.modal = Some(Modal::Approve(Box::new(Dialogue::new(view.clone()))));
    }

    fn rows(&self) -> usize {
        match self.tab {
            Tab::Approvals => self.pending.len(),
            Tab::Agents => views::agents(&self.policy.inventory).len(),
            Tab::Upstreams => views::upstreams(&self.policy.inventory).len(),
            Tab::Mcp => views::mcp_servers(&self.policy.inventory).len(),
            Tab::Acl => views::acl(&self.policy.inventory).len(),
            Tab::Credentials => self.policy.credentials.len(),
            Tab::Profiles => self.profiles.len(),
        }
    }

    fn clamp_cursors(&mut self) {
        for (index, tab) in Tab::ALL.iter().enumerate() {
            let rows = {
                let was = self.tab;
                self.tab = *tab;
                let rows = self.rows();
                self.tab = was;
                rows
            };
            let state = &mut self.cursor[index];
            match rows {
                0 => state.select(None),
                rows => state.select(Some(state.selected().unwrap_or(0).min(rows - 1))),
            }
        }
    }

    fn selected(&self) -> Option<usize> {
        self.cursor[self.tab.index()].selected()
    }

    fn say(&mut self, message: impl Into<String>) {
        self.flash = Some(Flash {
            message: message.into(),
            failed: false,
            at: Instant::now(),
        });
    }

    fn blame(&mut self, error: &anyhow::Error) {
        self.flash = Some(Flash {
            message: format!("{error:#}"),
            failed: true,
            at: Instant::now(),
        });
    }

    /// Re-read the policy file into the console and into the running proxy.
    fn refresh(&mut self) {
        if let Err(error) = self.policy.rebuild(&self.state) {
            self.blame(&error);
        }
    }

    // ---- keys -------------------------------------------------------------

    /// `true` to leave the console, which stops the proxy with it.
    fn handle(&mut self, key: KeyEvent) -> Result<bool> {
        if self.modal.is_some() {
            self.handle_modal(key);
            return Ok(false);
        }

        match key.code {
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(true),
            KeyCode::Esc => self.tab = Tab::Approvals,
            KeyCode::Char('?') => self.modal = Some(Modal::Help),
            KeyCode::Char(digit @ '1'..='7') => {
                self.tab = Tab::ALL[digit as usize - '1' as usize];
            }
            KeyCode::Tab | KeyCode::Right => {
                self.tab = Tab::ALL[(self.tab.index() + 1) % Tab::ALL.len()];
            }
            KeyCode::BackTab | KeyCode::Left => {
                self.tab = Tab::ALL[(self.tab.index() + Tab::ALL.len() - 1) % Tab::ALL.len()];
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_cursor(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_cursor(-1),
            KeyCode::Char('r') => {
                self.refresh();
                self.say("re-read the policy file");
            }
            code => self.handle_tab(code),
        }
        Ok(false)
    }

    fn move_cursor(&mut self, delta: isize) {
        let rows = self.rows();
        if rows == 0 {
            return;
        }
        let state = &mut self.cursor[self.tab.index()];
        let at = state.selected().unwrap_or(0) as isize;
        state.select(Some(
            at.saturating_add(delta).clamp(0, rows as isize - 1) as usize
        ));
    }

    fn handle_tab(&mut self, code: KeyCode) {
        match (self.tab, code) {
            (Tab::Approvals, KeyCode::Enter) => {
                if let Some(view) = self.selected().and_then(|at| self.pending.get(at)).cloned() {
                    self.dismissed.remove(&view.id);
                    self.modal = Some(Modal::Approve(Box::new(Dialogue::new(view))));
                }
            }
            (Tab::Approvals, KeyCode::Char('a')) => self.quick(Verdict::Allow),
            (Tab::Approvals, KeyCode::Char('d')) => self.quick(Verdict::Deny),
            (Tab::Approvals, KeyCode::Char('f')) => {
                self.state.broker.forget_all();
                self.say("forgot every standing answer — the next call asks again");
            }

            (Tab::Agents, KeyCode::Char('n')) => {
                self.modal = Some(Modal::Form(Box::new(agent_form())))
            }
            (Tab::Agents, KeyCode::Char('t')) => {
                if let Some(id) = self.agent_at_cursor() {
                    self.modal = Some(Modal::Confirm(Confirm {
                        question: format!("Mint a new token for `{id}`?"),
                        detail: "The current one stops working immediately. Nothing upstream \
                                 rotates — the real credential never left this proxy."
                            .into(),
                        prune: None,
                        intent: Destructive::RotateAgent(id),
                    }));
                }
            }
            (Tab::Agents, KeyCode::Char('x')) => {
                if let Some(id) = self.agent_at_cursor() {
                    self.modal = Some(Modal::Confirm(Confirm {
                        question: format!("Revoke `{id}`?"),
                        detail: "Its token stops being one. Rules naming it stay unless pruned."
                            .into(),
                        prune: Some(false),
                        intent: Destructive::RemoveAgent(id),
                    }));
                }
            }

            (Tab::Upstreams, KeyCode::Char('n')) => {
                self.modal = Some(Modal::Form(Box::new(upstream_form())))
            }
            (Tab::Upstreams, KeyCode::Char('x')) => {
                if let Some(name) = self.named_at_cursor(|inventory| {
                    inventory
                        .upstreams
                        .iter()
                        .flatten()
                        .map(|row| row.name.clone())
                        .collect()
                }) {
                    self.modal = Some(Modal::Confirm(Confirm {
                        question: format!("Remove upstream `{name}`?"),
                        detail: "The proxy stops injecting its credential once restarted.".into(),
                        prune: Some(false),
                        intent: Destructive::RemoveUpstream(name),
                    }));
                }
            }

            (Tab::Mcp, KeyCode::Char('n')) => self.modal = Some(Modal::Form(Box::new(mcp_form()))),
            (Tab::Mcp, KeyCode::Char('x')) => {
                if let Some(name) = self.named_at_cursor(|inventory| {
                    inventory
                        .mcp_servers
                        .iter()
                        .flatten()
                        .map(|row| row.name.clone())
                        .collect()
                }) {
                    self.modal = Some(Modal::Confirm(Confirm {
                        question: format!("Remove MCP server `{name}`?"),
                        detail: "The proxy stops fronting it once restarted.".into(),
                        prune: Some(false),
                        intent: Destructive::RemoveMcpServer(name),
                    }));
                }
            }

            (Tab::Acl, KeyCode::Char('n')) => self.modal = Some(Modal::Form(Box::new(rule_form()))),
            (Tab::Acl, KeyCode::Char('x')) => {
                if let Some(at) = self.selected() {
                    if let Some(rule) = self.policy.inventory.acl.iter().flatten().nth(at) {
                        self.modal = Some(Modal::Confirm(Confirm {
                            question: format!("Remove rule #{} `{}`?", rule.index, rule.name),
                            detail: "Everything after it moves up one. First match wins, so \
                                     removing a rule can change what the rules below it decide."
                                .into(),
                            prune: None,
                            intent: Destructive::RemoveRule(rule.index),
                        }));
                    }
                }
            }

            (Tab::Credentials, KeyCode::Char('c')) => {
                self.policy.check_credentials(&self.state);
                let broken = self
                    .policy
                    .credentials
                    .iter()
                    .filter(|row| matches!(row.resolves, Some(Err(_))))
                    .count();
                match broken {
                    0 => self.say("every reference resolves"),
                    n => self.say(format!("{n} reference(s) no longer resolve")),
                }
            }

            (Tab::Profiles, KeyCode::Enter) => {
                if let Some(profile) = self.selected().and_then(|at| self.profiles.get(at)) {
                    self.modal = Some(Modal::Form(Box::new(profile_form(profile))));
                }
            }
            _ => {}
        }
    }

    fn agent_at_cursor(&self) -> Option<String> {
        self.named_at_cursor(|inventory| {
            inventory
                .agents
                .iter()
                .flatten()
                .map(|row| row.id.clone())
                .collect()
        })
    }

    fn named_at_cursor(
        &self,
        names: impl Fn(&crate::list::Inventory) -> Vec<String>,
    ) -> Option<String> {
        names(&self.policy.inventory).get(self.selected()?).cloned()
    }

    /// `a` / `d` on the queue: this request, this once. The dialogue is where
    /// anything wider is chosen, deliberately — a single keystroke should never
    /// be able to grant more than the one call in front of it.
    fn quick(&mut self, verdict: Verdict) {
        let Some(view) = self.selected().and_then(|at| self.pending.get(at)).cloned() else {
            return;
        };
        self.state.broker.decide_scoped(&view.id, verdict, None);
        let what = match verdict {
            Verdict::Allow => "allowed",
            Verdict::Deny => "denied",
        };
        self.say(format!("{what} once: {}", view.summary));
    }

    fn handle_modal(&mut self, key: KeyEvent) {
        match self.modal.take() {
            Some(Modal::Help) | Some(Modal::Show { .. }) => {}
            Some(Modal::Approve(mut dialogue)) => match dialogue.handle(key) {
                None => self.modal = Some(Modal::Approve(dialogue)),
                Some(Answer::Dismiss) => {
                    self.dismissed.insert(dialogue.view.id.clone());
                }
                Some(Answer::Decide {
                    verdict,
                    duration,
                    reach,
                }) => self.answer(&dialogue.view, verdict, duration, *reach),
            },
            Some(Modal::Form(mut form)) => match form.handle(key) {
                Outcome::Continue => self.modal = Some(Modal::Form(form)),
                Outcome::Cancel => {}
                Outcome::Submit => match actions::submit(&self.policy, &form) {
                    Ok(effect) => {
                        self.refresh();
                        self.say(effect.message);
                        if let Some((id, token)) = effect.token {
                            self.modal = Some(Modal::Show {
                                title: format!("token for `{id}` — shown once"),
                                body: format!(
                                    "{token}\n\nGive this to the agent as IAP_TOKEN. It is not an \
                                     upstream key: it buys nothing anywhere else, and revoking it \
                                     rotates nothing. The file got only its sha256, so this is the \
                                     last time anything can print it."
                                ),
                                secret: true,
                            });
                        } else if let Some(preview) = effect.preview {
                            self.modal = Some(Modal::Show {
                                title: "dry run — nothing was written".into(),
                                body: preview,
                                secret: false,
                            });
                        }
                    }
                    Err(error) => {
                        form.error = Some(format!("{error:#}"));
                        self.modal = Some(Modal::Form(form));
                    }
                },
            },
            Some(Modal::Confirm(confirm)) => self.handle_confirm(confirm, key),
            None => {}
        }
    }

    fn handle_confirm(&mut self, mut confirm: Confirm, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Enter => {
                let prune = confirm.prune.unwrap_or(false);
                let result = self.destroy(&confirm.intent, prune);
                self.refresh();
                match result {
                    Ok(message) => self.say(message),
                    Err(error) => self.blame(&error),
                }
            }
            KeyCode::Char('p') if confirm.prune.is_some() => {
                confirm.prune = confirm.prune.map(|on| !on);
                self.modal = Some(Modal::Confirm(confirm));
            }
            KeyCode::Char('n') | KeyCode::Esc => {}
            _ => self.modal = Some(Modal::Confirm(confirm)),
        }
    }

    fn destroy(&mut self, intent: &Destructive, prune: bool) -> Result<String> {
        let path = self.policy.path.clone();
        match intent {
            Destructive::RemoveAgent(id) => {
                let removal = crate::enroll::remove_agent(&path, id, prune)?;
                Ok(format!(
                    "revoked `{id}` — {} rule(s) pruned, {} left naming it",
                    removal.pruned_rules.len(),
                    removal.orphaned_rules.len()
                ))
            }
            Destructive::RotateAgent(id) => {
                let agent = crate::enroll::rotate_agent(&path, id)?;
                let token = agent.token.clone();
                self.modal = Some(Modal::Show {
                    title: format!("new token for `{id}` — shown once"),
                    body: format!(
                        "{token}\n\nThe old token stopped working the moment this was written. \
                         Nothing upstream rotated."
                    ),
                    secret: true,
                });
                Ok(format!("re-keyed `{id}`"))
            }
            Destructive::RemoveUpstream(name) => {
                let removal = crate::enroll::remove_upstream(&path, name, prune)?;
                Ok(format!(
                    "removed upstream `{name}` — {} rule(s) pruned; restart to stop serving it",
                    removal.pruned_rules.len()
                ))
            }
            Destructive::RemoveMcpServer(name) => {
                let removal = crate::enroll::remove_mcp_server(&path, name, prune)?;
                Ok(format!(
                    "removed MCP server `{name}` — {} rule(s) pruned; restart to stop serving it",
                    removal.pruned_rules.len()
                ))
            }
            Destructive::RemoveRule(index) => {
                let removal = crate::enroll::remove_rule(&path, *index)?;
                Ok(format!(
                    "removed rule #{index} — {} left, renumbered from there",
                    removal.remaining
                ))
            }
        }
    }

    /// Carry out one answer from the dialogue: the request itself, plus
    /// whatever the chosen duration means beyond it.
    fn answer(
        &mut self,
        view: &PendingView,
        verdict: Verdict,
        duration: approve::Duration,
        reach: approve::Reach,
    ) {
        let word = match verdict {
            Verdict::Allow => "allow",
            Verdict::Deny => "deny",
        };

        match duration {
            approve::Duration::Once => {
                self.state.broker.decide_scoped(&view.id, verdict, None);
                self.say(format!("{word}ed once: {}", view.summary));
            }
            approve::Duration::UntilQuit => {
                self.state
                    .broker
                    .decide_scoped(&view.id, verdict, Some(reach.scope.clone()));
                self.say(format!(
                    "{word}ing {} until agent-iap exits",
                    reach.label.trim_start_matches("→ ")
                ));
            }
            approve::Duration::Forever => {
                // In front of the rule that asked, or appended when the default
                // did the asking. Either way the request in hand is answered
                // directly: the new rule governs the *next* call, and this one
                // is already parked behind it.
                let at = view.asked_by.as_ref().map(|rule| rule.index);
                match self.write_rule(&reach.rule, word, at) {
                    Ok(landed) => {
                        self.state.broker.decide_scoped(&view.id, verdict, None);
                        self.refresh();
                        self.say(format!(
                            "wrote rule #{landed} to {} — {word} {} from now on",
                            self.policy.path.display(),
                            reach.label.trim_start_matches("→ ")
                        ));
                    }
                    Err(error) => {
                        // The file was not written, so the request must not be
                        // answered as though it had been.
                        self.dismissed.insert(view.id.clone());
                        self.blame(&error);
                    }
                }
            }
        }
    }

    fn write_rule(
        &self,
        rule: &approve::RuleShape,
        action: &str,
        before: Option<usize>,
    ) -> Result<usize> {
        let name = format!("console-{action}-{}-{}", rule.agent, rule.target);
        let path = self.policy.path.as_path();
        match before {
            Some(index) => crate::enroll::insert_rule(
                path,
                index,
                Some(&name),
                &rule.agent,
                &rule.kind,
                &rule.target,
                &rule.methods,
                &rule.paths,
                action,
            ),
            None => crate::enroll::add_rule(
                path,
                Some(&name),
                &rule.agent,
                &rule.kind,
                &rule.target,
                &rule.methods,
                &rule.paths,
                action,
            ),
        }
    }

    // ---- drawing ----------------------------------------------------------

    fn draw(&mut self, frame: &mut Frame) {
        let areas = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(1),
                Constraint::Percentage(50),
                Constraint::Min(5),
                Constraint::Length(3),
            ])
            .split(frame.area());

        self.draw_header(frame, areas[0]);
        self.draw_tabs(frame, areas[1]);
        self.draw_body(frame, areas[2]);
        self.draw_feed(frame, areas[3]);
        self.draw_footer(frame, areas[4]);

        match &self.modal {
            Some(Modal::Approve(dialogue)) => dialogue.render(frame, frame.area()),
            Some(Modal::Form(form)) => form.render(frame, frame.area()),
            Some(Modal::Confirm(confirm)) => draw_confirm(frame, frame.area(), confirm),
            Some(Modal::Show {
                title,
                body,
                secret,
            }) => draw_show(frame, frame.area(), title, body, *secret),
            Some(Modal::Help) => draw_help(frame, frame.area()),
            None => {}
        }
    }

    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let waiting = self.pending.len();
        let pending_style = if waiting > 0 {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let mut spans = vec![
            Span::styled(
                " agent-iap ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("  proxy {}  ", self.state.config.server.listen)),
            Span::styled(format!("  {waiting} waiting  "), pending_style),
            Span::raw(format!(
                "  {} agents · {} upstreams · {} mcp · {} rules · default {} ",
                self.state.agents.len(),
                self.policy.config.upstreams.len(),
                self.policy.config.mcp_servers.len(),
                self.state.acl.rule_count(),
                self.state.acl.default_action(),
            )),
        ];

        // An edit that is in the file but not in this process is the one thing
        // an operator cannot see by looking at either.
        if !self.policy.restart_needed.is_empty() {
            spans.push(Span::styled(
                format!(
                    " restart to apply: {} ",
                    self.policy.restart_needed.join(", ")
                ),
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ));
        }

        frame.render_widget(
            Paragraph::new(Line::from(spans)).block(Block::default().borders(Borders::ALL)),
            area,
        );
    }

    fn draw_tabs(&self, frame: &mut Frame, area: Rect) {
        let mut spans = Vec::new();
        for (index, tab) in Tab::ALL.iter().enumerate() {
            let selected = *tab == self.tab;
            let badge = if *tab == Tab::Approvals && !self.pending.is_empty() {
                format!(" {}·{} ({}) ", index + 1, tab.label(), self.pending.len())
            } else {
                format!(" {}·{} ", index + 1, tab.label())
            };
            spans.push(Span::styled(
                badge,
                if selected {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                },
            ));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn draw_body(&mut self, frame: &mut Frame, area: Rect) {
        let index = self.tab.index();
        match self.tab {
            Tab::Approvals => {
                let split = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
                    .split(area);
                draw_pending(frame, split[0], &self.pending, &mut self.cursor[index]);
                draw_request(
                    frame,
                    split[1],
                    &self.pending,
                    self.cursor[index].selected(),
                );
            }
            Tab::Agents => views::agents(&self.policy.inventory).render(
                frame,
                area,
                "agents",
                &mut self.cursor[index],
            ),
            Tab::Upstreams => views::upstreams(&self.policy.inventory).render(
                frame,
                area,
                "upstreams",
                &mut self.cursor[index],
            ),
            Tab::Mcp => views::mcp_servers(&self.policy.inventory).render(
                frame,
                area,
                "mcp servers",
                &mut self.cursor[index],
            ),
            Tab::Acl => {
                let split = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(3), Constraint::Length(1)])
                    .split(area);
                views::acl(&self.policy.inventory).render(
                    frame,
                    split[0],
                    "acl — match order, first match wins",
                    &mut self.cursor[index],
                );
                frame.render_widget(
                    Paragraph::new(format!(
                        " nothing matched → {}",
                        self.state.acl.default_action()
                    ))
                    .style(Style::default().fg(Color::DarkGray)),
                    split[1],
                );
            }
            Tab::Credentials => {
                let split = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(3), Constraint::Length(1)])
                    .split(area);
                views::credentials(&self.policy.credentials).render(
                    frame,
                    split[0],
                    "credentials",
                    &mut self.cursor[index],
                );
                frame.render_widget(
                    Paragraph::new(
                        " references only — the proxy resolves these and never displays a value",
                    )
                    .style(Style::default().fg(Color::DarkGray)),
                    split[1],
                );
            }
            Tab::Profiles => {
                let split = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .split(area);
                views::profiles(&self.profiles).render(
                    frame,
                    split[0],
                    "profiles",
                    &mut self.cursor[index],
                );
                draw_profile(
                    frame,
                    split[1],
                    self.cursor[index]
                        .selected()
                        .and_then(|at| self.profiles.get(at)),
                );
            }
        }
    }

    fn draw_feed(&self, frame: &mut Frame, area: Rect) {
        let visible = area.height.saturating_sub(2) as usize;
        let items: Vec<ListItem> = self
            .feed
            .iter()
            .rev()
            .take(visible)
            .map(|event| {
                let decision = event
                    .record
                    .decision
                    .as_deref()
                    .unwrap_or(&event.record.event);
                let colour = if decision.starts_with("allow") {
                    Color::Green
                } else if decision.starts_with("deny") || decision.contains("denied") {
                    Color::Red
                } else if decision.starts_with("ask") {
                    Color::Yellow
                } else {
                    Color::DarkGray
                };
                // Just the clock: everything on screen shares a date.
                let time = event.ts.get(11..19).unwrap_or(&event.ts);
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{time} "), Style::default().fg(Color::DarkGray)),
                    Span::styled(format!("{decision:<22} "), Style::default().fg(colour)),
                    Span::raw(format!(
                        "{} {} {} {}",
                        event.record.agent,
                        event.record.target,
                        event.record.method,
                        event.record.path
                    )),
                    Span::styled(
                        event
                            .record
                            .status
                            .map(|s| format!(" → {s}"))
                            .unwrap_or_default(),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        event
                            .record
                            .rule
                            .as_deref()
                            .map(|rule| format!("  [{rule}]"))
                            .unwrap_or_default(),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]))
            })
            .collect();

        frame.render_widget(
            List::new(items).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" audit log (live) "),
            ),
            area,
        );
    }

    fn draw_footer(&self, frame: &mut Frame, area: Rect) {
        if let Some(flash) = &self.flash {
            let style = if flash.failed {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::Green)
            };
            frame.render_widget(
                Paragraph::new(flash.message.as_str())
                    .style(style)
                    .wrap(Wrap { trim: true })
                    .block(Block::default().borders(Borders::ALL)),
                area,
            );
            return;
        }

        let mut keys: Vec<(&str, &str)> = vec![("↑/↓", "move"), ("tab", "pane")];
        keys.extend_from_slice(self.tab.keys());
        keys.push(("r", "reload"));
        keys.push(("?", "help"));
        keys.push(("q", "quit"));

        let mut spans = Vec::new();
        for (key, description) in keys {
            spans.push(Span::styled(
                format!(" {key} "),
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw(format!(" {description}  ")));
        }
        frame.render_widget(
            Paragraph::new(Line::from(spans)).block(Block::default().borders(Borders::ALL)),
            area,
        );
    }
}

fn draw_pending(frame: &mut Frame, area: Rect, pending: &[PendingView], state: &mut ListState) {
    let items: Vec<ListItem> = pending
        .iter()
        .map(|view| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{:>4}s ", view.waited_ms / 1000),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("{} ", view.agent_name),
                    Style::default().fg(Color::Magenta),
                ),
                Span::raw(view.summary.clone()),
            ]))
        })
        .collect();

    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" waiting for you "),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ "),
        area,
        state,
    );
}

fn draw_request(frame: &mut Frame, area: Rect, pending: &[PendingView], selected: Option<usize>) {
    let block = Block::default().borders(Borders::ALL).title(" request ");

    let Some(view) = selected.and_then(|index| pending.get(index)) else {
        frame.render_widget(
            Paragraph::new(
                "Nothing is waiting.\n\nRequests matching an `ask` rule appear here, and the \
                 dialogue opens by itself.",
            )
            .style(Style::default().fg(Color::DarkGray))
            .block(block),
            area,
        );
        return;
    };

    let mut lines = vec![
        field(
            "agent",
            &format!("{} ({})", view.agent_name, view.request.agent),
        ),
        field("kind", view.request.kind.as_str()),
        field("target", &view.request.target),
        field("method", &view.request.method),
        field("path", &view.request.path),
        field("waiting", &format!("{}s", view.waited_ms / 1000)),
    ];
    if let Some(rule) = &view.asked_by {
        lines.push(field("rule", &format!("#{} {}", rule.index, rule.label)));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "Enter opens the dialogue: how long the answer holds, and how far it reaches.",
        Style::default().fg(Color::DarkGray),
    )));

    frame.render_widget(
        // `trim: false` keeps the right-aligned field labels aligned.
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

fn field<'a>(name: &'a str, value: &str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{name:>8}  "), Style::default().fg(Color::DarkGray)),
        Span::styled(value.to_string(), Style::default().fg(Color::White)),
    ])
}

fn draw_profile(frame: &mut Frame, area: Rect, profile: Option<&Profile>) {
    let block = Block::default().borders(Borders::ALL).title(" profile ");
    let Some(profile) = profile else {
        frame.render_widget(
            Paragraph::new("A profile is a service definition worked out in advance.")
                .style(Style::default().fg(Color::DarkGray))
                .block(block),
            area,
        );
        return;
    };

    let mut lines = vec![
        Line::from(Span::styled(
            profile.title.clone(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            profile.summary.clone(),
            Style::default().fg(Color::Gray),
        )),
        Line::raw(""),
        field("needs", &profile.credential.about),
        field("from", &profile.credential.url),
    ];
    for var in &profile.vars {
        lines.push(field("var", &format!("{} — {}", var.name, var.about)));
    }
    for level in &profile.access {
        lines.push(field(
            "access",
            &format!("{} — {}", level.name, level.about),
        ));
    }
    if let Some(note) = &profile.note {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            note.clone(),
            Style::default().fg(Color::Yellow),
        )));
    }

    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }).block(block),
        area,
    );
}

fn draw_confirm(frame: &mut Frame, area: Rect, confirm: &Confirm) {
    let popup = form::centred(area, 70.min(area.width), 11.min(area.height));
    frame.render_widget(Clear, popup);

    let mut lines = vec![
        Line::raw(""),
        Line::from(Span::styled(
            confirm.question.clone(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
        Line::from(Span::styled(
            confirm.detail.clone(),
            Style::default().fg(Color::DarkGray),
        )),
        Line::raw(""),
    ];
    if let Some(prune) = confirm.prune {
        lines.push(Line::from(vec![
            Span::styled(" p ", Style::default().fg(Color::Black).bg(Color::Cyan)),
            Span::raw(format!(
                "  also delete the rules that name it: {}",
                if prune { "yes" } else { "no" }
            )),
        ]));
        lines.push(Line::raw(""));
    }
    lines.push(Line::from(vec![
        Span::styled(
            " y ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" do it    "),
        Span::styled(" n ", Style::default().fg(Color::Black).bg(Color::DarkGray)),
        Span::raw(" leave it alone"),
    ]));

    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red))
                .title(" confirm "),
        ),
        popup,
    );
}

fn draw_show(frame: &mut Frame, area: Rect, title: &str, body: &str, secret: bool) {
    let height = (body.lines().count() as u16 + 8).min(area.height);
    let popup = form::centred(area, 80.min(area.width), height);
    frame.render_widget(Clear, popup);

    let accent = if secret { Color::Yellow } else { Color::Cyan };
    let mut lines = vec![Line::raw("")];
    for line in body.lines() {
        lines.push(Line::from(Span::styled(
            line.to_string(),
            if secret {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            },
        )));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "any key to close",
        Style::default().fg(Color::DarkGray),
    )));

    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(accent))
                .title(format!(" {title} ")),
        ),
        popup,
    );
}

fn draw_help(frame: &mut Frame, area: Rect) {
    let popup = form::centred(area, 72.min(area.width), 22.min(area.height));
    frame.render_widget(Clear, popup);

    let mut lines = vec![Line::raw("")];
    for (keys, what) in [
        ("1…7 / tab", "move between panes"),
        ("↑ ↓ / j k", "move within one"),
        ("n", "add — agent, upstream, MCP server, rule"),
        ("x", "remove what the cursor is on"),
        ("t", "mint a new token for the selected agent"),
        ("c", "re-resolve every credential reference"),
        ("enter", "answer a request, or add the selected profile"),
        ("a / d", "allow or deny the selected request, once"),
        ("f", "forget every standing answer"),
        ("r", "re-read the policy file from disk"),
        ("q", "quit — which stops the proxy"),
    ] {
        lines.push(Line::from(vec![
            Span::styled(format!("  {keys:<12}"), Style::default().fg(Color::Cyan)),
            Span::raw(what),
        ]));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "  Rules and agents written here take effect immediately. Upstreams and MCP \
         servers need a restart, and the header says so when one is owed.",
        Style::default().fg(Color::DarkGray),
    )));

    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" keys "),
        ),
        popup,
    );
}

// ---- the forms, one per enrolment command ---------------------------------

fn agent_form() -> Form {
    Form::new(
        Intent::Agent,
        "enrol an agent",
        "Mints a token and writes only its sha256. The token is shown once, here.",
        vec![
            Field::text("id", "id", "how the agent authenticates, and the name every audit record uses"),
            Field::text("name", "name", "what a human calls it, when the id is not that"),
            Field::text(
                "targets",
                "targets",
                "upstreams and MCP servers it may address at all. Blank means any, with the ACL still in charge.",
            ),
        ],
    )
}

fn upstream_form() -> Form {
    let mut fields = vec![
        Field::text(
            "name",
            "name",
            "routing prefix and policy name: agents call /<name>/<path>",
        ),
        Field::text(
            "base-url",
            "base url",
            "where the proxy forwards to, e.g. https://api.github.com",
        ),
    ];
    fields.extend(form::auth_fields());
    fields.push(Field::text(
        "set-header",
        "headers",
        "static headers to send upstream, NAME=VALUE — never a credential, that is what the secret is for",
    ));
    Form::new(
        Intent::Upstream,
        "add an upstream",
        "A service to front, and the credential to attach on the way out. The credential is a reference; the proxy resolves it.",
        fields,
    )
}

fn mcp_form() -> Form {
    let mut fields = vec![
        Field::text("name", "name", "policy name agents address, and the name every audit record uses"),
        Field::choice("transport", "transport", "a child process to spawn, or a remote endpoint", &["stdio", "http"]),
        Field::text("url", "url", "remote MCP endpoint").when("transport", &["http"]),
        Field::text("command", "command", "executable to spawn").when("transport", &["stdio"]),
        Field::text("args", "args", "arguments, in order").when("transport", &["stdio"]),
        Field::text(
            "env",
            "env",
            "child environment, NAME=<secret-ref> — how a stdio server gets its credential, as a reference",
        )
        .when("transport", &["stdio"]),
        Field::text("cwd", "cwd", "working directory for the child").when("transport", &["stdio"]),
    ];
    fields.extend(form::auth_fields());
    Form::new(
        Intent::McpServer,
        "add an MCP server",
        "The proxy sees every JSON-RPC message either way, and the ACL rules on tool names.",
        fields,
    )
}

fn rule_form() -> Form {
    Form::new(
        Intent::Rule,
        "add an ACL rule",
        "Rules match in file order and the first match wins, so where it lands is the policy.",
        vec![
            Field::text(
                "name",
                "name",
                "shown in the audit log and here, so a decision traces to a rule",
            ),
            Field::prefilled("agent", "agent", "agent id or glob", "*"),
            Field::choice(
                "kind",
                "kind",
                "which surface this rule covers",
                &["*", "http", "mcp"],
            ),
            Field::prefilled("target", "target", "upstream or MCP server name, or *", "*"),
            Field::prefilled(
                "methods",
                "methods",
                "HTTP verbs, or JSON-RPC methods such as tools/call",
                "*",
            ),
            Field::prefilled(
                "paths",
                "paths",
                "URL paths, or for MCP the tool name. * stops at /, ** crosses it.",
                "**",
            ),
            Field::choice(
                "action",
                "action",
                "ask stops the request on a human at this console",
                &["allow", "deny", "ask"],
            ),
            Field::text(
                "position",
                "position",
                "rule number to insert before. Blank appends, which means it is checked last.",
            ),
        ],
    )
}

fn profile_form(profile: &Profile) -> Form {
    let levels: Vec<&str> = profile
        .access
        .iter()
        .map(|level| level.name.as_str())
        .collect();
    let vars = profile
        .vars
        .iter()
        .map(|var| format!("{}={}", var.name, var.default.clone().unwrap_or_default()))
        .collect::<Vec<_>>()
        .join(", ");

    Form::new(
        Intent::Profile,
        &format!("add `{}`", profile.id),
        &format!("{} — {}", profile.credential.about, profile.credential.url),
        vec![
            Field::prefilled("id", "profile", "", &profile.id),
            Field::prefilled("as", "name", "name it takes in the policy file — how one proxy fronts two accounts of the same service", &profile.default_name),
            Field::text("secret", "secret", "credential reference: env:NAME, file:/path, op://vault/item/field"),
            Field::choice("access", "access", "which bundle of scopes and rules to write", &levels),
            Field::prefilled("var", "vars", "profile variables, NAME=VALUE", &vars),
            Field::text("agent", "agent", "scope the rules to one agent or glob. Blank means every agent."),
            Field::flag("dry-run", "dry run", "show the TOML it would write, and write nothing"),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::AccessRequest;
    use crate::approval::AskingRule;
    use crate::config::Config;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    const POLICY: &str = r#"
[audit]
path = "AUDIT"
stderr = false

[[agents]]
id = "claude-code"
name = "Claude Code"
token_sha256 = "HASH"

[[upstreams]]
name = "github"
base_url = "https://api.github.com"
auth = { type = "bearer", secret = "env:AGENT_IAP_TEST_TOKEN" }

[[acl]]
name = "github-writes-need-a-human"
target = "github"
methods = ["POST"]
action = "ask"
"#;

    fn app_for_test(dir: &std::path::Path) -> App {
        std::env::set_var("AGENT_IAP_TEST_TOKEN", "sk-not-real");
        let text = POLICY
            .replace("AUDIT", &dir.join("audit.jsonl").display().to_string())
            .replace("HASH", &crate::identity::token_hash("iap_test"));
        let path = dir.join("iap.toml");
        std::fs::write(&path, &text).unwrap();

        let config: Config = toml::from_str(&text).unwrap();
        let state = AppState::build(config, false).unwrap();
        App::new(state, &path).unwrap()
    }

    fn render(app: &mut App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        format!("{}", terminal.backend())
    }

    /// The request the policy above stops on a human.
    fn waiting() -> PendingView {
        PendingView {
            id: "abc".into(),
            request: AccessRequest::http("claude-code", "github", "POST", "/repos/acme/api/issues"),
            summary: "github POST /repos/acme/api/issues".into(),
            waited_ms: 4_000,
            agent_name: "Claude Code".into(),
            asked_by: Some(AskingRule {
                index: 0,
                label: "github-writes-need-a-human".into(),
            }),
        }
    }

    #[tokio::test]
    async fn the_console_shows_a_pending_request_and_the_keys_to_answer_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.pending = vec![waiting()];
        app.cursor[Tab::Approvals.index()].select(Some(0));
        app.feed.push_back(
            app.state
                .audit
                .write(crate::audit::AuditRecord {
                    kind: "http".into(),
                    event: "request".into(),
                    agent: "claude-code".into(),
                    target: "github".into(),
                    method: "GET".into(),
                    path: "/repos/acme/api".into(),
                    decision: Some("allow".into()),
                    rule: Some("github-reads".into()),
                    status: Some(200),
                    ..Default::default()
                })
                .unwrap(),
        );

        let rendered = render(&mut app, 120, 34);
        println!("{rendered}");

        for expected in [
            "agent-iap",
            "1 waiting",
            "Claude Code",
            "/repos/acme/api/issues",
            "audit log (live)",
            "github-reads",
            "approvals",
            "credentials",
        ] {
            assert!(
                rendered.contains(expected),
                "console did not render `{expected}`:\n{rendered}"
            );
        }
    }

    #[tokio::test]
    async fn an_empty_queue_says_so_rather_than_rendering_a_blank_panel() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        let rendered = render(&mut app, 120, 34);
        assert!(rendered.contains("Nothing is waiting"), "{rendered}");
    }

    #[tokio::test]
    async fn a_waiting_request_raises_the_dialogue_without_being_asked() {
        // The behaviour being copied: a request parked behind a pane nobody is
        // looking at times out, and a timeout denies.
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Credentials;
        app.pending = vec![waiting()];
        app.raise_dialogue();

        assert!(matches!(app.modal, Some(Modal::Approve(_))));
        assert_eq!(app.tab, Tab::Approvals, "and brings the queue up behind it");

        let rendered = render(&mut app, 120, 34);
        assert!(rendered.contains("wants to"), "{rendered}");
        assert!(rendered.contains("From now on"), "{rendered}");
        assert!(
            rendered.contains("does not hand it over"),
            "the dialogue has to say the credential is not what is being allowed:\n{rendered}"
        );
    }

    #[tokio::test]
    async fn dismissing_a_request_does_not_spring_the_dialogue_straight_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.pending = vec![waiting()];
        app.raise_dialogue();
        app.handle_modal(KeyEvent::from(KeyCode::Esc));
        assert!(app.modal.is_none());

        app.raise_dialogue();
        assert!(
            app.modal.is_none(),
            "the operator said `later`, and the timeout still fails closed"
        );
    }

    /// The console's whole reason to exist beyond the queue: policy written
    /// here is policy the proxy is running, without a restart.
    #[tokio::test]
    async fn allowing_from_now_on_writes_a_rule_in_front_of_the_one_that_asked() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        let view = waiting();

        let denied_before = app.state.acl.evaluate(&view.request).action;
        assert_eq!(denied_before, crate::config::Action::Ask);

        let reach = approve::reaches(&view).pop().unwrap();
        app.answer(&view, Verdict::Allow, approve::Duration::Forever, reach);

        // In the file, before the rule that asked…
        let written = std::fs::read_to_string(dir.path().join("iap.toml")).unwrap();
        assert!(
            written.contains("console-allow-claude-code-github"),
            "{written}"
        );
        let text = &written;
        assert!(
            text.find("console-allow").unwrap() < text.find("github-writes-need-a-human").unwrap(),
            "an appended rule would sit behind the `ask` and never be reached:\n{text}"
        );

        // …and in this process, now.
        assert_eq!(
            app.state.acl.evaluate(&view.request).action,
            crate::config::Action::Allow,
            "a rule that needs a restart to work is a rule that did not work"
        );
    }

    #[tokio::test]
    async fn until_quit_remembers_the_scope_that_was_chosen_not_just_the_one_call() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        let view = waiting();

        // The second row: anything on `github`.
        let reach = approve::reaches(&view)[1].clone();
        app.answer(&view, Verdict::Allow, approve::Duration::UntilQuit, reach);

        let other = AccessRequest::http("claude-code", "github", "DELETE", "/repos/acme/api");
        assert_eq!(
            app.state
                .broker
                .remembered()
                .iter()
                .find(|(scope, _)| scope.matches(&other))
                .map(|(_, verdict)| *verdict),
            Some(Verdict::Allow),
        );
        // Nothing was written: the point of the middle column.
        let written = std::fs::read_to_string(dir.path().join("iap.toml")).unwrap();
        assert!(!written.contains("console-allow"), "{written}");
    }

    #[tokio::test]
    async fn enrolling_an_agent_from_the_console_makes_its_token_work_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());

        let mut form = agent_form();
        form.fields[0].value = form::Value::Text("codex".into());
        form.fields[2].value = form::Value::Text("github".into());

        let effect = actions::submit(&app.policy, &form).unwrap();
        app.refresh();
        let (_, token) = effect.token.expect("a new agent is a new token");

        let authenticated = app.state.agents.authenticate(&token);
        assert_eq!(
            authenticated.map(|agent| agent.id.clone()),
            Some("codex".to_string()),
            "an agent enrolled here has to be able to call before the next restart"
        );
        assert!(app.policy.restart_needed.is_empty());
    }

    #[tokio::test]
    async fn adding_an_upstream_says_it_needs_a_restart_rather_than_pretending() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());

        let mut form = upstream_form();
        form.fields[0].value = form::Value::Text("linear".into());
        form.fields[1].value = form::Value::Text("https://api.linear.app".into());

        actions::submit(&app.policy, &form).unwrap();
        app.refresh();

        assert_eq!(app.policy.restart_needed, vec!["upstreams"]);
        let rendered = render(&mut app, 160, 34);
        assert!(rendered.contains("restart to apply"), "{rendered}");
    }

    #[tokio::test]
    async fn the_credentials_pane_shows_references_and_never_a_value() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Credentials;
        app.policy.check_credentials(&app.state);

        let rendered = render(&mut app, 140, 34);
        assert!(rendered.contains("env:AGENT_IAP_TEST_TOKEN"), "{rendered}");
        assert!(
            !rendered.contains("sk-not-real"),
            "the resolved value must never reach the screen:\n{rendered}"
        );
        assert!(rendered.contains("upstream github"), "{rendered}");
    }

    /// Draws every pane and every modal, at a comfortable size and at the
    /// smallest terminal anyone sensibly opens.
    ///
    /// The console is the one surface with no error path: a layout that divides
    /// by a zero-width column or indexes past a two-row pane takes the proxy
    /// down with it, and the proxy is holding the credentials.
    #[tokio::test]
    async fn every_pane_and_dialogue_draws_at_any_size_a_terminal_comes_in() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.pending = vec![waiting()];
        app.policy.check_credentials(&app.state);

        let modals: Vec<Box<dyn Fn() -> Option<Modal>>> = vec![
            Box::new(|| None),
            Box::new(|| Some(Modal::Help)),
            Box::new(|| Some(Modal::Approve(Box::new(Dialogue::new(waiting()))))),
            Box::new(|| Some(Modal::Form(Box::new(upstream_form())))),
            Box::new(|| Some(Modal::Form(Box::new(mcp_form())))),
            Box::new(|| Some(Modal::Form(Box::new(rule_form())))),
            Box::new(|| Some(Modal::Form(Box::new(agent_form())))),
            Box::new(|| {
                Some(Modal::Show {
                    title: "token".into(),
                    body: "iap_0123456789".into(),
                    secret: true,
                })
            }),
            Box::new(|| {
                Some(Modal::Confirm(Confirm {
                    question: "Revoke `claude-code`?".into(),
                    detail: "Its token stops being one.".into(),
                    prune: Some(true),
                    intent: Destructive::RemoveAgent("claude-code".into()),
                }))
            }),
        ];

        for (width, height) in [(160, 48), (120, 34), (80, 24), (60, 16)] {
            for tab in Tab::ALL {
                app.tab = tab;
                for modal in &modals {
                    app.modal = modal();
                    app.clamp_cursors();
                    render(&mut app, width, height);
                }
            }
        }
    }

    /// `run` is the console, so a terminal is all it should take to get one —
    /// and a unit file, which has no terminal, must not get one by accident.
    #[test]
    fn a_terminal_gets_the_console_and_a_unit_file_gets_the_log() {
        assert_eq!(choose(false, false, true), Console::Draw);
        assert_eq!(choose(false, false, false), Console::Headless);
    }

    #[test]
    fn either_flag_beats_what_the_terminal_looks_like() {
        // A terminal we failed to recognise; and a terminal whose operator
        // wants the log stream on it anyway.
        assert_eq!(choose(true, false, false), Console::Draw);
        assert_eq!(choose(false, true, true), Console::Headless);
    }
}
