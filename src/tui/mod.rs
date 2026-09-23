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
//! One form has no shell command behind it: `e` on an upstream opens the entry
//! as the file has it, to be corrected and written back. On a command line the
//! same thing needs a rule for what an omitted flag means, and "omitted" and
//! "no credential" are one keystroke apart; a form that opens on the answer and
//! sends all of it back does not have to have that rule.
//! Rules and agents take effect in this process the moment they are written;
//! services need a restart, and the console says so rather than pretending.
//!
//! It is not the only author, either. The daemon watches the policy file
//! whether or not this is drawn (`crate::reload`), so an edit made with the CLI
//! in the next terminal — or in an editor, or announced with `SIGHUP` — lands
//! in the running proxy on its own, and the console hears about it and catches
//! its panes up.
//!
//! No credential value is ever displayed. References are, and whether each one
//! still resolves — which is the question the file cannot answer.

mod actions;
mod approve;
mod browse;
mod catalogue;
mod choose;
mod form;
mod views;

use anyhow::{Context, Result};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::approval::{PendingView, Verdict};
use crate::audit::AuditEvent;
use crate::config::UpstreamConfig;
use crate::list::Inventory;
use crate::profiles::Profile;
use crate::reload::Trigger;
use crate::state::AppState;
use crate::verify;

use actions::Policy;
use approve::{Answer, Dialogue};
use choose::Candidate;
use form::{Field, Form, Intent, Outcome};

const FEED_CAPACITY: usize = 200;
const TICK: Duration = Duration::from_millis(120);
/// How long a result stays on the footer before the key hints come back.
const FLASH_TTL: Duration = Duration::from_secs(8);
/// Two clicks closer together than this, on the same cell, are a double click.
/// Generous: this is a terminal, and the operator may be on a trackpad.
const DOUBLE_CLICK: Duration = Duration::from_millis(450);

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

pub fn run(state: Arc<AppState>, watcher: Arc<crate::reload::Watcher>) -> Result<()> {
    let mut app = App::new(state, watcher)?;
    // `try_init` rather than `init`: now that the console is what `run` does by
    // default, a terminal it cannot drive has to name the flag that runs the
    // proxy anyway, not panic through a half-configured terminal.
    let mut terminal = ratatui::try_init().context(
        "opening the approval console — `agent-iap run --no-tui` runs the proxy without it",
    )?;
    catch_the_mouse();
    app.mouse = set_mouse(true);

    let result = app.event_loop(&mut terminal);

    set_mouse(false);
    ratatui::restore();
    result
}

/// Turn mouse reporting on or off, reporting whether it took.
///
/// A terminal that will not do it is not an error: the console is driven by the
/// keyboard and always has been, and refusing to open over a missing
/// convenience would be the wrong trade for the one surface that answers an
/// `ask`.
fn set_mouse(on: bool) -> bool {
    use std::io::stdout;
    let result = match on {
        true => crossterm::execute!(stdout(), EnableMouseCapture),
        false => crossterm::execute!(stdout(), DisableMouseCapture),
    };
    result.is_ok() && on
}

/// Make sure a panic turns mouse reporting back off.
///
/// `ratatui::try_init` installs a hook that leaves the alternate screen and
/// drops raw mode, and knows nothing about the mouse. Without this, a panic
/// would hand the operator back a shell that prints garbage every time they
/// move the pointer — and they would have to know to type `reset` blind.
fn catch_the_mouse() {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        set_mouse(false);
        hook(info);
    }));
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
            Tab::Upstreams => &[
                ("n", "add"),
                ("e", "edit"),
                ("v", "verify"),
                ("x", "remove"),
            ],
            Tab::Mcp => &[("n", "add"), ("v", "verify"), ("x", "remove")],
            Tab::Acl => &[("n", "add rule"), ("x", "remove rule"), ("R", "reset")],
            Tab::Credentials => &[("c", "re-read")],
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
    Show(Shown),
    Help,
}

/// A modal that is only there to be read — and, when it is holding a token,
/// copied.
struct Shown {
    title: String,
    body: String,
    /// Rendered as a warning — a token is on screen and will not be again.
    secret: bool,
    /// The token on its own, without the paragraph of explanation around it.
    /// `Some` is what makes `c` do anything.
    copy: Option<String>,
    /// What the last `c` did. Shown in the modal rather than flashed on the
    /// footer, which this may well be covering.
    note: Option<String>,
}

impl Shown {
    /// Is this one holding something that will not be on screen again?
    ///
    /// The one question that decides how hard it is to close: a preview can go
    /// on any key, because the thing it previewed is still there to look at.
    fn irreplaceable(&self) -> bool {
        self.secret
    }

    /// A dry run, a preview — something to read and close.
    fn plain(title: String, body: String) -> Self {
        Shown {
            title,
            body,
            secret: false,
            copy: None,
            note: None,
        }
    }

    /// A token: the warning colours, and `c` wired up to the value itself.
    fn token(title: String, token: &str, body: String) -> Self {
        Shown {
            title,
            body,
            secret: true,
            copy: Some(token.to_string()),
            note: None,
        }
    }
}

/// What `c` did, in a line short enough for the modal's footer.
///
/// Every outcome gets one, including the refusals: the operator pressed a key
/// and is owed an answer, and "nothing happened" is indistinguishable from a
/// console that has stopped responding.
///
/// `Sent` is the awkward one. The sequence left this process and that is all
/// anybody can know — so when a multiplexer is in the way, the line also names
/// the setting to go and check, because "paste it to be sure" is no help at all
/// to the operator who just did and found nothing there.
fn copy_note(outcome: crate::clipboard::Copied) -> String {
    use crate::clipboard::{Copied, Relay};
    match outcome {
        Copied::Sent => match crate::clipboard::relay() {
            Relay::None => "copied — OSC 52 is one-way, so paste it somewhere to be sure".into(),
            Relay::Tmux => "copied — paste it somewhere to be sure. If nothing arrived, tmux \
                            swallowed it: `set -g set-clipboard on`."
                .into(),
            Relay::Screen => "copied — paste it somewhere to be sure. If nothing arrived, \
                              screen swallowed it."
                .into(),
        },
        Copied::Declined => "not copied — IAP_NO_CLIPBOARD is set".into(),
        Copied::NoTerminal | Copied::Failed => "could not reach the terminal's clipboard".into(),
        Copied::TooLarge => "too long for OSC 52, so nothing was copied".into(),
    }
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
    /// Start over: every rule out, `acl_default` to `ask`, so the requests
    /// that were being decided by those rules come back here to be answered.
    ResetAcl,
}

/// Where the last frame put everything a pointer can hit.
///
/// A terminal reports a click as a row and a column and nothing else, and
/// immediate-mode drawing keeps no widget tree to ask what is there. So the
/// draw records what it put where, and the click looks it up. Rebuilt every
/// frame, which is also what keeps it honest — a hit map that outlived its
/// frame is a click on something that has moved.
#[derive(Default)]
struct Hits {
    tabs: Vec<(Rect, Tab)>,
    /// The rows of the current pane, and how far the list is scrolled.
    rows: Option<(Rect, usize)>,
    /// Footer hints: the rect, and the key the hint stands for.
    keys: Vec<(Rect, KeyCode)>,
    dialogue: Option<approve::Hits>,
    form: Option<form::Hits>,
    /// A modal with nothing to aim at — help, a shown token, a confirmation.
    /// Clicking it dismisses; clicking past it does nothing.
    plain_modal: Option<Rect>,
    confirm: Option<(Rect, Rect)>,
}

/// A verification the console started, and what became of it.
///
/// Kept beside the panes rather than in them: it is a fact about the service at
/// the other end, not about the policy file, and a reload that rewrites the
/// pane should not blank the column an operator is reading. Same reasoning as
/// `CredentialStatus`, one question further out.
pub enum Verification {
    Running,
    Done(Box<verify::Report>),
    /// It never got as far as a report — the name is not in the file any more.
    Failed(String),
}

impl Verification {
    /// The cell, and what colour it is.
    ///
    /// A glyph and two words. The column is scanned, not read: what it has to
    /// answer at a glance is which of these rows is not like the others, and
    /// `enter` on the row is one keystroke away from the sentence. The first
    /// version of this put the whole headline here, which ran off the side of
    /// the pane and made a healthy upstream look like an incident report.
    pub fn cell(&self) -> (String, Color) {
        match self {
            Verification::Running => ("… checking".to_string(), Color::Yellow),
            Verification::Failed(_) => ("✗ no report".to_string(), Color::Red),
            Verification::Done(report) => {
                let outcome = report.verdict();
                (
                    format!("{} {}", outcome.glyph(), report.brief()),
                    match outcome {
                        verify::Outcome::Passed => Color::Green,
                        verify::Outcome::Warned => Color::Yellow,
                        verify::Outcome::Failed => Color::Red,
                    },
                )
            }
        }
    }
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
    /// Is the terminal reporting the pointer? Off makes the terminal's own
    /// selection work again — the fallback for getting a token out of here
    /// when the terminal will not take an OSC 52 copy.
    mouse: bool,
    hits: Hits,
    /// The last click, for spotting the second one of a pair.
    clicked: Option<(Instant, u16, u16)>,
    /// What the last verification of each service found, by name.
    verified: HashMap<String, Verification>,
    /// Is a credential check out on the runtime? One at a time, so a held `c`
    /// is one pass over the vault rather than one per repeat.
    checking: bool,
    /// Where finished work reports back. Anything that reads a credential is a
    /// child process and usually a network call, so it runs on the runtime
    /// rather than on this thread — the console cannot stop drawing for
    /// seconds at a time, because the thing it exists to draw is a request
    /// waiting on an answer.
    inbox: (Post, RecvLanded),
    /// Where a reload is asked for. One thread does them, in the order they
    /// were asked for: `AppState::reload` installs a whole policy, and two of
    /// those overlapping is a proxy serving neither file.
    reloader: tokio::sync::mpsc::UnboundedSender<Said>,
    /// Reloads asked for and not yet heard back about. Two jobs: the header
    /// says so while it is happening, and `adopt` uses it to tell its own
    /// news from somebody else's edit.
    asked: usize,
    /// Every policy the proxy puts in charge, whoever caused it — this console
    /// pressing `r`, `agent-iap acl add` in the next terminal, an editor.
    reloads: tokio::sync::broadcast::Receiver<crate::state::Reloaded>,
    /// The audit log as it is written, for the feed at the bottom.
    records: tokio::sync::broadcast::Receiver<AuditEvent>,
}

/// A job the console started on the runtime, on its way back to the thread
/// that draws.
enum Landed {
    /// A verification of one service: what it was about, and what it found.
    Verified(String, Result<verify::Report>),
    /// A policy reload the console asked for, and the words it is owed.
    Reloaded(Result<()>, Said),
    /// A re-read of every credential reference: what each one answered.
    Checked(Vec<(String, Result<(), String>)>),
}

/// What a reload the console asked for is owed on the footer when it lands.
///
/// Two kinds of caller, and they want different things said. `r` asked for the
/// reload and nothing else, so the reload is the whole news either way. A write
/// asked for one *after* editing the file, and the write is its own good news —
/// already on the footer, because it is true the moment the file is written.
/// What is left to report there is only the bad case: the edit is in the file,
/// the proxy refused it, and every pane is showing the policy from before it.
/// See `stale`.
struct Said {
    /// The line for a reload that took. `None` where the caller already said
    /// its piece and only a refusal is still worth hearing about.
    ok: Option<String>,
    /// Was the policy file written before this reload was asked for?
    wrote: bool,
    /// A service to call once this reload has landed, and only then.
    ///
    /// The form's own `verify` step used to run the moment the write returned.
    /// That was correct while the reload was inline; once it moved onto a
    /// thread of its own the console was left verifying against the policy from
    /// *before* the write, and a service that had just been added was one
    /// `verify::target` had never heard of — "`linear` is neither an upstream
    /// nor an MCP server", on the screen where the operator had just added
    /// `linear`. So the verification rides on the reload and starts when the
    /// new policy is in force (SIRI-197).
    then_verify: Option<String>,
}

impl Said {
    /// `r`: the reload is the whole of what was asked for.
    fn asked(ok: impl Into<String>) -> Self {
        Said {
            ok: Some(ok.into()),
            wrote: false,
            then_verify: None,
        }
    }

    /// A reload that follows a write, whose own message is already on screen.
    fn after_a_write(then_verify: Option<String>) -> Self {
        Said {
            ok: None,
            wrote: true,
            then_verify,
        }
    }
}

type Post = tokio::sync::mpsc::UnboundedSender<Landed>;
type RecvLanded = tokio::sync::mpsc::UnboundedReceiver<Landed>;

/// The thread that re-reads the policy file, one reload at a time.
///
/// `AppState::reload` resolves every credential the file names before it
/// installs anything, and for `r` that means reading each one from source — a
/// subprocess and a network round trip each. None of that belongs on the thread
/// that draws: this console exists to put a waiting request in front of a
/// human, and a console that stops drawing while a vault is consulted is a
/// console that has stopped doing the one thing it is for.
///
/// One thread with a queue rather than a task per press. Two
/// `AppState::reload` calls overlapping is a proxy serving neither file; a
/// queue means a write that lands while a reload is outstanding still takes
/// effect, in the order it was asked for, and nothing is dropped.
fn spawn_reloader(
    state: &Arc<AppState>,
    watcher: &Arc<crate::reload::Watcher>,
    post: Post,
) -> tokio::sync::mpsc::UnboundedSender<Said> {
    let (ask, mut asked) = tokio::sync::mpsc::unbounded_channel::<Said>();
    let state = Arc::clone(state);
    let watcher = Arc::clone(watcher);
    tokio::task::spawn_blocking(move || {
        while let Some(said) = asked.blocking_recv() {
            // `r` is an operator asking for the file to be read again, and a
            // credential rotated behind an unchanged reference is one of the
            // things they are asking about. A reload that only follows a write
            // this console just made is not that question — see
            // `Trigger::rereads_credentials`.
            let why = match said.wrote {
                true => Trigger::Wrote,
                false => Trigger::Asked,
            };
            let result = watcher.reload(&state, why).map(|_| ());
            // The receiver is gone only when the console has already quit.
            if post.send(Landed::Reloaded(result, said)).is_err() {
                return;
            }
        }
    });
    ask
}

impl App {
    fn new(state: Arc<AppState>, watcher: Arc<crate::reload::Watcher>) -> Result<Self> {
        let policy = Policy::load(watcher, &state)?;
        let inbox = tokio::sync::mpsc::unbounded_channel();
        Ok(App {
            reloads: state.subscribe_reloads(),
            records: state.audit.subscribe(),
            reloader: spawn_reloader(&state, policy.watcher(), inbox.0.clone()),
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
            mouse: false,
            hits: Hits::default(),
            clicked: None,
            verified: HashMap::new(),
            checking: false,
            asked: 0,
            inbox,
        })
    }

    /// Take in everything that happened somewhere else: a policy the proxy put
    /// in charge, records the audit log wrote, and jobs coming back off the
    /// runtime. Cheap, and on every pass — none of it blocks.
    fn catch_up(&mut self) {
        // Collected before they are applied: each of these wants `&mut self`,
        // and the receivers are part of it.
        let mut configs = Vec::new();
        while let Ok(reloaded) = self.reloads.try_recv() {
            configs.push(reloaded.config);
        }
        for config in configs {
            self.adopt(config);
        }

        while let Ok(event) = self.records.try_recv() {
            if self.feed.len() == FEED_CAPACITY {
                self.feed.pop_front();
            }
            self.feed.push_back(event);
        }

        let mut landed = Vec::new();
        while let Ok(job) = self.inbox.1.try_recv() {
            landed.push(job);
        }
        for job in landed {
            self.landed(job);
        }
    }

    fn event_loop(&mut self, terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
        loop {
            self.catch_up();

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
            // One frame per burst rather than one frame per event. With the
            // pointer reported, the terminal sends a stream of motion events
            // for as long as the mouse is moving across the window, and a held
            // key arrives as a stream too — a full redraw between each one is a
            // console that falls behind what it is being given and then catches
            // up in jumps, which is what "sluggish" means here. Nothing is
            // dropped: everything already queued is handled, and the frame
            // after it shows the result of all of it.
            //
            // A burst is answered against the frame it was aimed at, which is
            // the safe direction here and not only the cheap one: the queue is
            // not re-read and no new dialogue is raised part-way through, so a
            // key held down cannot walk through a queue of waiting requests
            // answering them at a screen the operator never saw.
            loop {
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        if self.handle(key)? {
                            return Ok(());
                        }
                    }
                    Event::Mouse(mouse) => {
                        // A click is answered against the frame it was aimed
                        // at — `hits` is what the last `draw` put on screen —
                        // so the burst stops on one and the next click gets a
                        // frame of its own. Motion, drags and the wheel read
                        // the same whenever they are handled.
                        let aimed = matches!(mouse.kind, MouseEventKind::Down(_));
                        if self.handle_mouse(mouse)? {
                            return Ok(());
                        }
                        if aimed {
                            break;
                        }
                    }
                    _ => {}
                }
                if !event::poll(Duration::ZERO)? {
                    break;
                }
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
            Tab::Upstreams => views::upstreams(&self.policy.inventory, &self.verified).len(),
            Tab::Mcp => views::mcp_servers(&self.policy.inventory, &self.verified).len(),
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

    /// Why the approval queue is going to stay empty, if it is.
    ///
    /// The same diagnosis `check` and the headless banner give, from the policy
    /// as the file has it, with the way out spelled as the key it is on rather
    /// than as a command — this console is where `R` lives. Lockdown also stops
    /// the queue and is not this: the header says `LOCKDOWN` in red, and the
    /// policy underneath it is still whatever it was.
    fn cannot_ask(&self) -> Option<String> {
        let config = &self.policy.config;
        let warning = verify::cannot_ask_warning(&config.acl, config.acl_default.action)?;
        Some(format!(
            "{warning}\n\n`R` on the rules pane (5) clears the rules and makes the fallthrough \
             a question, so requests arrive here to be answered. One rule does it without \
             clearing anything: `n` on that pane, with action `ask`."
        ))
    }

    /// Is a modal holding something that will not be on screen again?
    fn showing_a_secret(&self) -> bool {
        matches!(&self.modal, Some(Modal::Show(shown)) if shown.irreplaceable())
    }

    /// Hand the credential in the focused field to agent-iap's own store, and
    /// put the reference to it back in the field.
    ///
    /// The console's answer to a credential with nowhere else to live. Typing
    /// one into a form used to be refused twice over — not a reference, and
    /// then `literal:` not committable — with nothing on screen saying what
    /// would be accepted. This is what is accepted, and it is one key away from
    /// where the refusal happened.
    ///
    /// Nothing is written to the policy file here. The field now holds an
    /// ordinary reference and the form is still open, so the operator can still
    /// cancel — which leaves a named credential in the store and nothing
    /// pointing at it, the one direction of that pair that breaks nothing.
    fn keep_credential(&self, form: &mut form::Form) -> Result<String> {
        let (index, typed) = form
            .keeping()
            .context("there is no typed credential in this field to keep")?;
        let key = form.fields[index].key.to_string();
        let store = self.state.resolver.store();

        // Trimmed, unlike a `literal:` payload. That payload sits in a TOML
        // string in a file somebody edited, where a trailing space is visible
        // and could conceivably be meant; this is a one-line text field that a
        // credential was pasted into, where it never is — and a token carrying
        // an invisible trailing space is a 401 with nothing on screen to
        // explain it.
        let value = typed.trim();
        let name = self.store_name(&key, form.subject().as_deref())?;
        store.set(&name, value).context("storing the credential")?;
        form.fill(index, format!("iap://{name}"));
        Ok(name)
    }

    /// A name for a credential the operator did not name.
    ///
    /// Derived from what is being enrolled, so `secret list` reads as an
    /// inventory rather than as `credential-1`…`credential-4`. Never one that
    /// is already taken: the operator did not choose this name, so it must not
    /// be the thing that silently replaces another upstream's credential.
    fn store_name(&self, field_key: &str, subject: Option<&str>) -> Result<String> {
        let mut base = match subject.map(sanitise_name).filter(|s| !s.is_empty()) {
            Some(subject) => subject,
            None => "credential".to_string(),
        };
        // `secret` is the only credential on most schemes, so naming it adds
        // nothing; `client-secret` and `private-key` are not, and a store with
        // two `stripe` entries in it would be a store nobody can read.
        if field_key != "secret" {
            base.push('-');
            base.push_str(&sanitise_name(field_key));
        }
        let store = self.state.resolver.store();
        let taken: std::collections::HashSet<String> = store
            .list()
            .context("reading the credential store")?
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        if !taken.contains(&base) {
            return Ok(base);
        }
        (2..100)
            .map(|n| format!("{base}-{n}"))
            .find(|candidate| !taken.contains(candidate))
            .context("too many stored credentials share that name — `agent-iap secret list`")
    }

    fn say(&mut self, message: impl Into<String>) {
        self.flash = Some(Flash {
            message: message.into(),
            failed: false,
            at: Instant::now(),
        });
    }

    /// A result the operator should not miss. Uses the failure colours
    /// without being a failure: the loudest thing on this screen is the right
    /// register for "nothing is getting through", and there is no third one.
    fn warn(&mut self, message: impl Into<String>) {
        self.flash = Some(Flash {
            message: message.into(),
            failed: true,
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

    /// Ask for the policy file to be re-read, and carry on drawing.
    ///
    /// Returns immediately — the reload itself happens on the reloader thread,
    /// because it is a vault lookup per credential and then a whole policy
    /// installed. The panes follow when the proxy has the new one in charge,
    /// through `adopt`, which is the same path an edit made in another terminal
    /// takes. The footer gets whatever `said` is owed when it lands.
    fn reload(&mut self, said: Said) {
        self.asked += 1;
        if self.reloader.send(said).is_err() {
            // The reloader is gone, which happens only on the way out.
            self.asked -= 1;
        }
    }

    /// `r`, end to end — for a test that is about what the new policy does
    /// rather than about how it got here. Asserts that the proxy took it: a
    /// `Said::asked` reload always leaves a line on the footer, and a refused
    /// one leaves it in the failure colours.
    #[cfg(test)]
    async fn reread(&mut self) {
        self.reload(Said::asked("re-read the policy file"));
        self.settle().await;
        assert!(
            self.flash.as_ref().is_some_and(|flash| !flash.failed),
            "the reload was refused: {:?}",
            self.flash.as_ref().map(|flash| flash.message.clone()),
        );
    }

    /// Wait for every job this console started, the way the event loop would.
    ///
    /// Only for tests. A reload and a credential check are each on a thread of
    /// their own now, so a test that presses a key and then reads the panes has
    /// to wait for it — `catch_up` is the same call the event loop makes on
    /// every pass.
    #[cfg(test)]
    async fn settle(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while (self.asked > 0 || self.checking) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(2)).await;
            self.catch_up();
        }
        assert_eq!(self.asked, 0, "a reload never came back");
        assert!(!self.checking, "a credential check never came back");
        self.catch_up();
    }

    /// A reload the console asked for came back.
    ///
    /// Nothing to install here: a reload that took was announced by
    /// `AppState::reload`, and `adopt` took the new policy on the pass that
    /// delivered it. This is only the words.
    fn reloaded(&mut self, result: Result<()>, said: Said) {
        self.asked = self.asked.saturating_sub(1);
        match result {
            Ok(()) => {
                if let Some(ok) = said.ok {
                    self.say(ok);
                }
                // The policy just written is the one in force now, so this is
                // the first moment the service exists to be called.
                if let Some(name) = said.then_verify {
                    self.verify(name);
                }
            }
            // What a refusal means depends on what was done before it. After a
            // write it is the worse story — see `stale`. On `r` it is a refused
            // reload and nothing else.
            // A refused reload leaves the running proxy on the old policy, so
            // there is nothing new to call: verifying here would report on a
            // service this process is not serving. `stale` is the louder
            // problem and says so.
            Err(error) if said.wrote => self.stale(&error),
            Err(error) => self.blame(&error),
        }
    }

    /// Report a write that landed in the file and a reload the proxy refused.
    ///
    /// Neither of the two obvious messages is true here. "enrolled `x`" is a lie
    /// about the running policy, which is still the one from before; the bare
    /// reload error is a lie about the file, which has the edit in it. And this
    /// is not a rare corner: `AppState::reload` resolves every credential the
    /// file names before it installs anything, so one reference the proxy
    /// cannot read — a path typed wrong in the form above, an item moved in the
    /// vault — is enough to refuse a policy that is otherwise fine.
    ///
    /// Saying it matters more than it looks. These panes are built from the
    /// config that is in force, so a refused reload leaves them showing the
    /// policy from before the write — and without this line, that stale pane is
    /// the *entire* symptom: the agent is in the file, the footer says it was
    /// enrolled, and the list it should have appeared in has not changed.
    fn stale(&mut self, error: &anyhow::Error) {
        let file = self.file_name();
        self.flash = Some(Flash {
            message: format!(
                "the edit is in {file}, but the proxy refused to reload it and is still serving \
                 the previous policy — these panes with it, so what they show is not what was \
                 just written: {error:#}"
            ),
            failed: true,
            at: Instant::now(),
        });
    }

    /// Catch up to a policy somebody else put in charge.
    ///
    /// The daemon's watcher does the reloading, so by the time this runs the
    /// proxy is already serving the new file — this is the panes following, not
    /// the policy changing. Which is why it says so rather than asking.
    fn adopt(&mut self, config: Arc<crate::config::Config>) {
        // A reload the console asked for has already been reported by whatever
        // asked; saying "changed on disk" for a form the operator just
        // submitted would be the console telling them their own news. Either
        // the panes are already on this policy, or the console has a reload of
        // its own outstanding and this is it arriving.
        let ours = Arc::ptr_eq(&self.policy.config, &config) || self.asked > 0;
        if let Err(error) = self.policy.show(config) {
            self.blame(&error);
            return;
        }
        if ours {
            return;
        }
        self.say(format!(
            "{} changed on disk — reloaded: {} agents, {} rules, {} upstreams, {} mcp",
            self.file_name(),
            self.state.agents.len(),
            self.state.acl.rule_count(),
            self.policy.config.upstreams.len(),
            self.policy.config.mcp_servers.len(),
        ));
    }

    fn file_name(&self) -> String {
        self.policy
            .path
            .file_name()
            .unwrap_or(self.policy.path.as_os_str())
            .to_string_lossy()
            .into_owned()
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
            KeyCode::Char('r') => self.reload(Said::asked("re-read the policy file")),
            // The panic button. Shifted so it is never a slip, and answered
            // on the footer rather than behind a confirmation: the direction
            // that needs no deliberation is the one that stops everything,
            // and a dialogue between an operator and that is a dialogue in
            // the way. Lifting it takes the same key, and the header says
            // which way it is the whole time it is on.
            KeyCode::Char('L') => {
                let on = !self.state.acl.locked_down();
                self.state.acl.set_lockdown(on);
                match on {
                    true => self.warn(
                        "LOCKDOWN — every request is denied, whatever the rules say. Nothing \
                         was written to the policy file; `L` again serves it as it stands.",
                    ),
                    false => self.say(format!(
                        "lockdown lifted — back to the file: {} rules, default {}",
                        self.state.acl.rule_count(),
                        self.state.acl.default_action(),
                    )),
                }
            }
            // Reporting the pointer is what stops the terminal's own
            // selection working, and the one thing an operator most wants to
            // select out of this screen is a token — which `c` now copies
            // outright, leaving this for the terminals that ignore OSC 52. So
            // it is a toggle, and it says which way it went.
            KeyCode::Char('m') => {
                self.mouse = set_mouse(!self.mouse);
                match self.mouse {
                    true => self.say("mouse on"),
                    false => self.say(
                        "mouse off — the terminal's own text selection works again, `m` to \
                         switch back",
                    ),
                }
            }
            code => self.handle_tab(code),
        }
        Ok(false)
    }

    // ---- the pointer ------------------------------------------------------

    /// Route a mouse event to whatever was drawn under it.
    ///
    /// Everything here ends in the same handlers the keyboard uses. A click
    /// that could grant something a keystroke could not would be a second
    /// policy surface, and this console has one job it cannot get wrong.
    fn handle_mouse(&mut self, mouse: MouseEvent) -> Result<bool> {
        let at = (mouse.column, mouse.row);
        match mouse.kind {
            MouseEventKind::ScrollUp => self.scroll(true),
            MouseEventKind::ScrollDown => self.scroll(false),
            MouseEventKind::Down(MouseButton::Left) => {
                let double = self.double_click(at);
                return self.click(at, double);
            }
            // Motion, drags, and the other buttons. A console that acted on a
            // pointer merely passing over a control would be a console you
            // could not read without changing something.
            _ => {}
        }
        Ok(false)
    }

    /// Is this the second click of a pair, on the same cell?
    fn double_click(&mut self, (column, row): (u16, u16)) -> bool {
        let double = self
            .clicked
            .is_some_and(|(at, x, y)| (x, y) == (column, row) && at.elapsed() < DOUBLE_CLICK);
        // Cleared on the second, so a third click does not read as a fourth.
        self.clicked = (!double).then(|| (Instant::now(), column, row));
        double
    }

    fn click(&mut self, at: (u16, u16), double: bool) -> Result<bool> {
        // A modal owns the screen. A click outside it is not a click on what
        // is showing through behind — that pane is not reachable right now,
        // and treating it as reachable is how a form gets abandoned by a
        // misaimed click.
        // Cloned rather than borrowed: routing a click needs `&mut self`, and
        // the hit map is a record of the last frame rather than state the
        // handler is allowed to change.
        if let Some(hits) = self.hits.dialogue.clone() {
            self.click_dialogue(at, &hits);
            return Ok(false);
        }
        if let Some(hits) = self.hits.form.clone() {
            self.click_form(at, double, &hits);
            return Ok(false);
        }
        if let Some((yes, no)) = self.hits.confirm {
            if within(yes, at) {
                self.handle_modal(KeyEvent::from(KeyCode::Char('y')));
            } else if within(no, at) {
                self.handle_modal(KeyEvent::from(KeyCode::Char('n')));
            }
            return Ok(false);
        }
        if let Some(popup) = self.hits.plain_modal {
            // A click dismisses a preview, which is what the modal says. Not a
            // token: a press of the left button over text is how a person
            // starts selecting it, and the text they are reaching for is the
            // one thing on this console that cannot be shown twice. Dismissing
            // on it throws the token away on behalf of somebody trying to copy
            // it, which is exactly what happened.
            if within(popup, at) && !self.showing_a_secret() {
                self.handle_modal(KeyEvent::from(KeyCode::Enter));
            }
            return Ok(false);
        }

        if let Some((_, tab)) = self.hits.tabs.iter().find(|(rect, _)| within(*rect, at)) {
            self.tab = *tab;
            return Ok(false);
        }

        if let Some((_, code)) = self.hits.keys.iter().find(|(rect, _)| within(*rect, at)) {
            let code = *code;
            return self.handle(KeyEvent::from(code));
        }

        if let Some((rows, offset)) = self.hits.rows {
            if within(rows, at) {
                let row = offset + (at.1 - rows.y) as usize;
                if row < self.rows() {
                    self.cursor[self.tab.index()].select(Some(row));
                    // A second click is the pane's own `enter`: open the
                    // dialogue, add the profile. One click only ever moves the
                    // cursor, which is what makes the first one safe.
                    if double {
                        self.handle_tab(KeyCode::Enter);
                    }
                }
            }
        }
        Ok(false)
    }

    fn click_dialogue(&mut self, at: (u16, u16), hits: &approve::Hits) {
        if !within(hits.popup, at) {
            return;
        }
        // The buttons go through the same handler the keys do, so a click and
        // a keystroke cannot grant different things.
        for (button, key) in [
            (hits.deny, KeyCode::Char('d')),
            (hits.allow, KeyCode::Char('a')),
            (hits.dismiss, KeyCode::Esc),
        ] {
            if within(button, at) {
                self.handle_modal(KeyEvent::from(key));
                return;
            }
        }

        let Some(Modal::Approve(dialogue)) = &mut self.modal else {
            return;
        };
        if let Some((_, index)) = hits.durations.iter().find(|(rect, _)| within(*rect, at)) {
            dialogue.choose_duration(*index);
        } else if let Some((_, index)) = hits.reaches.iter().find(|(rect, _)| within(*rect, at)) {
            dialogue.choose_reach(*index);
        }
    }

    fn click_form(&mut self, at: (u16, u16), double: bool, hits: &form::Hits) {
        // The picker is a modal over a modal: while it is up, a click is its
        // own or it is nothing. The fields behind it are not reachable.
        if let Some(picker) = &hits.browser {
            if let (Some(Modal::Form(form)), true) = (&mut self.modal, within(picker.popup, at)) {
                if let Some((_, row)) = picker.rows.iter().find(|(rect, _)| within(*rect, at)) {
                    let picked = picked(form);
                    form.click_browse(*row, double);
                    // A profile picked with the mouse is a different enrolment
                    // with different fields, exactly as one picked with
                    // `enter` is — and the rebuild lives on that keystroke's
                    // path, which a click never takes.
                    if let Some(before) = picked {
                        if form.text("id") != before {
                            **form = upstream_form(&self.profiles, &form.text("id"));
                        }
                    }
                }
            }
            return;
        }
        if !within(hits.popup, at) {
            return;
        }
        // `ctrl-o browse` sits on the focused field's own line, so it has to
        // be tested before the line it is drawn on.
        if hits.browse.iter().any(|rect| within(*rect, at)) {
            self.handle_modal(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));
            return;
        }
        // And `ctrl-k keep this value`, on the same terms — it is drawn on the
        // focused field's own line too, so it is tested before that line.
        if hits.keep.iter().any(|rect| within(*rect, at)) {
            self.handle_modal(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL));
            return;
        }
        let Some((_, index)) = hits.fields.iter().find(|(rect, _)| within(*rect, at)) else {
            return;
        };
        let Some(Modal::Form(form)) = &mut self.modal else {
            return;
        };
        let picked = picked(form);
        form.nudge(*index);
        // A click on the picker advances it, exactly as `→` does — and so it
        // has to swap the form the same way.
        if let Some(before) = picked {
            if form.text("id") != before {
                **form = upstream_form(&self.profiles, &form.text("id"));
            }
        }
    }

    /// The wheel. Over a modal it moves that modal's own list; otherwise it
    /// moves the pane's cursor, which is what scrolls the pane.
    fn scroll(&mut self, up: bool) {
        match &mut self.modal {
            // The wheel moves the scope list, not the duration strip: one is a
            // list and the other is a row of buttons, and a wheel that walked
            // sideways through "from now on" would be a hazard.
            Some(Modal::Approve(dialogue)) => {
                let key = if up { KeyCode::Up } else { KeyCode::Down };
                dialogue.handle(KeyEvent::from(key));
            }
            // Over the form the wheel walks the fields; over the picker it
            // scrolls the listing, which is what a wheel over a list of files
            // has to do.
            Some(Modal::Form(form)) if form.browsing() => form.scroll_browse(up),
            Some(Modal::Form(form)) => {
                let key = if up { KeyCode::BackTab } else { KeyCode::Tab };
                form.handle(KeyEvent::from(key));
            }
            Some(_) => {}
            // Three rows a notch: one is a wheel that feels broken, and a page
            // is a wheel that loses your place.
            None => self.move_cursor(if up { -3 } else { 3 }),
        }
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
                // Opened on the catalog rather than on the form behind it.
                // "Which service is this?" is the first thing the form asks
                // and the thing that decides every field under it, and the
                // answer is a list of sixty — so the list is the first screen,
                // and `esc` off it is the hand-written form for a service the
                // catalog does not have.
                let mut form = Box::new(upstream_form(&self.profiles, NO_PROFILE));
                form.pick();
                self.modal = Some(Modal::Form(form));
            }
            // `enter` too, so a double-click on the row opens what the row is
            // — the same pairing every other pane has.
            (Tab::Upstreams, KeyCode::Char('e')) | (Tab::Upstreams, KeyCode::Enter) => {
                if let Some(upstream) = self
                    .named_at_cursor(|inventory| {
                        inventory
                            .upstreams
                            .iter()
                            .flatten()
                            .map(|row| row.name.clone())
                            .collect()
                    })
                    .and_then(|name| self.policy.config.upstream(&name).cloned())
                {
                    self.modal = Some(Modal::Form(Box::new(upstream_edit_form(&upstream))));
                }
            }
            (Tab::Upstreams, KeyCode::Char('v')) => {
                if let Some(name) = self.named_at_cursor(|inventory| {
                    inventory
                        .upstreams
                        .iter()
                        .flatten()
                        .map(|row| row.name.clone())
                        .collect()
                }) {
                    self.verify(name);
                }
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
            (Tab::Mcp, KeyCode::Char('v')) => {
                if let Some(name) = self.named_at_cursor(|inventory| {
                    inventory
                        .mcp_servers
                        .iter()
                        .flatten()
                        .map(|row| row.name.clone())
                        .collect()
                }) {
                    self.verify(name);
                }
            }
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

            (Tab::Acl, KeyCode::Char('n')) => {
                self.modal = Some(Modal::Form(Box::new(rule_form(&self.policy.inventory))))
            }
            // Shifted, and not the `x` beside it: `x` takes out the one rule
            // the cursor is on, and the key that takes out all of them should
            // not be the one a slipped finger reaches.
            (Tab::Acl, KeyCode::Char('R')) => {
                let rules = self.state.acl.rule_count();
                self.modal = Some(Modal::Confirm(Confirm {
                    question: format!("Delete all {rules} rule(s) and set the default to ask?"),
                    detail: "Starting over: nothing matches, so every request stops here to be \
                             answered, and a standing answer writes the rule back. This is \
                             written to the policy file and outlives this process — `L` is the \
                             one that denies everything, and only while the proxy runs."
                        .into(),
                    prune: None,
                    intent: Destructive::ResetAcl,
                }));
            }
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

            (Tab::Credentials, KeyCode::Char('c')) => self.check_credentials(),

            (Tab::Profiles, KeyCode::Enter) => {
                if let Some(profile) = self.selected().and_then(|at| self.profiles.get(at)) {
                    self.modal = Some(Modal::Form(Box::new(profile_form(profile))));
                }
            }
            _ => {}
        }
    }

    /// Start a verification of one service, on the runtime rather than here.
    ///
    /// The credential is real and so is the call, so this is only ever on a
    /// keystroke or on a write the operator asked to have verified — never on a
    /// timer, and never twice at once for the same service.
    fn verify(&mut self, name: String) {
        if matches!(self.verified.get(&name), Some(Verification::Running)) {
            return;
        }
        self.verified.insert(name.clone(), Verification::Running);
        self.say(format!("verifying `{name}` — calling it now"));

        let config = Arc::clone(&self.policy.config);
        let resolver = Arc::clone(&self.state.resolver);
        // The daemon's log, so a token minted to answer this question is
        // recorded like any other token this process minted.
        let audit = Arc::clone(&self.state.audit);
        let post = self.inbox.0.clone();
        tokio::spawn(async move {
            let options = verify::Options {
                timeout: verify::DEFAULT_TIMEOUT,
                path: None,
                audit: Some(audit),
            };
            let report = verify::target(&config, &resolver, &name, &options).await;
            // The receiver is gone only when the console has already quit.
            let _ = post.send(Landed::Verified(name, report));
        });
    }

    /// Route one finished job to whatever was waiting for it.
    fn landed(&mut self, job: Landed) {
        match job {
            Landed::Verified(name, result) => self.verification_landed(name, result),
            Landed::Reloaded(result, said) => self.reloaded(result, said),
            Landed::Checked(answers) => self.check_landed(answers),
        }
    }

    /// `c` on the credentials pane: ask every source whether it still answers.
    ///
    /// A read from source, not from what this process is holding. The question
    /// this pane exists to answer is the one the file cannot — whether the
    /// vault is still unlocked and the variable still set — and a value
    /// resolved at startup answers a different question while rendering as the
    /// healthy one. It used to be cache-first, so on a long-running proxy `c`
    /// said `yes` down the column whatever had happened to the vault since.
    ///
    /// Which is why it is off the thread that draws: this is a subprocess and a
    /// network round trip per `op://` reference, and the console cannot stop
    /// putting a waiting request in front of a human for that. One at a time —
    /// a held-down `c` should not be a burst of vault lookups.
    fn check_credentials(&mut self) {
        if self.checking {
            return;
        }
        let mut references: Vec<String> = self
            .policy
            .credentials
            .iter()
            .map(|row| row.reference.clone())
            .collect();
        // Twenty upstreams sharing one vault item is one question, not twenty.
        references.sort();
        references.dedup();
        if references.is_empty() {
            self.say("no credential references in the policy file");
            return;
        }

        self.checking = true;
        self.say(format!(
            "re-reading {} reference(s) from source…",
            references.len()
        ));
        let resolver = Arc::clone(&self.state.resolver);
        let post = self.inbox.0.clone();
        tokio::task::spawn_blocking(move || {
            let answers = resolver.refresh_all(&references);
            let checked = references.into_iter().zip(answers).collect();
            // The receiver is gone only when the console has already quit.
            let _ = post.send(Landed::Checked(checked));
        });
    }

    /// A credential check came back.
    fn check_landed(&mut self, answers: Vec<(String, Result<(), String>)>) {
        self.checking = false;
        self.policy.checked(&answers);
        let broken = answers.iter().filter(|(_, answer)| answer.is_err()).count();
        match broken {
            0 => self.say(format!(
                "every reference still resolves ({} read)",
                answers.len()
            )),
            n => self.warn(format!("{n} reference(s) no longer resolve")),
        }
    }

    /// A verification came back.
    fn verification_landed(&mut self, name: String, result: Result<verify::Report>) {
        let held = match result {
            Ok(report) => {
                // The footer gets the short form too. It is one line under a
                // pane, so the sentence only ran off the end of it — and the
                // modal below, or `enter` on the row later, is where the
                // sentence belongs.
                let headline = format!("`{name}` {} {}", report.verdict().glyph(), report.brief());
                let failed = !report.ok();
                let detail = report_text(&report);
                // The whole report where there is room for it — a one-line
                // summary of a failed handshake is not enough to act on. Never
                // over something already on screen: a modal that appeared on
                // its own over a half-typed form is the console taking the
                // keyboard away.
                if self.modal.is_none() {
                    self.modal = Some(Modal::Show(Shown::plain(
                        format!("{} `{}`", report.kind, report.target),
                        detail,
                    )));
                }
                self.flash = Some(Flash {
                    message: headline,
                    failed,
                    at: Instant::now(),
                });
                Verification::Done(Box::new(report))
            }
            Err(error) => {
                let message = format!("{error:#}");
                self.flash = Some(Flash {
                    message: format!("could not verify `{name}`: {message}"),
                    failed: true,
                    at: Instant::now(),
                });
                Verification::Failed(message)
            }
        };
        self.verified.insert(name, held);
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
            Some(Modal::Help) => {}
            Some(Modal::Show(mut shown)) => {
                let copying = key.code == KeyCode::Char('c') && key.modifiers.is_empty();
                if let (true, Some(token)) = (copying, shown.copy.clone()) {
                    shown.note = Some(copy_note(crate::clipboard::copy(&token, true)));
                    self.modal = Some(Modal::Show(shown));
                    return;
                }
                // A preview goes on any key: whatever it was previewing is
                // still there to look at. A token does not — it is on screen
                // for the only time it will ever be on screen, and "any key"
                // includes the `j` of somebody who thought the modal had
                // already gone, or the second half of a two-character id typed
                // a moment too late. So it takes a key that means it, and says
                // which ones those are.
                if shown.irreplaceable() && !closes_a_secret(key.code) {
                    shown.note = Some(
                        "still here — `esc`, `enter` or `q` closes it, and then it is gone"
                            .to_string(),
                    );
                    self.modal = Some(Modal::Show(shown));
                }
            }
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
            Some(Modal::Form(mut form)) => {
                let was = picked(&form);
                match form.handle(key) {
                    Outcome::Continue => {
                        // The picker moved, so this is a different enrolment with
                        // different fields. Rebuilding rather than prefilling is
                        // what keeps a profile's own variables and access levels
                        // on screen under their own names.
                        if was.is_some_and(|before| before != form.text("id")) {
                            form = Box::new(upstream_form(&self.profiles, &form.text("id")));
                        }
                        self.modal = Some(Modal::Form(form))
                    }
                    Outcome::Cancel => {}
                    Outcome::Keep => {
                        match self.keep_credential(&mut form) {
                            Ok(name) => {
                                // The error, if there was one, is what sent
                                // them here — it is answered now and must not
                                // stay under a field that has been fixed.
                                form.error = None;
                                self.say(format!("agent-iap is keeping it as `iap://{name}`"));
                            }
                            Err(error) => form.error = Some(format!("{error:#}")),
                        }
                        self.modal = Some(Modal::Form(form));
                    }
                    Outcome::Submit => match actions::submit(&self.policy, &form) {
                        Ok(effect) => {
                            // The write landed, which is true the moment the
                            // file has it — so it is said now rather than at
                            // the far end of a reload the operator should not
                            // have to wait through. The reload is a separate
                            // question, and only its bad answer is still worth
                            // hearing: a refused one leaves these panes showing
                            // the policy from before the write.
                            self.say(effect.message);
                            // The verification rides on the reload rather than
                            // starting here: this policy is the one from before
                            // the write, and a service that is not in it yet is
                            // one `verify` reports as neither an upstream nor
                            // an MCP server. It still lands before it could
                            // cover the modals below — `verification_landed`
                            // refuses to draw over anything already on screen,
                            // and the token is the one thing that is only shown
                            // once.
                            self.reload(Said::after_a_write(effect.verify));
                            if let Some((id, token)) = effect.token {
                                let body = format!(
                                    "{token}\n\nGive this to the agent as IAP_TOKEN. It is not an \
                                 upstream key: it buys nothing anywhere else, and revoking it \
                                 rotates nothing. The file got only its sha256, so this is the \
                                 last time anything can print it — if it gets away, `t` on the \
                                 agents pane mints another and retires this one."
                                );
                                self.modal = Some(Modal::Show(Shown::token(
                                    format!("token for `{id}` — shown once"),
                                    &token,
                                    body,
                                )));
                            } else if let Some(preview) = effect.preview {
                                self.modal = Some(Modal::Show(Shown::plain(
                                    "dry run — nothing was written".into(),
                                    preview,
                                )));
                            }
                        }
                        Err(error) => {
                            form.error = Some(format!("{error:#}"));
                            self.modal = Some(Modal::Form(form));
                        }
                    },
                }
            }
            Some(Modal::Confirm(confirm)) => self.handle_confirm(confirm, key),
            None => {}
        }
    }

    fn handle_confirm(&mut self, mut confirm: Confirm, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Enter => {
                let prune = confirm.prune.unwrap_or(false);
                // A `destroy` that failed wrote nothing, so its own error is
                // the whole story and there is no reload to ask for.
                match self.destroy(&confirm.intent, prune) {
                    Err(error) => self.blame(&error),
                    Ok(message) => {
                        self.say(message);
                        self.reload(Said::after_a_write(None));
                    }
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
                let body = format!(
                    "{token}\n\nThe old token stopped working the moment this was written. \
                     Nothing upstream rotated. This is the only time it is printed — `t` again \
                     mints another if it gets away."
                );
                self.modal = Some(Modal::Show(Shown::token(
                    format!("new token for `{id}` — shown once"),
                    &token,
                    body,
                )));
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
            Destructive::ResetAcl => {
                let reset = crate::enroll::reset_acl(&path, crate::enroll::ResetTo::Ask)?;
                Ok(format!(
                    "started over — {} rule(s) removed, default was `{}` and is now `ask`; \
                     every request stops here until a rule says otherwise",
                    reset.removed.len(),
                    reset.was_default,
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
            // Both of these write a rule; the only difference is whether it
            // carries a deadline. In front of the rule that asked, or appended
            // when the default did the asking. Either way the request in hand
            // is answered directly: the new rule governs the *next* call, and
            // this one is already parked behind it.
            approve::Duration::For(_) | approve::Duration::Forever => {
                let at = view.asked_by.as_ref().map(|rule| rule.index);
                let ttl = duration.ttl();
                match self.write_rule(&reach.rule, word, at, ttl) {
                    Ok(landed) => {
                        self.state.broker.decide_scoped(&view.id, verdict, None);
                        // The request in hand is answered either way — that
                        // went to the broker, not to the file — and it is
                        // answered *now*, without waiting on a reload: the
                        // agent on the other end is holding a connection open
                        // until it hears. What a refused reload costs is the
                        // standing rule: it is in the file and it is not
                        // governing anything, which is the last thing to tell
                        // somebody who just chose "from now on", so `stale`
                        // still says it when the reload comes back.
                        self.reload(Said::after_a_write(None));
                        let until = match ttl {
                            Some(ttl) => format!(
                                "until {}",
                                (chrono::Utc::now() + ttl).format("%H:%M on %-d %b")
                            ),
                            None => "from now on".to_string(),
                        };
                        self.say(format!(
                            "wrote rule #{landed} to {} — {word} {} {until}",
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

    /// Write the grant the dialogue just made into the policy file.
    ///
    /// `before` is where it has to land: in front of the `ask` rule that raised
    /// the question, because first match wins. `ttl` is what turns "yes" into
    /// "yes, for now" — the rule carries its own deadline, so the grant runs
    /// out on the clock rather than on somebody remembering to take it back,
    /// and it survives a restart in between.
    fn write_rule(
        &self,
        rule: &approve::RuleShape,
        action: &str,
        before: Option<usize>,
        ttl: Option<chrono::TimeDelta>,
    ) -> Result<usize> {
        let name = format!("console-{action}-{}-{}", rule.agent, rule.target);
        let spec = crate::enroll::RuleSpec {
            name: Some(&name),
            agent: &rule.agent,
            kind: &rule.kind,
            target: &rule.target,
            methods: &rule.methods,
            paths: &rule.paths,
            action,
            expires: ttl.map(|ttl| chrono::Utc::now() + ttl),
        };
        let path = self.policy.path.as_path();
        match before {
            Some(index) => crate::enroll::insert_rule(path, index, &spec),
            None => crate::enroll::add_rule(path, &spec),
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

        // Rebuilt from scratch: what is on screen now is the only thing a
        // click can mean.
        self.hits = Hits::default();

        self.draw_header(frame, areas[0]);
        self.draw_tabs(frame, areas[1]);
        self.draw_body(frame, areas[2]);
        self.draw_feed(frame, areas[3]);
        self.draw_footer(frame, areas[4]);

        match &self.modal {
            Some(Modal::Approve(dialogue)) => {
                self.hits.dialogue = Some(dialogue.render(frame, frame.area()));
            }
            Some(Modal::Form(form)) => {
                self.hits.form = Some(form.render(frame, frame.area()));
            }
            Some(Modal::Confirm(confirm)) => {
                self.hits.confirm = Some(draw_confirm(frame, frame.area(), confirm));
            }
            Some(Modal::Show(shown)) => {
                self.hits.plain_modal = Some(draw_show(frame, frame.area(), shown));
            }
            Some(Modal::Help) => self.hits.plain_modal = Some(draw_help(frame, frame.area())),
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
            Span::raw(format!("  proxy {}  ", self.state.config().server.listen)),
            Span::styled(format!("  {waiting} waiting  "), pending_style),
        ];
        // Loud, and for as long as it is on: a flash fades after eight
        // seconds and lockdown does not, so without this the state in which
        // every request is being refused looks exactly like the state in
        // which the policy is being served.
        if self.state.acl.locked_down() {
            spans.push(Span::styled(
                "  LOCKDOWN  ",
                Style::default()
                    .fg(Color::White)
                    .bg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        // The reload is off this thread now, so the console keeps answering
        // while it runs — and something has to say that the numbers below are
        // the previous policy's until it comes back.
        if self.asked > 0 {
            spans.push(Span::styled(
                "  re-reading the policy…  ",
                Style::default().fg(Color::Cyan),
            ));
        }
        spans.push(Span::raw(format!(
            "  {} agents · {} upstreams · {} mcp · {} rules · default {} ",
            self.state.agents.len(),
            self.policy.config.upstreams.len(),
            self.policy.config.mcp_servers.len(),
            self.state.acl.rule_count(),
            self.state.acl.default_action(),
        )));

        frame.render_widget(
            Paragraph::new(Line::from(spans)).block(Block::default().borders(Borders::ALL)),
            area,
        );
    }

    fn draw_tabs(&mut self, frame: &mut Frame, area: Rect) {
        let mut spans = Vec::new();
        let mut x = area.x;
        for (index, tab) in Tab::ALL.iter().enumerate() {
            let selected = *tab == self.tab;
            let badge = if *tab == Tab::Approvals && !self.pending.is_empty() {
                format!(" {}·{} ({}) ", index + 1, tab.label(), self.pending.len())
            } else {
                format!(" {}·{} ", index + 1, tab.label())
            };
            // Measured from the label itself, so the strip and the hit map
            // cannot disagree about where a tab ends.
            let width = badge.chars().count() as u16;
            if x < area.right() {
                self.hits.tabs.push((
                    Rect {
                        x,
                        y: area.y,
                        width: width.min(area.right() - x),
                        height: 1,
                    },
                    *tab,
                ));
            }
            x = x.saturating_add(width);
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
        let rows = match self.tab {
            Tab::Approvals => {
                let split = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
                    .split(area);
                let rows = draw_pending(frame, split[0], &self.pending, &mut self.cursor[index]);
                draw_request(
                    frame,
                    split[1],
                    &self.pending,
                    self.cursor[index].selected(),
                    self.cannot_ask(),
                );
                rows
            }
            Tab::Agents => views::agents(&self.policy.inventory).render(
                frame,
                area,
                "agents",
                &mut self.cursor[index],
            ),
            Tab::Upstreams => views::upstreams(&self.policy.inventory, &self.verified).render(
                frame,
                area,
                "upstreams",
                &mut self.cursor[index],
            ),
            Tab::Mcp => views::mcp_servers(&self.policy.inventory, &self.verified).render(
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
                let rows = views::acl(&self.policy.inventory).render(
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
                rows
            }
            Tab::Credentials => {
                let split = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(3), Constraint::Length(1)])
                    .split(area);
                let rows = views::credentials(&self.policy.credentials).render(
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
                rows
            }
            Tab::Profiles => {
                let split = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .split(area);
                let rows = views::profiles(&self.profiles).render(
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
                rows
            }
        };

        // The offset is what turns a click's row into a row of the list once
        // the list has been scrolled past the top.
        self.hits.rows = rows.map(|rows| (rows, self.cursor[index].offset()));
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

    fn draw_footer(&mut self, frame: &mut Frame, area: Rect) {
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

        // The hints are also buttons. A footer that names the key for a thing
        // and then ignores a click on it is a footer that looks like a control
        // and is not one.
        let inner = block_inner(area);
        let mut x = inner.x;
        let mut spans = Vec::new();
        for (key, description) in keys {
            let width = (key.chars().count() + description.chars().count() + 4) as u16;
            if let Some(code) = hint_key(key) {
                if x < inner.right() {
                    self.hits.keys.push((
                        Rect {
                            x,
                            y: inner.y,
                            width: width.min(inner.right() - x),
                            height: 1,
                        },
                        code,
                    ));
                }
            }
            x = x.saturating_add(width);

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

/// The key a footer hint stands for, where it stands for a single one. `↑/↓`
/// and `tab` are directions rather than commands, and have nothing to click.
fn hint_key(hint: &str) -> Option<KeyCode> {
    match hint {
        "enter" => Some(KeyCode::Enter),
        "↑/↓" | "tab" => None,
        other => {
            let mut chars = other.chars();
            match (chars.next(), chars.next()) {
                (Some(only), None) => Some(KeyCode::Char(only)),
                _ => None,
            }
        }
    }
}

/// The keys that dismiss a modal holding something shown once.
///
/// Three rather than one, because each is what a different operator will
/// already be reaching for — and none of them is a key that arrives by
/// accident on the way to somewhere else.
fn closes_a_secret(code: KeyCode) -> bool {
    matches!(code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q'))
}

/// Is this cell inside that rectangle?
fn within(rect: Rect, (column, row): (u16, u16)) -> bool {
    rect.width > 0
        && rect.height > 0
        && column >= rect.x
        && column < rect.right()
        && row >= rect.y
        && row < rect.bottom()
}

fn draw_pending(
    frame: &mut Frame,
    area: Rect,
    pending: &[PendingView],
    state: &mut ListState,
) -> Option<Rect> {
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
    (!pending.is_empty()).then(|| block_inner(area))
}

/// The area inside a single-line border.
fn block_inner(area: Rect) -> Rect {
    Block::default().borders(Borders::ALL).inner(area)
}

fn draw_request(
    frame: &mut Frame,
    area: Rect,
    pending: &[PendingView],
    selected: Option<usize>,
    cannot_ask: Option<String>,
) {
    let block = Block::default().borders(Borders::ALL).title(" request ");

    let Some(view) = selected.and_then(|index| pending.get(index)) else {
        // An empty queue has two meanings and they are not the same news.
        // "Nothing has come in yet" is the one this pane used to give
        // unconditionally — under a policy that cannot ask it is a promise the
        // queue will never keep, on the one screen an operator watches while
        // the audit log fills with `<default>` refusals.
        let (text, style) = match cannot_ask {
            Some(reason) => (reason, Style::default().fg(Color::Yellow)),
            None => (
                "Nothing is waiting.\n\nRequests matching an `ask` rule appear here, and the \
                 dialogue opens by itself."
                    .to_string(),
                Style::default().fg(Color::DarkGray),
            ),
        };
        frame.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: false })
                .style(style)
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

/// Draw the confirmation, and hand back where `y` and `n` landed.
fn draw_confirm(frame: &mut Frame, area: Rect, confirm: &Confirm) -> (Rect, Rect) {
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
        Paragraph::new(lines.clone())
            .wrap(Wrap { trim: true })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red))
                    .title(" confirm "),
            ),
        popup,
    );

    // The buttons are the last line drawn, and `y` and `n` sit on it in that
    // order — measured from the same strings above.
    let row = popup.y + lines.len() as u16;
    let yes = Rect {
        x: popup.x + 1,
        y: row,
        width: 11.min(popup.width.saturating_sub(1)),
        height: 1,
    };
    let no = Rect {
        x: yes.right(),
        y: row,
        width: 20.min(popup.right().saturating_sub(yes.right())),
        height: 1,
    };
    (yes, no)
}

fn draw_show(frame: &mut Frame, area: Rect, shown: &Shown) -> Rect {
    let Shown {
        title,
        body,
        secret,
        copy,
        note,
    } = shown;
    let height = (body.lines().count() as u16 + 8).min(area.height);
    let popup = form::centred(area, 80.min(area.width), height);
    frame.render_widget(Clear, popup);

    let accent = if *secret { Color::Yellow } else { Color::Cyan };
    let mut lines = vec![Line::raw("")];
    for line in body.lines() {
        lines.push(Line::from(Span::styled(
            line.to_string(),
            if *secret {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            },
        )));
    }
    lines.push(Line::raw(""));
    if let Some(note) = note {
        lines.push(Line::from(Span::styled(
            note.clone(),
            Style::default().fg(accent),
        )));
    }
    lines.push(Line::from(Span::styled(
        match (copy, secret) {
            (Some(_), true) => {
                "`c` to copy it to your clipboard · `esc`, `enter` or `q` to close it for good"
            }
            (Some(_), false) => "`c` to copy it · any other key to close",
            (None, _) => "any key to close",
        },
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
    popup
}

fn draw_help(frame: &mut Frame, area: Rect) -> Rect {
    // Tall enough for the whole list and the paragraph under it: a help modal
    // that cuts its last line off is one the operator cannot trust to be the
    // whole list. Still clamped, so a short terminal gets what fits.
    let popup = form::centred(area, 72.min(area.width), 26.min(area.height));
    frame.render_widget(Clear, popup);

    let mut lines = vec![Line::raw("")];
    for (keys, what) in [
        ("click", "a tab, a row, a button, a footer hint"),
        ("double-click", "a row — the same as `enter` on it"),
        ("wheel", "scroll the pane, or the list in a dialogue"),
        ("1…7 / tab", "move between panes"),
        ("↑ ↓ / j k", "move within one"),
        (
            "n",
            "add — agent, upstream (from a profile, or spelled out), MCP server, rule",
        ),
        ("e", "edit the upstream the cursor is on"),
        (
            "v",
            "verify the upstream or MCP server the cursor is on — call it, with its credential",
        ),
        (
            "ctrl-o",
            "fill the field in from a list: the file a credential reference names, or the \
             agents, upstreams and MCP servers an ACL rule can name",
        ),
        ("x", "remove what the cursor is on"),
        ("t", "mint a new token for the selected agent"),
        (
            "c",
            "copy the token a modal is showing — or, on credentials, read every reference \
             from its source again",
        ),
        (
            "esc / q",
            "close a modal showing a token — it takes a named key, so a stray one cannot lose it",
        ),
        (
            "enter",
            "answer a request, open a row — edit, or add a profile",
        ),
        ("a / d", "allow or deny the selected request, once"),
        ("f", "forget every standing answer"),
        (
            "r",
            "re-read the policy file now, credentials and all — it is watched anyway, but a \
             value rotated behind an unchanged reference is not",
        ),
        (
            "R",
            "on the rules pane: start over — delete every rule, default to ask",
        ),
        (
            "L",
            "lockdown: deny everything until `L` again. Writes nothing; ends with this process",
        ),
        ("m", "pointer off, for the terminal's own text selection"),
        ("q", "quit — which stops the proxy"),
    ] {
        lines.push(Line::from(vec![
            Span::styled(format!("  {keys:<12}"), Style::default().fg(Color::Cyan)),
            Span::raw(what),
        ]));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "  Everything written here is in force before you look away — rules, agents, \
         services, credentials, even the address this proxy listens on. Nothing waits \
         for a restart, and the policy file is watched, so an edit from another \
         terminal lands the same way.",
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
    popup
}

// ---- the forms, one per enrolment command ---------------------------------

/// What the profile picker holds, for a form that has one.
///
/// Read before a keystroke and again after, because a picker that moved is not
/// a field that was edited — it is a form that has to be rebuilt.
fn picked(form: &Form) -> Option<String> {
    form.picker.then(|| form.text("id"))
}

fn agent_form() -> Form {
    Form::new(
        Intent::Agent,
        "enrol an agent",
        "Mints a token and writes only its sha256. The token is shown once, here — `c` copies it.",
        vec![
            Field::text("id", "id", "how the agent authenticates, and the name every audit record uses"),
            Field::text("name", "name", "what a human calls it, when the id is not that"),
            Field::text(
                "targets",
                "targets",
                "upstreams and MCP servers it may address at all. One of this and the switch below.",
            ),
            Field::flag(
                "any-target",
                "any target",
                "every upstream and MCP server, including ones added later — the widest thing this file can say about an agent",
            ),
        ],
    )
}

/// The first option on the profile picker: no profile, spell the service out.
/// Deliberately not a word that could ever be a profile id.
const NO_PROFILE: &str = "— none: spell it out below —";

/// The catalog as the full-screen picker reads it, in the order
/// `profiles::catalog` hands it over — which is alphabetical by id, and so
/// already the sections the picker's gutter draws.
fn catalogue_entries(offered: &[&Profile]) -> Vec<catalogue::Entry> {
    let mut entries = vec![catalogue::Entry::none(NO_PROFILE)];
    entries.extend(offered.iter().map(|profile| catalogue::Entry {
        value: profile.id.clone(),
        title: profile.title.clone(),
        vendor: profile.vendor.clone(),
        kind: profile.service.kind().to_string(),
        endpoint: profile.endpoint(),
        summary: profile.summary.clone(),
        none: false,
    }));
    entries
}

/// Add an upstream, from a profile or by hand.
///
/// The picker is the first field because it decides what the rest of the form
/// is. A profile already knows the base URL, the credential scheme and a set of
/// ACL rules narrow enough to be worth having; what is left to ask for is the
/// credential reference and what to call the service here. So picking one does
/// not prefill this form — it replaces it, and the console rebuilds it on the
/// keystroke. That is what lets a profile's own variables and access levels
/// arrive as labelled fields rather than as a `NAME=VALUE` line the operator
/// has to know how to complete.
///
/// Segregating the two was the bug: an operator who came here to add GitHub had
/// no way of learning from this form that a `github` profile existed, and so
/// typed out a base URL, a scheme and — the part that actually matters — a set
/// of ACL paths that nobody had reviewed.
///
/// Only the HTTP profiles are offered. An MCP profile is not an upstream: it
/// belongs to the `mcp` pane, and writing an `[[mcp_servers]]` entry from a
/// form headed "add an upstream" would be a form that lied about what it did.
fn upstream_form(catalogue: &[Profile], picked: &str) -> Form {
    let offered: Vec<&Profile> = catalogue
        .iter()
        .filter(|profile| profile.service.kind() == "http")
        .collect();
    let mut options = vec![NO_PROFILE.to_string()];
    options.extend(offered.iter().map(|profile| profile.id.clone()));
    let selected = options
        .iter()
        .position(|option| option == picked)
        .unwrap_or(0);

    // Keyed `id`, which is what the profile enrolment reads the profile out of
    // — the same key the profiles pane's own form uses, so one submit handler
    // covers both.
    let mut fields = vec![Field::choices(
        "id",
        "profile",
        "a service worked out in advance: its endpoint, its credential scheme and a reviewed set of ACL rules",
        options,
        selected,
    )
    .picking(catalogue_entries(&offered))];

    match offered.into_iter().find(|profile| profile.id == picked) {
        Some(profile) => {
            fields.extend(profile_fields(profile));
            fields.push(verify_field());
            Form::new(
                Intent::Profile,
                &format!("add an upstream — `{}`", profile.id),
                &format!("{} — {}", profile.credential.about, profile.credential.url),
                fields,
            )
        }
        None => {
            fields.push(Field::text(
                "name",
                "name",
                "routing prefix and policy name: agents call /<name>/<path>",
            ));
            fields.push(Field::text(
                "base-url",
                "base url",
                "where the proxy forwards to, e.g. https://api.github.com",
            ));
            fields.extend(form::auth_fields());
            fields.push(Field::text(
                "set-header",
                "headers",
                "static headers to send upstream, NAME=VALUE — never a credential, that is what the secret is for",
            ));
            fields.push(verify_field());
            Form::new(
                Intent::Upstream,
                "add an upstream",
                "Pick a profile above, or spell the service out. The credential is a reference — the proxy resolves it and attaches it on the way out.",
                fields,
            )
        }
    }
    .with_picker()
}

/// The same form, opened on an upstream that already exists.
///
/// Prefilled from the file rather than blank, and submitted whole: what is on
/// screen is what gets written, so a field left alone is a field that survives.
/// The name is missing on purpose — it is the routing prefix, and the ACL rules
/// and agent `targets` that name it would be pointing at nothing the moment it
/// changed.
fn upstream_edit_form(upstream: &UpstreamConfig) -> Form {
    let mut fields = vec![Field::prefilled(
        "base-url",
        "base url",
        "where the proxy forwards to, e.g. https://api.github.com",
        &upstream.base_url,
    )];
    fields.extend(form::auth_fields_for(&upstream.auth));
    fields.push(Field::prefilled(
        "set-header",
        "headers",
        "static headers to send upstream, NAME=VALUE — never a credential, that is what the secret is for",
        &upstream
            .headers
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(", "),
    ));
    fields.push(verify_field());
    Form::new(
        Intent::EditUpstream(upstream.name.clone()),
        &format!("edit upstream `{}`", upstream.name),
        "Rewrites this entry whole. Credentials are references, so what is shown is what the file holds — never a credential itself.",
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
    fields.push(verify_field());
    Form::new(
        Intent::McpServer,
        "add an MCP server",
        "The proxy sees every JSON-RPC message either way, and the ACL rules on tool names.",
        fields,
    )
}

/// The last field on every form that writes a service: call it once it is
/// written, and say what came back.
///
/// On by default. Adding a service you cannot reach is the mistake this catches
/// and the one an operator has no other way of noticing until an agent is
/// waiting on it — so it is a step of the form, there to be turned off with
/// `space` rather than found.
fn verify_field() -> Field {
    Field::switch(
        "verify",
        "verify",
        "after writing it, call the service with this credential and report what came back. Never undoes the write.",
        true,
    )
}

/// A report as a modal reads it. Pre-wrapped: `draw_show` sizes the box by
/// counting lines, so a line it has to wrap is a line drawn past the bottom.
fn report_text(report: &verify::Report) -> String {
    let mut text = format!("{}\n", report.endpoint);
    for step in &report.steps {
        for (at, line) in verify::wrap(&step.detail, 54).into_iter().enumerate() {
            let (outcome, name) = match at {
                0 => (step.outcome.label(), step.name),
                _ => ("", ""),
            };
            text.push_str(&format!("{outcome:<8} {name:<11} {line}\n"));
        }
    }
    text
}

/// Add an ACL rule, against the names this policy file already holds.
///
/// Two of these fields — `agent` and `target` — are names written down a few
/// lines further up the same file, and nothing checks them: a rule aimed at
/// `github-api` when the upstream is called `github` is accepted, written and
/// reloaded, and then matches nothing at all. With `acl_default = deny` behind
/// it, that is an agent refused by a policy that visibly contains the rule
/// which was supposed to let it through — the one mistake here with no
/// symptom. So both fields offer what the file holds (`ctrl-o`), and stay text
/// fields, because `*` and `claude-*` are legal values no list can hold.
fn rule_form(inventory: &Inventory) -> Form {
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
            Field::prefilled("agent", "agent", "agent id or glob", "*")
                .offering("an agent", enrolled_agents(inventory)),
            Field::choice(
                "kind",
                "kind",
                "which surface this rule covers",
                &["*", "http", "mcp"],
            ),
            Field::prefilled("target", "target", "upstream or MCP server name, or *", "*")
                .offering("a target", enrolled_targets(inventory)),
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
            // Opens on `ask`, not on the first option. Every other field in
            // this form is prefilled with the widest thing it can mean, so a
            // form walked through on its defaults writes one rule covering
            // every agent, target, method and path — and `allow` there is
            // `acl_default = deny` undone by the first rule in the file. `ask`
            // makes that same walkthrough stop here, at this console, which is
            // the answer a rule this wide deserves.
            Field::choices(
                "action",
                "action",
                "ask stops the request on a human at this console",
                vec!["allow".into(), "deny".into(), "ask".into()],
                2,
            ),
            Field::text(
                "position",
                "position",
                "rule number to insert before. Blank appends, which means it is checked last.",
            ),
        ],
    )
}

/// The agents an ACL rule could be written against: `*`, then every one the
/// file has enrolled, each beside what it is allowed to reach at all.
///
/// Empty when nothing is enrolled yet — `Field::offering` drops the
/// affordance, because a picker offering only `*` is a picker that teaches
/// nothing the prefilled field was not already saying.
fn enrolled_agents(inventory: &Inventory) -> Vec<Candidate> {
    let enrolled: Vec<Candidate> = inventory
        .agents
        .iter()
        .flatten()
        .map(|agent| {
            // An agent's `targets` is the gate in front of the ACL: a rule
            // naming a target this agent may not address is a rule that can
            // never fire, and this is where that is visible.
            let reach = match agent.targets.is_empty() {
                true => "any target".to_string(),
                false => agent.targets.join(", "),
            };
            let about = match agent.name == agent.id {
                true => reach,
                false => format!("{} — {reach}", agent.name),
            };
            Candidate::new(agent.id.clone(), about)
        })
        .collect();

    with_star(enrolled, "every agent, including ones enrolled later")
}

/// The targets an ACL rule could be written against: `*`, then the upstreams
/// and the MCP servers, each offered only for the `kind` it belongs to.
///
/// The `kind` filter is the point of listing them together. `kind = http` on a
/// rule pointed at an MCP server is the same never-matching rule as a typo,
/// and a form that offered the name anyway would be the console's own
/// suggestion to write one.
fn enrolled_targets(inventory: &Inventory) -> Vec<Candidate> {
    let mut named: Vec<Candidate> = inventory
        .upstreams
        .iter()
        .flatten()
        .map(|upstream| {
            Candidate::new(
                upstream.name.clone(),
                format!("upstream — {}", upstream.base_url),
            )
            .when("kind", &["*", "http"])
        })
        .collect();
    named.extend(inventory.mcp_servers.iter().flatten().map(|server| {
        Candidate::new(
            server.name.clone(),
            format!("mcp {} — {}", server.transport, server.endpoint),
        )
        .when("kind", &["*", "mcp"])
    }));

    with_star(
        named,
        "every upstream and MCP server, including ones added later",
    )
}

/// `*` at the top of a list that has something in it, and nothing at all for
/// one that does not. The glob goes first because it is the field's default:
/// a picker opened on a rule that has not been narrowed yet should land on
/// what the rule currently says.
fn with_star(named: Vec<Candidate>, about: &str) -> Vec<Candidate> {
    if named.is_empty() {
        return Vec::new();
    }
    let mut all = vec![Candidate::new("*", about)];
    all.extend(named);
    all
}

fn profile_form(profile: &Profile) -> Form {
    let mut fields = vec![Field::prefilled("id", "profile", "", &profile.id)];
    fields.extend(profile_fields(profile));
    Form::new(
        Intent::Profile,
        &format!("add `{}`", profile.id),
        &format!("{} — {}", profile.credential.about, profile.credential.url),
        fields,
    )
}

/// Everything a profile enrolment asks for beyond which profile it is.
///
/// Shared by the profiles pane, which knows the profile from the row the
/// cursor is on, and the upstream form, which knows it from its picker — so
/// the same profile asks for the same things whichever door it was reached
/// through.
fn profile_fields(profile: &Profile) -> Vec<Field> {
    let levels: Vec<&str> = profile
        .access
        .iter()
        .map(|level| level.name.as_str())
        .collect();
    let mut fields = vec![
        Field::prefilled("as", "name", "name it takes in the policy file — how one proxy fronts two accounts of the same service", &profile.default_name),
        Field::text(
            "secret",
            "secret",
            "credential reference: env:NAME, file:/path, op://vault/item/field",
        )
        .browsable(),
        Field::choice("access", "access", "which bundle of scopes the credential is minted with, and which rules `grant` would write", &levels),
    ];

    // One field per profile variable, keyed `var:<name>` and carrying the var's
    // own label and description — so a required one like DataForSEO's `login`
    // asks for the login by name instead of hiding, unexplained, inside a single
    // `NAME=VALUE` line the reader has to know to complete.
    for var in &profile.vars {
        let key = format!("var:{}", var.name);
        match &var.default {
            Some(default) => fields.push(Field::prefilled(
                key,
                var.name.clone(),
                var.about.clone(),
                default,
            )),
            None => fields.push(Field::text(key, var.name.clone(), var.about.clone())),
        }
    }

    // Off, and a step of the form rather than something to find: enrolling a
    // service is not the same act as granting standing access to it, and this
    // console exists to put that second decision in front of a human when the
    // agent actually makes the call.
    fields.push(Field::switch(
        "grant",
        "grant now",
        "also write this level's ACL rules — a standing allow. Off, nothing is permitted and the first call stops here, on this console.",
        false,
    ));
    fields.push(Field::text(
        "agent",
        "agent",
        "with `grant now`: scope the granted rules to one agent or glob. Blank means every agent.",
    ));
    fields.push(Field::flag(
        "dry-run",
        "dry run",
        "show the TOML it would write, and write nothing",
    ));

    fields
}

/// A store name from something a human wrote: an upstream's name, a field key.
///
/// The store's own `check_name` is the rule; this is what makes an arbitrary
/// string obey it, because the name here is derived rather than typed and a
/// refusal the operator cannot act on is not a refusal worth making.
fn sanitise_name(raw: &str) -> String {
    let mut out = String::new();
    for c in raw.trim().chars() {
        match c {
            c if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') => out.push(c),
            // One separator per run of anything else, so `My API (read)` is
            // `My-API-read` rather than `My-API--read-`.
            _ if !out.ends_with('-') && !out.is_empty() => out.push('-'),
            _ => {}
        }
    }
    // 48 leaves room under the store's own 64 for the `-2` a clash appends and
    // for a field key on a scheme with more than one credential.
    out.truncate(48);
    out.trim_matches('-').to_string()
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
        app_with(dir, POLICY)
    }

    /// The same, for a test that needs its own services in the file.
    fn app_with(dir: &std::path::Path, policy: &str) -> App {
        std::env::set_var("AGENT_IAP_TEST_TOKEN", "sk-not-real");
        let text = policy
            .replace("AUDIT", &dir.join("audit.jsonl").display().to_string())
            // A console test may write a credential to the store, so every one
            // of them points at its own — never the one belonging to whoever is
            // running the suite.
            .replace("STORE", &dir.join("secrets.toml").display().to_string())
            .replace("HASH", &crate::identity::token_hash("iap_test"));
        let path = dir.join("iap.toml");
        std::fs::write(&path, &text).unwrap();

        let config: Config = toml::from_str(&text).unwrap();
        let state = AppState::build(config, false).unwrap();
        App::new(
            state,
            Arc::new(crate::reload::Watcher::new(&path, Default::default())),
        )
        .unwrap()
    }

    fn render(app: &mut App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        format!("{}", terminal.backend())
    }

    /// A stand-in `op` that answers, and writes down that it was asked.
    ///
    /// Counting the calls is the only way to see this particular bug: nothing
    /// about a vault lookup shows up in the policy, the panes or the log. What
    /// the operator saw was 1Password asking for authorization; what the proxy
    /// did was run `op read`.
    #[cfg(unix)]
    fn counting_op(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let op = dir.join("op");
        let calls = dir.join("op-calls");
        std::fs::write(
            &op,
            format!(
                "#!/bin/sh\necho call >> {}\nprintf 'sk-not-real'\n",
                calls.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
        (op, calls)
    }

    #[cfg(unix)]
    fn vault_lookups(calls: &std::path::Path) -> usize {
        std::fs::read_to_string(calls)
            .map(|text| text.lines().count())
            .unwrap_or(0)
    }

    /// The policy above with its credential in a vault instead of the
    /// environment, and `op` pointed at a stand-in.
    #[cfg(unix)]
    fn app_backed_by_a_vault(dir: &std::path::Path) -> (App, std::path::PathBuf) {
        let (op, calls) = counting_op(dir);
        let app = app_with(
            dir,
            &POLICY
                .replace(
                    r#"secret = "env:AGENT_IAP_TEST_TOKEN""#,
                    r#"secret = "op://Private/github/credential""#,
                )
                .replace(
                    "[audit]",
                    &format!("[server]\nop_binary = \"{}\"\n\n[audit]", op.display()),
                ),
        );
        (app, calls)
    }

    /// Leave the policy file naming a credential this proxy cannot read.
    ///
    /// Repointed rather than deleted, because those are two different things
    /// now: a reference this process has already resolved keeps its value
    /// through a reload nobody asked for, and only one it has never seen is
    /// read — which is what a repointed reference is. See
    /// `Trigger::rereads_credentials`.
    fn repoint_at_nothing(policy: &std::path::Path, was: &std::path::Path) -> std::path::PathBuf {
        let gone = was.with_file_name("gone.key");
        let text = std::fs::read_to_string(policy)
            .unwrap()
            .replace(&was.display().to_string(), &gone.display().to_string());
        std::fs::write(policy, text).unwrap();
        gone
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

    /// The reported screen: agents and upstreams enrolled, no rules, the
    /// fallthrough a `deny`, an audit log filling with `<default>` refusals —
    /// and a pane promising that requests will turn up here.
    #[tokio::test]
    async fn an_empty_queue_under_a_policy_that_cannot_ask_says_why() {
        const NO_RULES: &str = r#"
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

[acl_default]
action = "deny"
"#;
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_with(dir.path(), NO_RULES);
        let rendered = render(&mut app, 120, 34);

        assert!(
            !rendered.contains("Nothing is waiting"),
            "a queue nothing can ever join must not say it is merely empty:\n{rendered}"
        );
        for expected in ["nothing in this policy can ask", "acl_default", "R"] {
            assert!(
                rendered.contains(expected),
                "the pane did not say `{expected}`:\n{rendered}"
            );
        }
    }

    /// And the other way: a policy that can ask keeps the plain message, so the
    /// warning cannot become the thing every console shows all the time.
    #[tokio::test]
    async fn a_policy_that_can_ask_keeps_the_plain_empty_message() {
        let dir = tempfile::tempdir().unwrap();
        let app = app_for_test(dir.path());
        assert!(
            app.cannot_ask().is_none(),
            "the fixture policy has an `ask` rule"
        );
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
        app.settle().await;

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

    /// The answer most questions actually deserve: yes, for now.
    #[tokio::test]
    async fn a_ttl_grant_writes_a_rule_that_expires_and_then_asks_again() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        let view = waiting();

        let hour = approve::Duration::For("1h");
        let reach = approve::reaches(&view).pop().unwrap();
        app.answer(&view, Verdict::Allow, hour, reach);
        app.settle().await;

        // Live now, in this process…
        assert_eq!(
            app.state.acl.evaluate(&view.request).action,
            crate::config::Action::Allow
        );

        // …and written down with its own deadline, in front of the `ask`, so a
        // restart in the meantime does not hand the grant back.
        let written = std::fs::read_to_string(dir.path().join("iap.toml")).unwrap();
        assert!(written.contains("expires = "), "{written}");
        assert!(
            written.find("console-allow").unwrap()
                < written.find("github-writes-need-a-human").unwrap(),
            "{written}"
        );

        // Wind the deadline back past now, as the clock would. By line, not by
        // searching for the timestamp: a tempdir path is random and the audit
        // path is written above this, so anything matched by shape would
        // sometimes match that instead.
        let expired: Vec<String> = written
            .lines()
            .map(|line| match line.starts_with("expires = ") {
                true => "expires = \"2020-01-01T00:00:00Z\"".to_string(),
                false => line.to_string(),
            })
            .collect();
        std::fs::write(dir.path().join("iap.toml"), expired.join("\n")).unwrap();
        app.reread().await;

        assert_eq!(
            app.state.acl.evaluate(&view.request).action,
            crate::config::Action::Ask,
            "a grant that has run out has to hand the question back, not keep answering it"
        );
        assert_eq!(app.state.acl.expired_count(), 1);

        app.tab = Tab::Acl;
        app.clamp_cursors();
        let rendered = render(&mut app, 160, 30);
        assert!(
            rendered.contains("expired"),
            "and the pane says so:\n{rendered}"
        );
    }

    #[tokio::test]
    async fn the_dialogue_names_the_agent_rather_than_calling_it_an_agent() {
        // One proxy fronts a fleet. "An agent is asking" is the one thing the
        // operator already knew.
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.pending = vec![waiting()];
        app.raise_dialogue();

        let rendered = render(&mut app, 120, 34);
        assert!(rendered.contains("Claude Code is asking"), "{rendered}");
        assert!(
            rendered.contains("(claude-code)"),
            "and the id too, because that is what every rule and audit record says:\n{rendered}"
        );
        assert!(!rendered.contains("an agent is asking"), "{rendered}");
    }

    /// Every segment on the duration strip, carried out and then checked
    /// against the mechanism it claims to be.
    ///
    /// A segment whose grant is not written where it says is a button that does
    /// nothing, and the operator finds out by pressing it — a week later, when
    /// the agent is still allowed or already is not.
    #[tokio::test]
    async fn every_duration_does_what_its_label_says() {
        for duration in approve::Duration::ALL {
            let dir = tempfile::tempdir().unwrap();
            let mut app = app_for_test(dir.path());
            let view = waiting();
            let reach = approve::reaches(&view).pop().unwrap();
            let scope = reach.scope.clone();

            app.answer(&view, Verdict::Allow, duration, reach);
            app.settle().await;
            assert!(
                app.flash.as_ref().is_some_and(|flash| !flash.failed),
                "{duration:?}: {:?}",
                app.flash.as_ref().map(|flash| &flash.message)
            );

            let written = std::fs::read_to_string(dir.path().join("iap.toml")).unwrap();
            let on_disk = written.contains("console-allow");
            let has_deadline = written.contains("expires = ");
            let remembered = app
                .state
                .broker
                .remembered()
                .iter()
                .any(|(scope, _)| scope.matches(&view.request));
            let decides = app.state.acl.evaluate(&view.request).action;

            match duration {
                // Answers the one request and leaves no trace anywhere.
                approve::Duration::Once => {
                    assert!(!on_disk, "{duration:?} wrote to the policy file");
                    assert!(!remembered, "{duration:?} left a standing answer");
                    assert_eq!(decides, crate::config::Action::Ask);
                }
                // In memory, covering the whole scope, and nothing on disk.
                approve::Duration::UntilQuit => {
                    assert!(!on_disk, "{duration:?} wrote to the policy file");
                    assert!(remembered, "{duration:?} remembered nothing");
                    assert_eq!(scope, scope.clone());
                    assert_eq!(decides, crate::config::Action::Ask);
                }
                // A rule, with a deadline on it.
                approve::Duration::For(_) => {
                    assert!(on_disk, "{duration:?} wrote no rule");
                    assert!(has_deadline, "{duration:?} wrote a rule with no expiry");
                    assert_eq!(decides, crate::config::Action::Allow);
                }
                // A rule, with none.
                approve::Duration::Forever => {
                    assert!(on_disk, "{duration:?} wrote no rule");
                    assert!(
                        !has_deadline,
                        "{duration:?} put a deadline on `from now on`"
                    );
                    assert_eq!(decides, crate::config::Action::Allow);
                }
            }
        }
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
        app.reread().await;
        let (_, token) = effect.token.expect("a new agent is a new token");

        let authenticated = app.state.agents.authenticate(&token);
        assert_eq!(
            authenticated.map(|agent| agent.id.clone()),
            Some("codex".to_string()),
            "an agent enrolled here has to be able to call before the next restart"
        );
    }

    /// `v` on a row calls the service and puts the answer in the pane.
    ///
    /// The whole point of the column: a service can be in the file, resolve its
    /// credential and still be unreachable, and until this the console had no
    /// way to say so.
    #[tokio::test]
    async fn verifying_from_the_console_fills_the_column_the_pane_shows() {
        // A local service standing in for the upstream, so the test makes a
        // real call and not a real internet call.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                axum::Router::new().fallback(axum::routing::any(|| async { "hello" })),
            )
            .await
            .unwrap()
        });

        let dir = tempfile::tempdir().unwrap();
        let mut app = app_with(
            dir.path(),
            &format!(
                r#"
[audit]
path = "AUDIT"
stderr = false

[[upstreams]]
name = "local"
base_url = "http://{addr}"

[[acl]]
name = "local-reads"
kind = "http"
target = "local"
methods = ["GET"]
paths = ["/**"]
action = "allow"
"#
            ),
        );
        app.tab = Tab::Upstreams;
        app.clamp_cursors();

        // Before anyone asks, the column says nobody has — never a blank that
        // could be read as a pass.
        let before = render(&mut app, 160, 24);
        assert!(before.contains("not checked"), "{before}");

        app.handle(KeyEvent::from(KeyCode::Char('v'))).unwrap();
        assert!(
            matches!(app.verified.get("local"), Some(Verification::Running)),
            "`v` starts one, and does not block the loop waiting for it"
        );

        let job = app
            .inbox
            .1
            .recv()
            .await
            .expect("the verification reports back");
        assert!(matches!(job, Landed::Verified(..)), "a verification");
        app.landed(job);

        // The whole report is put in front of the operator, because a one-line
        // summary of a failure is not enough to act on.
        assert!(
            matches!(&app.modal, Some(Modal::Show(shown)) if shown.title.contains("local")),
            "the report should be on screen"
        );
        let modal = render(&mut app, 160, 24);
        assert!(
            modal.contains("200 OK"),
            "the sentence belongs in the report: {modal}"
        );

        // Behind it, the column: a glyph and two words. The sentence used to be
        // here, where it ran off the side of the pane and made a healthy
        // upstream read like an incident report.
        app.handle(KeyEvent::from(KeyCode::Esc)).unwrap();
        assert!(app.modal.is_none());
        let pane = render(&mut app, 160, 24);
        assert!(pane.contains("✓ reachable"), "{pane}");
        assert!(
            !pane.contains("200 OK"),
            "the cell must not carry the report's prose: {pane}"
        );
    }

    /// The form's own step. On by default, and off is honoured — the flag
    /// decides whether a network call happens at all.
    #[tokio::test]
    async fn the_add_form_verifies_what_it_wrote_unless_told_not_to() {
        let dir = tempfile::tempdir().unwrap();
        let app = app_for_test(dir.path());

        let mut form = upstream_form(&app.profiles, NO_PROFILE);
        assert!(
            form.flag("verify"),
            "verifying is a step of the form, not an extra on it"
        );
        set(&mut form, "name", "linear");
        set(&mut form, "base-url", "https://api.linear.app");

        let effect = actions::submit(&app.policy, &form).unwrap();
        assert_eq!(effect.verify.as_deref(), Some("linear"));

        // The same form with the switch off writes the same entry and calls
        // nothing.
        let mut form = upstream_form(&app.profiles, NO_PROFILE);
        let field = form
            .fields
            .iter_mut()
            .find(|field| field.key == "verify")
            .unwrap();
        field.value = form::Value::Flag(false);
        set(&mut form, "name", "notion");
        set(&mut form, "base-url", "https://api.notion.com");
        assert_eq!(actions::submit(&app.policy, &form).unwrap().verify, None);
    }

    /// Editing is where a working upstream is most easily broken — a corrected
    /// base URL with a typo in it looks exactly like one without.
    #[tokio::test]
    async fn the_edit_form_offers_the_same_step() {
        let dir = tempfile::tempdir().unwrap();
        let app = app_for_test(dir.path());
        let upstream = app.policy.config.upstream("github").unwrap().clone();

        let form = upstream_edit_form(&upstream);
        assert!(form.flag("verify"));
        let effect = actions::submit(&app.policy, &form).unwrap();
        assert_eq!(effect.verify.as_deref(), Some("github"));
    }

    /// The reported bug: the form's own verify step ran against the policy
    /// from *before* the write.
    ///
    /// The reload moved onto a thread of its own, and the verification did not
    /// move with it — so an upstream added in the console was one
    /// `verify::target` looked for in a config that did not have it yet, and
    /// said so: "`local` is neither an upstream nor an MCP server", on the
    /// screen where `local` had just been typed. The operator's only way to a
    /// real answer was to press `v` again once the reload had quietly landed.
    #[tokio::test]
    async fn the_form_verifies_the_service_it_just_wrote_and_not_the_policy_before_it() {
        // A local service standing in for the upstream, so the test makes a
        // real call and not a real internet call.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                axum::Router::new().fallback(axum::routing::any(|| async { "hello" })),
            )
            .await
            .unwrap()
        });

        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Upstreams;

        let mut form = upstream_form(&app.profiles, NO_PROFILE);
        assert!(form.flag("verify"), "the step this test is about is on");
        set(&mut form, "name", "local");
        set(&mut form, "base-url", &format!("http://{addr}"));
        app.modal = Some(Modal::Form(Box::new(form)));
        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();

        // Nothing has been called yet: the reload has to land first, and it is
        // not on this thread.
        assert!(
            !app.verified.contains_key("local"),
            "the verification waits for the policy it is about to ask about"
        );
        app.settle().await;

        // Whenever it was started, the answer comes back through the inbox.
        // Drained on a deadline rather than a bare `recv`, because `settle`
        // itself drains — a verification that started too early has already
        // been applied by the time we get here, and waiting for a second one
        // would hang instead of reporting the first.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !matches!(
            app.verified.get("local"),
            Some(Verification::Done(_)) | Some(Verification::Failed(_))
        ) && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
            app.catch_up();
        }

        match app.verified.get("local") {
            Some(Verification::Done(report)) => assert!(
                report.ok(),
                "the upstream is up; the report should say so: {report:?}"
            ),
            Some(Verification::Failed(why)) => {
                panic!("the console verified the wrong policy: {why}")
            }
            _ => panic!("no verification came back for `local`"),
        }
    }

    /// Types a whole form in, the way an operator does, and looks at the pane.
    ///
    /// The form and the table are two views of the same file, and the moment
    /// after a write is exactly when they can disagree.
    #[tokio::test]
    async fn a_service_added_in_the_console_is_in_the_pane_behind_the_form() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Upstreams;

        app.handle(KeyEvent::from(KeyCode::Char('n'))).unwrap();
        // `n` opens on the catalogue and `esc` declines it: this is the
        // operator who is spelling the service out.
        app.handle(KeyEvent::from(KeyCode::Esc)).unwrap();
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap();
        type_in(&mut app, "linear");
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap();
        type_in(&mut app, "https://api.linear.app");
        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();

        assert!(app.modal.is_none(), "a saved form closes");
        app.settle().await;
        app.clamp_cursors();
        let rendered = render(&mut app, 140, 30);
        assert!(rendered.contains("api.linear.app"), "{rendered}");
    }

    #[tokio::test]
    async fn a_rule_added_in_the_console_is_in_the_pane_behind_the_form() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Acl;

        app.handle(KeyEvent::from(KeyCode::Char('n'))).unwrap();
        type_in(&mut app, "typed-in-the-console");
        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();
        app.settle().await;

        app.clamp_cursors();
        let rendered = render(&mut app, 140, 30);
        assert!(rendered.contains("typed-in-the-console"), "{rendered}");
        assert!(
            rendered.contains("2 rules"),
            "the header counts it too:\n{rendered}"
        );
    }

    /// The banner this replaced said "restart to apply". It does not any more,
    /// which is only allowed to be true if the upstream is genuinely routable
    /// the moment the form closes.
    #[tokio::test]
    async fn an_upstream_added_in_the_console_is_routable_without_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());

        let mut form = upstream_form(&app.profiles, NO_PROFILE);
        set(&mut form, "name", "linear");
        set(&mut form, "base-url", "https://api.linear.app");

        let effect = actions::submit(&app.policy, &form).unwrap();
        app.reread().await;

        assert!(
            !effect.message.contains("restart"),
            "the console does not ask for restarts: {}",
            effect.message
        );
        assert!(
            app.state.config().upstream("linear").is_some(),
            "the running proxy has to be able to route to it, not just draw it"
        );

        let rendered = render(&mut app, 160, 34);
        assert!(!rendered.contains("restart"), "{rendered}");
    }

    /// The bug this closes: the two doors to the same service were separate
    /// rooms. `n` on the upstreams pane opened a blank form, so the operator
    /// typed out a base URL, a credential scheme and — the part that actually
    /// matters — a set of ACL paths nobody reviewed, while a profile that had
    /// all three sat unfound on a pane they had no reason to visit.
    #[tokio::test]
    async fn an_upstream_can_be_added_from_a_profile_without_leaving_the_pane() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Upstreams;

        app.handle(KeyEvent::from(KeyCode::Char('n'))).unwrap();
        let picked = |app: &App| match &app.modal {
            Some(Modal::Form(form)) => form.text("id"),
            _ => panic!("the form is open"),
        };
        assert_eq!(
            picked(&app),
            NO_PROFILE,
            "it opens on no profile — the blank form is still one keystroke away"
        );

        // And it opens on the catalogue, which is the whole list and is drawn
        // over the form rather than beside it.
        let rendered = render(&mut app, 120, 34);
        assert!(
            rendered.contains("pick a profile") && rendered.contains("github"),
            "`n` opens the catalogue: {rendered}"
        );

        // Typed, not walked: `g` is the profiles filed under `g`.
        type_in(&mut app, "github");
        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();
        assert_eq!(picked(&app), "github", "the pick rebuilds the form");

        let Some(Modal::Form(form)) = &app.modal else {
            panic!("the form is open")
        };
        assert_eq!(
            form.text("as"),
            "github",
            "the picked profile names the service"
        );
        assert!(
            form.fields.iter().all(|field| field.key != "base-url"),
            "a profile already knows where it forwards to — asking again is the segregation"
        );
        assert_eq!(
            form.text("access"),
            "read",
            "and opens on the narrowest level it offers"
        );

        // Name it something this policy does not already front — one proxy
        // fronting two GitHub accounts is what `as` is for — and fill in the
        // one thing no profile can know.
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap(); // as
        app.handle(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL))
            .unwrap();
        type_in(&mut app, "gh");
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap(); // secret
        type_in(&mut app, "env:AGENT_IAP_TEST_TOKEN");
        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();
        assert!(app.modal.is_none(), "a saved form closes");
        app.reread().await;

        let config = app.state.config();
        let upstream = config
            .upstream("gh")
            .expect("the profile writes an upstream, routable without a restart");
        assert_eq!(upstream.base_url, "https://api.github.com");
        // And nothing else. The profile brought the endpoint and the credential
        // scheme; what it may be used for is still nobody's decision but the
        // operator's, taken when an agent actually calls.
        assert!(
            !config.acl.iter().any(gh_rule),
            "a profile grants nothing on its own: {:?}",
            config.acl
        );
    }

    /// `grant now` is the advanced half of the same form: the reviewed rules,
    /// written up front, by a human who asked for them.
    #[tokio::test]
    async fn the_profile_form_writes_the_access_levels_rules_when_told_to() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());

        let mut form = upstream_form(&app.profiles, "github");
        assert!(
            !form.flag("grant"),
            "the switch is off until somebody turns it on"
        );
        set(&mut form, "as", "gh");
        set(&mut form, "secret", "env:AGENT_IAP_TEST_TOKEN");
        let field = form
            .fields
            .iter_mut()
            .find(|field| field.key == "grant")
            .expect("the form offers it");
        field.value = form::Value::Flag(true);

        actions::submit(&app.policy, &form).unwrap();
        app.reread().await;

        let config = app.state.config();
        assert!(
            config.acl.iter().any(gh_rule),
            "asked for, the rules are written: {:?}",
            config.acl
        );
    }

    fn gh_rule(rule: &crate::config::AclRuleConfig) -> bool {
        rule.name
            .as_deref()
            .is_some_and(|name| name.starts_with("gh-"))
    }

    /// The reported problem: the catalogue was a `◂ … ▸` strip, so reaching
    /// the profile you came for meant pressing `→` past every one before it.
    /// Typing a letter now brings up that letter's profiles, on a screen big
    /// enough to show them — which is also how you find out what is in there.
    #[tokio::test]
    async fn a_letter_brings_up_the_profiles_filed_under_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Upstreams;
        app.clamp_cursors();
        app.handle(KeyEvent::from(KeyCode::Char('n'))).unwrap();

        type_in(&mut app, "s");
        let rendered = render(&mut app, 120, 34);
        for filed_under_s in ["semrush", "sentry", "slack", "spotify", "stripe"] {
            assert!(
                rendered.contains(filed_under_s),
                "`s` should bring up `{filed_under_s}`: {rendered}"
            );
        }
        assert!(
            !rendered.contains("anthropic"),
            "`anthropic` merely contains an `s`; it is not filed under one: {rendered}"
        );

        // And `esc` puts back what was typed rather than the form, so a
        // mistyped letter does not cost the catalogue.
        app.handle(KeyEvent::from(KeyCode::Esc)).unwrap();
        let rendered = render(&mut app, 120, 34);
        assert!(rendered.contains("anthropic"), "{rendered}");
        assert!(rendered.contains("pick a profile"), "{rendered}");
    }

    /// `esc` off the catalogue is the hand-written form, and `ctrl-o` on the
    /// `profile` field is the way back in — so declining the list once is not
    /// a decision you are stuck with.
    #[tokio::test]
    async fn the_catalogue_can_be_declined_and_reopened() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Upstreams;
        app.clamp_cursors();
        app.handle(KeyEvent::from(KeyCode::Char('n'))).unwrap();
        app.handle(KeyEvent::from(KeyCode::Esc)).unwrap();

        let rendered = render(&mut app, 120, 34);
        assert!(
            rendered.contains("add an upstream") && !rendered.contains("pick a profile"),
            "`esc` leaves the catalogue and keeps the form: {rendered}"
        );
        assert!(
            rendered.contains("ctrl-o"),
            "the way back into the catalogue is announced: {rendered}"
        );

        app.handle(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL))
            .unwrap();
        let rendered = render(&mut app, 120, 34);
        assert!(rendered.contains("pick a profile"), "{rendered}");
    }

    /// An MCP profile is not an upstream. Offering one here would write an
    /// `[[mcp_servers]]` entry from a form headed "add an upstream".
    #[test]
    fn the_upstream_picker_offers_only_the_services_an_upstream_can_be() {
        let catalogue = crate::profiles::catalog();
        let form = upstream_form(&catalogue, NO_PROFILE);
        let form::Value::Choice { options, .. } = &form.fields[0].value else {
            panic!("the picker is a choice")
        };

        for profile in &catalogue {
            let offered = options.contains(&profile.id);
            assert_eq!(
                offered,
                profile.service.kind() == "http",
                "`{}` is {} and {} offered",
                profile.id,
                profile.service.kind(),
                if offered { "is" } else { "is not" }
            );
        }
        assert!(
            catalogue.iter().any(|p| p.service.kind() == "mcp"),
            "the assertion above is only worth making while MCP profiles exist"
        );
    }

    /// The pane could add and remove and nothing else, so "this API moved" or
    /// "the credential is in a different vault item now" meant an editor and a
    /// restart.
    #[tokio::test]
    async fn an_upstream_can_be_edited_in_the_console_without_losing_its_credential() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Upstreams;
        app.clamp_cursors();

        app.handle(KeyEvent::from(KeyCode::Char('e'))).unwrap();
        assert!(
            matches!(app.modal, Some(Modal::Form(_))),
            "`e` on an upstream opens the form"
        );
        // The cursor starts on the base URL, filled in with what the file
        // holds — so this is a correction, not a retyping of the whole entry.
        app.handle(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL))
            .unwrap();
        type_in(&mut app, "https://github.example.com/api/v3");
        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();
        assert!(app.modal.is_none(), "a saved form closes");
        app.settle().await;

        let upstream = app
            .state
            .config()
            .upstream("github")
            .cloned()
            .expect("still there, under the name its rules and targets use");
        assert_eq!(
            upstream.base_url, "https://github.example.com/api/v3",
            "the running proxy forwards to the edited address, without a restart"
        );
        assert!(
            matches!(&upstream.auth, crate::config::AuthConfig::Bearer { secret }
                     if secret == "env:AGENT_IAP_TEST_TOKEN"),
            "a form that never asked about the credential must not have dropped it: {:?}",
            upstream.auth
        );
        assert_eq!(
            app.state.acl.rule_count(),
            1,
            "and the rule aimed at it is still aimed at it"
        );

        let rendered = render(&mut app, 140, 30);
        assert!(rendered.contains("github.example.com"), "{rendered}");
        assert!(!rendered.contains("restart"), "{rendered}");
    }

    /// The path is the one thing on a credential form that nothing checks
    /// until the proxy tries to resolve it, so it is the one worth not typing.
    #[tokio::test]
    async fn a_credential_can_be_pointed_at_a_file_by_walking_to_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        std::fs::write(dir.path().join("anthropic.key"), "sk-not-real").unwrap();
        app.tab = Tab::Upstreams;
        app.clamp_cursors();

        app.handle(KeyEvent::from(KeyCode::Char('e'))).unwrap();
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap(); // auth
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap(); // secret
        app.handle(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL))
            .unwrap();
        type_in(&mut app, &format!("file:{}/", dir.path().display()));
        app.handle(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL))
            .unwrap();

        // The listing is drawn over the form, showing the directory the
        // half-typed path named rather than one the operator has to walk to.
        let rendered = render(&mut app, 140, 40);
        assert!(rendered.contains("pick a file"), "{rendered}");
        assert!(rendered.contains("anthropic.key"), "{rendered}");

        type_in(&mut app, "anthropic");
        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();
        assert!(
            matches!(app.modal, Some(Modal::Form(_))),
            "picking a file returns to the form rather than saving it"
        );
        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();
        assert!(
            app.modal.is_none(),
            "and then the form saves as it always did"
        );
        app.settle().await;

        let auth = app.state.config().upstream("github").unwrap().auth.clone();
        assert!(
            matches!(&auth, crate::config::AuthConfig::Bearer { secret }
                     if secret == &format!("file:{}", dir.path().join("anthropic.key").display())),
            "the field takes the reference, not the bare path: {auth:?}"
        );
        // And what was written resolves, which is the whole point of having
        // chosen the file off the filesystem instead of typing its name.
        assert_eq!(
            app.state
                .resolver
                .resolve(auth.secret_refs()[0])
                .unwrap()
                .expose(),
            "sk-not-real"
        );
    }

    /// The bug this replaces: the key that opens the picker was only ever
    /// named on the hint line, and the hint line is also where a failed save
    /// puts its error. So the state you actually reach it from — `n`, pick the
    /// profile, `enter`, "needs `--secret <REF>`" — was the one state where
    /// nothing on screen said how to get there.
    #[tokio::test]
    async fn the_key_that_opens_the_picker_survives_an_error_on_the_hint_line() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Upstreams;
        app.clamp_cursors();
        app.handle(KeyEvent::from(KeyCode::Char('n'))).unwrap();

        // Any profile whose credential is a file will do; this is the one the
        // report came in on. Reached the way an operator reaches it: typed
        // into the catalogue `n` opened on, then `enter`.
        let wanted = "google-analytics-data";
        type_in(&mut app, wanted);
        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();
        match &app.modal {
            Some(Modal::Form(form)) => assert_eq!(form.text("id"), wanted),
            _ => panic!("picking a profile rebuilds the form rather than closing it"),
        }
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap(); // name
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap(); // secret
        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();

        let rendered = render(&mut app, 120, 34);
        assert!(
            rendered.contains("needs `--secret <REF>`"),
            "the state under test is the one with an error showing: {rendered}"
        );
        assert!(
            rendered.matches("ctrl-o").count() >= 2,
            "the key belongs on the field and in the key row, which an error \
             cannot cover: {rendered}"
        );
    }

    /// And both places it is drawn are buttons, because the console promises
    /// that anything it draws with a key on it can be clicked instead.
    #[tokio::test]
    async fn every_drawn_browse_affordance_opens_the_picker() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Upstreams;
        app.clamp_cursors();
        app.handle(KeyEvent::from(KeyCode::Char('e'))).unwrap();
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap(); // auth
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap(); // secret
                                                           // Empty, so both are drawn; filled, so only the key row is.
        app.handle(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL))
            .unwrap();
        for (typed, drawn) in [("", 2), ("op://Private/Anthropic/key", 1)] {
            type_in(&mut app, typed);
            render(&mut app, 120, 34);
            let targets = app.hits.form.as_ref().unwrap().browse.clone();
            assert_eq!(targets.len(), drawn, "with `{typed}` in the field");
            for rect in targets {
                app.click((rect.x + 1, rect.y), false).unwrap();
                assert!(
                    matches!(&app.modal, Some(Modal::Form(form)) if form.browsing()),
                    "a click at {rect:?} left the picker shut"
                );
                app.handle(KeyEvent::from(KeyCode::Esc)).unwrap();
            }
        }
    }

    /// The offer sits immediately past the caret, so the moment there is a
    /// value it reads as part of it — `op://` followed by a highlighted
    /// `ctrl-o` looks like a field holding something it does not hold. It goes
    /// when you type and comes back when the field is cleared; the key row
    /// keeps the route open throughout, so nothing is lost by hiding it.
    #[tokio::test]
    async fn the_offer_gets_out_of_the_way_of_what_is_being_typed() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Upstreams;
        app.clamp_cursors();
        app.handle(KeyEvent::from(KeyCode::Char('e'))).unwrap();
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap(); // auth
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap(); // secret
        app.handle(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL))
            .unwrap();

        let on_the_field = |app: &mut App| {
            render(app, 120, 34)
                .lines()
                .any(|line| line.contains("secret") && line.contains("ctrl-o"))
        };
        assert!(on_the_field(&mut app), "an empty field offers the picker");

        type_in(&mut app, "op://");
        let rendered = render(&mut app, 120, 34);
        assert!(
            !rendered
                .lines()
                .any(|l| l.contains("op://") && l.contains("ctrl-o")),
            "nothing should sit against what is being typed: {rendered}"
        );
        assert!(
            rendered.contains("ctrl-o"),
            "but the key row still says the picker is there: {rendered}"
        );
        // And `ctrl-o` still works while it is hidden, which is what makes
        // hiding it safe.
        app.handle(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL))
            .unwrap();
        assert!(matches!(&app.modal, Some(Modal::Form(form)) if form.browsing()));
        app.handle(KeyEvent::from(KeyCode::Esc)).unwrap();

        app.handle(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL))
            .unwrap();
        assert!(on_the_field(&mut app), "clearing the field brings it back");
    }

    /// Same form, from the pointer: a double-click opens the row.
    #[tokio::test]
    async fn enter_on_an_upstream_opens_the_same_editor() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Upstreams;
        app.clamp_cursors();

        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();

        match &app.modal {
            Some(Modal::Form(form)) => {
                assert_eq!(form.intent, form::Intent::EditUpstream("github".into()));
                assert_eq!(
                    form.text("base-url"),
                    "https://api.github.com",
                    "it opens on the entry as the file has it"
                );
            }
            other => panic!(
                "`enter` on an upstream should open its form, got {:?}",
                other.is_some()
            ),
        }
    }

    /// Pressing enter through the rule form prompts; it does not grant.
    ///
    /// Every other field in that form opens on the widest thing it can mean —
    /// every agent, every target, every method, every path — so the action is
    /// the only thing between a form walked through on its defaults and one
    /// rule that allows everything to everyone, ahead of the `acl_default =
    /// deny` the file itself promises. It opened on `allow`, and this is the
    /// test that was missing when it did.
    #[test]
    fn the_rule_form_opens_on_ask_because_its_other_defaults_are_wide_open() {
        let form = rule_form(&Inventory::default());

        assert_eq!(form.text("agent"), "*");
        assert_eq!(form.text("target"), "*");
        assert_eq!(form.list("methods"), vec!["*".to_string()]);
        assert_eq!(form.list("paths"), vec!["**".to_string()]);
        assert_eq!(
            form.text("action"),
            "ask",
            "a rule this wide stops on a human, it does not wave the request through"
        );
    }

    /// A policy file with an agent, an upstream and an MCP server in it, for
    /// the tests about writing a rule against those names.
    const POLICY_WITH_MCP: &str = r#"
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

[[mcp_servers]]
name = "linear"
transport = "stdio"
command = "linear-mcp"
args = ["--stdio"]
"#;

    const POLICY_WITH_STORE: &str = r#"
[server]
secret_store = "STORE"

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
"#;

    /// Open the `add an upstream` form on `bearer`, named, with the cursor on
    /// `secret` and a credential typed into it — the state the refusal used to
    /// be a dead end from.
    async fn upstream_form_with_a_typed_credential(app: &mut App, name: &str, credential: &str) {
        app.tab = Tab::Upstreams;
        app.clamp_cursors();
        app.handle(KeyEvent::from(KeyCode::Char('n'))).unwrap();
        // `n` opens on the catalogue; `esc` off it is the hand-written form,
        // which is the one this helper is setting up.
        app.handle(KeyEvent::from(KeyCode::Esc)).unwrap();

        let Some(Modal::Form(form)) = &mut app.modal else {
            panic!("the upstream form is not open");
        };
        set(form, "name", name);
        // `secret` is only on screen for a scheme that reads one, so the scheme
        // is chosen first — as it is on the way in.
        let auth = form
            .fields
            .iter()
            .position(|field| field.key == "auth")
            .unwrap();
        form.focus(auth);
        while form.text("auth") != "bearer" {
            form.handle(KeyEvent::from(KeyCode::Right));
        }
        let at = form
            .fields
            .iter()
            .position(|field| field.key == "secret")
            .unwrap();
        form.focus(at);
        assert_eq!(form.fields[at].key, "secret");

        // Typed through the console, so this is the keystroke path an operator
        // takes rather than a value poked into the struct.
        for c in credential.chars() {
            app.handle(KeyEvent::from(KeyCode::Char(c))).unwrap();
        }
        let Some(Modal::Form(form)) = &app.modal else {
            panic!("the form closed while it was being filled in");
        };
        assert_eq!(form.text("secret"), credential);
    }

    /// The console's way out of the refusal that had none.
    ///
    /// Typing a credential where a reference goes used to be answered by an
    /// error and nothing else — the value was not a reference, and the spelling
    /// the error named was refused by the next command. `ctrl-k` is the third
    /// thing to do, and it happens without leaving the form the refusal came
    /// from.
    #[tokio::test]
    async fn typing_a_credential_into_the_form_can_be_kept_without_leaving_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_with(dir.path(), POLICY_WITH_STORE);
        upstream_form_with_a_typed_credential(&mut app, "readonly", "ghp_a_readonly_token").await;

        app.handle(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL))
            .unwrap();

        let Some(Modal::Form(form)) = &app.modal else {
            panic!("keeping a value closed the form");
        };
        // The name is derived from what is being enrolled, so the store reads
        // as an inventory rather than as `credential-1`.
        assert_eq!(form.text("secret"), "iap://readonly");
        assert!(form.error.is_none(), "{:?}", form.error);

        // The value is in the store, under that name, and nowhere else.
        let store = crate::store::Store::at(dir.path().join("secrets.toml"));
        assert_eq!(
            store.get("readonly").unwrap().expose(),
            "ghp_a_readonly_token"
        );

        // …and the form is still the operator's to cancel. Nothing has been
        // written to the policy file yet.
        let policy = std::fs::read_to_string(dir.path().join("iap.toml")).unwrap();
        assert!(!policy.contains("readonly"), "{policy}");
    }

    /// A name the operator did not choose must never be the thing that replaces
    /// another upstream's credential.
    #[tokio::test]
    async fn keeping_a_second_credential_under_a_taken_name_does_not_overwrite_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::at(dir.path().join("secrets.toml"));
        store.set("readonly", "the-first-one").unwrap();

        let mut app = app_with(dir.path(), POLICY_WITH_STORE);
        upstream_form_with_a_typed_credential(&mut app, "readonly", "the-second-one").await;
        app.handle(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL))
            .unwrap();

        let Some(Modal::Form(form)) = &app.modal else {
            panic!("the form closed");
        };
        assert_eq!(form.text("secret"), "iap://readonly-2");
        assert_eq!(store.get("readonly").unwrap().expose(), "the-first-one");
        assert_eq!(store.get("readonly-2").unwrap().expose(), "the-second-one");
    }

    /// Everything drawn with a key on it is a button here, so both places the
    /// `ctrl-k` offer appears have to keep the value — and the offer has to come
    /// off the field once it holds a reference, as the `ctrl-o` one does.
    #[tokio::test]
    async fn every_drawn_keep_affordance_stores_the_value() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_with(dir.path(), POLICY_WITH_STORE);
        upstream_form_with_a_typed_credential(&mut app, "readonly", "ghp_a_readonly_token").await;

        let rendered = render(&mut app, 120, 34);
        assert!(rendered.contains("ctrl-k"), "{rendered}");
        let offers = app.hits.form.as_ref().unwrap().keep.clone();
        assert_eq!(
            offers.len(),
            2,
            "the offer belongs on the field's own line and in the key row"
        );

        // Either of them, clicked, does what the key does.
        let rect = offers[0];
        app.click((rect.x + 1, rect.y), false).unwrap();
        let Some(Modal::Form(form)) = &app.modal else {
            panic!("the form closed");
        };
        assert_eq!(form.text("secret"), "iap://readonly");

        // And now that the field holds a reference the offer is gone — from the
        // line and from the key row, because there is nothing left to keep.
        let rendered = render(&mut app, 120, 34);
        assert!(!rendered.contains("ctrl-k"), "{rendered}");
        assert!(app.hits.form.as_ref().unwrap().keep.is_empty());
    }

    /// The names in an ACL rule are the ones written further up the same file,
    /// and a rule that misspells one matches nothing — silently, which with
    /// `acl_default = deny` looks exactly like a policy working as written. So
    /// the form offers them, end to end over the keyboard.
    #[tokio::test]
    async fn a_rule_can_be_written_by_picking_the_names_the_file_holds() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_with(dir.path(), POLICY_WITH_MCP);
        app.tab = Tab::Acl;
        app.clamp_cursors();
        app.handle(KeyEvent::from(KeyCode::Char('n'))).unwrap();
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap(); // name -> agent

        app.handle(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL))
            .unwrap();
        let rendered = render(&mut app, 120, 34);
        assert!(
            rendered.contains("claude-code") && rendered.contains("Claude Code"),
            "the enrolled agent is offered, beside what it is: {rendered}"
        );

        type_in(&mut app, "claude");
        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();
        let Some(Modal::Form(form)) = &app.modal else {
            panic!("picking a name must not submit the form it was opened from");
        };
        assert_eq!(form.text("agent"), "claude-code");

        // And the same for the target, which is the other half of the rule.
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap(); // -> kind
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap(); // -> target
        app.handle(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL))
            .unwrap();
        let rendered = render(&mut app, 120, 34);
        assert!(
            rendered.contains("api.github.com"),
            "an upstream is offered by name and by the host it fronts: {rendered}"
        );
        type_in(&mut app, "github");
        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();

        // The rule writes, and the proxy it was written into agrees with it.
        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();
        let written = std::fs::read_to_string(dir.path().join("iap.toml")).unwrap();
        assert!(written.contains("agent = \"claude-code\""), "{written}");
        assert!(written.contains("target = \"github\""), "{written}");
    }

    /// `kind` decides which names can match at all: an MCP server under
    /// `kind = "http"` is the same never-firing rule as a typo, so the picker
    /// does not offer one. A console that suggested it would be suggesting the
    /// mistake this picker exists to prevent.
    #[tokio::test]
    async fn the_target_picker_offers_only_what_the_rules_kind_can_reach() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_with(dir.path(), POLICY_WITH_MCP);
        app.tab = Tab::Acl;
        app.clamp_cursors();

        for (kind, offered, withheld) in [
            ("*", "github", None),
            ("http", "github", Some("linear")),
            ("mcp", "linear", Some("github")),
        ] {
            app.handle(KeyEvent::from(KeyCode::Char('n'))).unwrap();
            if let Some(Modal::Form(form)) = &mut app.modal {
                set(form, "kind", kind);
                let at = form
                    .fields
                    .iter()
                    .position(|field| field.key == "target")
                    .unwrap();
                form.focus(at);
            }
            app.handle(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL))
                .unwrap();
            assert!(
                matches!(&app.modal, Some(Modal::Form(form)) if form.browsing()),
                "`ctrl-o` on the target field opens the picker"
            );

            let rendered = render(&mut app, 120, 34);
            assert!(
                rendered.contains(offered),
                "`kind = {kind}` should offer `{offered}`: {rendered}"
            );
            if let Some(withheld) = withheld {
                assert!(
                    !rendered.contains(withheld),
                    "`kind = {kind}` cannot match `{withheld}`, so it must not be offered: \
                     {rendered}"
                );
            }
            app.handle(KeyEvent::from(KeyCode::Esc)).unwrap(); // the picker
            app.handle(KeyEvent::from(KeyCode::Esc)).unwrap(); // the form
        }
    }

    /// Everything drawn with a key on it is a button here, so both places the
    /// offer appears have to open the picker — and a row of the picker has to
    /// take a double-click, as every other list in this console does.
    #[tokio::test]
    async fn every_drawn_choose_affordance_opens_the_picker() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_with(dir.path(), POLICY_WITH_MCP);
        app.tab = Tab::Acl;
        app.clamp_cursors();
        app.handle(KeyEvent::from(KeyCode::Char('n'))).unwrap();
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap(); // name -> agent

        render(&mut app, 120, 34);
        let targets = app.hits.form.as_ref().unwrap().browse.clone();
        assert_eq!(
            targets.len(),
            2,
            "the offer belongs on the field's own line and in the key row"
        );
        for rect in targets {
            app.click((rect.x + 1, rect.y), false).unwrap();
            assert!(
                matches!(&app.modal, Some(Modal::Form(form)) if form.browsing()),
                "a click at {rect:?} left the picker shut"
            );
            app.handle(KeyEvent::from(KeyCode::Esc)).unwrap();
        }

        // And the list itself: the second row is the enrolled agent, under `*`.
        app.handle(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL))
            .unwrap();
        render(&mut app, 120, 34);
        let rows = app
            .hits
            .form
            .as_ref()
            .and_then(|hits| hits.browser.clone())
            .expect("the picker reports its rows")
            .rows;
        let (row, _) = rows[1];
        app.click((row.x + 2, row.y), true).unwrap();
        let Some(Modal::Form(form)) = &app.modal else {
            panic!("a double-click on a name fills the field, it does not save the form");
        };
        assert_eq!(form.text("agent"), "claude-code");

        // Now that the field holds a name somebody chose, the offer comes off
        // it — as it does for a path — and the key row keeps the way back.
        let rendered = render(&mut app, 120, 34);
        assert!(
            !rendered
                .lines()
                .any(|line| line.contains("claude-code") && line.contains("ctrl-o")),
            "nothing should sit against a value the operator chose: {rendered}"
        );
        assert_eq!(
            app.hits.form.as_ref().unwrap().browse.len(),
            1,
            "the key row still offers the list, so the choice can be changed"
        );
    }

    /// A picker with nothing behind it is not announced. The first rule in a
    /// fresh file is written against a policy that names nothing yet, and a
    /// `ctrl-o` that opens an empty box teaches less than the prefilled `*`
    /// already said.
    #[test]
    fn a_policy_that_names_nothing_yet_offers_nothing() {
        let form = rule_form(&Inventory::default());
        for key in ["agent", "target"] {
            let field = form
                .fields
                .iter()
                .find(|field| field.key == key)
                .unwrap_or_else(|| panic!("no `{key}` field on this form"));
            assert!(
                field.offers.is_empty(),
                "`{key}` offered a list built from an empty policy file"
            );
        }
    }

    /// The daemon reloads; the console follows.
    ///
    /// The watching itself is `crate::reload`'s and tested there. What matters
    /// here is that the panes and the footer catch up to a policy that went
    /// into force without anybody pressing anything.
    #[tokio::test]
    async fn an_edit_made_outside_the_console_lands_in_the_panes() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Acl;

        // What `agent-iap acl add` in the next terminal does.
        crate::enroll::add_rule(
            &dir.path().join("iap.toml"),
            &crate::enroll::RuleSpec {
                name: Some("added-from-a-shell"),
                agent: "*",
                kind: "http",
                target: "github",
                methods: &["GET".into()],
                paths: &["/repos/**".into()],
                action: "allow",
                expires: None,
            },
        )
        .unwrap();

        let config = reloaded(&app);
        app.adopt(config);
        app.clamp_cursors();

        let rendered = render(&mut app, 140, 30);
        assert!(rendered.contains("added-from-a-shell"), "{rendered}");
        assert!(
            rendered.contains("changed on disk"),
            "and says so:\n{rendered}"
        );
        assert_eq!(
            app.state.acl.rule_count(),
            2,
            "in the running proxy, not just on screen"
        );
    }

    /// An upstream added from a shell is routable, and nothing asks for a
    /// restart on the way.
    #[tokio::test]
    async fn an_upstream_added_from_a_shell_is_routable_too() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());

        crate::enroll::add_upstream(
            &dir.path().join("iap.toml"),
            "linear",
            "https://api.linear.app",
            &crate::enroll::AuthSpec::None,
            &[],
        )
        .unwrap();

        let config = reloaded(&app);
        app.adopt(config);

        let flash = app.flash.as_ref().expect("an edit is worth a word");
        assert!(!flash.failed, "{}", flash.message);
        assert!(
            !flash.message.contains("restart"),
            "an upstream added from a shell is live too: {}",
            flash.message
        );
        assert!(app.state.config().upstream("linear").is_some());
    }

    /// The bug this console was reported for: `r` took seconds.
    ///
    /// A reload re-resolves every credential the policy names, and an `op://`
    /// reference is a subprocess and a network round trip. That used to happen
    /// on the thread that draws, so pressing `r` under a policy backed by
    /// 1Password froze the console — the one surface an agent's request is
    /// parked on waiting for a human — for as long as the vault took. It is on
    /// a thread of its own now: the keystroke returns, the console keeps
    /// drawing and keeps answering, and the reload reports back when it lands.
    #[cfg(unix)]
    #[tokio::test]
    async fn pressing_r_answers_at_once_even_when_the_vault_is_slow() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let op = dir.path().join("op");
        std::fs::write(&op, "#!/bin/sh\nsleep 1\nprintf 'sk-not-real'\n").unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mut app = app_with(
            dir.path(),
            &POLICY
                .replace(
                    r#"secret = "env:AGENT_IAP_TEST_TOKEN""#,
                    r#"secret = "op://Private/github/credential""#,
                )
                .replace(
                    "[audit]",
                    &format!("[server]\nop_binary = \"{}\"\n\n[audit]", op.display()),
                ),
        );

        let started = Instant::now();
        app.handle(KeyEvent::from(KeyCode::Char('r'))).unwrap();
        let keystroke = started.elapsed();
        assert!(
            keystroke < Duration::from_millis(200),
            "`r` held the console for {keystroke:?} — the reload is back on the drawing thread"
        );

        // And it kept drawing, with the request it exists to show still on it.
        app.pending = vec![waiting()];
        app.cursor[Tab::Approvals.index()].select(Some(0));
        let rendered = render(&mut app, 140, 30);
        assert!(rendered.contains("re-reading the policy"), "{rendered}");
        assert!(
            rendered.contains("POST /repos/acme/api/issues"),
            "{rendered}"
        );

        // The reload still lands, and still says so.
        app.settle().await;
        assert!(
            started.elapsed() >= Duration::from_secs(1),
            "the vault was consulted"
        );
        assert_eq!(
            app.flash.as_ref().map(|flash| flash.message.as_str()),
            Some("re-read the policy file")
        );
    }

    /// The bug this is the fix for: answering an `ask` raised a 1Password
    /// prompt.
    ///
    /// A standing answer writes a rule and reloads so the rule governs the next
    /// call, and a reload re-read every credential reference the file named —
    /// one `op read` each, whether or not the edit had anything to do with a
    /// credential. On a desktop 1Password every one of those is an
    /// authorization dialogue, drawn over the console, in front of the operator
    /// who was answering the request. The grant they just wrote names no
    /// credential at all (SIRI-205).
    #[cfg(unix)]
    #[tokio::test]
    async fn granting_from_the_dialogue_does_not_go_back_to_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let (mut app, calls) = app_backed_by_a_vault(dir.path());
        assert_eq!(
            vault_lookups(&calls),
            1,
            "startup reads it once, which is where the value being served came from"
        );

        let view = waiting();
        let reach = approve::reaches(&view).pop().unwrap();
        app.answer(&view, Verdict::Allow, approve::Duration::Forever, reach);
        app.settle().await;

        // The grant took — this is not a reload that quietly did not happen.
        assert_eq!(
            app.state.acl.evaluate(&view.request).action,
            crate::config::Action::Allow,
            "a rule that needs a restart to work is a rule that did not work"
        );
        let written = std::fs::read_to_string(&app.policy.path).unwrap();
        assert!(written.contains("console-allow"), "{written}");

        assert_eq!(
            vault_lookups(&calls),
            1,
            "an `[[acl]]` rule sent the operator back to 1Password"
        );
    }

    /// And the other half: a reload somebody *asked* for still re-reads.
    ///
    /// A credential rotated behind an unchanged reference is invisible in the
    /// file, so the only thing that can pick it up is reading it again — `r`
    /// here, `SIGHUP` under a unit file. Taking that away to stop the prompts
    /// would have traded one bug for a proxy serving a retired key until it was
    /// restarted.
    #[cfg(unix)]
    #[tokio::test]
    async fn pressing_r_still_re_reads_a_credential_that_may_have_rotated() {
        let dir = tempfile::tempdir().unwrap();
        let (mut app, calls) = app_backed_by_a_vault(dir.path());
        assert_eq!(vault_lookups(&calls), 1);

        app.reread().await;

        assert_eq!(
            vault_lookups(&calls),
            2,
            "`r` is an operator asking for the file to be read again, vault and all"
        );
    }

    /// `c` on the credentials pane asks the source, not this process.
    ///
    /// The column answers the one question the file cannot — whether the vault
    /// is still unlocked and the variable still set — and it used to answer it
    /// cache-first. Every reference this proxy had ever resolved therefore read
    /// `yes` for the life of the process, which is the healthy render for a
    /// question nobody asked: the operator watching that column would have been
    /// the last to know.
    #[tokio::test]
    async fn checking_the_credentials_pane_asks_the_source_rather_than_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("upstream.key");
        std::fs::write(&secret, "sk-not-real").unwrap();
        let mut app = app_with(
            dir.path(),
            &POLICY.replace(
                r#"secret = "env:AGENT_IAP_TEST_TOKEN""#,
                &format!(r#"secret = "file:{}""#, secret.display()),
            ),
        );
        app.tab = Tab::Credentials;
        app.clamp_cursors();

        // The source goes away under a proxy that already resolved it — the
        // vault relocking, which is the ordinary way this happens.
        std::fs::remove_file(&secret).unwrap();

        app.handle(KeyEvent::from(KeyCode::Char('c'))).unwrap();
        app.settle().await;

        let rendered = render(&mut app, 160, 30);
        assert!(
            !rendered.contains(" yes "),
            "the pane still says the vault is answering:\n{rendered}"
        );
        let flash = app.flash.as_ref().expect("the console said something");
        assert!(
            flash.failed && flash.message.contains("no longer resolve"),
            "`{}`",
            flash.message
        );

        // And the value it is still serving was not evicted by the failed read:
        // a relocked vault must not also strip a credential the proxy is using.
        assert_eq!(
            app.state
                .resolver
                .resolve(&format!("file:{}", secret.display()))
                .unwrap()
                .expose(),
            "sk-not-real"
        );
    }

    /// A reload the console itself caused is not news to the console.
    #[tokio::test]
    async fn the_console_does_not_report_its_own_write_as_somebody_elses_edit() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Acl;

        app.handle(KeyEvent::from(KeyCode::Char('n'))).unwrap();
        type_in(&mut app, "mine");
        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();

        let said = app.flash.as_ref().map(|flash| flash.message.clone());
        // The broadcast for that write arrives on the next turn of the loop.
        app.adopt(app.state.config());

        assert_eq!(
            app.flash.as_ref().map(|flash| flash.message.clone()),
            said,
            "the console told the operator their own news"
        );
    }

    /// The watcher does the refusing; this is the console reporting it.
    #[tokio::test]
    async fn a_policy_the_proxy_will_not_take_is_reported_on_the_footer() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        std::fs::write(dir.path().join("iap.toml"), "this is not toml {{{").unwrap();

        // `r`, which is the console asking for the reload the watcher would
        // have done a moment later anyway.
        app.handle(KeyEvent::from(KeyCode::Char('r'))).unwrap();
        app.settle().await;

        assert!(app.flash.as_ref().is_some_and(|flash| flash.failed));
        // And the proxy is still running the policy that compiled.
        assert_eq!(app.state.acl.rule_count(), 1);
        assert!(app.state.agents.by_id("claude-code").is_some());
    }

    /// Drive the shared watcher the way the daemon's task does, and hand back
    /// what the console's loop would have received.
    fn reloaded(app: &App) -> Arc<crate::config::Config> {
        app.policy
            .watcher()
            .reload(&app.state, crate::reload::Trigger::Edited)
            .expect("the edit loads")
    }

    /// The token modal is the one place in this console with a secret on
    /// screen, and the key that copies it must not be the key that dismisses
    /// it — otherwise the answer about the clipboard arrives after the only
    /// copy of the token has gone.
    #[tokio::test]
    async fn copying_a_shown_token_leaves_it_up_and_says_what_happened() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.modal = Some(Modal::Show(Shown::token(
            "token for `codex` — shown once".into(),
            "iap_deadbeef",
            "iap_deadbeef\n\nGive this to the agent as IAP_TOKEN.".into(),
        )));

        let before = render(&mut app, 100, 30);
        assert!(before.contains("`c` to copy"), "{before}");

        app.handle(KeyEvent::from(KeyCode::Char('c'))).unwrap();
        assert!(app.modal.is_some(), "`c` copies; it does not dismiss");

        let after = render(&mut app, 100, 30);
        assert!(
            after.contains("iap_deadbeef"),
            "the token is still up:\n{after}"
        );
        // Under `cargo test` there is no terminal to copy to, so which note
        // this is depends on the environment. That there is one does not.
        assert_ne!(before, after, "pressing `c` has to say something:\n{after}");

        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();
        assert!(app.modal.is_none(), "every other key still closes it");
    }

    #[tokio::test]
    async fn a_modal_with_nothing_to_copy_does_not_offer_to() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.modal = Some(Modal::Show(Shown::plain(
            "dry run — nothing was written".into(),
            "[[acl]]".into(),
        )));

        let rendered = render(&mut app, 100, 30);
        assert!(rendered.contains("any key to close"), "{rendered}");
        assert!(!rendered.contains("`c` to copy"), "{rendered}");

        app.handle(KeyEvent::from(KeyCode::Char('c'))).unwrap();
        assert!(app.modal.is_none(), "`c` is any key here");
    }

    fn type_in(app: &mut App, text: &str) {
        for c in text.chars() {
            app.handle(KeyEvent::from(KeyCode::Char(c))).unwrap();
        }
    }

    /// Fill a field by the key the submit handler reads it back by. Indices
    /// move as a form grows fields; the key is the contract.
    fn set(form: &mut Form, key: &str, value: &str) {
        let field = form
            .fields
            .iter_mut()
            .find(|field| field.key == key)
            .unwrap_or_else(|| panic!("no `{key}` field on this form"));
        field.value = form::Value::Text(value.into());
    }

    /// The regression this guards: the profile add form used to fold every
    /// variable into one unexplained `NAME=VALUE` line, so DataForSEO's required
    /// `login` never actually asked for the email — and a form saved as-is wrote
    /// an empty username that 401s. Each variable now gets its own labelled,
    /// described field, and round-trips into the basic-auth username.
    #[tokio::test]
    async fn a_profile_form_asks_for_each_variable_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let app = app_for_test(dir.path());

        let profile = crate::profiles::get("dataforseo").unwrap();
        let mut form = profile_form(&profile);

        let login = form
            .fields
            .iter()
            .find(|field| field.key.as_ref() == "var:login")
            .expect("the login variable has a field of its own");
        assert_eq!(login.label.as_ref(), "login");
        assert!(
            login.hint.contains("email"),
            "the field says what to type: {}",
            login.hint
        );

        // Fill it in as the operator would, plus the credential, and enrol.
        for field in &mut form.fields {
            match field.key.as_ref() {
                "var:login" => field.value = form::Value::Text("me@example.com".into()),
                "secret" => field.value = form::Value::Text("env:AGENT_IAP_TEST_TOKEN".into()),
                _ => {}
            }
        }

        actions::submit(&app.policy, &form).unwrap();

        let written = std::fs::read_to_string(&app.policy.path).unwrap();
        assert!(
            written.contains(r#"username = "me@example.com""#),
            "the login has to land in the basic-auth username, not a dropped var:\n{written}"
        );
    }

    /// The same shape of gap, one service along: the console's `cloudflare`
    /// form asked for a token and nothing else, and a Cloudflare token is half
    /// an address — the account is what the API's paths and its own
    /// token-verify endpoint are addressed by.
    #[tokio::test]
    async fn the_cloudflare_form_asks_for_the_account_and_saves_it_into_the_probe() {
        let dir = tempfile::tempdir().unwrap();
        let app = app_for_test(dir.path());

        let profile = crate::profiles::get("cloudflare").unwrap();
        let mut form = profile_form(&profile);

        let account = form
            .fields
            .iter()
            .find(|field| field.key.as_ref() == "var:account_id")
            .expect("the account has a field of its own");
        assert_eq!(account.label.as_ref(), "account_id");

        for field in &mut form.fields {
            match field.key.as_ref() {
                "var:account_id" => {
                    field.value = form::Value::Text("9a7b1c0d2e3f4a5b6c7d8e9f0a1b2c3d".into())
                }
                "secret" => field.value = form::Value::Text("env:AGENT_IAP_TEST_TOKEN".into()),
                _ => {}
            }
        }

        actions::submit(&app.policy, &form).unwrap();

        // `v` on this row, now or in a year, calls the endpoint that answers
        // "is this token good" rather than the root, which answers `7000 no
        // route for that URI` to a good token and a bad one alike.
        let written = std::fs::read_to_string(&app.policy.path).unwrap();
        assert!(
            written.contains(
                r#"verify_path = "/accounts/9a7b1c0d2e3f4a5b6c7d8e9f0a1b2c3d/tokens/verify""#
            ),
            "the account never reached the probe:\n{written}"
        );
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
    // ---- a token is on screen once, and only a named key takes it off ------

    fn token_modal(app: &mut App) -> Rect {
        app.modal = Some(Modal::Show(Shown::token(
            "token for `claude-code` — shown once".into(),
            "iap_the_only_copy",
            "iap_the_only_copy\n\nGive this to the agent as IAP_TOKEN.".into(),
        )));
        // Drawing is what records the hit box a click is tested against.
        render(app, 120, 34);
        app.hits
            .plain_modal
            .expect("the modal registered a hit box")
    }

    /// The report: `c` did not reach the clipboard under tmux, so the operator
    /// reached for the mouse — and the click that starts a text selection over
    /// the token is the click that threw the token away.
    #[tokio::test]
    async fn a_click_on_a_token_does_not_throw_it_away() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        let popup = token_modal(&mut app);

        app.click((popup.x + 4, popup.y + 2), false).unwrap();

        assert!(
            app.showing_a_secret(),
            "a click over the token dismissed the one modal that can never be reopened"
        );
        assert!(render(&mut app, 120, 34).contains("iap_the_only_copy"));
    }

    /// The same for the keyboard: "any key" includes every key pressed by
    /// somebody who thought the modal had already gone.
    #[tokio::test]
    async fn a_stray_key_does_not_throw_a_token_away() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        token_modal(&mut app);

        for stray in ['j', 'n', 'x', '2'] {
            app.handle(KeyEvent::from(KeyCode::Char(stray))).unwrap();
            assert!(
                app.showing_a_secret(),
                "`{stray}` took the token off screen"
            );
        }

        // And it says so, rather than looking like a console that has stopped
        // responding to the keyboard.
        let rendered = render(&mut app, 120, 34);
        assert!(rendered.contains("still here"), "{rendered}");
    }

    #[tokio::test]
    async fn a_named_key_closes_the_token_for_good() {
        let dir = tempfile::tempdir().unwrap();
        for key in [KeyCode::Esc, KeyCode::Enter, KeyCode::Char('q')] {
            let mut app = app_for_test(dir.path());
            token_modal(&mut app);
            app.handle(KeyEvent::from(key)).unwrap();
            assert!(app.modal.is_none(), "{key:?} did not close the modal");
        }
    }

    /// A preview is not a secret: whatever it was previewing is still there, so
    /// it keeps the cheaper dismissal.
    #[tokio::test]
    async fn a_dry_run_still_closes_on_any_key_and_on_a_click() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.modal = Some(Modal::Show(Shown::plain(
            "dry run — nothing was written".into(),
            "[[upstreams]]".into(),
        )));
        app.handle(KeyEvent::from(KeyCode::Char('j'))).unwrap();
        assert!(app.modal.is_none());

        app.modal = Some(Modal::Show(Shown::plain("dry run".into(), "x".into())));
        let popup = {
            render(&mut app, 120, 34);
            app.hits.plain_modal.unwrap()
        };
        app.click((popup.x + 2, popup.y + 2), false).unwrap();
        assert!(app.modal.is_none());
    }

    // ---- a write that lands and a reload that does not --------------------

    /// The reported symptom, and the reason it was only a symptom: the pane did
    /// not refresh because the reload was refused, and the footer said the
    /// enrolment had worked anyway.
    #[tokio::test]
    async fn a_refused_reload_after_a_write_is_not_reported_as_success() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("upstream.key");
        std::fs::write(&secret, "sk-not-real").unwrap();
        let mut app = app_with(
            dir.path(),
            &POLICY.replace(
                r#"secret = "env:AGENT_IAP_TEST_TOKEN""#,
                &format!(r#"secret = "file:{}""#, secret.display()),
            ),
        );
        app.tab = Tab::Agents;
        assert_eq!(views::agents(&app.policy.inventory).len(), 1);

        // Somebody repointed the upstream at a credential this proxy cannot
        // read — in an editor, in the next terminal — and the reload behind
        // the enrolment below is where that is found out. A reload resolves
        // every reference the file names before it installs anything, so one
        // it cannot read refuses a policy that is otherwise fine.
        let gone = repoint_at_nothing(&app.policy.path, &secret);

        app.handle(KeyEvent::from(KeyCode::Char('n'))).unwrap();
        for ch in "new-agent".chars() {
            app.handle(KeyEvent::from(KeyCode::Char(ch))).unwrap();
        }
        // id → name → targets, and say what it may reach: the form will not
        // enrol an agent that has not been told.
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap();
        app.handle(KeyEvent::from(KeyCode::Tab)).unwrap();
        for ch in "github".chars() {
            app.handle(KeyEvent::from(KeyCode::Char(ch))).unwrap();
        }
        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();
        app.settle().await;

        let written = std::fs::read_to_string(&app.policy.path).unwrap();
        assert!(written.contains("new-agent"), "the write itself landed");
        assert_eq!(
            views::agents(&app.policy.inventory).len(),
            1,
            "the pane is showing the policy still in force, which is the old one"
        );

        let flash = app.flash.as_ref().expect("the console said something");
        assert!(
            flash.failed,
            "reported as a success: `{}`, with a stale pane as the only hint",
            flash.message
        );
        assert!(
            flash.message.contains("the edit is in iap.toml")
                && flash.message.contains(&gone.display().to_string()),
            "the line has to name both halves — the file has it, the proxy does not: `{}`",
            flash.message
        );
    }

    /// And the ordinary case is untouched: the write lands, the reload takes,
    /// and the pane has the new row before the operator looks away.
    #[tokio::test]
    async fn enrolling_puts_the_agent_in_the_pane_and_the_token_on_the_screen() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Agents;

        app.handle(KeyEvent::from(KeyCode::Char('n'))).unwrap();
        for ch in "new-agent".chars() {
            app.handle(KeyEvent::from(KeyCode::Char(ch))).unwrap();
        }
        // id → name → targets → the `any target` switch, turned on.
        for _ in 0..3 {
            app.handle(KeyEvent::from(KeyCode::Tab)).unwrap();
        }
        app.handle(KeyEvent::from(KeyCode::Char(' '))).unwrap();
        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();
        app.settle().await;

        assert_eq!(views::agents(&app.policy.inventory).len(), 2);
        assert!(app.showing_a_secret(), "the token is the modal that is up");
        assert!(!app.flash.as_ref().unwrap().failed);
    }

    /// And the form will not do it by being left alone. Same rule as the
    /// command line: the blanket grant is a decision, not a default.
    #[tokio::test]
    async fn the_enrol_form_will_not_grant_every_target_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Agents;

        app.handle(KeyEvent::from(KeyCode::Char('n'))).unwrap();
        for ch in "new-agent".chars() {
            app.handle(KeyEvent::from(KeyCode::Char(ch))).unwrap();
        }
        app.handle(KeyEvent::from(KeyCode::Enter)).unwrap();

        assert_eq!(
            views::agents(&app.policy.inventory).len(),
            1,
            "nothing was enrolled"
        );
        assert!(!app.showing_a_secret(), "and no token was minted");
        // The form stays up with the reason on it, rather than closing on a
        // flash: what is missing is a field, and the answer goes in this form.
        let Some(Modal::Form(form)) = &app.modal else {
            panic!("the form should still be open");
        };
        let error = form.error.as_deref().expect("with the reason on it");
        assert!(error.contains("--any-target"), "{error}");
    }
    /// `R` on the rules pane. The confirm first — this is the one key in the
    /// console that can delete a policy — then the file, then the running
    /// proxy, which is the part a file-only test would miss.
    #[tokio::test]
    async fn resetting_the_rules_empties_the_file_and_the_running_policy() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Acl;
        assert_eq!(app.state.acl.rule_count(), 1);

        app.handle(KeyEvent::from(KeyCode::Char('R'))).unwrap();
        assert!(
            matches!(app.modal, Some(Modal::Confirm(_))),
            "it asks first"
        );
        app.handle(KeyEvent::from(KeyCode::Char('y'))).unwrap();
        app.settle().await;

        assert_eq!(app.state.acl.rule_count(), 0, "in force, not just on disk");
        // `ask`, not `deny`: the console is where the requests those rules
        // were deciding now come to be answered, and a default that denied
        // would make wiping the list the quietest thing in the program.
        assert_eq!(app.state.acl.default_action(), crate::config::Action::Ask);
        assert!(app.state.acl.can_ask());
        let config: crate::config::Config =
            toml::from_str(&std::fs::read_to_string(dir.path().join("iap.toml")).unwrap()).unwrap();
        assert!(config.acl.is_empty());
        assert_eq!(config.acl_default.action, crate::config::Action::Ask);
        assert!(!app.flash.as_ref().unwrap().failed);
    }

    /// And `n` — the key beside it — still means "one rule", so the reset is
    /// not something the rules pane does by accident.
    #[tokio::test]
    async fn the_lower_case_keys_on_the_rules_pane_are_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Acl;

        app.handle(KeyEvent::from(KeyCode::Char('r'))).unwrap();

        assert!(app.modal.is_none(), "`r` is still a re-read, not a reset");
        assert_eq!(app.state.acl.rule_count(), 1);
    }

    /// `L`, both ways. It writes nothing and it is not a modal: the moment an
    /// operator wants everything to stop is not the moment for a dialogue.
    #[tokio::test]
    async fn lockdown_stops_everything_and_lifting_it_gives_the_policy_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        let before = std::fs::read_to_string(dir.path().join("iap.toml")).unwrap();
        let request =
            AccessRequest::http("claude-code", "github", "POST", "/repos/acme/api/issues");
        assert_eq!(
            app.state.acl.evaluate(&request).action,
            crate::config::Action::Ask
        );

        app.handle(KeyEvent::from(KeyCode::Char('L'))).unwrap();

        assert!(app.modal.is_none(), "no dialogue in the way");
        assert!(app.state.acl.locked_down());
        assert_eq!(
            app.state.acl.evaluate(&request).action,
            crate::config::Action::Deny,
            "the `ask` never reaches a human now"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("iap.toml")).unwrap(),
            before,
            "and nothing was written"
        );
        // Said loudly, and said for as long as it lasts rather than for the
        // eight seconds a flash is up.
        let rendered = render(&mut app, 120, 34);
        assert!(rendered.contains("LOCKDOWN"), "{rendered}");

        app.handle(KeyEvent::from(KeyCode::Char('L'))).unwrap();

        assert!(!app.state.acl.locked_down());
        assert_eq!(
            app.state.acl.evaluate(&request).action,
            crate::config::Action::Ask,
            "the file said `ask` the whole time, and says it again"
        );
        assert!(!render(&mut app, 120, 34).contains("LOCKDOWN"));
    }

    /// `t` on the agents pane — "new token" — end to end: the confirm, the
    /// mint, and the one moment the token exists outside the file.
    #[tokio::test]
    async fn minting_a_new_token_leaves_it_on_screen_and_the_old_one_dead() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_for_test(dir.path());
        app.tab = Tab::Agents;
        app.cursor[Tab::Agents.index()].select(Some(0));
        assert!(app.state.agents.authenticate("iap_test").is_some());

        app.handle(KeyEvent::from(KeyCode::Char('t'))).unwrap();
        assert!(
            matches!(app.modal, Some(Modal::Confirm(_))),
            "it asks first"
        );
        app.handle(KeyEvent::from(KeyCode::Char('y'))).unwrap();
        app.settle().await;

        assert!(app.showing_a_secret(), "the new token has to be on screen");
        assert!(
            app.state.agents.authenticate("iap_test").is_none(),
            "and the old one has to be dead in the running proxy, not just in the file"
        );
        let rendered = render(&mut app, 120, 34);
        assert!(rendered.contains("iap_"), "{rendered}");
        assert!(rendered.contains("`t` again mints another"), "{rendered}");
    }

    /// The worst combination: the mint succeeded, the reload did not. The
    /// token is still the only copy there will ever be, so the refusal is
    /// reported *around* it rather than in place of it.
    #[tokio::test]
    async fn a_refused_reload_never_takes_the_minted_token_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("upstream.key");
        std::fs::write(&secret, "sk-not-real").unwrap();
        let mut app = app_with(
            dir.path(),
            &POLICY.replace(
                r#"secret = "env:AGENT_IAP_TEST_TOKEN""#,
                &format!(r#"secret = "file:{}""#, secret.display()),
            ),
        );
        app.tab = Tab::Agents;
        app.cursor[Tab::Agents.index()].select(Some(0));
        repoint_at_nothing(&app.policy.path, &secret);

        app.handle(KeyEvent::from(KeyCode::Char('t'))).unwrap();
        app.handle(KeyEvent::from(KeyCode::Char('y'))).unwrap();
        app.settle().await;

        assert!(
            app.showing_a_secret(),
            "the token went down with the reload"
        );
        assert!(app.flash.as_ref().unwrap().failed, "and nobody was told");
    }
}
