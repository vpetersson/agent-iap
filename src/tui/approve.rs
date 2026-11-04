//! The dialogue an `ask` rule raises.
//!
//! Little Snitch's, in a terminal, and for the same reason: the question "may
//! this connect" is unanswerable on its own. What an operator can answer is
//! "may *this agent* do *this much*, for *how long*" — so the two axes that
//! made that dialogue work are the two axes here. Across the top, how long the
//! answer holds; down the middle, how far it reaches.
//!
//! The durations are four different mechanisms, and the dialogue says which:
//! once is this request; a TTL and "from now on" are both rules written into
//! the policy file, in front of the `ask` that raised the question — appended
//! after it, first-match-wins would leave the new rule unreachable and the same
//! question coming back — differing only in whether the rule carries a deadline;
//! until quit is remembered in this process and dies with it.
//!
//! The TTLs are the interesting ones, and the reason the dialogue is worth
//! having at all. Most of what an operator wants to say is not "yes" and not
//! "no" but "yes, while I am doing this" — and a console that cannot spell that
//! leaves them picking between a grant that outlives the reason for it and
//! being asked again in thirty seconds. Both of those end the same way.

use chrono::{TimeDelta, Utc};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::acl::Kind;
use crate::approval::{PendingView, Scope, Verdict};

use super::form::centred;

/// How long an answer holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Duration {
    /// This request, and nothing after it.
    Once,
    /// Everything the scope covers, until the deadline — a rule in the policy
    /// file that carries its own expiry, so the grant survives a restart and
    /// runs out whether or not anyone remembers it.
    For(&'static str),
    /// Everything the scope covers, until this proxy exits. The only answer
    /// that writes nothing.
    UntilQuit,
    /// Everything the scope covers, written into the policy file to stay.
    Forever,
}

impl Duration {
    /// Left to right, shortest first: the cursor starts on the left, so the
    /// order is also a ranking of how much is being given away.
    pub const ALL: [Duration; 6] = [
        Duration::Once,
        Duration::For("5m"),
        Duration::For("1h"),
        Duration::For("1d"),
        Duration::UntilQuit,
        Duration::Forever,
    ];

    fn label(self) -> String {
        match self {
            Duration::Once => "Once".into(),
            Duration::For("5m") => "5 min".into(),
            Duration::For("1h") => "1 hour".into(),
            Duration::For("1d") => "1 day".into(),
            Duration::For(ttl) => ttl.to_string(),
            Duration::UntilQuit => "Until quit".into(),
            Duration::Forever => "From now on".into(),
        }
    }

    /// How long this grant lasts, for the ones that have an answer.
    pub fn ttl(self) -> Option<TimeDelta> {
        match self {
            // Parsed rather than carried as a `TimeDelta` so the spelling on
            // screen and the length of the grant are the same one string.
            Duration::For(ttl) => crate::enroll::parse_ttl(ttl).ok(),
            _ => None,
        }
    }
}

/// The ACL rule a `Forever` answer would write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleShape {
    pub agent: String,
    pub kind: String,
    pub target: String,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
}

/// One row of the dialogue's scope list: what it reads as, what it remembers,
/// and what it would write.
#[derive(Debug, Clone)]
pub struct Reach {
    pub label: String,
    pub scope: Scope,
    pub rule: RuleShape,
}

/// How far an answer can be made to reach, broadest first — the order the
/// original dialogue used, with the cursor starting on the narrowest.
///
/// Every row names the service the request was for. There used to be one above
/// these that did not — "any request from <agent>", which wrote a rule with
/// `target = "*"` — and it was the console's own way into the reported bug
/// (SIRI-186): one keystroke turned an answer about this call into a standing
/// grant over every service the proxy would ever front, so the next
/// `agent-iap upstream add` was allowed before anybody saw it, and this queue
/// stayed empty. The blanket grant is still available, said out loud, from the
/// one surface where it can be read back before it is written:
/// `agent-iap acl add --action allow --any-target`.
pub fn reaches(view: &PendingView) -> Vec<Reach> {
    let request = &view.request;
    let agent = request.agent.clone();
    let kind = request.kind.as_str().to_string();
    let target = request.target.clone();
    let method = request.method.clone();

    let mut reaches = vec![
        Reach {
            label: format!("→ anything on {target}"),
            scope: Scope {
                agent: Some(agent.clone()),
                kind: Some(request.kind),
                target: Some(target.clone()),
                ..Scope::default()
            },
            rule: RuleShape {
                agent: agent.clone(),
                kind: kind.clone(),
                target: target.clone(),
                methods: vec!["*".into()],
                paths: vec!["**".into()],
            },
        },
        Reach {
            label: format!("→ {method} on {target}"),
            scope: Scope {
                agent: Some(agent.clone()),
                kind: Some(request.kind),
                target: Some(target.clone()),
                method: Some(method.clone()),
                ..Scope::default()
            },
            rule: RuleShape {
                agent: agent.clone(),
                kind: kind.clone(),
                target: target.clone(),
                methods: vec![method.clone()],
                paths: vec!["**".into()],
            },
        },
    ];

    // `tools/list` names nothing, so "this method" already *is* the narrowest
    // thing there is to allow. Offering a fourth row identical to the third
    // would be a choice between two spellings of the same grant.
    if !request.path.is_empty() {
        reaches.push(path_reach(view, &literal_glob(&request.path)));
    }

    reaches
}

/// The path row, at `pattern` — the request's own path, or a glob over it that
/// the operator widened to with `g` or typed with `e`.
fn path_reach(view: &PendingView, pattern: &str) -> Reach {
    let request = &view.request;
    Reach {
        label: format!("→ {} {pattern} on {}", request.method, request.target),
        scope: if pattern == literal_glob(&request.path) {
            Scope::exact(request)
        } else {
            Scope {
                path: None,
                path_pattern: Some(pattern.to_string()),
                ..Scope::exact(request)
            }
        },
        rule: RuleShape {
            agent: request.agent.clone(),
            kind: request.kind.as_str().to_string(),
            target: request.target.clone(),
            methods: vec![request.method.clone()],
            paths: vec![pattern.to_string()],
        },
    }
}

/// What `g` steps through, narrowest first: the path itself, its siblings, and
/// then each ancestor's whole subtree up to the first segment. Stops short of
/// `/**`, which the method row already says.
///
/// A path that does not start with `/` is an MCP tool name, which has no
/// parent to widen to.
fn path_ladder(path: &str) -> Vec<String> {
    let mut ladder = vec![literal_glob(path)];
    let Some(rest) = path.strip_prefix('/') else {
        return ladder;
    };
    let escaped: Vec<String> = rest.split('/').map(literal_glob).collect();
    let segments: Vec<&str> = escaped.iter().map(String::as_str).collect();
    let parent = &segments[..segments.len() - 1];
    ladder.push(format!("/{}", [parent, &["*"]].concat().join("/")));
    for kept in (1..parent.len()).rev() {
        ladder.push(format!("/{}/**", segments[..kept].join("/")));
    }
    ladder.dedup();
    ladder
}

/// A glob matching exactly this path. The path is the agent's, percent-decoded,
/// so `%2A%2A` arrives as `**`: copied into a rule unescaped, a call that reads
/// as one literal path would write a grant over a whole subtree.
fn literal_glob(path: &str) -> String {
    // `\` is an escape in globset's default syntax on Unix, which the ACL uses.
    globset::escape(&path.replace('\\', "\\\\"))
}

/// Why a typed path glob cannot be the answer, if it cannot: it does not
/// compile under the ACL's own matcher, or it does not cover the request on
/// screen — and an answer that does not reach the call it answers writes a rule
/// that leaves the same question coming back.
fn check_path_pattern(pattern: &str, path: &str) -> Result<(), String> {
    let compiled = crate::acl::path_glob(pattern).map_err(|error| format!("{error:#}"))?;
    if !crate::acl::path_matches(&[compiled], path) {
        return Err(format!(
            "`{pattern}` does not cover {path}, the request being answered"
        ));
    }
    Ok(())
}

/// The path row's pattern while it is being typed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Edit {
    pattern: String,
    /// Characters, not bytes, before the cursor.
    cursor: usize,
    error: Option<String>,
}

impl Edit {
    fn byte_at(&self, cursor: usize) -> usize {
        self.pattern
            .char_indices()
            .nth(cursor)
            .map_or(self.pattern.len(), |(byte, _)| byte)
    }
}

/// What the event loop should do once the operator has answered.
pub enum Answer {
    /// Left pending — the operator wants to look at something first. The
    /// approval timeout is still running, and it still fails closed.
    Dismiss,
    Decide {
        verdict: Verdict,
        duration: Duration,
        /// Boxed: the reach carries the whole rule it would write, and every
        /// `Dismiss` would otherwise be that big too.
        reach: Box<Reach>,
    },
}

/// Where the dialogue drew the things a mouse can hit.
///
/// This dialogue is the one place in the console where pointing at the thing
/// you mean is the native idiom — it is a copy of a dialogue that only ever had
/// buttons — so its controls are recorded precisely rather than approximated by
/// the row they happen to be on.
#[derive(Default, Clone)]
pub struct Hits {
    /// The whole dialogue. A click outside it belongs to nothing.
    pub popup: Rect,
    pub durations: Vec<(Rect, usize)>,
    pub reaches: Vec<(Rect, usize)>,
    pub deny: Rect,
    pub allow: Rect,
    pub dismiss: Rect,
}

pub struct Dialogue {
    pub view: PendingView,
    reaches: Vec<Reach>,
    duration: usize,
    reach: usize,
    ladder: Vec<String>,
    rung: usize,
    edit: Option<Edit>,
}

impl Dialogue {
    pub fn new(view: PendingView) -> Self {
        let reaches = reaches(&view);
        Dialogue {
            // Start on the narrowest grant. Anything else is a dialogue that
            // hands out more than was asked for when somebody hits enter.
            reach: reaches.len() - 1,
            reaches,
            duration: 0,
            ladder: path_ladder(&view.request.path),
            rung: 0,
            edit: None,
            view,
        }
    }

    /// Whether the last row is about a path, so `g` and `e` have one to change.
    fn has_path_row(&self) -> bool {
        !self.view.request.path.is_empty()
    }

    fn set_path(&mut self, pattern: &str) {
        let last = self.reaches.len() - 1;
        self.reaches[last] = path_reach(&self.view, pattern);
        self.reach = last;
    }

    fn step_path(&mut self, rung: usize) {
        self.rung = rung.min(self.ladder.len() - 1);
        let pattern = self.ladder[self.rung].clone();
        self.set_path(&pattern);
    }

    fn handle_edit(&mut self, key: KeyEvent, mut edit: Edit) {
        match key.code {
            KeyCode::Esc => return,
            KeyCode::Enter => match check_path_pattern(&edit.pattern, &self.view.request.path) {
                Ok(()) => {
                    if let Some(rung) = self.ladder.iter().position(|step| *step == edit.pattern) {
                        self.rung = rung;
                    }
                    self.set_path(&edit.pattern);
                    return;
                }
                Err(error) => edit.error = Some(error),
            },
            KeyCode::Left => edit.cursor = edit.cursor.saturating_sub(1),
            KeyCode::Right => edit.cursor = (edit.cursor + 1).min(edit.pattern.chars().count()),
            KeyCode::Home => edit.cursor = 0,
            KeyCode::End => edit.cursor = edit.pattern.chars().count(),
            KeyCode::Backspace if edit.cursor > 0 => {
                edit.cursor -= 1;
                edit.pattern.remove(edit.byte_at(edit.cursor));
                edit.error = None;
            }
            KeyCode::Delete if edit.cursor < edit.pattern.chars().count() => {
                edit.pattern.remove(edit.byte_at(edit.cursor));
                edit.error = None;
            }
            KeyCode::Char(character) => {
                edit.pattern.insert(edit.byte_at(edit.cursor), character);
                edit.cursor += 1;
                edit.error = None;
            }
            _ => {}
        }
        self.edit = Some(edit);
    }

    pub fn handle(&mut self, key: KeyEvent) -> Option<Answer> {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Some(Answer::Dismiss);
        }
        if let Some(edit) = self.edit.take() {
            self.handle_edit(key, edit);
            return None;
        }
        match key.code {
            KeyCode::Char('g') if self.has_path_row() => self.step_path(self.rung + 1),
            KeyCode::Char('G') if self.has_path_row() => {
                self.step_path(self.rung.saturating_sub(1))
            }
            KeyCode::Char('e') if self.has_path_row() => {
                let pattern = self.reaches[self.reaches.len() - 1].rule.paths[0].clone();
                self.edit = Some(Edit {
                    cursor: pattern.chars().count(),
                    pattern,
                    error: None,
                });
                self.reach = self.reaches.len() - 1;
            }
            KeyCode::Esc => return Some(Answer::Dismiss),
            KeyCode::Right | KeyCode::Tab => {
                self.duration = (self.duration + 1) % Duration::ALL.len();
            }
            KeyCode::Left | KeyCode::BackTab => {
                self.duration = (self.duration + Duration::ALL.len() - 1) % Duration::ALL.len();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.reach = (self.reach + 1).min(self.reaches.len() - 1);
            }
            KeyCode::Up | KeyCode::Char('k') => self.reach = self.reach.saturating_sub(1),
            KeyCode::Enter | KeyCode::Char('a') => return Some(self.answer(Verdict::Allow)),
            KeyCode::Char('d') => return Some(self.answer(Verdict::Deny)),
            _ => {}
        }
        None
    }

    /// Pick a duration by position — what a click on a segment means.
    pub fn choose_duration(&mut self, index: usize) {
        if index < Duration::ALL.len() {
            self.duration = index;
        }
    }

    /// Pick a reach by position — what a click on a radio row means.
    pub fn choose_reach(&mut self, index: usize) {
        if index < self.reaches.len() {
            self.reach = index;
        }
    }

    fn answer(&self, verdict: Verdict) -> Answer {
        Answer::Decide {
            verdict,
            duration: Duration::ALL[self.duration],
            reach: Box::new(self.reaches[self.reach].clone()),
        }
    }

    /// One sentence saying what the current pair of choices will actually do.
    /// The dialogue's whole risk is an operator who thinks "Once" and picks
    /// "From now on", so the consequence is spelled out rather than inferred.
    fn consequence(&self) -> String {
        if let Some(edit) = &self.edit {
            return edit.error.clone().unwrap_or_else(|| {
                "a path glob — `*` is one segment, `**` any depth; ←/→ home end move, enter \
                 keeps it, esc puts the path back"
                    .into()
            });
        }
        let reach = &self.reaches[self.reach];
        let duration = Duration::ALL[self.duration];
        match duration {
            // "This one request" is a lie whenever an agent has retried: the
            // row is several of them and they are all about to be answered.
            Duration::Once if self.view.waiting > 1 => format!(
                "answers the {} identical requests waiting; the next call asks again",
                self.view.waiting
            ),
            Duration::Once => "answers this one request; the next identical call asks again".into(),
            Duration::UntilQuit => format!(
                "remembered for `{}` until agent-iap exits — nothing is written to disk",
                reach.label.trim_start_matches("→ ")
            ),
            // The deadline as a wall-clock time, not as the length again: the
            // segment already says "1 hour", and what an operator cannot work
            // out from that is when they will be asked next.
            Duration::For(_) => match duration.ttl() {
                Some(ttl) => format!(
                    "writes an acl rule {}, expiring {} — after that this asks again",
                    self.in_front_of(),
                    (Utc::now() + ttl).format("at %H:%M on %-d %b"),
                ),
                None => "writes an acl rule with a deadline".into(),
            },
            Duration::Forever => format!(
                "writes an acl rule {}, with no end — `x` on the acl pane is what undoes it",
                self.in_front_of()
            ),
        }
    }

    /// Where a written rule lands, which is the whole of whether it works.
    fn in_front_of(&self) -> String {
        match &self.view.asked_by {
            Some(rule) => format!("at #{}, in front of `{}`", rule.index, rule.label),
            None => "at the end — the default action asked, so there is no rule to get in front of"
                .into(),
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect) -> Hits {
        let width = 76.min(area.width.saturating_sub(4));
        // The headline grows a line when it has to say how many requests this
        // one answer covers, and the box grows with it rather than pushing the
        // reassurance about the credential off the bottom.
        let repeated = u16::from(self.view.waiting > 1);
        let height = (self.reaches.len() as u16 + 15 + repeated).min(area.height);
        let popup = centred(area, width, height);

        frame.render_widget(Clear, popup);
        frame.render_widget(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                // Named, not "an agent": this dialogue can be one of several on
                // a proxy fronting a fleet, and "who is asking" is the first
                // half of the question being answered. A title that does not
                // say it makes the operator read the body to find out what they
                // are even looking at.
                .title(format!(" {} is asking ", self.view.agent_name))
                .title_bottom(format!(" waiting {}s ", self.view.waited_ms / 1000)),
            popup,
        );

        let inner = popup.inner(ratatui::layout::Margin::new(3, 1));
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4 + repeated),
                Constraint::Length(2),
                Constraint::Min(1),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(inner);

        frame.render_widget(
            Paragraph::new(self.headline()).wrap(Wrap { trim: true }),
            rows[0],
        );
        frame.render_widget(Paragraph::new(self.durations()), rows[1]);
        frame.render_widget(Paragraph::new(self.options()), rows[2]);

        let mut hits = Hits {
            popup,
            // The strip is drawn on the second of the two lines this row holds.
            durations: self.duration_hits(Rect {
                y: rows[1].y.saturating_add(1),
                height: 1,
                ..rows[1]
            }),
            // One radio per line, from the top of the options block.
            reaches: (0..self.reaches.len())
                .map(|index| {
                    (
                        Rect {
                            y: rows[2].y.saturating_add(index as u16),
                            height: 1,
                            ..rows[2]
                        },
                        index,
                    )
                })
                .collect(),
            ..Hits::default()
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::raw(""),
                Line::from(Span::styled(
                    self.consequence(),
                    Style::default().fg(Color::DarkGray),
                )),
            ])
            .wrap(Wrap { trim: true }),
            rows[3],
        );
        frame.render_widget(Paragraph::new(self.buttons()), rows[4]);

        // The button row, carved up the way `buttons()` lays it out. Widths
        // taken from the same strings, so the two cannot drift.
        let mut x = rows[4].x.saturating_add(4);
        for (label, slot) in [
            (" d  Deny    ", &mut hits.deny),
            (" a  Allow    ", &mut hits.allow),
            (" esc  leave it waiting", &mut hits.dismiss),
        ] {
            let width = label.chars().count() as u16;
            *slot = Rect {
                x,
                y: rows[4].y,
                width: width.min(rows[4].right().saturating_sub(x)),
                height: 1,
            };
            x = x.saturating_add(width);
        }

        hits
    }

    /// Where each duration segment landed, measured from the same labels the
    /// strip is drawn from.
    fn duration_hits(&self, row: Rect) -> Vec<(Rect, usize)> {
        let mut x = row.x.saturating_add(4);
        let mut hits = Vec::new();
        for (index, duration) in Duration::ALL.iter().enumerate() {
            // `format!(" {label} ")` and then a space, exactly as `durations()`.
            let width = duration.label().chars().count() as u16 + 3;
            if x >= row.right() {
                break;
            }
            hits.push((
                Rect {
                    x,
                    y: row.y,
                    width: width.min(row.right() - x),
                    height: 1,
                },
                index,
            ));
            x = x.saturating_add(width);
        }
        hits
    }

    fn headline(&self) -> Vec<Line<'_>> {
        let request = &self.view.request;
        let wants = match request.kind {
            Kind::Http => format!("{} {}", request.method, request.path),
            Kind::Mcp if request.path.is_empty() => request.method.clone(),
            Kind::Mcp => format!("{} {}", request.method, request.path),
        };

        // Said in the headline, not left to the consequence line: what is on
        // screen is one question, and an operator who reads it as one request
        // is being asked to answer for six without being told.
        let repeats = (self.view.waiting > 1).then(|| {
            Line::from(Span::styled(
                format!(
                    "{} identical requests are waiting — this answers all of them",
                    self.view.waiting
                ),
                Style::default().fg(Color::Yellow),
            ))
        });

        let mut lines = vec![
            Line::from(vec![
                Span::styled(
                    self.view.agent_name.clone(),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                // The id as well as the name: the id is what every audit record
                // and every ACL rule says, so it is what the operator will type
                // if this turns into a rule they write by hand later.
                Span::styled(
                    format!("  ({})", request.agent),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(vec![
                Span::raw("wants to "),
                Span::styled(wants, Style::default().fg(Color::Yellow)),
                Span::raw(" on "),
                Span::styled(request.target.clone(), Style::default().fg(Color::Cyan)),
            ]),
        ];
        lines.extend(repeats);
        lines.push(Line::from(Span::styled(
            "agent-iap holds the credential and attaches it on the way out — allowing this \
             does not hand it over.",
            Style::default().fg(Color::DarkGray),
        )));
        lines
    }

    fn durations(&self) -> Vec<Line<'_>> {
        let mut spans = vec![Span::raw("    ")];
        for (index, duration) in Duration::ALL.iter().enumerate() {
            let selected = index == self.duration;
            spans.push(Span::styled(
                format!(" {} ", duration.label()),
                if selected {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                },
            ));
            spans.push(Span::raw(" "));
        }
        vec![Line::raw(""), Line::from(spans)]
    }

    fn options(&self) -> Vec<Line<'_>> {
        let request = &self.view.request;
        let mut lines: Vec<Line> = self
            .reaches
            .iter()
            .enumerate()
            .map(|(index, reach)| {
                let selected = index == self.reach;
                let label = match &self.edit {
                    Some(edit) if index == self.reaches.len() - 1 => {
                        let (before, after) = edit.pattern.split_at(edit.byte_at(edit.cursor));
                        format!(
                            "→ {} {before}▏{after} on {}",
                            request.method, request.target
                        )
                    }
                    _ => reach.label.clone(),
                };
                Line::from(vec![
                    Span::raw("    "),
                    Span::styled(
                        if selected { "(•) " } else { "( ) " },
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::styled(
                        label,
                        if selected {
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::Gray)
                        },
                    ),
                ])
            })
            .collect();
        // Drawn in the one spare line the box already leaves under the rows.
        if self.has_path_row() && self.edit.is_none() {
            lines.push(Line::from(Span::styled(
                "        g/G widens or narrows the path · e types it",
                Style::default().fg(Color::DarkGray),
            )));
        }
        lines
    }

    fn buttons(&self) -> Line<'_> {
        Line::from(vec![
            Span::raw("    "),
            Span::styled(
                " d ",
                Style::default()
                    .fg(Color::White)
                    .bg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Deny    "),
            Span::styled(
                " a ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Allow    "),
            Span::styled(
                " esc ",
                Style::default().fg(Color::Black).bg(Color::DarkGray),
            ),
            Span::styled(" leave it waiting", Style::default().fg(Color::DarkGray)),
        ])
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;
    use crate::acl::AccessRequest;

    fn view(request: AccessRequest) -> PendingView {
        PendingView {
            id: "one".into(),
            summary: request.summary(),
            request,
            waited_ms: 0,
            newest_ms: 0,
            waiting: 1,
            agent_name: "Claude Code".into(),
            asked_by: None,
        }
    }

    #[test]
    fn the_cursor_starts_on_the_narrowest_grant() {
        let dialogue = Dialogue::new(view(AccessRequest::http(
            "claude",
            "github",
            "POST",
            "/repos/acme/api/issues",
        )));
        let Some(Answer::Decide {
            reach, duration, ..
        }) = ({
            let mut d = dialogue;
            d.handle(KeyEvent::from(KeyCode::Enter))
        })
        else {
            panic!("enter answers the dialogue")
        };

        assert_eq!(duration, Duration::Once, "and on the shortest duration");
        assert_eq!(reach.rule.paths, vec!["/repos/acme/api/issues"]);
        assert_eq!(reach.rule.methods, vec!["POST"]);
        assert_eq!(
            reach.scope,
            Scope::exact(
                &view(AccessRequest::http(
                    "claude",
                    "github",
                    "POST",
                    "/repos/acme/api/issues"
                ))
                .request
            )
        );
    }

    #[test]
    fn a_call_that_names_nothing_gets_no_path_scoped_row() {
        // `tools/list` has no tool name, so "this method" is already as narrow
        // as a grant goes and a fourth row would just repeat the third.
        let reaches = reaches(&view(AccessRequest::mcp(
            "claude",
            "sentry",
            "tools/list",
            "",
        )));
        assert_eq!(reaches.len(), 2);
        assert!(reaches.last().unwrap().label.contains("tools/list"));
    }

    /// The row that wrote `target = "*"`, gone. An answer given about one
    /// service is not an answer about the service enrolled tomorrow.
    #[test]
    fn no_row_offers_a_grant_over_a_service_the_request_never_named() {
        for request in [
            AccessRequest::http("claude", "github", "POST", "/repos/acme/api/issues"),
            AccessRequest::mcp("claude", "sentry", "tools/call", "create_issue"),
        ] {
            let target = request.target.clone();
            for reach in reaches(&view(request)) {
                assert_eq!(reach.rule.target, target, "{}", reach.label);
                assert_eq!(reach.scope.target.as_deref(), Some(target.as_str()));
                assert!(
                    !crate::acl::is_pattern(&reach.rule.target),
                    "a console answer may not write a rule about services that are not \
                     in the file: {}",
                    reach.label
                );
            }
        }
    }

    #[test]
    fn widening_the_scope_widens_the_rule_it_would_write() {
        let mut dialogue = Dialogue::new(view(AccessRequest::mcp(
            "claude",
            "sentry",
            "tools/call",
            "create_issue",
        )));
        dialogue.handle(KeyEvent::from(KeyCode::Up));
        dialogue.handle(KeyEvent::from(KeyCode::Up));
        let Some(Answer::Decide { reach, .. }) =
            dialogue.handle(KeyEvent::from(KeyCode::Char('a')))
        else {
            panic!("a allows")
        };

        assert_eq!(reach.rule.target, "sentry");
        assert_eq!(reach.rule.kind, "mcp");
        assert_eq!(reach.rule.methods, vec!["*"]);
        assert!(
            reach.scope.method.is_none(),
            "and forgets the method with it"
        );
    }

    fn issue_edit() -> Dialogue {
        Dialogue::new(view(AccessRequest::http(
            "claude",
            "github",
            "PATCH",
            "/repos/acme/api/issues/108",
        )))
    }

    fn press(dialogue: &mut Dialogue, keys: &str) -> Option<Answer> {
        keys.chars()
            .map(|key| dialogue.handle(KeyEvent::from(KeyCode::Char(key))))
            .last()
            .flatten()
    }

    fn allowed_reach(dialogue: &mut Dialogue) -> Reach {
        match dialogue.handle(KeyEvent::from(KeyCode::Enter)) {
            Some(Answer::Decide { reach, .. }) => *reach,
            _ => panic!("enter allows"),
        }
    }

    fn patch_rule(path: &str) -> RuleShape {
        RuleShape {
            agent: "claude".into(),
            kind: "http".into(),
            target: "github".into(),
            methods: vec!["PATCH".into()],
            paths: vec![path.into()],
        }
    }

    fn patch_scope(path_pattern: &str) -> Scope {
        Scope {
            agent: Some("claude".into()),
            kind: Some(Kind::Http),
            target: Some("github".into()),
            method: Some("PATCH".into()),
            path: None,
            path_pattern: Some(path_pattern.into()),
        }
    }

    #[test]
    fn test_generalize__when_pressed_once__should_cover_sibling_paths() {
        let mut dialogue = issue_edit();
        press(&mut dialogue, "g");
        let reach = allowed_reach(&mut dialogue);
        assert_eq!(reach.rule, patch_rule("/repos/acme/api/issues/*"));
        assert_eq!(reach.scope, patch_scope("/repos/acme/api/issues/*"));
        assert_eq!(reach.label, "→ PATCH /repos/acme/api/issues/* on github");
    }

    #[test]
    fn test_generalize__when_pressed_twice__should_cover_parent_subtree() {
        let mut dialogue = issue_edit();
        press(&mut dialogue, "gg");
        assert_eq!(
            allowed_reach(&mut dialogue).rule,
            patch_rule("/repos/acme/api/**")
        );
    }

    #[test]
    fn test_generalize__when_pressed_past_first_segment__should_stop_at_first_segment() {
        let mut dialogue = issue_edit();
        press(&mut dialogue, "gggggg");
        assert_eq!(allowed_reach(&mut dialogue).rule, patch_rule("/repos/**"));
    }

    #[test]
    fn test_generalize__when_narrowed_back__should_return_to_exact_path() {
        let mut dialogue = issue_edit();
        press(&mut dialogue, "ggGG");
        let reach = allowed_reach(&mut dialogue);
        assert_eq!(reach.rule, patch_rule("/repos/acme/api/issues/108"));
        assert_eq!(
            reach.scope,
            Scope::exact(&AccessRequest::http(
                "claude",
                "github",
                "PATCH",
                "/repos/acme/api/issues/108"
            ))
        );
    }

    #[test]
    fn test_generalize__when_cursor_is_on_wider_row__should_select_path_row() {
        let mut dialogue = issue_edit();
        dialogue.handle(KeyEvent::from(KeyCode::Up));
        press(&mut dialogue, "g");
        assert_eq!(
            allowed_reach(&mut dialogue).rule,
            patch_rule("/repos/acme/api/issues/*")
        );
    }

    #[test]
    fn test_edit__when_glob_covers_request__should_write_typed_pattern() {
        let mut dialogue = issue_edit();
        press(&mut dialogue, "e");
        for _ in "/repos/acme/api/issues/108".chars() {
            dialogue.handle(KeyEvent::from(KeyCode::Backspace));
        }
        assert!(press(&mut dialogue, "/repos/acme/*/issues/*").is_none());
        dialogue.handle(KeyEvent::from(KeyCode::Enter));
        let reach = allowed_reach(&mut dialogue);
        assert_eq!(reach.rule, patch_rule("/repos/acme/*/issues/*"));
        assert_eq!(reach.scope, patch_scope("/repos/acme/*/issues/*"));
    }

    #[test]
    fn test_edit__when_glob_misses_request__should_keep_editing_with_error() {
        let mut dialogue = issue_edit();
        press(&mut dialogue, "e");
        dialogue.handle(KeyEvent::from(KeyCode::Backspace));
        press(&mut dialogue, "9");
        assert!(dialogue.handle(KeyEvent::from(KeyCode::Enter)).is_none());
        assert_eq!(
            dialogue.edit,
            Some(Edit {
                pattern: "/repos/acme/api/issues/109".into(),
                cursor: 26,
                error: Some(
                    "`/repos/acme/api/issues/109` does not cover /repos/acme/api/issues/108, \
                     the request being answered"
                        .into()
                ),
            })
        );
    }

    #[test]
    fn test_edit__when_glob_is_invalid__should_keep_editing_with_error() {
        let mut dialogue = issue_edit();
        press(&mut dialogue, "e");
        press(&mut dialogue, "[");
        assert!(dialogue.handle(KeyEvent::from(KeyCode::Enter)).is_none());
        assert_eq!(
            dialogue.edit,
            Some(Edit {
                pattern: "/repos/acme/api/issues/108[".into(),
                cursor: 27,
                error: Some(
                    "invalid path pattern `/repos/acme/api/issues/108[`: error parsing glob '/repos/acme/api/issues/108[': \
                     unclosed character class; missing ']'"
                        .into()
                ),
            })
        );
    }

    fn press_key(dialogue: &mut Dialogue, key: KeyCode, times: usize) {
        for _ in 0..times {
            dialogue.handle(KeyEvent::from(key));
        }
    }

    #[test]
    fn test_edit__when_cursor_moved_into_middle__should_replace_segment_there() {
        let mut dialogue = issue_edit();
        press(&mut dialogue, "e");
        press_key(&mut dialogue, KeyCode::Left, "/api/issues/108".len());
        press_key(&mut dialogue, KeyCode::Backspace, "acme".len());
        press(&mut dialogue, "*");
        dialogue.handle(KeyEvent::from(KeyCode::Enter));
        assert_eq!(
            allowed_reach(&mut dialogue).rule,
            patch_rule("/repos/*/api/issues/108")
        );
    }

    #[test]
    fn test_edit__when_home_then_delete__should_remove_characters_after_cursor() {
        let mut dialogue = issue_edit();
        press(&mut dialogue, "e");
        press_key(&mut dialogue, KeyCode::Home, 1);
        press_key(&mut dialogue, KeyCode::Right, 1);
        press_key(&mut dialogue, KeyCode::Delete, "repos".len());
        press(&mut dialogue, "orgs");
        assert_eq!(
            dialogue.edit,
            Some(Edit {
                pattern: "/orgs/acme/api/issues/108".into(),
                cursor: 5,
                error: None,
            })
        );
    }

    #[test]
    fn test_edit__when_end_pressed_after_home__should_append_at_end() {
        let mut dialogue = issue_edit();
        press(&mut dialogue, "e");
        press_key(&mut dialogue, KeyCode::Home, 1);
        press_key(&mut dialogue, KeyCode::End, 1);
        press(&mut dialogue, "9");
        assert_eq!(
            dialogue.edit,
            Some(Edit {
                pattern: "/repos/acme/api/issues/1089".into(),
                cursor: 27,
                error: None,
            })
        );
    }

    #[test]
    fn test_edit__when_cursor_pushed_past_either_end__should_stop_at_that_end() {
        let mut dialogue = issue_edit();
        press(&mut dialogue, "e");
        press_key(&mut dialogue, KeyCode::Right, 3);
        press(&mut dialogue, "9");
        press_key(&mut dialogue, KeyCode::Left, 40);
        press_key(&mut dialogue, KeyCode::Backspace, 1);
        press(&mut dialogue, "x");
        assert_eq!(
            dialogue.edit,
            Some(Edit {
                pattern: "x/repos/acme/api/issues/1089".into(),
                cursor: 1,
                error: None,
            })
        );
    }

    #[test]
    fn test_edit__when_path_has_multibyte_characters__should_move_by_character() {
        let mut dialogue = Dialogue::new(view(AccessRequest::http(
            "claude", "github", "PATCH", "/café/1",
        )));
        press(&mut dialogue, "e");
        press_key(&mut dialogue, KeyCode::Left, 2);
        press(&mut dialogue, "x");
        assert_eq!(
            dialogue.edit,
            Some(Edit {
                pattern: "/caféx/1".into(),
                cursor: 6,
                error: None,
            })
        );
    }

    #[test]
    fn test_edit__when_escaped__should_keep_dialogue_open_and_path_unchanged() {
        let mut dialogue = issue_edit();
        press(&mut dialogue, "e");
        press(&mut dialogue, "ad");
        assert!(dialogue.handle(KeyEvent::from(KeyCode::Esc)).is_none());
        assert_eq!(dialogue.edit, None);
        assert_eq!(
            allowed_reach(&mut dialogue).rule,
            patch_rule("/repos/acme/api/issues/108")
        );
    }

    #[test]
    fn test_exact_row__when_request_path_holds_glob_characters__should_write_them_literally() {
        let mut dialogue = Dialogue::new(view(AccessRequest::http(
            "claude",
            "github",
            "PATCH",
            "/repos/**/a\\b/{x,y}?",
        )));
        assert_eq!(
            allowed_reach(&mut dialogue).rule,
            patch_rule("/repos/[*][*]/a\\\\b/[{]x,y[}][?]")
        );
    }

    #[test]
    fn test_generalize__when_request_path_holds_glob_characters__should_keep_them_literal() {
        let mut dialogue = Dialogue::new(view(AccessRequest::http(
            "claude",
            "github",
            "PATCH",
            "/repos/**/api/issues/108",
        )));
        press(&mut dialogue, "g");
        let reach = allowed_reach(&mut dialogue);
        assert_eq!(reach.rule, patch_rule("/repos/[*][*]/api/issues/*"));
        assert_eq!(
            [
                reach.scope.matches(&AccessRequest::http(
                    "claude",
                    "github",
                    "PATCH",
                    "/repos/**/api/issues/109"
                )),
                reach.scope.matches(&AccessRequest::http(
                    "claude",
                    "github",
                    "PATCH",
                    "/repos/acme/api/issues/109"
                )),
            ],
            [true, false]
        );
    }

    #[test]
    fn test_generalize__when_request_is_mcp_tool__should_leave_tool_name_exact() {
        let mut dialogue = Dialogue::new(view(AccessRequest::mcp(
            "claude",
            "sentry",
            "tools/call",
            "create_issue",
        )));
        press(&mut dialogue, "g");
        assert_eq!(
            allowed_reach(&mut dialogue).rule,
            RuleShape {
                agent: "claude".into(),
                kind: "mcp".into(),
                target: "sentry".into(),
                methods: vec!["tools/call".into()],
                paths: vec!["create_issue".into()],
            }
        );
    }

    #[test]
    fn escape_leaves_the_request_waiting_rather_than_answering_it() {
        let mut dialogue = Dialogue::new(view(AccessRequest::http("claude", "gh", "GET", "/x")));
        assert!(matches!(
            dialogue.handle(KeyEvent::from(KeyCode::Esc)),
            Some(Answer::Dismiss)
        ));
    }
}
