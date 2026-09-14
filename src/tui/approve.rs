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
pub fn reaches(view: &PendingView) -> Vec<Reach> {
    let request = &view.request;
    let agent = request.agent.clone();
    let kind = request.kind.as_str().to_string();
    let target = request.target.clone();
    let method = request.method.clone();

    let mut reaches = vec![
        Reach {
            label: format!("any request from {}", view.agent_name),
            scope: Scope {
                agent: Some(agent.clone()),
                ..Scope::default()
            },
            rule: RuleShape {
                agent: agent.clone(),
                kind: "*".into(),
                target: "*".into(),
                methods: vec!["*".into()],
                paths: vec!["**".into()],
            },
        },
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
        reaches.push(Reach {
            label: format!("→ {method} {} on {target}", request.path),
            scope: Scope::exact(request),
            rule: RuleShape {
                agent,
                kind,
                target,
                methods: vec![method],
                paths: vec![request.path.clone()],
            },
        });
    }

    reaches
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
            view,
        }
    }

    pub fn handle(&mut self, key: KeyEvent) -> Option<Answer> {
        match key.code {
            KeyCode::Esc => return Some(Answer::Dismiss),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Some(Answer::Dismiss)
            }
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
        let reach = &self.reaches[self.reach];
        let duration = Duration::ALL[self.duration];
        match duration {
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
        let height = (self.reaches.len() as u16 + 15).min(area.height);
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
                Constraint::Length(4),
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

        vec![
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
            Line::from(Span::styled(
                "agent-iap holds the credential and attaches it on the way out — allowing this \
                 does not hand it over.",
                Style::default().fg(Color::DarkGray),
            )),
        ]
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
        self.reaches
            .iter()
            .enumerate()
            .map(|(index, reach)| {
                let selected = index == self.reach;
                Line::from(vec![
                    Span::raw("    "),
                    Span::styled(
                        if selected { "(•) " } else { "( ) " },
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::styled(
                        reach.label.clone(),
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
            .collect()
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
mod tests {
    use super::*;
    use crate::acl::AccessRequest;

    fn view(request: AccessRequest) -> PendingView {
        PendingView {
            id: "one".into(),
            summary: request.summary(),
            request,
            waited_ms: 0,
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
        assert_eq!(reaches.len(), 3);
        assert!(reaches.last().unwrap().label.contains("tools/list"));
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

    #[test]
    fn escape_leaves_the_request_waiting_rather_than_answering_it() {
        let mut dialogue = Dialogue::new(view(AccessRequest::http("claude", "gh", "GET", "/x")));
        assert!(matches!(
            dialogue.handle(KeyEvent::from(KeyCode::Esc)),
            Some(Answer::Dismiss)
        ));
    }
}
