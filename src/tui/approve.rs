//! The dialogue an `ask` rule raises.
//!
//! Little Snitch's, in a terminal, and for the same reason: the question "may
//! this connect" is unanswerable on its own. What an operator can answer is
//! "may *this agent* do *this much*, for *how long*" — so the two axes that
//! made that dialogue work are the two axes here. Across the top, how long the
//! answer holds; down the middle, how far it reaches.
//!
//! The three durations are three different mechanisms, and the dialogue says
//! which: once is this request; until quit is remembered in this process and
//! dies with it; from now on is a rule written into the policy file, in front
//! of the `ask` that raised the question — appended after it, first-match-wins
//! would leave the new rule unreachable and the same question coming back.

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
    /// Everything the scope covers, until this proxy exits.
    UntilQuit,
    /// Everything the scope covers, written into the policy file.
    Forever,
}

impl Duration {
    pub const ALL: [Duration; 3] = [Duration::Once, Duration::UntilQuit, Duration::Forever];

    fn label(self) -> &'static str {
        match self {
            Duration::Once => "Once",
            Duration::UntilQuit => "Until quit",
            Duration::Forever => "From now on",
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
        match Duration::ALL[self.duration] {
            Duration::Once => "answers this one request; the next identical call asks again".into(),
            Duration::UntilQuit => format!(
                "remembered for `{}` until agent-iap exits — nothing is written to disk",
                reach.label.trim_start_matches("→ ")
            ),
            Duration::Forever => match &self.view.asked_by {
                Some(rule) => format!(
                    "writes an acl rule into the policy file at #{}, in front of `{}`",
                    rule.index, rule.label
                ),
                None => "appends an acl rule to the policy file — the default action asked, so \
                         there is no rule to get in front of"
                    .into(),
            },
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let width = 76.min(area.width.saturating_sub(4));
        let height = (self.reaches.len() as u16 + 15).min(area.height);
        let popup = centred(area, width, height);

        frame.render_widget(Clear, popup);
        frame.render_widget(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                .title(" an agent is asking ")
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
    }

    fn headline(&self) -> Vec<Line<'_>> {
        let request = &self.view.request;
        let wants = match request.kind {
            Kind::Http => format!("{} {}", request.method, request.path),
            Kind::Mcp if request.path.is_empty() => request.method.clone(),
            Kind::Mcp => format!("{} {}", request.method, request.path),
        };

        vec![
            Line::from(Span::styled(
                self.view.agent_name.clone(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )),
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
