//! The read-only half of the console: what this proxy is holding.
//!
//! Every table here is built from `list::Inventory`, the same structure
//! `agent-iap list` prints. The console is a second front end onto that answer,
//! not a second answer — a row that reads differently in the two would be a
//! reason to distrust both.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, HighlightSpacing, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use crate::config::Action;
use crate::list::Inventory;
use crate::profiles::Profile;

/// A credential reference and whether it currently resolves.
///
/// The status is the reason this pane exists rather than a `grep` of the file:
/// a reference that stopped resolving — a vault locked, a variable unset, a
/// file moved — is a service that will 502 on its next call, and the file looks
/// exactly the same either way.
pub struct CredentialStatus {
    pub owner: String,
    pub field: String,
    pub reference: String,
    /// `Ok` once it has been checked; `Err` with the reason; `None` unchecked.
    pub resolves: Option<Result<(), String>>,
}

/// What marks the selected row. Every other row, and the header, is indented
/// by the same amount so the columns do not jump when the cursor moves.
const CURSOR: &str = "▶ ";

pub struct Row {
    pub cells: Vec<String>,
    pub accent: Option<Color>,
}

impl Row {
    fn new<I: Into<String>>(cells: impl IntoIterator<Item = I>) -> Self {
        Row {
            cells: cells.into_iter().map(Into::into).collect(),
            accent: None,
        }
    }

    fn accented<I: Into<String>>(cells: impl IntoIterator<Item = I>, accent: Color) -> Self {
        Row {
            accent: Some(accent),
            ..Row::new(cells)
        }
    }
}

pub struct Table {
    pub headers: Vec<&'static str>,
    pub rows: Vec<Row>,
    /// Shown instead of the table when there is nothing in it. A blank pane
    /// reads as a broken one, and "none yet, press n" is the next instruction.
    pub empty: &'static str,
}

impl Table {
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, title: &str, state: &mut ListState) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {title} ({}) ", self.rows.len()));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        if self.rows.is_empty() {
            frame.render_widget(
                Paragraph::new(self.empty).style(Style::default().fg(Color::DarkGray)),
                inner,
            );
            return;
        }

        // The header belongs over its columns, not on the border: a heading a
        // row's width away from the value it names is worse than none.
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(0)])
            .split(inner);

        let widths = self.widths();
        frame.render_widget(Paragraph::new(self.line(&widths, None)), split[0]);

        let items: Vec<ListItem> = self
            .rows
            .iter()
            .map(|row| ListItem::new(self.line(&widths, Some(row))))
            .collect();

        frame.render_stateful_widget(
            List::new(items)
                .highlight_style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol(CURSOR)
                // Reserved whether or not anything is selected, so the columns
                // do not shift sideways the first time the cursor appears.
                .highlight_spacing(HighlightSpacing::Always),
            split[1],
            state,
        );
    }

    /// One row, or the header when there is no row — laid out on the same
    /// column stops. The header carries the cursor's own indent, which the list
    /// adds to every row for itself.
    fn line(&self, widths: &[usize], row: Option<&Row>) -> Line<'static> {
        let mut spans = match row {
            None => vec![Span::raw(" ".repeat(CURSOR.chars().count()))],
            Some(_) => Vec::new(),
        };
        for (column, header) in self.headers.iter().enumerate() {
            let (text, style) = match row {
                None => (
                    (*header).to_string(),
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                ),
                Some(row) => {
                    let base = Style::default().fg(row.accent.unwrap_or(Color::Gray));
                    (
                        row.cells.get(column).cloned().unwrap_or_default(),
                        // The first column names the thing, so it is what the
                        // eye should land on.
                        if column == 0 {
                            base.add_modifier(Modifier::BOLD)
                        } else {
                            base
                        },
                    )
                }
            };
            spans.push(Span::styled(pad(&text, widths[column]), style));
        }
        Line::from(spans)
    }

    fn widths(&self) -> Vec<usize> {
        (0..self.headers.len())
            .map(|column| {
                self.rows
                    .iter()
                    .filter_map(|row| row.cells.get(column))
                    .map(|cell| cell.chars().count())
                    .chain(std::iter::once(self.headers[column].len()))
                    .max()
                    .unwrap_or(0)
            })
            .collect()
    }
}

fn pad(value: &str, width: usize) -> String {
    let mut padded = value.to_string();
    let len = value.chars().count();
    padded.extend(std::iter::repeat_n(' ', width.saturating_sub(len) + 2));
    padded
}

fn joined(values: &[String], empty: &str) -> String {
    if values.is_empty() {
        empty.to_string()
    } else {
        values.join(", ")
    }
}

pub fn agents(inventory: &Inventory) -> Table {
    Table {
        headers: vec!["ID", "NAME", "TARGETS", "TOKEN"],
        rows: inventory
            .agents
            .iter()
            .flatten()
            .map(|agent| {
                Row::new([
                    agent.id.clone(),
                    agent.name.clone(),
                    joined(&agent.targets, "any"),
                    agent.token.clone(),
                ])
            })
            .collect(),
        empty: "No agents enrolled.\n\nPress `n` to mint a token for one.",
    }
}

pub fn upstreams(inventory: &Inventory) -> Table {
    Table {
        headers: vec!["NAME", "BASE URL", "AUTH", "CREDENTIAL"],
        rows: inventory
            .upstreams
            .iter()
            .flatten()
            .map(|upstream| {
                Row::new([
                    upstream.name.clone(),
                    upstream.base_url.clone(),
                    upstream.auth.clone(),
                    joined(&upstream.credentials, "—"),
                ])
            })
            .collect(),
        empty: "No upstreams.\n\nPress `n` to front an API, or pick one off the profiles pane.",
    }
}

pub fn mcp_servers(inventory: &Inventory) -> Table {
    Table {
        headers: vec!["NAME", "TRANSPORT", "COMMAND OR URL", "CREDENTIALS"],
        rows: inventory
            .mcp_servers
            .iter()
            .flatten()
            .map(|server| {
                Row::new([
                    server.name.clone(),
                    server.transport.clone(),
                    server.endpoint.clone(),
                    joined(&server.credentials, "—"),
                ])
            })
            .collect(),
        empty: "No MCP servers.\n\nPress `n` to add one, or pick one off the profiles pane.",
    }
}

pub fn acl(inventory: &Inventory) -> Table {
    Table {
        headers: vec![
            "#", "NAME", "AGENT", "KIND", "TARGET", "METHODS", "PATHS", "ACTION", "EXPIRES",
        ],
        rows: inventory
            .acl
            .iter()
            .flatten()
            .map(|rule| {
                let expires = rule.expires_in.clone();
                // A rule whose deadline has passed is still in the file and
                // still numbered, because the numbering is what `x` takes — but
                // it decides nothing, and colouring it as though it did is the
                // console telling the operator something untrue.
                let spent = expires.as_deref() == Some("expired");
                Row::accented(
                    [
                        rule.index.to_string(),
                        rule.name.clone(),
                        rule.agent.clone(),
                        rule.kind.clone(),
                        rule.target.clone(),
                        rule.methods.join(","),
                        rule.paths.join(","),
                        rule.action.to_string(),
                        expires.unwrap_or_else(|| "—".into()),
                    ],
                    if spent {
                        Color::DarkGray
                    } else {
                        action_colour(rule.action)
                    },
                )
            })
            .collect(),
        empty: "No rules — everything falls through to the default.\n\nPress `n` to add one.",
    }
}

pub fn action_colour(action: Action) -> Color {
    match action {
        Action::Allow => Color::Green,
        Action::Deny => Color::Red,
        Action::Ask => Color::Yellow,
    }
}

pub fn credentials(rows: &[CredentialStatus]) -> Table {
    Table {
        headers: vec!["HOLDER", "FIELD", "REFERENCE", "RESOLVES"],
        rows: rows
            .iter()
            .map(|row| {
                let (status, accent) = match &row.resolves {
                    None => ("not checked".to_string(), Color::DarkGray),
                    Some(Ok(())) => ("yes".to_string(), Color::Green),
                    Some(Err(error)) => (error.clone(), Color::Red),
                };
                Row::accented(
                    [
                        row.owner.clone(),
                        row.field.clone(),
                        row.reference.clone(),
                        status,
                    ],
                    accent,
                )
            })
            .collect(),
        empty:
            "No credentials in the policy file.\n\nAdd an upstream or an MCP server that needs one.",
    }
}

pub fn profiles(catalogue: &[Profile]) -> Table {
    Table {
        headers: vec!["ID", "VENDOR", "KIND", "ENDPOINT", "ACCESS"],
        rows: catalogue
            .iter()
            .map(|profile| {
                Row::new([
                    profile.id.clone(),
                    profile.vendor.clone(),
                    profile.service.kind().to_string(),
                    profile.endpoint(),
                    profile
                        .access
                        .iter()
                        .map(|level| level.name.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ])
            })
            .collect(),
        empty: "No profiles.",
    }
}
