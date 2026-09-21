//! The picker for names the policy file already holds.
//!
//! An ACL rule's `agent` and `target` are not free text in any useful sense:
//! they are the id of an enrolled agent and the name of an upstream or an MCP
//! server, both of them written down a few lines further up the same file. And
//! nothing checks them. A rule typed `github-api` against an upstream called
//! `github` is accepted, written, reloaded — and then matches nothing, so with
//! `acl_default = deny` the agent is refused by a policy that visibly contains
//! the rule that was supposed to let it through. That is the worst shape a
//! mistake can take here: silent, and indistinguishable from the policy
//! working as written.
//!
//! So the same offer the file picker makes for a path is made for a name. This
//! is a list of what the file says, not a validator: `*` and `claude-*` are
//! legal values that no list can hold, which is why the field underneath stays
//! a text field and this is only a way of filling it in.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use super::browse::{Hits, Pick};
use super::form::{centred, key_style};

/// How far `page up` and `page down` move, as in the file picker.
const PAGE: isize = 10;

/// One thing the field could be filled in with.
#[derive(Clone)]
pub struct Candidate {
    /// What goes into the field.
    pub value: String,
    /// What it is, shown beside it — a base URL, the command behind an MCP
    /// server, an agent's human name. The reason to offer a list rather than
    /// a hint that one exists: `anthropic` and `anthropic-admin` are told
    /// apart by what is next to them, not by their names.
    pub about: String,
    /// Offered only while the `Choice` field named here is on one of these
    /// options — the same rule `Field::shown_for` uses, so a rule narrowed to
    /// `kind = http` is not offered an MCP server to point at.
    pub shown_for: Option<(&'static str, Vec<String>)>,
}

impl Candidate {
    pub fn new(value: impl Into<String>, about: impl Into<String>) -> Self {
        Candidate {
            value: value.into(),
            about: about.into(),
            shown_for: None,
        }
    }

    pub fn when(mut self, field: &'static str, options: &[&str]) -> Self {
        self.shown_for = Some((field, options.iter().map(|o| o.to_string()).collect()));
        self
    }
}

pub struct Chooser {
    /// Index of the field the pick lands in. Like the file picker, this never
    /// reaches into the form: it hands a string back and the form writes it.
    pub field: usize,
    /// What is being picked, for the title — "an agent", "a target".
    what: String,
    entries: Vec<Candidate>,
    /// Indices into `entries` the typed filter leaves, in order.
    matching: Vec<usize>,
    /// Position within `matching`, not within `entries`.
    at: usize,
    filter: String,
}

impl Chooser {
    /// Open on the field at `index`, with the cursor on `held` when that is one
    /// of the names offered — so re-opening the picker lands on the choice
    /// already made rather than at the top of the list.
    pub fn open(field: usize, what: &str, entries: Vec<Candidate>, held: &str) -> Chooser {
        let mut chooser = Chooser {
            field,
            what: what.to_string(),
            entries,
            matching: Vec::new(),
            at: 0,
            filter: String::new(),
        };
        chooser.refilter();
        if let Some(at) = chooser
            .matching
            .iter()
            .position(|index| chooser.entries[*index].value == held)
        {
            chooser.at = at;
        }
        chooser
    }

    pub fn handle(&mut self, key: KeyEvent) -> Pick {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            // The filter first, then the picker — the order they were entered,
            // as in the file picker.
            KeyCode::Esc if !self.filter.is_empty() => {
                self.filter.clear();
                self.refilter();
            }
            KeyCode::Esc => return Pick::Close,
            KeyCode::Char('c') if control => return Pick::Close,
            KeyCode::Char('u') if control => {
                self.filter.clear();
                self.refilter();
            }
            KeyCode::Up => self.move_by(-1),
            KeyCode::Down => self.move_by(1),
            KeyCode::PageUp => self.move_by(-PAGE),
            KeyCode::PageDown => self.move_by(PAGE),
            KeyCode::Home => self.at = 0,
            KeyCode::End => self.at = self.matching.len().saturating_sub(1),
            KeyCode::Backspace => {
                self.filter.pop();
                self.refilter();
            }
            KeyCode::Enter | KeyCode::Right => return self.pick(),
            KeyCode::Char(c) if !control => {
                self.filter.push(c);
                self.refilter();
            }
            _ => {}
        }
        Pick::Continue
    }

    /// A click on a row. The second one picks, exactly as in the file picker
    /// and the panes behind it — one click only ever moves the cursor.
    pub fn click(&mut self, at: usize, double: bool) -> Pick {
        if at >= self.matching.len() {
            return Pick::Continue;
        }
        self.at = at;
        match double {
            true => self.pick(),
            false => Pick::Continue,
        }
    }

    /// The wheel, a notch at a time.
    pub fn scroll(&mut self, up: bool) {
        self.move_by(if up { -3 } else { 3 });
    }

    fn pick(&mut self) -> Pick {
        // Nothing under the cursor is nothing picked: a filter that matches no
        // name must not write the one that was selected before it was typed.
        match self.selected() {
            Some(entry) => Pick::Chose(entry.value.clone()),
            None => Pick::Continue,
        }
    }

    /// Narrow to the names or descriptions containing what has been typed,
    /// case insensitively. The description counts too, so `api.github.com`
    /// finds the upstream whatever it was called locally.
    fn refilter(&mut self) {
        let needle = self.filter.to_lowercase();
        self.matching = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.value.to_lowercase().contains(&needle)
                    || entry.about.to_lowercase().contains(&needle)
            })
            .map(|(index, _)| index)
            .collect();
        self.at = self.at.min(self.matching.len().saturating_sub(1));
    }

    fn move_by(&mut self, delta: isize) {
        if self.matching.is_empty() {
            return;
        }
        let last = self.matching.len() as isize - 1;
        self.at = (self.at as isize).saturating_add(delta).clamp(0, last) as usize;
    }

    fn selected(&self) -> Option<&Candidate> {
        self.entries.get(*self.matching.get(self.at)?)
    }

    pub fn render(&self, frame: &mut Frame, area: Rect) -> Hits {
        let width = 72.min(area.width.saturating_sub(4));
        // Sized to the list rather than to the screen: this is a box over a
        // form the operator is in the middle of, and every row of it they do
        // not need is a row of that form it covers up. Five for the frame,
        // the note and the key row, and one more so the last name is not
        // sitting against the note underneath it.
        let height =
            ((self.entries.len() as u16).saturating_add(6)).min(area.height.saturating_sub(2));
        let popup = centred(area, width, height);

        frame.render_widget(Clear, popup);
        frame.render_widget(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(format!(" pick {} ", self.what)),
            popup,
        );

        let inner = popup.inner(ratatui::layout::Margin::new(2, 1));
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(1),
                Constraint::Length(2),
                Constraint::Length(1),
            ])
            .split(inner);

        let mut hits = Hits {
            popup,
            rows: Vec::new(),
        };
        let window = rows[0].height as usize;
        // Centred on the cursor rather than remembered, so there is no second
        // piece of state to get out of step with a filtered listing.
        let offset = self
            .at
            .saturating_sub(window / 2)
            .min(self.matching.len().saturating_sub(window));
        let name_width = self
            .matching
            .iter()
            .map(|index| self.entries[*index].value.chars().count())
            .max()
            .unwrap_or(0)
            .min(24);

        let lines: Vec<Line> = (0..window)
            .filter_map(|row| {
                let at = offset + row;
                let entry = self.entries.get(*self.matching.get(at)?)?;
                hits.rows.push((
                    Rect {
                        y: rows[0].y.saturating_add(row as u16),
                        height: 1,
                        ..rows[0]
                    },
                    at,
                ));
                let here = at == self.at;
                let mut spans = vec![
                    Span::styled(
                        if here { "▶ " } else { "  " },
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(
                        format!("{:<name_width$}", entry.value),
                        match here {
                            true => Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                            false => Style::default().fg(Color::Gray),
                        },
                    ),
                ];
                if !entry.about.is_empty() {
                    let room = (rows[0].width as usize)
                        .saturating_sub(name_width + 4)
                        .max(1);
                    spans.push(Span::raw("  "));
                    spans.push(Span::styled(
                        clip(&entry.about, room),
                        Style::default().fg(Color::DarkGray),
                    ));
                }
                Some(Line::from(spans))
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), rows[0]);

        let status = match self.filter.is_empty() {
            false => Paragraph::new(format!(
                "filter: {}   ({} of {})",
                self.filter,
                self.matching.len(),
                self.entries.len()
            ))
            .style(Style::default().fg(Color::Yellow)),
            // Said here because it is the thing about this picker an operator
            // has to know: it is a list of what the file holds, and the field
            // it fills in will also take a glob that is not on it.
            true => Paragraph::new(
                "type to filter. The field takes a glob as well — `*`, or `claude-*` — typed \
                 straight into it rather than picked here.",
            )
            .style(Style::default().fg(Color::DarkGray)),
        };
        frame.render_widget(status.wrap(Wrap { trim: true }), rows[1]);

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" ↑/↓ ", key_style()),
                Span::raw(" move  "),
                Span::styled(" enter ", key_style()),
                Span::raw(" pick  "),
                Span::styled(" esc ", key_style()),
                Span::raw(" back"),
            ]))
            .style(Style::default().fg(Color::DarkGray)),
            rows[2],
        );

        hits
    }
}

/// Keep the start of a description that will not fit: a base URL is told from
/// another by its host, which is at the front.
fn clip(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count <= width || width == 0 {
        return text.to_string();
    }
    let kept: String = text.chars().take(width.saturating_sub(1)).collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offered() -> Vec<Candidate> {
        vec![
            Candidate::new("*", "every target"),
            Candidate::new("github", "upstream — https://api.github.com"),
            Candidate::new("anthropic", "upstream — https://api.anthropic.com"),
            Candidate::new("playwright", "mcp server — npx @playwright/mcp"),
        ]
    }

    fn typed(chooser: &mut Chooser, text: &str) {
        for c in text.chars() {
            chooser.handle(KeyEvent::from(KeyCode::Char(c)));
        }
    }

    #[test]
    fn a_pick_is_the_name_the_rule_takes() {
        let mut chooser = Chooser::open(0, "a target", offered(), "*");
        typed(&mut chooser, "playw");
        let Pick::Chose(value) = chooser.handle(KeyEvent::from(KeyCode::Enter)) else {
            panic!("`enter` picks the name under the cursor");
        };
        assert_eq!(value, "playwright");
    }

    /// Re-opening the picker on a field that already names something lands on
    /// that name — a picker that reopened at the top would make correcting one
    /// field of a rule a hunt for where you already were.
    #[test]
    fn it_opens_on_the_name_the_field_holds() {
        let chooser = Chooser::open(0, "a target", offered(), "anthropic");
        assert_eq!(
            chooser.selected().map(|entry| entry.value.clone()),
            Some("anthropic".into())
        );
    }

    #[test]
    fn the_description_is_searched_as_well_as_the_name() {
        let mut chooser = Chooser::open(0, "a target", offered(), "*");
        typed(&mut chooser, "api.github.com");
        assert_eq!(
            chooser.selected().map(|entry| entry.value.clone()),
            Some("github".into()),
            "an upstream is findable by the host it fronts"
        );
    }

    #[test]
    fn escape_leaves_the_filter_before_it_leaves_the_picker() {
        let mut chooser = Chooser::open(0, "a target", offered(), "*");
        typed(&mut chooser, "git");
        assert!(matches!(
            chooser.handle(KeyEvent::from(KeyCode::Esc)),
            Pick::Continue
        ));
        assert!(chooser.filter.is_empty());
        assert!(matches!(
            chooser.handle(KeyEvent::from(KeyCode::Esc)),
            Pick::Close
        ));
    }

    #[test]
    fn a_filter_that_matches_nothing_picks_nothing() {
        let mut chooser = Chooser::open(0, "a target", offered(), "*");
        chooser.handle(KeyEvent::from(KeyCode::End));
        typed(&mut chooser, "zzz");
        assert!(chooser.matching.is_empty());
        assert!(
            matches!(
                chooser.handle(KeyEvent::from(KeyCode::Enter)),
                Pick::Continue
            ),
            "`enter` on nothing must not write the name that used to be selected"
        );
    }
}
