//! The profile picker: the whole catalog, on the whole screen.
//!
//! Picking a profile is the first decision the upstream form asks for and the
//! one that decides every field under it, and it used to be a `◂ … ▸` strip
//! cycled one entry at a time. That works for the four options of a credential
//! scheme. It does not work for a catalog approaching sixty entries, where
//! reaching `stripe` means pressing `→` fifty times past every Cloudflare MCP
//! server, reading each one as it goes by, with no way to see what else is on
//! the list and no way to jump. An operator who could not face that typed the
//! base URL out by hand instead — which is exactly the mistake profiles exist
//! to prevent, arrived at through the affordance meant to prevent it.
//!
//! So this is the list, drawn on the whole terminal rather than in a box over
//! the form: at that size the entire catalog is on screen at once, which is
//! what makes "what is in here?" a question the picker answers by being open.
//!
//! **Typing narrows by what things are called, not by what they contain.** `s`
//! leaves `semrush`, `sentry`, `slack`, `spotify`, `stripe` and Google's
//! *Search* Console — every profile filed under `s` — rather than the forty
//! whose description happens to contain the letter. A needle matches at the
//! start of a word: the id, each `-` separated part of it, and each word of
//! the vendor and title. `mcp` therefore finds every `*-mcp` profile and
//! `analytics` finds the two GA ones. Only when that finds nothing at all does
//! it fall back to looking anywhere in the text, so nothing is unreachable —
//! but the common case, one letter, answers with the letter's own section.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use super::browse::{Hits, Pick};
use super::form::key_style;

/// How far `page up` and `page down` move, as in every other picker here.
const PAGE: isize = 10;

/// One profile as the picker shows it.
///
/// Flattened out of `profiles::Profile` on the way in rather than borrowed:
/// the picker is a list of rows and a filter over their text, and giving it
/// the catalog type would give it opinions about access levels and credential
/// schemes it has no business holding.
#[derive(Clone)]
pub struct Entry {
    /// What goes into the field, and what the form is rebuilt from.
    pub value: String,
    pub title: String,
    pub vendor: String,
    /// `http` or `mcp`, for a catalog that holds both.
    pub kind: String,
    /// Base URL, remote MCP URL, or the command a stdio server spawns.
    pub endpoint: String,
    pub summary: String,
    /// The "no profile, spell it out" row. Always first, and off the list the
    /// moment anything is typed: it answers no search, and leaving it in one
    /// would put "write the base URL by hand" under a cursor that was aiming
    /// at a profile.
    pub none: bool,
}

impl Entry {
    /// The row that declines the catalog. `value` is what the form reads back.
    pub fn none(value: &str) -> Entry {
        Entry {
            value: value.to_string(),
            title: "spell the service out below".into(),
            vendor: String::new(),
            kind: String::new(),
            endpoint: String::new(),
            summary: "base URL, credential scheme and ACL paths typed by hand".into(),
            none: true,
        }
    }
}

/// How well an entry answers what was typed. The order is the order they are
/// listed in, so the profile whose *name* starts with `s` sits above the one
/// that merely has a word starting with `s` in its title.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum Rank {
    /// The id itself starts with it: `s` → `semrush`.
    Name,
    /// A word of the id, vendor or title does: `s` → Google *Search* Console.
    Word,
    /// Only the fallback pass found it, anywhere in any of the text.
    Anywhere,
}

pub struct Catalogue {
    /// Index of the field the pick lands in. Like every picker here, this
    /// never reaches into the form: it hands a string back and the form
    /// writes it.
    pub field: usize,
    entries: Vec<Entry>,
    /// Indices into `entries` the filter leaves, best match first.
    matching: Vec<usize>,
    /// Position within `matching`, not within `entries`.
    at: usize,
    filter: String,
}

impl Catalogue {
    /// Open on the field at `index`, with the cursor on the profile it already
    /// names — so re-opening the picker lands on the choice already made.
    pub fn open(field: usize, entries: Vec<Entry>, held: &str) -> Catalogue {
        let mut catalogue = Catalogue {
            field,
            entries,
            matching: Vec::new(),
            at: 0,
            filter: String::new(),
        };
        catalogue.refilter();
        if let Some(at) = catalogue
            .matching
            .iter()
            .position(|index| catalogue.entries[*index].value == held)
        {
            catalogue.at = at;
        }
        catalogue
    }

    pub fn handle(&mut self, key: KeyEvent) -> Pick {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            // Two things to leave, in the order they were entered: what was
            // typed first, then the picker. A letter pressed in a long list
            // should not cost the form its place as well.
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

    /// A click on a row. The second one picks, as everywhere else here — one
    /// click only ever moves the cursor.
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

    pub fn scroll(&mut self, up: bool) {
        self.move_by(if up { -3 } else { 3 });
    }

    fn pick(&mut self) -> Pick {
        // Nothing under the cursor is nothing picked: a filter that matches no
        // profile must not write the one that was selected before it was typed.
        match self.selected() {
            Some(entry) => Pick::Chose(entry.value.clone()),
            None => Pick::Continue,
        }
    }

    /// Re-run the filter, keeping the cursor on whatever it was on when that
    /// entry survives. Typing a second letter of a name you are already on
    /// should narrow the list around you, not send you back to the top of it.
    fn refilter(&mut self) {
        let held = self.selected().map(|entry| entry.value.clone());
        let needle = self.filter.trim().to_lowercase();

        let mut ranked: Vec<(Rank, usize)> = Vec::new();
        if needle.is_empty() {
            ranked = (0..self.entries.len())
                .map(|index| (Rank::Name, index))
                .collect();
        } else {
            for (index, entry) in self.entries.iter().enumerate() {
                if entry.none {
                    continue;
                }
                if let Some(rank) = rank(entry, &needle) {
                    ranked.push((rank, index));
                }
            }
            // Nothing is called this, so look inside everything — a summary is
            // the only place `sitemap` or `logpush` is written down, and a
            // picker that answers a real word with an empty screen teaches its
            // operator that the search does not work.
            if ranked.is_empty() {
                for (index, entry) in self.entries.iter().enumerate() {
                    if !entry.none && haystack(entry).contains(&needle) {
                        ranked.push((Rank::Anywhere, index));
                    }
                }
            }
        }
        // Stable, so the catalog's own order — which is alphabetical by id —
        // decides within a rank.
        ranked.sort_by_key(|(rank, _)| *rank);
        self.matching = ranked.into_iter().map(|(_, index)| index).collect();

        self.at = held
            .and_then(|value| {
                self.matching
                    .iter()
                    .position(|index| self.entries[*index].value == value)
            })
            .unwrap_or(0)
            .min(self.matching.len().saturating_sub(1));
    }

    fn move_by(&mut self, delta: isize) {
        if self.matching.is_empty() {
            return;
        }
        let last = self.matching.len() as isize - 1;
        self.at = (self.at as isize).saturating_add(delta).clamp(0, last) as usize;
    }

    fn selected(&self) -> Option<&Entry> {
        self.entries.get(*self.matching.get(self.at)?)
    }

    pub fn render(&self, frame: &mut Frame, area: Rect) -> Hits {
        // The whole terminal. Every other picker here is a box over the form
        // because it is filling in one field of it; this one replaces the form
        // — nothing under it is still true once a profile is chosen — and the
        // size is the feature: sixty entries on screen at once is the
        // difference between a list you search and a list you read.
        frame.render_widget(Clear, area);
        frame.render_widget(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" pick a profile ")
                // Profiles, both sides — the row that declines the catalog is
                // not one of them, and counting it would make an untouched
                // picker report one more profile than the catalog has.
                .title_bottom(format!(
                    " {} of {} ",
                    self.matching
                        .iter()
                        .filter(|index| !self.entries[**index].none)
                        .count(),
                    self.entries.iter().filter(|entry| !entry.none).count()
                )),
            area,
        );

        let inner = area.inner(ratatui::layout::Margin::new(2, 1));
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(1),
                Constraint::Length(2),
                Constraint::Length(1),
            ])
            .split(inner);

        frame.render_widget(
            Paragraph::new(match self.filter.is_empty() {
                true => Line::from(vec![
                    Span::styled("search: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        "type a name — one letter is enough",
                        Style::default().fg(Color::DarkGray),
                    ),
                ]),
                false => Line::from(vec![
                    Span::styled("search: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{}▏", self.filter),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
            }),
            rows[0],
        );

        let mut hits = Hits {
            popup: area,
            rows: Vec::new(),
        };
        let window = rows[1].height as usize;
        // Centred on the cursor rather than remembered, so there is no second
        // piece of state to get out of step with a narrowed listing.
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
            .clamp(8, 32);
        let vendor_width = self
            .matching
            .iter()
            .map(|index| self.entries[*index].vendor.chars().count())
            .max()
            .unwrap_or(0)
            .min(14);

        let lines: Vec<Line> = (0..window)
            .filter_map(|row| {
                let at = offset + row;
                let index = *self.matching.get(at)?;
                let entry = self.entries.get(index)?;
                hits.rows.push((
                    Rect {
                        y: rows[1].y.saturating_add(row as u16),
                        height: 1,
                        ..rows[1]
                    },
                    at,
                ));
                let here = at == self.at;
                // The initial, once per run of names that share it. The list is
                // alphabetical, so this is the section heading `s` takes you to
                // — drawn in the gutter rather than on a row of its own, since
                // a heading row is a row the cursor has to skip over.
                let initial = match self.initial_here(at) {
                    Some(letter) => letter.to_uppercase().to_string(),
                    None => " ".into(),
                };
                let mut spans = vec![
                    Span::styled(initial, Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        if here { " ▶ " } else { "   " },
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(
                        format!("{:<name_width$}", clip(&entry.value, name_width)),
                        match (here, entry.none) {
                            (true, _) => Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                            (false, true) => Style::default().fg(Color::DarkGray),
                            (false, false) => Style::default().fg(Color::Gray),
                        },
                    ),
                    Span::raw("  "),
                    Span::styled(
                        format!("{:<vendor_width$}", clip(&entry.vendor, vendor_width)),
                        Style::default().fg(Color::DarkGray),
                    ),
                ];
                // `mcp` is called out because it is the one thing on this row
                // that changes what the entry *is* rather than what it fronts.
                if entry.kind == "mcp" {
                    spans.push(Span::styled("  mcp ", Style::default().fg(Color::Magenta)));
                } else {
                    spans.push(Span::raw("      "));
                }
                let used: usize = spans.iter().map(|span| span.content.chars().count()).sum();
                let room = (rows[1].width as usize).saturating_sub(used + 2).max(1);
                spans.push(Span::raw("  "));
                spans.push(Span::styled(
                    clip(&entry.title, room),
                    match here {
                        true => Style::default().fg(Color::Gray),
                        false => Style::default().fg(Color::DarkGray),
                    },
                ));
                Some(Line::from(spans))
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), rows[1]);

        // What the cursor is on, spelled out: the row above holds a title and
        // this is where the endpoint and the sentence about it go, so a wide
        // list stays readable and the thing being chosen is still described.
        let about = match self.selected() {
            Some(entry) if entry.none => {
                Paragraph::new(entry.summary.clone()).style(Style::default().fg(Color::DarkGray))
            }
            Some(entry) => Paragraph::new(Line::from(vec![
                Span::styled(entry.endpoint.clone(), Style::default().fg(Color::Cyan)),
                Span::raw("  "),
                Span::styled(entry.summary.clone(), Style::default().fg(Color::DarkGray)),
            ])),
            None => Paragraph::new(format!(
                "nothing is called `{}` — `esc` clears it, or keep typing",
                self.filter
            ))
            .style(Style::default().fg(Color::Yellow)),
        };
        frame.render_widget(about.wrap(Wrap { trim: true }), rows[2]);

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" ↑/↓ ", key_style()),
                Span::raw(" move  "),
                Span::styled(" a–z ", key_style()),
                Span::raw(" narrow  "),
                Span::styled(" enter ", key_style()),
                Span::raw(" pick  "),
                Span::styled(" esc ", key_style()),
                Span::raw(match self.filter.is_empty() {
                    true => " back to the form",
                    false => " clear what was typed",
                }),
            ]))
            .style(Style::default().fg(Color::DarkGray)),
            rows[3],
        );

        hits
    }

    /// The initial to draw in the gutter at `at`, or `None` where the row above
    /// already carries it.
    fn initial_here(&self, at: usize) -> Option<char> {
        let letter = self
            .entries
            .get(*self.matching.get(at)?)
            .filter(|entry| !entry.none)?
            .value
            .chars()
            .next()?;
        let above = at
            .checked_sub(1)
            .and_then(|above| self.matching.get(above))
            .and_then(|index| self.entries.get(*index))
            .filter(|entry| !entry.none)
            .and_then(|entry| entry.value.chars().next());
        (above != Some(letter)).then_some(letter)
    }
}

/// Everything about an entry that a fallback search looks through.
fn haystack(entry: &Entry) -> String {
    format!(
        "{} {} {} {} {}",
        entry.value, entry.title, entry.vendor, entry.endpoint, entry.summary
    )
    .to_lowercase()
}

/// How well `entry` answers `needle`, or `None` when no word of it starts with
/// the needle.
fn rank(entry: &Entry, needle: &str) -> Option<Rank> {
    if entry.value.to_lowercase().starts_with(needle) {
        return Some(Rank::Name);
    }
    let named = format!("{} {} {}", entry.value, entry.vendor, entry.title).to_lowercase();
    let matched = words(&named).any(|word| word.starts_with(needle));
    matched.then_some(Rank::Word)
}

/// The words of a name, splitting on what separates words in an id as well as
/// in a sentence: `semrush-mcp` is two, and so is `Search Console`.
fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
}

/// Keep the start of something that will not fit — a name is told from another
/// by its beginning.
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

    const NONE: &str = "— none: spell it out below —";

    fn entry(value: &str, vendor: &str, title: &str, summary: &str) -> Entry {
        Entry {
            value: value.into(),
            title: title.into(),
            vendor: vendor.into(),
            kind: "http".into(),
            endpoint: format!("https://api.{value}.example"),
            summary: summary.into(),
            none: false,
        }
    }

    /// A slice of the real catalog, in the order `profiles::catalog` hands it
    /// over: alphabetical by id.
    fn catalogue() -> Vec<Entry> {
        vec![
            Entry::none(NONE),
            entry(
                "anthropic",
                "Anthropic",
                "Anthropic API",
                "Messages and models.",
            ),
            entry(
                "cloudflare",
                "Cloudflare",
                "Cloudflare API",
                "The client/v4 surface.",
            ),
            entry(
                "google-analytics-data",
                "Google",
                "Google Analytics 4 — Data API",
                "runReport and the rest.",
            ),
            entry(
                "google-search-console",
                "Google",
                "Google Search Console",
                "Search analytics and sitemaps.",
            ),
            entry(
                "semrush",
                "Semrush",
                "Semrush Analytics v3",
                "Domain and keyword reports.",
            ),
            entry(
                "semrush-mcp",
                "Semrush",
                "Semrush MCP",
                "The same reports as tools.",
            ),
            entry(
                "sentry",
                "Sentry",
                "Sentry API",
                "Issues, events and releases.",
            ),
            entry("slack", "Slack", "Slack Web API", "Post messages."),
            entry(
                "spotify",
                "Spotify",
                "Spotify Web API",
                "The public catalogue.",
            ),
            entry("stripe", "Stripe", "Stripe API", "Customers and invoices."),
        ]
    }

    fn typed(picker: &mut Catalogue, text: &str) {
        for c in text.chars() {
            picker.handle(KeyEvent::from(KeyCode::Char(c)));
        }
    }

    fn listed(picker: &Catalogue) -> Vec<String> {
        picker
            .matching
            .iter()
            .map(|index| picker.entries[*index].value.clone())
            .collect()
    }

    /// The whole point of the change: one letter is the letter's own section,
    /// and nothing else. `anthropic` contains an `s`; it must not be here.
    #[test]
    fn a_letter_brings_up_the_profiles_filed_under_it() {
        let mut picker = Catalogue::open(0, catalogue(), NONE);
        typed(&mut picker, "s");
        assert_eq!(
            listed(&picker),
            vec![
                "semrush",
                "semrush-mcp",
                "sentry",
                "slack",
                "spotify",
                "stripe",
                // Filed under `s` by its title rather than its id, and so
                // listed under the ones whose name starts with it.
                "google-search-console",
            ]
        );
    }

    /// An id's parts are words too, which is what makes the MCP profiles
    /// reachable as a group — they are spread through an alphabetical list.
    #[test]
    fn a_word_inside_an_id_is_searchable() {
        let mut picker = Catalogue::open(0, catalogue(), NONE);
        typed(&mut picker, "mcp");
        assert_eq!(listed(&picker), vec!["semrush-mcp"]);
    }

    /// Nothing is *called* `sitemaps`, so rather than an empty screen the
    /// search looks inside the descriptions — but only then.
    #[test]
    fn a_needle_that_names_nothing_falls_back_to_the_descriptions() {
        let mut picker = Catalogue::open(0, catalogue(), NONE);
        typed(&mut picker, "sitemaps");
        assert_eq!(listed(&picker), vec!["google-search-console"]);
    }

    #[test]
    fn a_pick_is_the_profile_the_form_is_rebuilt_from() {
        let mut picker = Catalogue::open(0, catalogue(), NONE);
        typed(&mut picker, "spo");
        let Pick::Chose(value) = picker.handle(KeyEvent::from(KeyCode::Enter)) else {
            panic!("`enter` picks the profile under the cursor");
        };
        assert_eq!(value, "spotify");
    }

    /// Re-opening on a form that already names a profile lands on it, so
    /// correcting one field is not a hunt for where you already were.
    #[test]
    fn it_opens_on_the_profile_the_form_holds() {
        let picker = Catalogue::open(0, catalogue(), "sentry");
        assert_eq!(
            picker.selected().map(|entry| entry.value.clone()),
            Some("sentry".into())
        );
    }

    /// Narrowing around the cursor rather than resetting it: `s` then `e` then
    /// `n` should be walking towards `sentry`, not back to the top each time.
    #[test]
    fn narrowing_keeps_the_cursor_on_the_entry_it_was_on() {
        let mut picker = Catalogue::open(0, catalogue(), NONE);
        typed(&mut picker, "sen");
        assert_eq!(
            picker.selected().map(|entry| entry.value.clone()),
            Some("sentry".into())
        );
        picker.handle(KeyEvent::from(KeyCode::Backspace));
        assert_eq!(
            picker.selected().map(|entry| entry.value.clone()),
            Some("sentry".into()),
            "widening the search should not move the cursor off what it was on"
        );
    }

    /// "Spell it out by hand" is not a search result. It is the row you land
    /// on before searching and the one `esc` brings back.
    #[test]
    fn the_hand_written_row_is_never_a_match() {
        let mut picker = Catalogue::open(0, catalogue(), NONE);
        assert_eq!(listed(&picker).first().map(String::as_str), Some(NONE));
        typed(&mut picker, "s");
        assert!(!listed(&picker).contains(&NONE.to_string()));
        picker.handle(KeyEvent::from(KeyCode::Esc));
        assert_eq!(listed(&picker).first().map(String::as_str), Some(NONE));
    }

    #[test]
    fn escape_clears_what_was_typed_before_it_leaves_the_picker() {
        let mut picker = Catalogue::open(0, catalogue(), NONE);
        typed(&mut picker, "spo");
        assert!(matches!(
            picker.handle(KeyEvent::from(KeyCode::Esc)),
            Pick::Continue
        ));
        assert!(picker.filter.is_empty());
        assert!(matches!(
            picker.handle(KeyEvent::from(KeyCode::Esc)),
            Pick::Close
        ));
    }

    #[test]
    fn a_search_that_matches_nothing_picks_nothing() {
        let mut picker = Catalogue::open(0, catalogue(), NONE);
        picker.handle(KeyEvent::from(KeyCode::End));
        typed(&mut picker, "zzzz");
        assert!(picker.matching.is_empty());
        assert!(
            matches!(
                picker.handle(KeyEvent::from(KeyCode::Enter)),
                Pick::Continue
            ),
            "`enter` on nothing must not write the profile that used to be selected"
        );
    }

    /// The count is profiles, both sides. Counting the row that declines the
    /// catalog would have an untouched picker report one more profile than
    /// the catalog holds.
    #[test]
    fn the_count_is_profiles_rather_than_rows() {
        let picker = Catalogue::open(0, catalogue(), NONE);
        let profiles = catalogue().iter().filter(|entry| !entry.none).count();
        assert_eq!(
            picker.matching.len(),
            profiles + 1,
            "the none row is listed"
        );
        let frame = drawn(&picker, 100, 24);
        assert!(
            frame.contains(&format!(" {profiles} of {profiles} ")),
            "{frame}"
        );
    }

    /// Everything the picker draws has to survive a terminal, so the render
    /// runs rather than being reasoned about.
    fn drawn(picker: &Catalogue, width: u16, height: u16) -> String {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| {
                picker.render(frame, frame.area());
            })
            .unwrap();
        format!("{}", terminal.backend())
    }

    /// The gutter carries the initial once per run, which is what makes an
    /// alphabetical list read as sections rather than as sixty rows.
    #[test]
    fn the_initial_is_drawn_once_per_run_of_names() {
        let picker = Catalogue::open(0, catalogue(), NONE);
        let listed = listed(&picker);
        let semrush = listed.iter().position(|value| value == "semrush").unwrap();
        assert_eq!(picker.initial_here(semrush), Some('s'));
        assert_eq!(
            picker.initial_here(semrush + 1),
            None,
            "`semrush-mcp` is under the same letter as the row above it"
        );
    }
}
