//! The file picker.
//!
//! `file:/run/secrets/anthropic` is a path typed from memory into a form that
//! cannot check it: nothing resolves a credential reference until the proxy
//! does, so a transposed character is a service that enrols cleanly and 502s
//! on its first call. Every field that takes a reference therefore also opens
//! here, and a file picked off the filesystem is a path that exists.
//!
//! It lists what is there and nothing else. No preview, no peeking at the
//! first line to tell two keys apart — the file it is pointed at holds a
//! credential, and the console spends every other modal keeping those off the
//! terminal.

use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use super::form::{centred, key_style};

/// How far `page up` and `page down` move. A screenful would need the height,
/// which is a thing only `render` knows.
const PAGE: isize = 10;

/// One row of the listing.
struct Entry {
    name: String,
    path: PathBuf,
    dir: bool,
}

/// What the form should do with the picker after a keystroke.
pub enum Pick {
    Continue,
    /// Closed without picking. The field keeps whatever it already held.
    Close,
    /// The reference to write into the field.
    Chose(String),
}

pub struct Browser {
    /// Index of the field the pick lands in. The picker never reaches into
    /// the form: it hands a string back and the form writes it.
    pub field: usize,
    dir: PathBuf,
    entries: Vec<Entry>,
    /// Indices into `entries` the typed filter leaves, in order.
    matching: Vec<usize>,
    /// Position within `matching`, not within `entries`.
    at: usize,
    filter: String,
    /// A directory that would not open. Reported in place rather than thrown,
    /// because the common cause — `/root`, another user's `~/.ssh` — is a
    /// wrong turn while navigating, not a reason to lose the form.
    error: Option<String>,
}

impl Browser {
    /// Open on the field at `index`, which currently holds `value`.
    pub fn open(field: usize, value: &str) -> Browser {
        let start = start_at(value);
        let mut browser = Browser {
            field,
            dir: start.clone(),
            entries: Vec::new(),
            matching: Vec::new(),
            at: 0,
            filter: String::new(),
            error: None,
        };
        browser.go(start);
        browser
    }

    pub fn handle(&mut self, key: KeyEvent) -> Pick {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            // Two things to leave, in the order they were entered: the filter
            // first, then the picker. Four letters typed into a long directory
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
            KeyCode::Left => self.up(),
            // Backspace is the filter's while there is a filter, and the way
            // back out of a directory once there is not.
            KeyCode::Backspace => match self.filter.pop() {
                Some(_) => self.refilter(),
                None => self.up(),
            },
            KeyCode::Enter | KeyCode::Right => return self.enter(),
            KeyCode::Char(c) if !control => {
                self.filter.push(c);
                self.refilter();
            }
            _ => {}
        }
        Pick::Continue
    }

    /// A click on a row. The second one is `enter`, exactly as it is in the
    /// panes behind — one click only ever moves the cursor.
    pub fn click(&mut self, at: usize, double: bool) -> Pick {
        if at >= self.matching.len() {
            return Pick::Continue;
        }
        self.at = at;
        match double {
            true => self.enter(),
            false => Pick::Continue,
        }
    }

    /// The wheel, a notch at a time.
    pub fn scroll(&mut self, up: bool) {
        self.move_by(if up { -3 } else { 3 });
    }

    /// Open what is selected: descend into a directory, pick a file.
    fn enter(&mut self) -> Pick {
        let Some(entry) = self.selected() else {
            return Pick::Continue;
        };
        if entry.dir {
            let path = entry.path.clone();
            self.go(path);
            return Pick::Continue;
        }
        Pick::Chose(format!("file:{}", entry.path.display()))
    }

    fn up(&mut self) {
        let Some(parent) = self.dir.parent().map(Path::to_path_buf) else {
            return;
        };
        let leaving = self.dir.clone();
        self.go(parent);
        // Land back on the directory just left rather than at the top of a
        // listing it may not even be visible in.
        self.select(&leaving);
    }

    /// List `dir` — or stay where we are and say why not.
    fn go(&mut self, dir: PathBuf) {
        match read(&dir) {
            Ok(entries) => {
                self.dir = dir;
                self.entries = entries;
                self.filter.clear();
                self.error = None;
                self.at = 0;
                self.refilter();
            }
            Err(error) => self.error = Some(format!("{}: {error}", dir.display())),
        }
    }

    fn select(&mut self, path: &Path) {
        if let Some(at) = self
            .matching
            .iter()
            .position(|index| self.entries[*index].path == path)
        {
            self.at = at;
        }
    }

    /// Narrow the listing to the names containing what has been typed, case
    /// insensitively. A substring rather than a prefix: `id_ed25519` is found
    /// by typing `ed25519`, which is the part anybody remembers.
    fn refilter(&mut self) {
        let needle = self.filter.to_lowercase();
        self.matching = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.name.to_lowercase().contains(&needle))
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

    fn selected(&self) -> Option<&Entry> {
        self.entries.get(*self.matching.get(self.at)?)
    }

    pub fn render(&self, frame: &mut Frame, area: Rect) -> Hits {
        let width = 72.min(area.width.saturating_sub(4));
        let height = 22.min(area.height.saturating_sub(2));
        let popup = centred(area, width, height);

        frame.render_widget(Clear, popup);
        frame.render_widget(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" pick a file "),
            popup,
        );

        let inner = popup.inner(ratatui::layout::Margin::new(2, 1));
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Min(1),
                Constraint::Length(2),
                Constraint::Length(1),
            ])
            .split(inner);

        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                clip(&self.dir.display().to_string(), rows[0].width as usize),
                Style::default().fg(Color::Cyan),
            ))),
            rows[0],
        );

        let mut hits = Hits {
            popup,
            rows: Vec::new(),
        };
        let window = rows[1].height as usize;
        // Kept centred rather than remembered: the offset is a function of
        // where the cursor is, so there is no second piece of state to get out
        // of step with the listing when a directory changes under it.
        let offset = self
            .at
            .saturating_sub(window / 2)
            .min(self.matching.len().saturating_sub(window));

        let lines: Vec<Line> = (0..window)
            .filter_map(|row| {
                let at = offset + row;
                let entry = self.entries.get(*self.matching.get(at)?)?;
                hits.rows.push((
                    Rect {
                        y: rows[1].y.saturating_add(row as u16),
                        height: 1,
                        ..rows[1]
                    },
                    at,
                ));
                let here = at == self.at;
                let name = match entry.dir {
                    true => format!("{}/", entry.name),
                    false => entry.name.clone(),
                };
                Some(Line::from(vec![
                    Span::styled(
                        if here { "▶ " } else { "  " },
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(
                        clip(&name, rows[1].width.saturating_sub(2) as usize),
                        match (here, entry.dir) {
                            (true, _) => Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                            (false, true) => Style::default().fg(Color::Cyan),
                            (false, false) => Style::default().fg(Color::Gray),
                        },
                    ),
                ]))
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), rows[1]);

        let status = match (&self.error, self.filter.is_empty()) {
            (Some(error), _) => {
                Paragraph::new(error.as_str()).style(Style::default().fg(Color::Red))
            }
            (None, false) => Paragraph::new(format!(
                "filter: {}   ({} of {})",
                self.filter,
                self.matching.len(),
                self.entries.len()
            ))
            .style(Style::default().fg(Color::Yellow)),
            (None, true) => Paragraph::new(
                "type to filter. The reference goes in as `file:<path>` — the proxy reads \
                 the file, nothing here does.",
            )
            .style(Style::default().fg(Color::DarkGray)),
        };
        frame.render_widget(status.wrap(Wrap { trim: true }), rows[2]);

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" ↑/↓ ", key_style()),
                Span::raw(" move  "),
                Span::styled(" enter ", key_style()),
                Span::raw(" open or pick  "),
                Span::styled(" ← ", key_style()),
                Span::raw(" up  "),
                Span::styled(" esc ", key_style()),
                Span::raw(" back"),
            ]))
            .style(Style::default().fg(Color::DarkGray)),
            rows[3],
        );

        hits
    }
}

/// Where the picker drew the things a mouse can hit.
#[derive(Clone)]
pub struct Hits {
    /// The whole dialogue, so a click outside it can be told from one inside.
    pub popup: Rect,
    /// Each drawn row, with its position in the listing.
    pub rows: Vec<(Rect, usize)>,
}

/// Everything in `dir`, directories first and then files, each half sorted by
/// name without regard to case.
///
/// Dotfiles are listed like anything else. A picker that hid them would hide
/// `~/.ssh`, `~/.config` and `.env` — which is very nearly the whole list of
/// places the file this picker exists for is kept.
fn read(dir: &Path) -> std::io::Result<Vec<Entry>> {
    let mut entries: Vec<Entry> = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| {
            let path = entry.path();
            Entry {
                name: entry.file_name().to_string_lossy().into_owned(),
                // Followed rather than read off the directory entry: a secrets
                // directory is a symlink on plenty of machines, and one the
                // picker would not walk into is a file it cannot reach.
                dir: std::fs::metadata(&path).is_ok_and(|meta| meta.is_dir()),
                path,
            }
        })
        .collect();
    entries.sort_by(|left, right| {
        right
            .dir
            .cmp(&left.dir)
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
    });
    // `..` at the top, after the sort so it stays there. Not for want of `←`,
    // but because a picker that offers no visible way back up is one you leave
    // by cancelling.
    if let Some(parent) = dir.parent() {
        entries.insert(
            0,
            Entry {
                name: "..".into(),
                path: parent.to_path_buf(),
                dir: true,
            },
        );
    }
    Ok(entries)
}

/// Which directory to open on, given whatever the field already holds.
///
/// A half-typed path is the best hint there is about where the operator was
/// headed, so `file:/run/sec` opens on `/run`. Anything else — an `env:`
/// reference, an `op://` one, an empty field — says nothing about the
/// filesystem, and home is the nearest thing to an answer.
fn start_at(value: &str) -> PathBuf {
    let raw = value.trim();
    let path = raw.strip_prefix("file:").unwrap_or(raw);
    let looks_like_a_path =
        raw.starts_with("file:") || path.starts_with('/') || path.starts_with('~');
    let named = looks_like_a_path
        .then(|| expand(path))
        .filter(|path| !path.as_os_str().is_empty());

    match named {
        Some(path) if path.is_dir() => path,
        // A path far enough in to name a directory that exists opens there;
        // one that names nothing real falls back rather than opening on a
        // listing of nowhere.
        Some(path) => path
            .parent()
            .filter(|parent| parent.is_dir())
            .map(Path::to_path_buf)
            .unwrap_or_else(home),
        None => home(),
    }
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_dir())
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn expand(path: &str) -> PathBuf {
    match path.strip_prefix('~') {
        Some(rest) => home().join(rest.trim_start_matches('/')),
        None => PathBuf::from(path),
    }
}

/// Keep the end of a string that will not fit, not the start: the leaf of a
/// path is the part being chosen between.
fn clip(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count <= width || width == 0 {
        return text.to_string();
    }
    let kept: String = text.chars().skip(count - width.saturating_sub(1)).collect();
    format!("…{kept}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEvent;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    fn typed(browser: &mut Browser, text: &str) {
        for c in text.chars() {
            browser.handle(key(KeyCode::Char(c)));
        }
    }

    /// A tree with a dotted directory and a dotted file in it, because those
    /// are the ones this picker exists to reach.
    fn tree() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(".secrets")).unwrap();
        std::fs::write(root.path().join(".secrets/.env"), "x").unwrap();
        std::fs::write(root.path().join(".secrets/anthropic.key"), "x").unwrap();
        std::fs::write(root.path().join("notes.txt"), "x").unwrap();
        root
    }

    #[test]
    fn a_pick_is_the_reference_the_config_file_takes() {
        // The one thing the picker owes the form: not a path, a `file:`
        // reference — which is what `SecretRef::parse` reads and what the
        // field would have had to be typed with by hand.
        let root = tree();
        let mut browser = Browser::open(0, &format!("file:{}/", root.path().display()));
        typed(&mut browser, "notes");
        let Pick::Chose(value) = browser.handle(key(KeyCode::Enter)) else {
            panic!("`enter` on a file picks it");
        };
        assert_eq!(
            value,
            format!("file:{}", root.path().join("notes.txt").display())
        );
        assert!(crate::secrets::SecretRef::parse(&value).is_ok());
    }

    #[test]
    fn dotted_directories_and_dotted_files_are_reachable() {
        let root = tree();
        let mut browser = Browser::open(0, &root.path().display().to_string());
        typed(&mut browser, ".secrets");
        assert!(matches!(
            browser.handle(key(KeyCode::Enter)),
            Pick::Continue
        ));
        typed(&mut browser, ".env");
        let Pick::Chose(value) = browser.handle(key(KeyCode::Enter)) else {
            panic!("a dotfile is a file like any other");
        };
        assert_eq!(
            value,
            format!("file:{}", root.path().join(".secrets/.env").display())
        );
    }

    #[test]
    fn it_opens_where_the_half_typed_path_was_going() {
        let root = tree();
        // A path that names a file that does not exist yet still says which
        // directory was meant.
        let browser = Browser::open(0, &format!("file:{}/noth", root.path().display()));
        assert_eq!(browser.dir, root.path());

        // A reference to somewhere else entirely says nothing about the
        // filesystem, so it opens at home rather than on a listing of nowhere.
        for reference in ["", "env:GITHUB_TOKEN", "op://Private/Anthropic/credential"] {
            assert_eq!(
                Browser::open(0, reference).dir,
                home(),
                "`{reference}` is not a path"
            );
        }
    }

    #[test]
    fn escape_leaves_the_filter_before_it_leaves_the_picker() {
        let root = tree();
        let mut browser = Browser::open(0, &root.path().display().to_string());
        typed(&mut browser, "notes");
        assert!(matches!(browser.handle(key(KeyCode::Esc)), Pick::Continue));
        assert!(browser.filter.is_empty());
        assert!(matches!(browser.handle(key(KeyCode::Esc)), Pick::Close));
    }

    #[test]
    fn walking_out_of_a_directory_lands_on_it() {
        let root = tree();
        let mut browser = Browser::open(0, &root.path().join(".secrets").display().to_string());
        browser.handle(key(KeyCode::Left));
        assert_eq!(browser.dir, root.path());
        assert_eq!(
            browser.selected().map(|entry| entry.path.clone()),
            Some(root.path().join(".secrets")),
            "the cursor should be on the directory just left"
        );
    }

    #[test]
    fn a_directory_that_will_not_open_is_reported_rather_than_entered() {
        let root = tree();
        let gone = root.path().join("gone");
        let mut browser = Browser::open(0, &root.path().display().to_string());
        browser.go(gone);
        assert_eq!(browser.dir, root.path(), "we are still where we were");
        assert!(browser.error.is_some(), "and told why we are");
    }

    #[test]
    fn the_cursor_stays_inside_a_listing_the_filter_shrank() {
        let root = tree();
        let mut browser = Browser::open(0, &root.path().display().to_string());
        browser.handle(key(KeyCode::End));
        typed(&mut browser, "notes");
        assert!(browser.at < browser.matching.len());
        assert_eq!(
            browser.selected().map(|e| e.name.clone()),
            Some("notes.txt".into())
        );

        // A filter that matches nothing leaves nothing selected — and `enter`
        // on nothing must not pick the entry that used to be under the cursor.
        typed(&mut browser, "zzz");
        assert!(browser.matching.is_empty());
        assert!(matches!(
            browser.handle(key(KeyCode::Enter)),
            Pick::Continue
        ));
    }
}
