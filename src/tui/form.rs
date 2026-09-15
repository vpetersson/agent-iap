//! The console's data entry.
//!
//! Everything the enrolment commands take as flags, taken here as fields. One
//! form widget rather than one per noun, because the interesting part of `agent
//! -iap upstream add` is not its layout — it is which of its seventeen
//! credential flags the scheme you picked actually reads, and that answer lives
//! in `enroll::AuthInput` where the CLI reads it too.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use std::borrow::Cow;

use super::browse::{self, Browser, Pick};
use crate::config::AuthConfig;
use crate::enroll::{AuthInput, AUTH_SCHEMES};

/// What a field holds.
pub enum Value {
    Text(String),
    /// One of a fixed set, cycled with ← and →.
    Choice {
        options: Vec<String>,
        selected: usize,
    },
    /// A `--flag`, toggled with space.
    Flag(bool),
}

pub struct Field {
    /// Stable name the submit handler reads the value back by. Matches the
    /// CLI flag it stands in for, so the two are greppable against each other.
    /// Owned rather than `&'static`, so a form can grow a field for something
    /// only known at runtime — one per a profile's variables, keyed by name.
    pub key: Cow<'static, str>,
    pub label: Cow<'static, str>,
    pub hint: Cow<'static, str>,
    pub value: Value,
    /// Shown only when the `Choice` field named here is on one of these
    /// options. A credential form that asks for a token endpoint while you are
    /// enrolling a bearer token is a form that gets filled in wrong.
    pub shown_for: Option<(&'static str, Vec<String>)>,
    /// This field takes a secret *reference*, one shape of which is a path —
    /// so it can be filled in from the file picker as well as typed. See
    /// `browse`.
    pub browses: bool,
}

impl Field {
    pub fn text(
        key: impl Into<Cow<'static, str>>,
        label: impl Into<Cow<'static, str>>,
        hint: impl Into<Cow<'static, str>>,
    ) -> Self {
        Field {
            key: key.into(),
            label: label.into(),
            hint: hint.into(),
            value: Value::Text(String::new()),
            shown_for: None,
            browses: false,
        }
    }

    pub fn prefilled(
        key: impl Into<Cow<'static, str>>,
        label: impl Into<Cow<'static, str>>,
        hint: impl Into<Cow<'static, str>>,
        value: &str,
    ) -> Self {
        Field {
            value: Value::Text(value.to_string()),
            ..Field::text(key, label, hint)
        }
    }

    pub fn choice(
        key: impl Into<Cow<'static, str>>,
        label: impl Into<Cow<'static, str>>,
        hint: impl Into<Cow<'static, str>>,
        options: &[&str],
    ) -> Self {
        Field::choices(
            key,
            label,
            hint,
            options.iter().map(|o| o.to_string()).collect(),
            0,
        )
    }

    /// A `Choice` whose options are only known at runtime — the profile
    /// catalogue — opened on one of them rather than on the first.
    pub fn choices(
        key: impl Into<Cow<'static, str>>,
        label: impl Into<Cow<'static, str>>,
        hint: impl Into<Cow<'static, str>>,
        options: Vec<String>,
        selected: usize,
    ) -> Self {
        // Clamped rather than trusted: `rendered` indexes this, and a caller
        // that looked a since-removed option up should get the first entry,
        // not a panic in the middle of a draw.
        let selected = if selected < options.len() {
            selected
        } else {
            0
        };
        Field {
            value: Value::Choice { options, selected },
            ..Field::text(key, label, hint)
        }
    }

    pub fn flag(
        key: impl Into<Cow<'static, str>>,
        label: impl Into<Cow<'static, str>>,
        hint: impl Into<Cow<'static, str>>,
    ) -> Self {
        Field::switch(key, label, hint, false)
    }

    /// A `Flag` that starts on. For the one that is a step of the form rather
    /// than an extra on it: `verify` is what the form does next, so it is there
    /// to be turned off, not to be found.
    pub fn switch(
        key: impl Into<Cow<'static, str>>,
        label: impl Into<Cow<'static, str>>,
        hint: impl Into<Cow<'static, str>>,
        on: bool,
    ) -> Self {
        Field {
            value: Value::Flag(on),
            ..Field::text(key, label, hint)
        }
    }

    pub fn when(mut self, field: &'static str, options: &[&str]) -> Self {
        self.shown_for = Some((field, options.iter().map(|o| o.to_string()).collect()));
        self
    }

    /// Say that this field names a file, so `ctrl-o` on it opens the picker.
    pub fn browsable(mut self) -> Self {
        self.browses = true;
        self
    }

    fn rendered(&self) -> String {
        match &self.value {
            Value::Text(text) => text.clone(),
            Value::Choice { options, selected } => {
                options.get(*selected).cloned().unwrap_or_default()
            }
            Value::Flag(true) => "yes".into(),
            Value::Flag(false) => "no".into(),
        }
    }
}

/// Where the form drew the things a mouse can hit.
#[derive(Clone)]
pub struct Hits {
    /// The whole dialogue, so a click outside it can be told from one inside.
    pub popup: Rect,
    pub fields: Vec<(Rect, usize)>,
    /// Where `[browse]` was drawn beside the focused field, when that field
    /// takes a path.
    pub browse: Option<Rect>,
    /// The picker, when it is open over the form. Present means it owns the
    /// screen, and the fields underneath are not reachable.
    pub browser: Option<browse::Hits>,
}

/// What the event loop should do with the form after a keystroke.
pub enum Outcome {
    Continue,
    Cancel,
    Submit,
}

pub struct Form {
    pub title: String,
    pub about: String,
    /// What the submit handler is for, so one match in the event loop covers
    /// every form rather than each form carrying a closure through the borrow
    /// checker.
    pub intent: Intent,
    pub fields: Vec<Field>,
    focus: usize,
    pub error: Option<String>,
    /// This form opens on a profile picker, so moving that choice is not an
    /// edit to a field — it is a different form. The console rebuilds it;
    /// this module knows nothing about the catalogue, only that the first
    /// field decides what the rest of them are.
    pub picker: bool,
    /// The file picker, open over this form and filling one of its fields.
    /// While it is up it takes every keystroke — including `enter`, which in
    /// here opens a directory rather than submitting an unfinished form.
    browser: Option<Browser>,
}

/// Which enrolment a filled-in form is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intent {
    Agent,
    Upstream,
    /// Rewriting the upstream it names. The name travels with the intent
    /// rather than as a field, because it is the one thing on this form that
    /// is not being edited — ACL rules and agents' `targets` point at it.
    EditUpstream(String),
    McpServer,
    Rule,
    Profile,
}

impl Form {
    pub fn new(intent: Intent, title: &str, about: &str, fields: Vec<Field>) -> Self {
        let mut form = Form {
            title: title.to_string(),
            about: about.to_string(),
            intent,
            fields,
            focus: 0,
            error: None,
            picker: false,
            browser: None,
        };
        form.focus = form.visible().first().copied().unwrap_or(0);
        form
    }

    /// Say that the first field is a profile picker. See `picker`.
    pub fn with_picker(mut self) -> Self {
        self.picker = true;
        self
    }

    /// Indices of the fields the current choices make relevant.
    pub fn visible(&self) -> Vec<usize> {
        self.fields
            .iter()
            .enumerate()
            .filter(|(_, field)| match &field.shown_for {
                None => true,
                Some((other, allowed)) => self
                    .raw(other)
                    .is_some_and(|value| allowed.iter().any(|option| option == &value)),
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn raw(&self, key: &str) -> Option<String> {
        self.fields
            .iter()
            .find(|field| field.key.as_ref() == key)
            .map(Field::rendered)
    }

    /// A text field's contents, trimmed. Missing fields read as empty, so a
    /// submit handler can ask for a field only some variants carry.
    pub fn text(&self, key: &str) -> String {
        self.raw(key).unwrap_or_default().trim().to_string()
    }

    /// The same, as `None` when it was left blank — the shape every optional
    /// CLI flag takes.
    pub fn opt(&self, key: &str) -> Option<String> {
        Some(self.text(key)).filter(|value| !value.is_empty())
    }

    /// A field's contents with the spaces left on, or `None` when there is
    /// nothing but spaces.
    ///
    /// For the one field whose trailing space is the field: a `prefix` of
    /// `Token ` is what separates the word from the credential, and trimming it
    /// would send `Tokensk-…` upstream. Everywhere else the trim is right —
    /// a stray space in a URL or a secret reference is a typo.
    fn verbatim(&self, key: &str) -> Option<String> {
        self.raw(key).filter(|value| !value.trim().is_empty())
    }

    pub fn flag(&self, key: &str) -> bool {
        matches!(
            self.fields
                .iter()
                .find(|field| field.key.as_ref() == key)
                .map(|field| &field.value),
            Some(Value::Flag(true))
        )
    }

    /// A repeatable flag, typed once: `a, b c` is three values. Commas and
    /// whitespace both separate, because both are what people type.
    pub fn list(&self, key: &str) -> Vec<String> {
        self.text(key)
            .split([',', ' ', '\t'])
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(String::from)
            .collect()
    }

    /// A repeatable `NAME=VALUE` flag. Split on the *first* `=` only: an
    /// `op://` reference has none, but a value certainly may.
    pub fn pairs(&self, key: &str) -> anyhow::Result<Vec<(String, String)>> {
        self.text(key)
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                entry
                    .split_once('=')
                    .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
                    .ok_or_else(|| {
                        anyhow::anyhow!("`{entry}` is not `NAME=VALUE` — {key} takes pairs")
                    })
            })
            .collect()
    }

    /// The `value` of every field keyed `<prefix><name>`, paired back with that
    /// `name` and dropping the ones left blank. How a form that grew one field
    /// per thing — a profile's variables, each its own labelled field — gathers
    /// them back into the `name=value` list the enrolment takes.
    pub fn prefixed(&self, prefix: &str) -> Vec<(String, String)> {
        self.fields
            .iter()
            .filter_map(|field| {
                let name = field.key.strip_prefix(prefix)?;
                let Value::Text(value) = &field.value else {
                    return None;
                };
                let value = value.trim();
                (!value.is_empty()).then(|| (name.to_string(), value.to_string()))
            })
            .collect()
    }

    /// The credential half of the form, in the shape `enroll` validates.
    pub fn auth(&self) -> AuthInput {
        AuthInput {
            scheme: self.text("auth"),
            secret: self.opt("secret"),
            header: self.opt("header"),
            prefix: self.verbatim("prefix"),
            username: self.opt("username"),
            username_secret: self.opt("username-secret"),
            param: self.opt("param"),
            key_file: self.opt("key-file"),
            private_key: self.opt("private-key"),
            issuer: self.opt("issuer"),
            key_id: self.opt("key-id"),
            token_url: self.opt("token-url"),
            audience: self.opt("audience"),
            scopes: self.list("scope"),
            subject: self.opt("subject"),
            lifetime_secs: self.opt("lifetime-secs").and_then(|v| v.parse().ok()),
            client_id: self.opt("client-id"),
            client_secret: self.opt("client-secret"),
        }
    }

    pub fn handle(&mut self, key: KeyEvent) -> Outcome {
        if self.browser.is_some() {
            return self.handle_browse(key);
        }
        let visible = self.visible();
        let at = visible.iter().position(|index| *index == self.focus);

        match key.code {
            KeyCode::Esc => return Outcome::Cancel,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Outcome::Cancel
            }
            KeyCode::Enter => return Outcome::Submit,
            KeyCode::Tab | KeyCode::Down => {
                if let Some(at) = at {
                    self.focus = visible[(at + 1) % visible.len()];
                }
            }
            KeyCode::BackTab | KeyCode::Up => {
                if let Some(at) = at {
                    self.focus = visible[(at + visible.len() - 1) % visible.len()];
                }
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some(Value::Text(text)) = self.focused_mut() {
                    text.clear();
                }
            }
            KeyCode::Char('o') if key.modifiers.contains(KeyModifiers::CONTROL) => self.browse(),
            code => self.edit(code),
        }

        // A choice that moved may have hidden the field the cursor is on.
        let visible = self.visible();
        if !visible.contains(&self.focus) {
            self.focus = visible.first().copied().unwrap_or(0);
        }
        Outcome::Continue
    }

    fn focused_mut(&mut self) -> Option<&mut Value> {
        self.fields
            .get_mut(self.focus)
            .map(|field| &mut field.value)
    }

    /// Is the picker up? The console asks because the wheel and a click mean
    /// different things over it than they do over the form.
    pub fn browsing(&self) -> bool {
        self.browser.is_some()
    }

    /// Open the picker on the focused field, when that field names a file.
    /// A no-op anywhere else: `ctrl-o` on a header name has nothing to pick.
    pub fn browse(&mut self) {
        let Some(field) = self.fields.get(self.focus) else {
            return;
        };
        let (true, Value::Text(text)) = (field.browses, &field.value) else {
            return;
        };
        self.browser = Some(Browser::open(self.focus, text));
    }

    /// A click on a row of the open picker.
    pub fn click_browse(&mut self, at: usize, double: bool) {
        let Some(browser) = &mut self.browser else {
            return;
        };
        let picked = browser.click(at, double);
        self.settle(picked);
    }

    /// The wheel over the open picker.
    pub fn scroll_browse(&mut self, up: bool) {
        if let Some(browser) = &mut self.browser {
            browser.scroll(up);
        }
    }

    fn handle_browse(&mut self, key: KeyEvent) -> Outcome {
        let Some(browser) = &mut self.browser else {
            return Outcome::Continue;
        };
        let picked = browser.handle(key);
        self.settle(picked);
        // Never `Submit`: `enter` in the picker opens a directory, and a form
        // that saved itself halfway through choosing a file would write the
        // credential that was there before.
        Outcome::Continue
    }

    /// Write back whatever the picker decided, and close it if it is done.
    fn settle(&mut self, picked: Pick) {
        let field = match picked {
            Pick::Continue => return,
            Pick::Close => {
                self.browser = None;
                return;
            }
            Pick::Chose(reference) => {
                let Some(browser) = self.browser.take() else {
                    return;
                };
                if let Some(Value::Text(text)) =
                    self.fields.get_mut(browser.field).map(|f| &mut f.value)
                {
                    *text = reference;
                }
                browser.field
            }
        };
        // Back on the field that was just filled in, not wherever the form
        // happened to be — the picker was opened from there.
        self.focus(field);
    }

    fn edit(&mut self, code: KeyCode) {
        let Some(value) = self.focused_mut() else {
            return;
        };
        match (code, value) {
            (KeyCode::Char(c), Value::Text(text)) => text.push(c),
            (KeyCode::Backspace, Value::Text(text)) => {
                text.pop();
            }
            (KeyCode::Char(' '), Value::Flag(on)) => *on = !*on,
            (KeyCode::Left, Value::Flag(on)) | (KeyCode::Right, Value::Flag(on)) => *on = !*on,
            (KeyCode::Right, Value::Choice { options, selected }) if !options.is_empty() => {
                *selected = (*selected + 1) % options.len();
            }
            (KeyCode::Left, Value::Choice { options, selected }) if !options.is_empty() => {
                *selected = (*selected + options.len() - 1) % options.len();
            }
            _ => {}
        }
    }

    /// Put the cursor on a field by index, ignoring one that is not on screen.
    pub fn focus(&mut self, index: usize) {
        if self.visible().contains(&index) {
            self.focus = index;
        }
    }

    /// Advance a `Choice` field, for a click on the value itself. A text field
    /// is only focused — clicking into a word should not retype it.
    pub fn nudge(&mut self, index: usize) {
        self.focus(index);
        if matches!(
            self.fields.get(index).map(|f| &f.value),
            Some(Value::Choice { .. })
        ) {
            self.edit(KeyCode::Right);
        }
    }

    /// Draw the form, and hand back where each visible field landed so a click
    /// can be turned back into the field it hit.
    pub fn render(&self, frame: &mut Frame, area: Rect) -> Hits {
        let visible = self.visible();
        let height = (visible.len() as u16 + 8).min(area.height.saturating_sub(2));
        let width = 78.min(area.width.saturating_sub(4));
        let popup = centred(area, width, height);

        frame.render_widget(Clear, popup);
        frame.render_widget(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(format!(" {} ", self.title)),
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
            Paragraph::new(self.about.as_str())
                .style(Style::default().fg(Color::DarkGray))
                .wrap(Wrap { trim: true }),
            rows[0],
        );

        let label_width = visible
            .iter()
            .map(|index| self.fields[*index].label.len())
            .max()
            .unwrap_or(0);

        let mut hits = Hits {
            popup,
            fields: Vec::new(),
            browse: None,
            browser: None,
        };
        let lines: Vec<Line> = visible
            .iter()
            .enumerate()
            .map(|(row, index)| {
                // One field per line, in order, starting at the top of the
                // field block — which is what makes the mapping back this
                // simple.
                let line = Rect {
                    y: rows[1].y.saturating_add(row as u16),
                    height: 1,
                    ..rows[1]
                };
                hits.fields.push((line, *index));
                let field = &self.fields[*index];
                let focused = *index == self.focus;
                let value = field.rendered();
                let shown = match (&field.value, focused) {
                    (Value::Text(_), true) => format!("{value}▏"),
                    (Value::Choice { .. }, _) => format!("◂ {value} ▸"),
                    _ => value,
                };
                let mut spans = vec![
                    Span::styled(
                        if focused { "▶ " } else { "  " },
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(
                        format!("{:>label_width$}  ", field.label),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        shown.clone(),
                        if focused {
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::Gray)
                        },
                    ),
                ];
                // A field that names a file says so on the line, while the
                // cursor is on it — and the words are a button, because the
                // console has already promised that what it draws can be
                // clicked.
                if focused && field.browses {
                    let before = 4 + label_width + shown.chars().count();
                    spans.push(Span::styled(BROWSE, key_style()));
                    if before + BROWSE.len() <= line.width as usize {
                        hits.browse = Some(Rect {
                            x: line.x.saturating_add(before as u16),
                            width: BROWSE.len() as u16,
                            ..line
                        });
                    }
                }
                Line::from(spans)
            })
            .collect();

        frame.render_widget(Paragraph::new(lines), rows[1]);

        let hint: Cow<'_, str> = match self.fields.get(self.focus) {
            Some(field) if field.browses => {
                Cow::Owned(format!("{}  —  ctrl-o to pick the file", field.hint))
            }
            Some(field) => Cow::Borrowed(field.hint.as_ref()),
            None => Cow::Borrowed(""),
        };
        let footer = match &self.error {
            Some(error) => Paragraph::new(error.as_str()).style(Style::default().fg(Color::Red)),
            None => Paragraph::new(hint.as_ref()).style(Style::default().fg(Color::DarkGray)),
        };
        frame.render_widget(footer.wrap(Wrap { trim: true }), rows[2]);

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" tab ", key_style()),
                Span::raw(" next  "),
                Span::styled(" ←/→ ", key_style()),
                Span::raw(" choose  "),
                Span::styled(" enter ", key_style()),
                Span::raw(" save  "),
                Span::styled(" esc ", key_style()),
                Span::raw(" cancel"),
            ]))
            .style(Style::default().fg(Color::DarkGray)),
            rows[3],
        );

        // Last, and over everything else: while the picker is up it owns the
        // screen, and the fields behind it are not reachable by a click.
        if let Some(browser) = &self.browser {
            hits.browser = Some(browser.render(frame, area));
        }

        hits
    }
}

/// What a field that names a file is offered with, and the width the hit box
/// is worked out from. ASCII, so `len` is the column count.
const BROWSE: &str = " browse ";

pub(super) fn key_style() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(Color::Cyan)
        .add_modifier(Modifier::BOLD)
}

pub fn centred(area: Rect, width: u16, height: u16) -> Rect {
    Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width: width.min(area.width),
        height: height.min(area.height),
    }
}

/// The credential fields, each visible for exactly the schemes that read it.
///
/// Both the set and the order come from `AuthInput::fields_for`, walked scheme
/// by scheme — so the form cannot offer a field the validator ignores, cannot
/// hide one it requires, and picks up a new scheme's fields the moment `enroll`
/// declares them. Only the wording is local.
pub fn auth_fields() -> Vec<Field> {
    let mut fields = vec![Field::choice(
        "auth",
        "auth",
        "how the credential is attached on the way out",
        AUTH_SCHEMES,
    )];

    for scheme in AUTH_SCHEMES {
        for key in AuthInput::fields_for(scheme) {
            if fields.iter().any(|field| field.key.as_ref() == *key) {
                continue;
            }
            let schemes: Vec<&str> = AUTH_SCHEMES
                .iter()
                .copied()
                .filter(|other| AuthInput::fields_for(other).contains(key))
                .collect();
            let (label, hint) = wording(key);
            let field = Field::text(*key, label, hint).when("auth", &schemes);
            // Which fields the picker is offered on comes from `enroll` too,
            // for the same reason the set of fields does: a reference is a
            // reference wherever it is typed, and a second list here would be
            // a second list to forget to add a scheme to.
            fields.push(match AuthInput::is_reference(key) {
                true => field.browsable(),
                false => field,
            });
        }
    }

    fields
}

/// The same fields, filled in from a credential the policy file already holds.
///
/// An edit form that opened on blanks would be a form where saving a changed
/// base URL writes `auth = none` — the credential silently gone from an
/// upstream that still routes. So the form starts as the file reads, and every
/// value in it is a reference rather than a credential, which is the only
/// reason showing them is safe at all.
pub fn auth_fields_for(auth: &AuthConfig) -> Vec<Field> {
    let filled = AuthInput::of(auth);
    let mut fields = auth_fields();
    for field in &mut fields {
        let scheme = field.key == "auth";
        let held = filled.value(field.key.as_ref());
        match &mut field.value {
            Value::Choice { options, selected } if scheme => {
                if let Some(at) = options.iter().position(|option| *option == filled.scheme) {
                    *selected = at;
                }
            }
            Value::Text(text) => {
                if let Some(value) = held {
                    *text = value;
                }
            }
            _ => {}
        }
    }
    fields
}

/// What each credential field is called on screen, and the one line under it.
fn wording(key: &'static str) -> (&'static str, &'static str) {
    match key {
        "secret" => (
            "secret",
            "credential reference — env:NAME, file:/path, op://vault/item/field. Never the credential itself.",
        ),
        "header" => ("header", "header name to send it in, e.g. x-api-key"),
        "prefix" => ("prefix", "value prefix, when the API wants one"),
        "username" => ("username", "the user half of basic auth"),
        "username-secret" => (
            "username ref",
            "reference for a user field that IS the credential — Graylog's <token>:token",
        ),
        "param" => ("query param", "query parameter to put it in, e.g. key"),
        "token-url" => ("token url", "endpoint the assertion is exchanged at"),
        "client-id" => ("client id", "OAuth2 client id"),
        "client-secret" => ("client secret", "reference to the client secret"),
        "scope" => ("scopes", "space- or comma-separated"),
        "audience" => ("audience", "the aud claim; defaults to the token url"),
        "key-file" => (
            "key file",
            "reference to the service-account JSON key, exactly as the vendor issues it",
        ),
        "private-key" => (
            "private key",
            "or spell it out: reference to a PKCS#8 PEM key",
        ),
        "issuer" => ("issuer", "the iss claim, for a private key"),
        "key-id" => ("key id", "the kid in the JWT header"),
        "subject" => ("subject", "user to impersonate (domain-wide delegation)"),
        "lifetime-secs" => (
            "lifetime",
            "assertion lifetime in seconds; clamped to an hour",
        ),
        // A scheme `enroll` grew and nobody came back here to word. Shown
        // under its own flag name rather than dropped: an unpolished label
        // beats a credential the form cannot be told about at all.
        other => (other, "see `agent-iap upstream add --help`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_form_offers_exactly_the_fields_the_scheme_reads() {
        // The invariant worth having: a field on screen that `to_spec` ignores
        // is a credential typed in and not sent, and a field it requires but
        // the form never shows is a scheme the console cannot enrol at all.
        for scheme in AUTH_SCHEMES {
            let mut form = Form::new(Intent::Upstream, "t", "a", auth_fields());
            while form.text("auth") != *scheme {
                form.handle(KeyEvent::from(KeyCode::Right));
            }

            let mut shown: Vec<&str> = form
                .visible()
                .into_iter()
                .map(|index| form.fields[index].key.as_ref())
                .filter(|key| *key != "auth")
                .collect();
            let mut wanted: Vec<&str> = AuthInput::fields_for(scheme).to_vec();
            shown.sort_unstable();
            wanted.sort_unstable();
            assert_eq!(shown, wanted, "form for `{scheme}`");
        }
    }

    /// The invariant the edit form rests on: it opens showing what the file
    /// holds, on the scheme the file names. A form that opened blank would
    /// write `auth = none` over a live credential the first time somebody
    /// corrected a base URL.
    #[test]
    fn an_edit_form_opens_on_the_credential_the_file_holds() {
        for auth in [
            AuthConfig::Bearer {
                secret: "env:GITHUB_TOKEN".into(),
            },
            AuthConfig::Header {
                header: "x-api-key".into(),
                secret: "op://Private/Anthropic/key".into(),
                prefix: Some("Token ".into()),
            },
            AuthConfig::Oauth2ClientCredentials {
                token_url: "https://id.example.com/oauth2/token".into(),
                client_id: "iap".into(),
                client_secret: "op://Private/Example/client-secret".into(),
                scope: Some("read:things write:things".into()),
                audience: None,
            },
            AuthConfig::ServiceAccountJwt {
                key_file: Some("op://Private/GCP/credential".into()),
                issuer: None,
                private_key: None,
                key_id: None,
                token_url: None,
                audience: None,
                scopes: vec!["https://www.googleapis.com/auth/webmasters.readonly".into()],
                subject: Some("person@example.com".into()),
                lifetime_secs: Some(600),
            },
        ] {
            let form = Form::new(Intent::Upstream, "t", "a", auth_fields_for(&auth));
            let filled = AuthInput::of(&auth);

            assert_eq!(
                form.text("auth"),
                filled.scheme,
                "opened on the wrong scheme"
            );
            assert_eq!(
                form.auth(),
                filled,
                "a form read straight back must be the credential it was opened on: {auth:?}"
            );
            // And the scheme's own fields are the ones on screen, filled in.
            for key in AuthInput::fields_for(&filled.scheme) {
                let index = form
                    .fields
                    .iter()
                    .position(|field| field.key == *key)
                    .unwrap();
                assert!(form.visible().contains(&index), "`{key}` is not on screen");
            }
        }
    }

    #[test]
    fn a_hidden_field_never_keeps_the_cursor() {
        let mut form = Form::new(Intent::Upstream, "t", "a", auth_fields());
        while form.text("auth") != "bearer" {
            form.handle(KeyEvent::from(KeyCode::Right));
        }
        // Move onto `secret`, then change the scheme out from under it.
        form.handle(KeyEvent::from(KeyCode::Tab));
        assert_eq!(form.fields[form.focus].key, "secret");
        form.fields[0].value = Value::Choice {
            options: AUTH_SCHEMES.iter().map(|s| s.to_string()).collect(),
            selected: 0,
        };
        form.handle(KeyEvent::from(KeyCode::Tab));
        assert!(
            form.visible().contains(&form.focus),
            "the cursor cannot be left on a field that is no longer on screen"
        );
    }

    /// The picker is offered where a path is a legal value and nowhere else.
    /// A `browse` on `--header` would fill a header name with `file:/…`.
    #[test]
    fn the_picker_is_offered_on_the_fields_that_take_a_reference() {
        let form = Form::new(Intent::Upstream, "t", "a", auth_fields());
        for field in &form.fields {
            assert_eq!(
                field.browses,
                AuthInput::is_reference(field.key.as_ref()),
                "`{}`",
                field.key
            );
        }
    }

    /// End to end, over the keyboard: `ctrl-o` on the secret, walk to a file,
    /// `enter` — and the field holds the reference the config file takes.
    #[test]
    fn picking_a_file_fills_the_field_it_was_opened_from() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("anthropic.key"), "x").unwrap();

        let mut form = Form::new(Intent::Upstream, "t", "a", auth_fields());
        while form.text("auth") != "bearer" {
            form.handle(KeyEvent::from(KeyCode::Right));
        }
        form.handle(KeyEvent::from(KeyCode::Tab));
        assert_eq!(form.fields[form.focus].key, "secret");
        let on = form.focus;

        let ctrl = |code| KeyEvent::new(code, KeyModifiers::CONTROL);
        for c in format!("file:{}/", dir.path().display()).chars() {
            form.handle(KeyEvent::from(KeyCode::Char(c)));
        }
        form.handle(ctrl(KeyCode::Char('o')));
        assert!(form.browsing(), "ctrl-o opens the picker");

        // `enter` belongs to the picker while it is up: it opens what is under
        // the cursor, and must not submit a form in the middle of being filled.
        for c in "anthropic".chars() {
            form.handle(KeyEvent::from(KeyCode::Char(c)));
        }
        assert!(matches!(
            form.handle(KeyEvent::from(KeyCode::Enter)),
            Outcome::Continue
        ));

        assert!(!form.browsing(), "picking closes the picker");
        assert_eq!(form.focus, on, "and puts the cursor back where it opened");
        assert_eq!(
            form.text("secret"),
            format!("file:{}", dir.path().join("anthropic.key").display())
        );
        assert_eq!(
            form.auth().secret.as_deref(),
            Some(form.text("secret").as_str())
        );
    }

    #[test]
    fn a_field_that_takes_no_path_has_no_picker() {
        let mut form = Form::new(Intent::Upstream, "t", "a", auth_fields());
        while form.text("auth") != "header" {
            form.handle(KeyEvent::from(KeyCode::Right));
        }
        let at = form
            .fields
            .iter()
            .position(|field| field.key == "header")
            .unwrap();
        form.focus(at);
        form.handle(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));
        assert!(!form.browsing());
        assert_eq!(form.text("header"), "", "and ctrl-o is not typed into it");
    }

    #[test]
    fn leaving_the_picker_leaves_the_field_as_it_was() {
        let mut form = Form::new(Intent::Upstream, "t", "a", auth_fields());
        while form.text("auth") != "bearer" {
            form.handle(KeyEvent::from(KeyCode::Right));
        }
        form.handle(KeyEvent::from(KeyCode::Tab));
        for c in "env:ANTHROPIC_API_KEY".chars() {
            form.handle(KeyEvent::from(KeyCode::Char(c)));
        }
        form.handle(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));
        assert!(form.browsing());
        assert!(matches!(
            form.handle(KeyEvent::from(KeyCode::Esc)),
            Outcome::Continue
        ));
        assert!(!form.browsing(), "esc closes the picker");
        assert_eq!(
            form.text("secret"),
            "env:ANTHROPIC_API_KEY",
            "and not the form, nor the reference it already held"
        );
    }

    #[test]
    fn repeatable_flags_are_typed_once() {
        let mut form = Form::new(
            Intent::Rule,
            "t",
            "a",
            vec![
                Field::prefilled("methods", "methods", "", "GET, POST"),
                Field::prefilled("env", "env", "", "TOKEN=op://v/i/f, HOST=env:HOST"),
            ],
        );
        assert_eq!(form.list("methods"), vec!["GET", "POST"]);
        assert_eq!(
            form.pairs("env").unwrap(),
            vec![
                ("TOKEN".to_string(), "op://v/i/f".to_string()),
                ("HOST".to_string(), "env:HOST".to_string()),
            ]
        );
        form.fields[1].value = Value::Text("TOKEN".into());
        assert!(form.pairs("env").is_err(), "a pair without `=` is a typo");
    }
}
