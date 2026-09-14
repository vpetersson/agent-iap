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
    pub key: &'static str,
    pub label: &'static str,
    pub hint: &'static str,
    pub value: Value,
    /// Shown only when the `Choice` field named here is on one of these
    /// options. A credential form that asks for a token endpoint while you are
    /// enrolling a bearer token is a form that gets filled in wrong.
    pub shown_for: Option<(&'static str, Vec<String>)>,
}

impl Field {
    pub fn text(key: &'static str, label: &'static str, hint: &'static str) -> Self {
        Field {
            key,
            label,
            hint,
            value: Value::Text(String::new()),
            shown_for: None,
        }
    }

    pub fn prefilled(
        key: &'static str,
        label: &'static str,
        hint: &'static str,
        value: &str,
    ) -> Self {
        Field {
            value: Value::Text(value.to_string()),
            ..Field::text(key, label, hint)
        }
    }

    pub fn choice(
        key: &'static str,
        label: &'static str,
        hint: &'static str,
        options: &[&str],
    ) -> Self {
        Field {
            value: Value::Choice {
                options: options.iter().map(|o| o.to_string()).collect(),
                selected: 0,
            },
            ..Field::text(key, label, hint)
        }
    }

    pub fn flag(key: &'static str, label: &'static str, hint: &'static str) -> Self {
        Field {
            value: Value::Flag(false),
            ..Field::text(key, label, hint)
        }
    }

    pub fn when(mut self, field: &'static str, options: &[&str]) -> Self {
        self.shown_for = Some((field, options.iter().map(|o| o.to_string()).collect()));
        self
    }

    fn rendered(&self) -> String {
        match &self.value {
            Value::Text(text) => text.clone(),
            Value::Choice { options, selected } => options[*selected].clone(),
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
}

/// Which enrolment a filled-in form is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    Agent,
    Upstream,
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
        };
        form.focus = form.visible().first().copied().unwrap_or(0);
        form
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
            .find(|field| field.key == key)
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

    pub fn flag(&self, key: &str) -> bool {
        matches!(
            self.fields
                .iter()
                .find(|field| field.key == key)
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

    /// The credential half of the form, in the shape `enroll` validates.
    pub fn auth(&self) -> AuthInput {
        AuthInput {
            scheme: self.text("auth"),
            secret: self.opt("secret"),
            header: self.opt("header"),
            prefix: self.opt("prefix"),
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
            (KeyCode::Right, Value::Choice { options, selected }) => {
                *selected = (*selected + 1) % options.len();
            }
            (KeyCode::Left, Value::Choice { options, selected }) => {
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
        };
        let lines: Vec<Line> = visible
            .iter()
            .enumerate()
            .map(|(row, index)| {
                // One field per line, in order, starting at the top of the
                // field block — which is what makes the mapping back this
                // simple.
                hits.fields.push((
                    Rect {
                        y: rows[1].y.saturating_add(row as u16),
                        height: 1,
                        ..rows[1]
                    },
                    *index,
                ));
                let field = &self.fields[*index];
                let focused = *index == self.focus;
                let value = field.rendered();
                let shown = match (&field.value, focused) {
                    (Value::Text(_), true) => format!("{value}▏"),
                    (Value::Choice { .. }, _) => format!("◂ {value} ▸"),
                    _ => value,
                };
                Line::from(vec![
                    Span::styled(
                        if focused { "▶ " } else { "  " },
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(
                        format!("{:>label_width$}  ", field.label),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        shown,
                        if focused {
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

        frame.render_widget(Paragraph::new(lines), rows[1]);

        let hint = self
            .fields
            .get(self.focus)
            .map(|field| field.hint)
            .unwrap_or_default();
        let footer = match &self.error {
            Some(error) => Paragraph::new(error.as_str()).style(Style::default().fg(Color::Red)),
            None => Paragraph::new(hint).style(Style::default().fg(Color::DarkGray)),
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

        hits
    }
}

fn key_style() -> Style {
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
            if fields.iter().any(|field| field.key == *key) {
                continue;
            }
            let schemes: Vec<&str> = AUTH_SCHEMES
                .iter()
                .copied()
                .filter(|other| AuthInput::fields_for(other).contains(key))
                .collect();
            let (label, hint) = wording(key);
            fields.push(Field::text(key, label, hint).when("auth", &schemes));
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
                .map(|index| form.fields[index].key)
                .filter(|key| *key != "auth")
                .collect();
            let mut wanted: Vec<&str> = AuthInput::fields_for(scheme).to_vec();
            shown.sort_unstable();
            wanted.sort_unstable();
            assert_eq!(shown, wanted, "form for `{scheme}`");
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
