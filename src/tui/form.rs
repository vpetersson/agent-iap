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
use super::catalogue::{self, Catalogue};
use super::choose::{Candidate, Chooser};
use crate::config::AuthConfig;
use crate::enroll::{AuthInput, AUTH_SCHEMES};
use crate::secrets::SecretRef;

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
    /// Names this field could take that the policy file already holds — the
    /// enrolled agents, the upstreams, the MCP servers — offered as a list on
    /// the same key the file picker uses. Empty where there is nothing to
    /// offer, and a text field either way: an ACL glob is on no list. See
    /// `choose`.
    pub offers: Vec<Candidate>,
    /// What the `offers` list is a list of, for the picker's title.
    what: &'static str,
    /// The service catalog, for the one field that picks a profile. Its own
    /// list rather than `offers` because it opens a different picker: a name
    /// off the policy file is a box over the form, and a profile is the whole
    /// screen — see `catalogue`.
    pub catalogue: Vec<catalogue::Entry>,
    /// Has the operator put anything in this field? A prefilled default is
    /// not an answer — the `*` on an ACL rule is the form talking, not the
    /// operator — so an offer of the names it could hold stays up over one,
    /// and comes off the moment there is a value somebody chose.
    touched: bool,
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
            offers: Vec::new(),
            what: "",
            catalogue: Vec::new(),
            touched: false,
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

    /// Say what this field could name that the policy file already holds, so
    /// `ctrl-o` on it offers them. `what` completes "pick …": `an agent`.
    ///
    /// A field offered an empty list keeps no affordance at all — a policy
    /// with no upstreams in it yet has nothing to show, and a picker that
    /// opens on an empty box is worse than one that was never advertised.
    pub fn offering(mut self, what: &'static str, candidates: Vec<Candidate>) -> Self {
        self.what = what;
        self.offers = candidates;
        self
    }

    /// Say that this field names a profile, so `ctrl-o` on it opens the
    /// catalog on the whole screen. The field stays a `Choice` over the same
    /// ids, so `←`/`→` still steps through them for anyone who was used to it
    /// — the picker is the way in, not the only way.
    pub fn picking(mut self, entries: Vec<catalogue::Entry>) -> Self {
        self.catalogue = entries;
        self
    }

    /// Is this field holding a credential somebody typed instead of a
    /// reference to one?
    ///
    /// Only on the fields that take a reference — the same `browses` list
    /// `AuthConfig::secret_fields` is held against, so a scheme that grows a
    /// sixth reference gets this with it — and only when what is in it parses
    /// as no reference at all. A field holding `op://…` is a field that is
    /// already right, and offering to take a copy of it would be offering to
    /// duplicate a vault item into a plaintext file.
    fn keeps(&self) -> bool {
        let Value::Text(text) = &self.value else {
            return false;
        };
        self.browses && !text.trim().is_empty() && SecretRef::parse(text).is_err()
    }

    /// Which picker `ctrl-o` opens here, or nothing for a field with none
    /// behind it.
    fn opens(&self) -> Option<Opens> {
        if self.browses {
            return Some(Opens::Files);
        }
        if !self.catalogue.is_empty() {
            return Some(Opens::Profiles);
        }
        (!self.offers.is_empty()).then_some(Opens::Names)
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
    /// Everywhere the focused field's `ctrl-o` affordance was drawn: once on
    /// the field's own line, once in the key row. Clicking any of them opens
    /// that field's picker.
    pub browse: Vec<Rect>,
    /// Everywhere the `ctrl-k` offer was drawn, on the same terms as `browse`:
    /// once on the field's line, once in the key row. Clicking either keeps
    /// the value that field is holding.
    pub keep: Vec<Rect>,
    /// The picker, when it is open over the form. Present means it owns the
    /// screen, and the fields underneath are not reachable.
    pub browser: Option<browse::Hits>,
}

/// What the event loop should do with the form after a keystroke.
pub enum Outcome {
    Continue,
    Cancel,
    Submit,
    /// `ctrl-k` on a field holding a bare credential: hand it to agent-iap's
    /// own store and put the reference back in the field.
    ///
    /// Answered by the console rather than here because it writes a file, and
    /// this module is the one part of the dialogue that does not — a form that
    /// could put a credential on disk from inside `handle` would be a form
    /// whose tests write to the operator's store.
    Keep,
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
    /// A picker, open over this form and filling one of its fields. While one
    /// is up it takes every keystroke — including `enter`, which in there
    /// opens a directory rather than submitting an unfinished form.
    overlay: Option<Overlay>,
}

/// A picker open over the form.
///
/// Two of them, reached by the same key and both answering with a string the
/// form writes into the field it was opened from: the filesystem, for a field
/// that names a file, and the policy file's own names, for a field that names
/// something already in it.
enum Overlay {
    Files(Browser),
    Names(Chooser),
    /// The service catalog, over the whole terminal. See `catalogue`.
    Profiles(Box<Catalogue>),
}

impl Overlay {
    /// Which field the pick lands in.
    fn field(&self) -> usize {
        match self {
            Overlay::Files(browser) => browser.field,
            Overlay::Names(chooser) => chooser.field,
            Overlay::Profiles(catalogue) => catalogue.field,
        }
    }

    fn handle(&mut self, key: KeyEvent) -> Pick {
        match self {
            Overlay::Files(browser) => browser.handle(key),
            Overlay::Names(chooser) => chooser.handle(key),
            Overlay::Profiles(catalogue) => catalogue.handle(key),
        }
    }

    fn click(&mut self, at: usize, double: bool) -> Pick {
        match self {
            Overlay::Files(browser) => browser.click(at, double),
            Overlay::Names(chooser) => chooser.click(at, double),
            Overlay::Profiles(catalogue) => catalogue.click(at, double),
        }
    }

    fn scroll(&mut self, up: bool) {
        match self {
            Overlay::Files(browser) => browser.scroll(up),
            Overlay::Names(chooser) => chooser.scroll(up),
            Overlay::Profiles(catalogue) => catalogue.scroll(up),
        }
    }

    fn render(&self, frame: &mut Frame, area: Rect) -> browse::Hits {
        match self {
            Overlay::Files(browser) => browser.render(frame, area),
            Overlay::Names(chooser) => chooser.render(frame, area),
            Overlay::Profiles(catalogue) => catalogue.render(frame, area),
        }
    }
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
            overlay: None,
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
            .filter(|(_, field)| self.shows(&field.shown_for))
            .map(|(index, _)| index)
            .collect()
    }

    /// Does what a `shown_for` guards belong on screen as the form now reads?
    /// Shared by the fields and by a picker's candidates, so a rule narrowed
    /// to one surface hides the same things in both places.
    fn shows(&self, shown_for: &Option<(&'static str, Vec<String>)>) -> bool {
        match shown_for {
            None => true,
            Some((other, allowed)) => self
                .raw(other)
                .is_some_and(|value| allowed.iter().any(|option| option == &value)),
        }
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
        if self.overlay.is_some() {
            return self.handle_picker(key);
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
            KeyCode::Char('o') if key.modifiers.contains(KeyModifiers::CONTROL) => self.pick(),
            // Never typed into the field, whether or not there is anything to
            // keep: a `ctrl-k` that lands as a literal `k` in the middle of a
            // credential is a credential that no longer works, discovered
            // later as a 401.
            KeyCode::Char('k') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if self.keeping().is_some() {
                    return Outcome::Keep;
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

    /// The field `ctrl-k` would act on, and the value it is holding.
    ///
    /// `None` unless the cursor is on a reference field with a bare credential
    /// in it, which is the only place the offer is drawn.
    pub fn keeping(&self) -> Option<(usize, String)> {
        let field = self.fields.get(self.focus)?;
        if !field.keeps() || !self.visible().contains(&self.focus) {
            return None;
        }
        match &field.value {
            Value::Text(text) => Some((self.focus, text.clone())),
            _ => None,
        }
    }

    /// Write a value into a field by index, as a picker does. What the console
    /// puts the `iap://` reference back through once the store has the value.
    pub fn fill(&mut self, index: usize, value: String) {
        if let Some(Value::Text(text)) = self.fields.get_mut(index).map(|f| &mut f.value) {
            *text = value;
        }
        self.focus(index);
    }

    /// The name of the thing being enrolled, for a store name derived from it.
    /// `as` is what a profile form calls it and `name` is what the others do.
    pub fn subject(&self) -> Option<String> {
        ["as", "name"]
            .iter()
            .map(|key| self.text(key))
            .find(|value| !value.trim().is_empty())
    }

    fn focused_mut(&mut self) -> Option<&mut Value> {
        self.fields
            .get_mut(self.focus)
            .map(|field| &mut field.value)
    }

    /// Is a picker up? The console asks because the wheel and a click mean
    /// different things over one than they do over the form.
    pub fn browsing(&self) -> bool {
        self.overlay.is_some()
    }

    /// Open the focused field's picker: the filesystem for a field that names
    /// a file, the policy file's own names for one that names something in it.
    /// A no-op anywhere else — `ctrl-o` on a header name has nothing to pick.
    pub fn pick(&mut self) {
        let Some(field) = self.fields.get(self.focus) else {
            return;
        };
        // What the field holds, whatever shape it holds it in: the profile
        // picker sits on a `Choice`, and every other picker on a text field.
        let held = field.rendered();
        let text = match &field.value {
            Value::Text(text) => text.as_str(),
            _ => "",
        };
        self.overlay = match field.opens() {
            Some(Opens::Files) => Some(Overlay::Files(Browser::open(self.focus, text))),
            Some(Opens::Profiles) => Some(Overlay::Profiles(Box::new(Catalogue::open(
                self.focus,
                field.catalogue.clone(),
                &held,
            )))),
            Some(Opens::Names) => {
                // Only the candidates this form's own choices leave standing:
                // a rule already narrowed to `kind = mcp` should not be
                // offered an upstream it can never match.
                let offered: Vec<Candidate> = field
                    .offers
                    .iter()
                    .filter(|candidate| self.shows(&candidate.shown_for))
                    .cloned()
                    .collect();
                (!offered.is_empty())
                    .then(|| Overlay::Names(Chooser::open(self.focus, field.what, offered, text)))
            }
            None => return,
        };
    }

    /// A click on a row of the open picker.
    pub fn click_browse(&mut self, at: usize, double: bool) {
        let Some(overlay) = &mut self.overlay else {
            return;
        };
        let picked = overlay.click(at, double);
        self.settle(picked);
    }

    /// The wheel over the open picker.
    pub fn scroll_browse(&mut self, up: bool) {
        if let Some(overlay) = &mut self.overlay {
            overlay.scroll(up);
        }
    }

    fn handle_picker(&mut self, key: KeyEvent) -> Outcome {
        let Some(overlay) = &mut self.overlay else {
            return Outcome::Continue;
        };
        let picked = overlay.handle(key);
        self.settle(picked);
        // Never `Submit`: `enter` in a picker opens a directory or takes a
        // name, and a form that saved itself halfway through choosing one
        // would write whatever the field held before.
        Outcome::Continue
    }

    /// Write back whatever the picker decided, and close it if it is done.
    fn settle(&mut self, picked: Pick) {
        let field = match picked {
            Pick::Continue => return,
            Pick::Close => {
                self.overlay = None;
                return;
            }
            Pick::Chose(value) => {
                let Some(overlay) = self.overlay.take() else {
                    return;
                };
                let at = overlay.field();
                if let Some(field) = self.fields.get_mut(at) {
                    match &mut field.value {
                        Value::Text(text) => {
                            *text = value;
                            field.touched = true;
                        }
                        // The profile picker's field. Moved to the option the
                        // pick names rather than left where it was: a picker
                        // that answered with something the field cannot hold
                        // would close silently and change nothing, which is the
                        // shape of bug this console is built to avoid.
                        Value::Choice { options, selected } => {
                            if let Some(index) = options.iter().position(|option| *option == value)
                            {
                                *selected = index;
                                field.touched = true;
                            }
                        }
                        Value::Flag(_) => {}
                    }
                }
                at
            }
        };
        // Back on the field that was just filled in, not wherever the form
        // happened to be — the picker was opened from there.
        self.focus(field);
    }

    fn edit(&mut self, code: KeyCode) {
        let Some(field) = self.fields.get_mut(self.focus) else {
            return;
        };
        match (code, &mut field.value) {
            (KeyCode::Char(c), Value::Text(text)) => {
                text.push(c);
                field.touched = true;
            }
            (KeyCode::Backspace, Value::Text(text)) => {
                text.pop();
                field.touched = true;
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
            browse: Vec::new(),
            keep: Vec::new(),
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
                let blank = value.trim().is_empty();
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
                // A field with a picker behind it says so on its own line
                // while the cursor is on it — and says it the way every other
                // affordance in this console does, as the key and then what
                // the key does. A lone highlighted word reads as decoration:
                // it tells you a picker exists without telling you how to
                // reach it, which is worse than not drawing it at all.
                //
                // A file field's offer goes the moment you type in it.
                // Sitting immediately past the caret it reads as part of the
                // value being entered — `op://` followed by a highlighted
                // `ctrl-o` is a field that looks like it already contains
                // something it does not — and an offer to go and find a file
                // is noise over somebody who is plainly typing a reference to
                // somewhere else. The key row below keeps it for as long as
                // the cursor is here, so the route is announced without
                // standing in the way of the thing it is announcing itself
                // next to.
                //
                // A list of names goes when one has been chosen, and not
                // before: an ACL rule's `agent` opens on `*`, which is the
                // form's own widest default rather than anything the operator
                // said, and a field nobody has answered yet is exactly where
                // the offer belongs. `ctrl-u` empties it and the offer comes
                // back, as it does for a path.
                // The profile field's offer never comes off. The other two
                // fill in a value you could also have typed, so the offer has
                // done its job once there is one; this one is the only way to
                // read the catalog at all, and the field it sits on always
                // holds something — `— none —` at worst. Taken away on the
                // same rule as the others it would be an affordance that
                // vanished before it was ever needed.
                let offer = field.opens().filter(|opens| match opens {
                    Opens::Files => blank,
                    Opens::Names => blank || !field.touched,
                    Opens::Profiles => true,
                });
                if let (true, Some(opens)) = (focused, offer) {
                    let before = 4 + label_width + shown.chars().count();
                    spans.push(Span::styled(PICK_KEY, key_style()));
                    spans.push(Span::raw(opens.what()));
                    hits.browse.extend(fits(line, before, opens.width()));
                }
                // The other way out of a credential field, and the opposite
                // case to the one above: `ctrl-o browse` is for a field with
                // nothing in it, and this is for a field with the credential
                // itself in it. They never appear together, because a typed
                // value is not blank and a blank field is not a credential.
                //
                // Drawn here rather than left to the save error because by the
                // time the error arrives the operator has typed a credential
                // into a field, been told it is not a reference, and has no way
                // of knowing from the form that the console will take it. This
                // is the moment they can still act on.
                if focused && field.keeps() {
                    let before = 4 + label_width + shown.chars().count();
                    spans.push(Span::styled(KEEP_KEY, key_style()));
                    spans.push(Span::raw(KEEP_WHAT));
                    hits.keep.extend(fits(line, before, keep_width()));
                }
                Line::from(spans)
            })
            .collect();

        frame.render_widget(Paragraph::new(lines), rows[1]);

        let hint: Cow<'_, str> = match self.fields.get(self.focus) {
            Some(field) if field.keeps() => Cow::Owned(format!(
                "{}  —  ctrl-k to let agent-iap keep this value and use a reference to it",
                field.hint
            )),
            Some(field) => match field.opens() {
                Some(opens) => Cow::Owned(format!("{}  —  ctrl-o {}", field.hint, opens.route())),
                None => Cow::Borrowed(field.hint.as_ref()),
            },
            None => Cow::Borrowed(""),
        };
        let footer = match &self.error {
            Some(error) => Paragraph::new(error.as_str()).style(Style::default().fg(Color::Red)),
            None => Paragraph::new(hint.as_ref()).style(Style::default().fg(Color::DarkGray)),
        };
        frame.render_widget(footer.wrap(Wrap { trim: true }), rows[2]);

        // The key row, which is the one line of this dialogue that is always
        // what it says it is. The line above it is the focused field's hint
        // *or* the reason the last save failed — and a form you have just been
        // told needs a `--secret <REF>` is exactly when you want to be told
        // that the console will go and find the file for you. So the key lives
        // down here as well, where an error cannot take it away.
        let mut keys = vec![
            Span::styled(" tab ", key_style()),
            Span::raw(" next  "),
            Span::styled(" ←/→ ", key_style()),
            Span::raw(" choose  "),
            Span::styled(" enter ", key_style()),
            Span::raw(" save  "),
            Span::styled(" esc ", key_style()),
            Span::raw(" cancel"),
        ];
        // One offer, as on the field line above, and for a plainer reason than
        // taste: this row is four keys wide already and the dialogue is 78
        // columns whatever the terminal is, so a second one is an offer drawn
        // off the end of the line — announced, by `fits`, to nobody.
        //
        // Which one is not a close call. `ctrl-o browse` is the offer for a
        // field with nothing in it; a field holding a credential has the one
        // problem this console can solve from here, and `ctrl-o` on it would
        // replace what was typed with a path. Emptying the field with `ctrl-u`
        // brings the picker's offer straight back, exactly as it does on the
        // field's own line.
        let focused = self.fields.get(self.focus);
        if focused.is_some_and(Field::keeps) {
            let before: usize = keys.iter().map(|span| span.content.chars().count()).sum();
            keys.push(Span::raw("  "));
            keys.push(Span::styled(KEEP_KEY, key_style()));
            keys.push(Span::raw(KEEP_WHAT));
            hits.keep.extend(fits(rows[3], before + 2, keep_width()));
        } else if let Some(opens) = focused.and_then(Field::opens) {
            let before: usize = keys.iter().map(|span| span.content.chars().count()).sum();
            keys.push(Span::raw("  "));
            keys.push(Span::styled(PICK_KEY, key_style()));
            keys.push(Span::raw(opens.what()));
            hits.browse.extend(fits(rows[3], before + 2, opens.width()));
        }
        frame.render_widget(
            Paragraph::new(Line::from(keys)).style(Style::default().fg(Color::DarkGray)),
            rows[3],
        );

        // Last, and over everything else: while a picker is up it owns the
        // screen, and the fields behind it are not reachable by a click.
        if let Some(overlay) = &self.overlay {
            hits.browser = Some(overlay.render(frame, area));
        }

        hits
    }
}

/// The key every picker in this console is reached by. ASCII, so `len` is the
/// column count.
const PICK_KEY: &str = " ctrl-o ";

/// The key that hands a typed credential to agent-iap's own store. ASCII, as
/// `PICK_KEY` is.
const KEEP_KEY: &str = " ctrl-k ";
const KEEP_WHAT: &str = " keep";

fn keep_width() -> usize {
    KEEP_KEY.len() + KEEP_WHAT.len()
}

/// Which picker a field opens, and how the offer of it is worded.
///
/// One key, two destinations, because from the operator's side they are the
/// same offer: the console knows something about this field and will go and
/// get it rather than making you remember it.
#[derive(Clone, Copy)]
enum Opens {
    Files,
    Names,
    Profiles,
}

impl Opens {
    /// What the key does, drawn after it. ASCII, as `PICK_KEY` is.
    fn what(self) -> &'static str {
        match self {
            Opens::Files => " browse",
            Opens::Names => " choose",
            Opens::Profiles => " catalog",
        }
    }

    /// The same, spelled out for the hint line under the fields.
    fn route(self) -> &'static str {
        match self {
            Opens::Files => "to pick the file",
            Opens::Names => "to choose from what the policy file holds",
            Opens::Profiles => "for the whole catalog, searchable",
        }
    }

    fn width(self) -> usize {
        PICK_KEY.len() + self.what().len()
    }
}

/// The hit box for something `width` columns wide drawn `before` columns into
/// `line` — or nothing at all, when the line was too narrow to have drawn it
/// where the click would land.
fn fits(line: Rect, before: usize, width: usize) -> Option<Rect> {
    (before + width <= line.width as usize).then(|| Rect {
        x: line.x.saturating_add(before as u16),
        width: width as u16,
        ..line
    })
}

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

    /// A form opened on `bearer` with the cursor on `secret`, which is where
    /// every one of these starts.
    fn on_the_secret() -> Form {
        let mut form = Form::new(Intent::Upstream, "t", "a", auth_fields());
        while form.text("auth") != "bearer" {
            form.handle(KeyEvent::from(KeyCode::Right));
        }
        form.handle(KeyEvent::from(KeyCode::Tab));
        assert_eq!(form.fields[form.focus].key, "secret");
        form
    }

    fn type_in(form: &mut Form, text: &str) {
        for c in text.chars() {
            form.handle(KeyEvent::from(KeyCode::Char(c)));
        }
    }

    /// The offer exists exactly where a credential has been typed where a
    /// reference goes — which used to be a dead end, and is the one state the
    /// operator needs a way out of.
    #[test]
    fn keeping_is_offered_on_a_typed_credential_and_nowhere_else() {
        let mut form = on_the_secret();
        // Nothing typed: the field is blank, and `ctrl-o browse` is the offer.
        assert!(form.keeping().is_none());

        type_in(&mut form, "ghp_areadonlytoken");
        assert_eq!(
            form.keeping().map(|(_, value)| value),
            Some("ghp_areadonlytoken".to_string())
        );

        // A reference is already right. Offering to take a copy of a vault item
        // into a plaintext file is not a favour.
        form.handle(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        type_in(&mut form, "op://Private/GitHub/token");
        assert!(form.keeping().is_none());

        form.handle(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        type_in(&mut form, "env:GITHUB_TOKEN");
        assert!(form.keeping().is_none());
    }

    /// `--header x-api-key` is a header name, not a credential. An offer to
    /// store it would be an offer to put a header name in the credential store
    /// and a `iap://` reference in the header.
    #[test]
    fn a_field_that_takes_no_reference_is_never_offered_the_store() {
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
        type_in(&mut form, "x-api-key");
        assert!(form.keeping().is_none());
    }

    /// `ctrl-k` is never typed. A `k` landing in the middle of a credential is
    /// a credential that no longer works, found later as a 401.
    #[test]
    fn ctrl_k_is_answered_or_ignored_but_never_typed_into_the_field() {
        let ctrl_k = KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL);

        let mut form = on_the_secret();
        type_in(&mut form, "ghp_token");
        assert!(matches!(form.handle(ctrl_k), Outcome::Keep));
        assert_eq!(form.text("secret"), "ghp_token", "nothing typed into it");

        // And where there is nothing to keep it is inert — not a `k`, and not
        // a `Keep` the console would have to answer with an error.
        let mut form = on_the_secret();
        type_in(&mut form, "env:TOKEN");
        assert!(matches!(form.handle(ctrl_k), Outcome::Continue));
        assert_eq!(form.text("secret"), "env:TOKEN");
    }

    /// What the console writes back once the store has the value.
    #[test]
    fn filling_the_field_puts_the_reference_where_the_credential_was() {
        let mut form = on_the_secret();
        type_in(&mut form, "ghp_token");
        let (at, _) = form.keeping().unwrap();
        form.fill(at, "iap://gh".into());
        assert_eq!(form.text("secret"), "iap://gh");
        // And the offer is gone, because the field now holds a reference.
        assert!(form.keeping().is_none());
        assert_eq!(form.auth().secret.as_deref(), Some("iap://gh"));
    }

    /// The name a derived store name is built from, whichever form asked.
    #[test]
    fn the_subject_is_read_from_whichever_key_the_form_names_it_with() {
        let form = Form::new(
            Intent::Upstream,
            "t",
            "a",
            vec![Field::prefilled("name", "name", "", "github")],
        );
        assert_eq!(form.subject().as_deref(), Some("github"));

        // A profile form calls it `as`.
        let form = Form::new(
            Intent::Profile,
            "t",
            "a",
            vec![Field::prefilled("as", "name", "", "github-2")],
        );
        assert_eq!(form.subject().as_deref(), Some("github-2"));

        let form = Form::new(Intent::Upstream, "t", "a", auth_fields());
        assert_eq!(form.subject(), None, "nothing named yet");
    }
}
