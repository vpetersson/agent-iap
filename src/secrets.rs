//! Secret references and resolution.
//!
//! The whole point of the IAP is that the agent never sees the real credential.
//! Credentials therefore live behind a *reference* in the config file — the file
//! itself stays safe to commit — and are resolved inside this process only.

use anyhow::{bail, Context, Result};
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use zeroize::Zeroize;

/// A resolved credential. Never `Debug`-printed, zeroed when the last handle drops.
#[derive(Clone)]
pub struct Secret(Arc<SecretInner>);

struct SecretInner(String);

impl Drop for SecretInner {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Secret {
    pub fn new(value: String) -> Self {
        Secret(Arc::new(SecretInner(value)))
    }

    pub fn expose(&self) -> &str {
        &self.0 .0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// Where a secret comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRef {
    /// `env:ANTHROPIC_API_KEY`
    Env(String),
    /// `file:/run/secrets/anthropic`
    File(PathBuf),
    /// `op://Private/Anthropic/credential` — resolved with the 1Password CLI.
    ///
    /// `reference` is what `op` is handed: the reference with any `?account=`
    /// taken off, and every other query parameter — 1Password's own
    /// `?attribute=otp`, `?ssh-format=openssh` — left on. `account` is the
    /// 1Password account the reference named for itself, if it named one.
    OnePassword {
        reference: String,
        account: Option<String>,
    },
    /// `iap://github-readonly` — a credential agent-iap keeps itself, in its
    /// own store rather than in the policy file. See `store`.
    Managed(String),
    /// `literal:sk-...` — supported for tests and demos, warned about on load.
    Literal(String),
}

impl SecretRef {
    pub fn parse(raw: &str) -> Result<Self> {
        // Whitespace *inside* a reference is part of it: a 1Password vault,
        // item, section or field may be called `agent-iap tls` or `private
        // key`, and `op read` takes the whole reference as one argument. The
        // whitespace *around* one never is — a reference is a pointer, and a
        // stray space in front of it is a typo rather than a different vault.
        // Trimmed here so the policy file and the flags agree with the console,
        // whose fields have always been trimmed on the way in.
        let reference = raw.trim();

        if let Some(rest) = reference.strip_prefix("env:") {
            if rest.is_empty() {
                bail!("`env:` secret reference is missing a variable name");
            }
            Ok(SecretRef::Env(rest.to_string()))
        } else if let Some(rest) = reference.strip_prefix("file:") {
            if rest.is_empty() {
                bail!("`file:` secret reference is missing a path");
            }
            Ok(SecretRef::File(PathBuf::from(rest)))
        } else if reference.starts_with("op://") {
            let (reference, account) = split_op_account(reference)?;
            Ok(SecretRef::OnePassword { reference, account })
        } else if let Some(rest) = reference.strip_prefix("iap://") {
            // A name, not a credential — so the same trimming the other
            // pointers get, and the same validation `secret set` applied when
            // it wrote the name down. A typo here is caught where it is typed
            // rather than at the next `op`-less resolution.
            crate::store::Store::check_name(rest)
                .context("`iap://` names a credential stored by `agent-iap secret set`")?;
            Ok(SecretRef::Managed(rest.to_string()))
        } else if let Some(rest) = raw.trim_start().strip_prefix("literal:") {
            // The one scheme whose payload *is* the credential, so only the
            // space in front of it comes off: a trailing one may be part of the
            // value, and silently shortening a credential is not this parser's
            // to do.
            Ok(SecretRef::Literal(rest.to_string()))
        } else {
            // `literal:` is deliberately not offered here. It is the one
            // spelling that would put the credential in the policy file, so
            // every enrolment surface refuses it — and this message used to
            // suggest it, which meant a pasted value was answered by a scheme
            // that was then refused for a different reason, with no way out
            // between them (SIRI-215). `iap://` is the way out: the value is
            // kept by agent-iap and the file still holds a pointer.
            bail!(
                "unrecognised secret reference `{}` — a reference points at the credential \
                 rather than being it. Expected `env:NAME`, `file:/path`, \
                 `op://vault/item/field`, or `iap://NAME` for a value agent-iap keeps itself \
                 (`agent-iap secret set NAME`)",
                redact_for_error(reference)
            )
        }
    }

    /// True for reference kinds that put the plaintext in the config file itself.
    ///
    /// `iap://` is not one of them, and that is the whole reason it exists: the
    /// credential is in agent-iap's own store under the state directory, and
    /// the policy file holds the name of it. A file full of `iap://` references
    /// is as safe to commit as one full of `op://` ones.
    pub fn is_inline(&self) -> bool {
        matches!(self, SecretRef::Literal(_))
    }
}

/// A reference rendered for display. Everything but `literal:` is a *pointer*
/// to a credential and safe to print; `literal:` is the credential itself, so it
/// is masked — `agent-iap list` must never put a secret on a terminal.
pub fn display_ref(raw: &str) -> String {
    match SecretRef::parse(raw) {
        Ok(SecretRef::Literal(_)) => "literal:***".to_string(),
        // The reference as the resolver will use it, which is the trimmed one —
        // an inventory that prints a stray space is an inventory nobody can
        // match against the vault.
        Ok(_) => raw.trim().to_string(),
        // Unparseable references never resolve, but a pasted credential is
        // exactly how one gets written, so mask it the way errors do.
        Err(_) => redact_for_error(raw),
    }
}

/// Take `?account=` off a 1Password reference, and keep everything else.
///
/// The account is agent-iap's to read and not `op`'s: handed through, it would
/// be taken for a field query and the read would fail on a field nobody asked
/// for. 1Password's own parameters are the opposite — `?attribute=otp` and
/// `?ssh-format=openssh` change what `op` returns — so they stay, in the order
/// they were written.
fn split_op_account(reference: &str) -> Result<(String, Option<String>)> {
    let Some((path, query)) = reference.split_once('?') else {
        return Ok((reference.to_string(), None));
    };
    let mut account = None;
    let mut kept = Vec::new();
    for param in query.split('&') {
        let value = match param.split_once('=') {
            Some(("account", value)) => value,
            None if param == "account" => "",
            _ => {
                kept.push(param);
                continue;
            }
        };
        let value = value.trim();
        if value.is_empty() {
            bail!(
                "`{path}` has `?account=` with no account after it — name the 1Password account \
                 by its sign-in address (`my.1password.com`), account ID or user ID"
            );
        }
        if account.replace(value.to_string()).is_some() {
            bail!(
                "`{path}` names `?account=` more than once; a reference is read from one account"
            );
        }
    }
    let reference = match kept.is_empty() {
        true => path.to_string(),
        false => format!("{path}?{}", kept.join("&")),
    };
    Ok((reference, account))
}

/// Does `raw` name its 1Password account itself, with `?account=`?
///
/// Output that says which account a reference was read from says it only where
/// the policy chose — the reference already says so where it did not.
pub fn names_op_account(raw: &str) -> bool {
    matches!(
        SecretRef::parse(raw),
        Ok(SecretRef::OnePassword {
            account: Some(_),
            ..
        })
    )
}

/// Which 1Password account each `op://` reference is read from.
///
/// Most precise first: the reference's own `?account=`, then the `op_account`
/// of the upstream or MCP server it belongs to, then `[secrets] op_account`.
/// Nothing at all is today's behaviour — no `--account`, and `op` picks the
/// account it would have picked anyway.
///
/// Keyed by the reference rather than by where it sits, because that is what
/// the resolver is asked about. `Config::validate` refuses a reference that
/// would need two different accounts depending on which service used it, so
/// one answer per reference is always the right answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpAccounts {
    default: Option<String>,
    targets: HashMap<String, String>,
}

impl OpAccounts {
    /// `default` is `[secrets] op_account`, for every reference nothing more
    /// specific speaks for.
    pub fn new(default: Option<String>) -> Self {
        OpAccounts {
            default: default.filter(|account| !account.trim().is_empty()),
            targets: HashMap::new(),
        }
    }

    /// Read `raw` from `account` unless it names an account itself — the
    /// `op_account` of the service that uses it.
    pub fn assign(&mut self, raw: &str, account: &str) {
        self.targets
            .insert(raw.trim().to_string(), account.trim().to_string());
    }

    /// The account `raw` is read from, or `None` for "whichever `op` defaults
    /// to" — and always `None` for anything that is not an `op://` reference.
    pub fn account_for(&self, raw: &str) -> Option<String> {
        match SecretRef::parse(raw) {
            Ok(SecretRef::OnePassword {
                account: Some(account),
                ..
            }) => Some(account),
            Ok(SecretRef::OnePassword { account: None, .. }) => self
                .targets
                .get(raw.trim())
                .or(self.default.as_ref())
                .cloned(),
            _ => None,
        }
    }
}

/// The account, said the way an error says it. Empty for the default one,
/// so a policy that never names an account reads exactly as it always did.
fn in_account(account: Option<&str>) -> String {
    match account {
        Some(account) => format!(" for 1Password account `{account}`"),
        None => String::new(),
    }
}

/// `--account <account>` for `op`, or nothing.
fn account_args(account: Option<&str>) -> Vec<&str> {
    match account {
        Some(account) => vec!["--account", account],
        None => vec![],
    }
}

fn redact_for_error(raw: &str) -> String {
    // Never echo a possible credential back into logs or error strings.
    match raw.split_once(':') {
        Some((scheme, _)) => format!("{scheme}:***"),
        None => "***".to_string(),
    }
}

/// Resolves secret references, caching results so a 1Password lookup happens once.
pub struct SecretResolver {
    cache: Mutex<HashMap<String, Secret>>,
    op_bin: String,
    /// Which 1Password account each `op://` reference is read from. Swapped
    /// on reload, which is why it is behind a lock rather than fixed at
    /// construction.
    accounts: RwLock<OpAccounts>,
    /// Where `iap://` references are read from. Defaults to the store this
    /// machine uses, so every existing caller gets one without being changed —
    /// the path is only named by a test, which must not read the operator's.
    store: crate::store::Store,
}

/// How many secret references are read at the same time.
///
/// The `op://` ones no longer come through here — they are read together, in
/// one process, by `read_onepassword_together`. What is left is `env:`,
/// `file:` and `literal:`, which are a variable lookup and a small read, plus
/// the one-at-a-time fallback for a batch that did not come off. The bound
/// stays so that neither of those becomes a fan-out nobody chose.
const REFRESH_AT_ONCE: usize = 8;

fn render(error: anyhow::Error) -> String {
    format!("{error:#}")
}

/// Start `op`, waiting out an executable that is momentarily busy.
///
/// `ETXTBSY` is what `exec` says when the binary is open for writing somewhere
/// else: a package manager part-way through replacing `op`, or another thread
/// of a program that has just written one and not closed it yet. It clears on
/// its own in microseconds, and the alternative to waiting is a reload that
/// failed for a reason which has nothing to do with the policy — or, worse, a
/// batch that "could not run" and sends every reference to the vault on its own.
fn spawn_op(command: &mut Command) -> std::io::Result<std::process::Child> {
    const TRIES: usize = 4;
    const BUSY: std::time::Duration = std::time::Duration::from_millis(5);

    for _ in 1..TRIES {
        match command.spawn() {
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(BUSY)
            }
            settled => return settled,
        }
    }
    command.spawn()
}

/// What a reference is told when 1Password refused earlier in the same read.
///
/// It is not "this reference is broken" — nothing has been asked about it. The
/// operator has one thing to fix, named on the line that does carry a reason,
/// and the rest of the list says why it is a list of one.
const NOT_ASKED_AGAIN: &str = "not read — 1Password refused this read and was not asked again";

/// The same, naming the account that refused. "Not signed in" is about one
/// account now, and a policy reading from two needs to know which.
fn not_asked_again(account: Option<&str>) -> String {
    match account {
        Some(account) => format!(
            "not read — 1Password account `{account}` refused this read and was not asked again"
        ),
        None => NOT_ASKED_AGAIN.to_string(),
    }
}

/// Did 1Password decline to answer *at all*, as opposed to answering about a
/// reference?
///
/// The difference is the whole of what SIRI-205 had left. "Authorization prompt
/// dismissed" is a human closing a dialogue; reading the next reference asks
/// them again, and reading eight asks them eight times — which is the thing
/// they were closing dialogues about. A field that is not there, a vault that is
/// not theirs, an `op` too old to have `inject`: those are answers, the
/// authorization behind them is already given, and reading the rest one at a
/// time costs nothing but a moment.
///
/// Matched on text because `op` exits 1 for everything; the needles are
/// deliberately broad, since the cost of calling a reference error a refusal is
/// one re-run, and the cost of calling a refusal a reference error is the stack
/// of dialogues this exists to prevent.
pub fn is_authorization_failure(error: &str) -> bool {
    const REFUSALS: [&str; 8] = [
        "authoriz",
        "error initializing client",
        "not signed in",
        "no account",
        "session expired",
        "desktop app",
        "biometric",
        "unlock",
    ];
    let error = error.to_ascii_lowercase();
    REFUSALS.iter().any(|needle| error.contains(needle))
}

impl SecretResolver {
    pub fn new(op_bin: impl Into<String>) -> Self {
        SecretResolver {
            cache: Mutex::new(HashMap::new()),
            op_bin: op_bin.into(),
            accounts: RwLock::new(OpAccounts::default()),
            store: crate::store::Store::at(crate::store::Store::default_path()),
        }
    }

    /// The resolver a policy file describes: its `op` binary, its store, and
    /// the 1Password account each of its references is read from.
    pub fn for_config(config: &crate::config::Config) -> Self {
        SecretResolver::new(config.server.op_binary.clone())
            .with_store(config.server.secret_store_path())
            .with_op_accounts(config.op_accounts())
    }

    /// Read `op://` references from the accounts `accounts` names.
    pub fn with_op_accounts(self, accounts: OpAccounts) -> Self {
        *self.accounts.write() = accounts;
        self
    }

    /// Point this resolver at a reloaded policy's accounts, and hand back the
    /// ones it had, so a reload that is refused can put them back.
    pub fn set_op_accounts(&self, accounts: OpAccounts) -> OpAccounts {
        std::mem::replace(&mut *self.accounts.write(), accounts)
    }

    /// The 1Password account `raw` is read from, if it is an `op://`
    /// reference read from anything but `op`'s default.
    pub fn op_account(&self, raw: &str) -> Option<String> {
        self.accounts.read().account_for(raw)
    }

    /// What a value is cached under: the reference, and for one read from a
    /// named account, the account too. A reload that moves a reference to
    /// another account must not be answered with the value the old account
    /// gave — the spelling in the file did not change, but the credential
    /// behind it did.
    fn key(&self, raw: &str) -> String {
        match self.op_account(raw) {
            Some(account) => format!("{raw}\u{0}{account}"),
            None => raw.to_string(),
        }
    }

    /// Read `iap://` references from a store somewhere else. For tests, and for
    /// anything that has already decided where the state directory is.
    pub fn with_store(mut self, path: impl Into<PathBuf>) -> Self {
        self.store = crate::store::Store::at(path);
        self
    }

    /// The store behind this resolver's `iap://` references.
    pub fn store(&self) -> &crate::store::Store {
        &self.store
    }

    /// Seed the cache directly. Used by tests and by `--standalone` bootstrapping.
    pub fn preset(&self, raw: &str, value: Secret) {
        let key = self.key(raw);
        self.cache.lock().insert(key, value);
    }

    /// Re-read a reference from its source and replace the cached value with
    /// what comes back.
    ///
    /// The cache exists so twenty upstreams sharing a vault item cost one `op`
    /// call — the right default for a value that stays put under a running
    /// proxy. `refresh` is how a value that *did* move takes effect without a
    /// restart: a renewed certificate, replaced on disk every ninety days, and
    /// a rotated credential, whose reference string is unchanged but whose
    /// secret behind it is new. Nothing in the file says either of those
    /// happened, so this is reached from the triggers that mean *re-read*:
    /// `SIGHUP`, the console's `r`, and its `c` on the credentials pane.
    ///
    /// The old value is replaced only if the re-read succeeds. A refresh that
    /// cannot reach the source — a locked vault, a half-written file — returns
    /// the error and leaves the last good value in the cache, so a reload that
    /// refuses does not also evict a credential the proxy is still serving.
    pub fn refresh(&self, raw: &str) -> Result<Secret> {
        let secret = self.read(raw)?;
        let key = self.key(raw);
        self.cache.lock().insert(key, secret.clone());
        Ok(secret)
    }

    /// Re-read many references at once, one answer per reference, in the order
    /// they were given. Every one of them goes to its source.
    ///
    /// `refresh` on an `op://` reference is a subprocess and a network round
    /// trip, and these used to be done one after another: a policy naming eight
    /// of them cost eight vault lookups back to back. That is paid on startup,
    /// on every `SIGHUP`, and on the console's `r`, where it was seconds of a
    /// console that had stopped drawing the request somebody was waiting to
    /// answer.
    ///
    /// The `op://` ones now go in a single `op`, which is both halves of that
    /// cost at once — one round trip instead of eight, and, because the desktop
    /// app authorizes a process, one authorization dialogue instead of eight
    /// (see `prime_onepassword`). Forking them together fixed the waiting and
    /// made the dialogues simultaneous, which was worse. What is left here runs
    /// in parallel because nothing in it depends on anything else in it.
    ///
    /// Only *whether* each one resolved comes back. Every caller is asking
    /// about the references rather than about the credentials behind them, and
    /// the values themselves are already where they are wanted — in the cache.
    pub fn refresh_all(&self, references: &[String]) -> Vec<Result<(), String>> {
        self.read_all(references, true)
    }

    /// The same, cache-first: a reference this process has already read is
    /// answered from what it read, and only one it has never seen costs a
    /// lookup.
    ///
    /// What a reload nobody asked for uses. An `[[acl]]` rule appended by the
    /// approval dialogue says nothing about any credential, and re-reading
    /// twenty references because of it is twenty vault lookups for an edit that
    /// touched none of them — which on a desktop 1Password is an authorization
    /// prompt in front of the operator every time they answer an `ask`
    /// (SIRI-205). A reference the edit *added* or repointed is not in the
    /// cache under its new spelling, so it is still read here and a policy that
    /// names a credential this process cannot get is still refused at reload
    /// rather than on the first live call.
    pub fn resolve_all(&self, references: &[String]) -> Vec<Result<(), String>> {
        self.read_all(references, false)
    }

    fn read_one(&self, reference: &str, fresh: bool) -> Result<(), String> {
        match fresh {
            true => self.refresh(reference),
            false => self.resolve(reference),
        }
        .map(|_| ())
        .map_err(render)
    }

    fn read_all(&self, references: &[String], fresh: bool) -> Vec<Result<(), String>> {
        // 1Password first, and apart from everything else. However many
        // references this pass needs from the vault, it is one process if it
        // can be — and it never asks a second time once the answer was no.
        let vault = self.read_onepassword_pass(references, fresh);
        let read_one = |reference: &String| match vault.get(reference.as_str()) {
            Some(answer) => answer.clone(),
            // Everything the vault pass did not take: `env:`, `file:`,
            // `iap://`, `literal:`, and the `op://` references it had no reason
            // to read because this process already holds them.
            None => self.read_one(reference, fresh),
        };

        if references.len() < 2 {
            return references.iter().map(read_one).collect();
        }

        let width = references.len().div_ceil(REFRESH_AT_ONCE);
        std::thread::scope(|scope| {
            let running: Vec<_> = references
                .chunks(width)
                .map(|chunk| {
                    (
                        chunk,
                        scope.spawn(|| chunk.iter().map(&read_one).collect::<Vec<_>>()),
                    )
                })
                .collect();
            running
                .into_iter()
                .flat_map(|(chunk, handle)| match handle.join() {
                    Ok(answers) => answers,
                    // A panicked read is not a reference that resolved. Fail
                    // closed: every reference in that chunk is reported
                    // unresolved, which is what refuses the policy.
                    Err(_) => chunk
                        .iter()
                        .map(|_| Err("panicked while reading this reference".to_string()))
                        .collect(),
                })
                .collect()
        })
    }

    /// Every `op://` reference this pass needs from the vault, read in as few
    /// `op` processes as it can be done in — and in none at all once 1Password
    /// has said no. One answer per reference, keyed by the spelling the policy
    /// file used.
    ///
    /// A process is the unit of authorization on a desktop 1Password: each `op`
    /// is a separate client asking the app for CLI access. A proxy fronting
    /// eight vault-backed services asked eight times, and asked them at once,
    /// so the grant given to the first dialogue could not cover the seven
    /// already stacked behind it. One `op inject` is one dialogue, whatever the
    /// policy names.
    ///
    /// The batch is not promised, and *how* it fails decides what happens next.
    ///
    /// * 1Password refused — the prompt was dismissed, the app is not running,
    ///   nobody is signed in. Nothing was authorized, so reading one at a time
    ///   would put the same question in front of the same person once per
    ///   reference. That is the bug, not the fallback: every reference gets the
    ///   one reason, and no further `op` runs.
    /// * Anything else — an `op` too old for `inject`, a template it would not
    ///   take. The authorization is already given, so reading each one costs a
    ///   moment and nothing else, and it buys back the per-reference error an
    ///   operator needs: `op inject` fails a template whole and names one
    ///   cause, and "which of your eight is the broken one" is not a question a
    ///   policy file should have to be bisected to answer. Sequential, and it
    ///   stops at the first refusal, for the reason above.
    ///
    /// A policy reading from more than one 1Password account is one batch per
    /// account: `op` reads from one account per process, and `--account` is
    /// how it is told which. The accounts are asked one after another, in the
    /// order the file first names them, and a refusal stops the account that
    /// refused — being signed out of one account says nothing about another.
    fn read_onepassword_pass(
        &self,
        references: &[String],
        fresh: bool,
    ) -> HashMap<String, Result<(), String>> {
        let wanted = self.onepassword_wanted(references, fresh);
        let mut answers = HashMap::new();
        for (account, group) in self.by_account(&wanted) {
            answers.extend(self.read_onepassword_account(&group, account.as_deref()));
        }
        answers
    }

    /// `references` split by the 1Password account each is read from, the
    /// accounts in the order they first appear and the references in theirs.
    fn by_account<'a>(&self, references: &[&'a str]) -> Vec<(Option<String>, Vec<&'a str>)> {
        let accounts = self.accounts.read();
        let mut groups: Vec<(Option<String>, Vec<&'a str>)> = Vec::new();
        for raw in references {
            let account = accounts.account_for(raw);
            match groups.iter_mut().find(|(group, _)| *group == account) {
                Some((_, group)) => group.push(raw),
                None => groups.push((account, vec![raw])),
            }
        }
        groups
    }

    /// One account's share of a pass: one `op inject` if it can be, one `op
    /// read` each if it cannot, and nothing more once that account refused.
    fn read_onepassword_account(
        &self,
        wanted: &[&str],
        account: Option<&str>,
    ) -> HashMap<String, Result<(), String>> {
        let mut answers = HashMap::new();
        if wanted.is_empty() {
            return answers;
        }

        // One reference is already one process, and `op read` says more about
        // it than `op inject` would.
        if wanted.len() > 1 {
            match self.read_onepassword_together(wanted, account) {
                Ok(values) => {
                    let keys: Vec<String> = wanted.iter().map(|raw| self.key(raw)).collect();
                    let mut cache = self.cache.lock();
                    for ((raw, key), value) in wanted.iter().zip(keys).zip(values) {
                        // The one answer `op read` calls an error rather than a
                        // value, kept an error here.
                        if value.expose().is_empty() {
                            answers.insert(
                                (*raw).to_string(),
                                Err(format!("`{}` resolved to an empty value", display_ref(raw))),
                            );
                            continue;
                        }
                        cache.insert(key, value);
                        answers.insert((*raw).to_string(), Ok(()));
                    }
                    return answers;
                }
                Err(error) => {
                    let error = render(error);
                    if is_authorization_failure(&error) {
                        tracing::warn!(
                            %error,
                            references = wanted.len(),
                            account = account.unwrap_or("(default)"),
                            "1Password would not authorize this read; not asking again for it"
                        );
                        // The reason once, on the first line, and the rest
                        // saying why they are not eight more reasons. Eight
                        // copies of the same sentence is a wall an operator
                        // has to read all of to learn there is one thing wrong.
                        for (at, raw) in wanted.iter().enumerate() {
                            let answer = match at {
                                0 => error.clone(),
                                _ => not_asked_again(account),
                            };
                            answers.insert((*raw).to_string(), Err(answer));
                        }
                        return answers;
                    }
                    // Loud, because the consequence is visible and the cause is
                    // not: one process becomes one per reference, and on a
                    // desktop 1Password that is the difference between one
                    // dialogue and a column of them. An operator seeing the
                    // dialogues should be able to find out why from the log.
                    tracing::warn!(
                        %error,
                        references = wanted.len(),
                        account = account.unwrap_or("(default)"),
                        "could not read the 1Password references together; \
                         falling back to one `op read` each"
                    );
                }
            }
        }

        let mut refused: Option<String> = None;
        for raw in wanted {
            if refused.is_some() {
                answers.insert((*raw).to_string(), Err(not_asked_again(account)));
                continue;
            }
            match self.read(raw) {
                Ok(value) => {
                    let key = self.key(raw);
                    self.cache.lock().insert(key, value);
                    answers.insert((*raw).to_string(), Ok(()));
                }
                Err(error) => {
                    let error = render(error);
                    if is_authorization_failure(&error) {
                        refused = Some(error.clone());
                    }
                    answers.insert((*raw).to_string(), Err(error));
                }
            }
        }
        answers
    }

    /// The `op://` references a pass has to go to the vault for: the ones this
    /// process has never read, or all of them when the caller asked for a
    /// re-read. Deduplicated — twenty upstreams sharing a vault item are one
    /// question — and in the order the file named them, which is the order the
    /// failures come back in.
    fn onepassword_wanted<'a>(&self, references: &'a [String], fresh: bool) -> Vec<&'a str> {
        let mut seen = HashSet::new();
        let mut wanted = Vec::new();
        for raw in references {
            if !matches!(SecretRef::parse(raw), Ok(SecretRef::OnePassword { .. })) {
                continue;
            }
            // Cache-first means this one is not going near `op`, so it is not
            // part of the question being asked.
            if !fresh && self.cache.lock().contains_key(&self.key(raw)) {
                continue;
            }
            if seen.insert(raw.as_str()) {
                wanted.push(raw.as_str());
            }
        }
        wanted
    }

    /// The single `op` invocation: a template naming every reference, answered
    /// with every value.
    ///
    /// `op read` takes one reference; `op inject` takes a template and fills in
    /// each `{{ op://… }}` it finds. The template here is the references and
    /// nothing else, separated by a marker drawn fresh each time — a credential
    /// can be any bytes at all, including a line that looks like a separator,
    /// and 122 random bits is what makes "the value contained the delimiter"
    /// not a thing that happens. Anything unexpected in the shape of the answer
    /// is an error rather than a guess: a mis-split here would hand one
    /// service's credential to another.
    fn read_onepassword_together(
        &self,
        references: &[&str],
        account: Option<&str>,
    ) -> Result<Vec<Secret>> {
        use std::io::Write;

        let marker = format!("--{}--", uuid::Uuid::new_v4().simple());
        let template = references
            .iter()
            // The reference as `op` knows it: trimmed, for the same reason
            // `read` trims it — the whitespace around one is a typo, not part
            // of the field's name — and without the `?account=` that is this
            // process's business, which `--account` carries instead.
            .map(|raw| match SecretRef::parse(raw) {
                Ok(SecretRef::OnePassword { reference, .. }) => {
                    Ok(format!("{{{{ {reference} }}}}"))
                }
                _ => Err(anyhow::anyhow!(
                    "`{}` is not a 1Password reference",
                    display_ref(raw)
                )),
            })
            .collect::<Result<Vec<_>>>()?
            .join(&marker);

        let mut child = spawn_op(
            Command::new(&self.op_bin)
                .arg("inject")
                .args(account_args(account))
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped()),
        )
        .with_context(|| format!("running `{} inject`{}", self.op_bin, in_account(account)))?;
        let mut stdin = child
            .stdin
            .take()
            .context("`op inject` accepted no template")?;
        // Kept rather than returned. An `op` that objects to something before
        // it reads the template — not signed in, a flag it does not have —
        // exits while this write is still going, and the write then fails with
        // a broken pipe. Reporting *that* loses the only thing worth knowing:
        // 1Password's own reason, which is on the process's stderr, and which
        // decides whether the references are read one at a time next or not
        // asked about again at all. The write is asked about after the process
        // has had its say.
        let wrote = stdin.write_all(template.as_bytes());
        drop(stdin);
        let output = child
            .wait_with_output()
            .context("waiting for `op inject`")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "`op inject` failed{} ({}): {}",
                in_account(account),
                output.status,
                stderr.trim()
            );
        }
        // A process that says it succeeded on a template it did not get is a
        // different problem, and this is where it surfaces.
        wrote.context("writing the template to `op inject`")?;

        let mut filled =
            String::from_utf8(output.stdout).context("1Password returned a non-UTF-8 secret")?;
        let values: Vec<&str> = filled.split(marker.as_str()).collect();
        if values.len() != references.len() {
            let answered = values.len();
            filled.zeroize();
            bail!(
                "`op inject` answered {answered} of {} references",
                references.len()
            );
        }
        let secrets: Vec<Secret> = values
            .into_iter()
            // The same trailing newline `op read --no-newline` is asked not to
            // add, so a value read this way is the value read the other way.
            .map(|value| Secret::new(value.trim_end_matches(['\n', '\r']).to_string()))
            .collect();
        // Every credential in the file passed through this one buffer; a
        // `Secret` zeroes itself and the thing it was cut out of should too.
        filled.zeroize();
        Ok(secrets)
    }

    /// Resolve a raw reference string, returning a cached value when there is
    /// one. Blocking: 1Password shells out to `op`.
    pub fn resolve(&self, raw: &str) -> Result<Secret> {
        let key = self.key(raw);
        if let Some(hit) = self.cache.lock().get(&key) {
            return Ok(hit.clone());
        }
        let secret = self.read(raw)?;
        self.cache.lock().insert(key, secret.clone());
        Ok(secret)
    }

    /// Read a reference straight from its source, touching no cache on either
    /// side. The shared body of `resolve` and `refresh`.
    fn read(&self, raw: &str) -> Result<Secret> {
        Ok(match SecretRef::parse(raw)? {
            SecretRef::Env(name) => {
                let value = std::env::var(&name).with_context(|| {
                    format!("environment variable `{name}` is not set (from `env:{name}`)")
                })?;
                Secret::new(value)
            }
            SecretRef::File(path) => {
                let value = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading secret file `{}`", path.display()))?;
                Secret::new(value.trim_end_matches(['\n', '\r']).to_string())
            }
            SecretRef::OnePassword { reference, .. } => {
                self.resolve_onepassword(&reference, self.op_account(raw).as_deref())?
            }
            SecretRef::Managed(name) => self.store.get(&name)?,
            SecretRef::Literal(value) => Secret::new(value),
        })
    }

    fn resolve_onepassword(&self, reference: &str, account: Option<&str>) -> Result<Secret> {
        let child = spawn_op(
            Command::new(&self.op_bin)
                .args(["read", "--no-newline", reference])
                .args(account_args(account))
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped()),
        )
        .with_context(|| {
            format!(
                "running `{}` — install the 1Password CLI to use `op://` references",
                self.op_bin
            )
        })?;
        let output = child
            .wait_with_output()
            .with_context(|| format!("waiting for `{} read`", self.op_bin))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "`op read {reference}` failed{} ({}): {}",
                in_account(account),
                output.status,
                stderr.trim()
            );
        }

        let value = String::from_utf8(output.stdout)
            .context("1Password returned a non-UTF-8 secret")?
            .trim_end_matches(['\n', '\r'])
            .to_string();

        if value.is_empty() {
            bail!(
                "`op read {reference}` returned an empty value{}",
                in_account(account)
            );
        }
        Ok(Secret::new(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_password(reference: &str) -> SecretRef {
        SecretRef::OnePassword {
            reference: reference.into(),
            account: None,
        }
    }

    #[test]
    fn parses_every_supported_scheme() {
        assert_eq!(
            SecretRef::parse("env:TOKEN").unwrap(),
            SecretRef::Env("TOKEN".into())
        );
        assert_eq!(
            SecretRef::parse("file:/run/secrets/x").unwrap(),
            SecretRef::File(PathBuf::from("/run/secrets/x"))
        );
        assert_eq!(
            SecretRef::parse("op://Private/Anthropic/credential").unwrap(),
            one_password("op://Private/Anthropic/credential")
        );
        assert_eq!(
            SecretRef::parse("literal:hunter2").unwrap(),
            SecretRef::Literal("hunter2".into())
        );
    }

    /// A 1Password vault, item, section or field is named by a human, so it has
    /// spaces in it: `op://Infra/agent-iap tls/private key` is one reference,
    /// not three words. The whole thing is the argument `op read` is handed.
    #[test]
    fn whitespace_inside_a_1password_reference_is_part_of_it() {
        for raw in [
            "op://Infra/agent-iap tls/private key",
            "op://Private/Anthropic API/credential",
            // vault / item / section / field, the four-segment form
            "op://development/aws/Access Keys/access_key_id",
        ] {
            assert_eq!(SecretRef::parse(raw).unwrap(), one_password(raw), "`{raw}`");
            assert_eq!(display_ref(raw), raw);
        }
    }

    /// And the whitespace *around* one is not. A leading space used to make a
    /// perfectly good reference "unrecognised" — reported as `op:***`, which
    /// redacts away the only part that would have explained it — and a trailing
    /// one used to be handed to `op` as part of the field name.
    #[test]
    fn whitespace_around_a_reference_is_a_typo_and_not_part_of_it() {
        let wanted = "op://Infra/agent-iap tls/private key";
        for raw in [
            " op://Infra/agent-iap tls/private key",
            "op://Infra/agent-iap tls/private key ",
            "\top://Infra/agent-iap tls/private key\n",
        ] {
            assert_eq!(
                SecretRef::parse(raw).unwrap(),
                one_password(wanted),
                "`{raw}`"
            );
            assert_eq!(display_ref(raw), wanted, "`{raw}`");
        }

        assert_eq!(
            SecretRef::parse(" env:TOKEN\n").unwrap(),
            SecretRef::Env("TOKEN".into())
        );
        assert_eq!(
            SecretRef::parse(" file:/run/secrets/x ").unwrap(),
            SecretRef::File(PathBuf::from("/run/secrets/x"))
        );
    }

    /// `literal:` is the credential rather than a pointer to one, so trimming
    /// its payload would quietly change a secret. Only the space in front of
    /// the scheme comes off.
    #[test]
    fn a_literal_keeps_the_value_it_was_given() {
        assert_eq!(
            SecretRef::parse("  literal:hunter2 ").unwrap(),
            SecretRef::Literal("hunter2 ".into())
        );
    }

    /// End to end, through a stand-in for the 1Password CLI: the reference
    /// arrives as one argument with its spaces intact. `op read` is never run
    /// through a shell, so nothing here needs quoting — this is the test that
    /// says so.
    #[cfg(unix)]
    #[test]
    fn a_1password_reference_reaches_op_as_a_single_argument() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let op = dir.path().join("op");
        // Echoes back the reference it was given, and refuses to be given two.
        std::fs::write(
            &op,
            "#!/bin/sh\n\
             [ \"$1\" = read ] || exit 2\n\
             [ \"$2\" = --no-newline ] || exit 2\n\
             [ $# -eq 3 ] || exit 3\n\
             printf '%s' \"$3\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();

        let reference = "op://Infra/agent-iap tls/private key";
        let resolver = SecretResolver::new(op.to_str().unwrap());
        assert_eq!(resolver.resolve(reference).unwrap().expose(), reference);

        // And the trimmed form is what a reference written with a stray space
        // resolves to, rather than a field name with a space on the end.
        assert_eq!(
            resolver
                .resolve(&format!(" {reference}\n"))
                .unwrap()
                .expose(),
            reference
        );
    }

    /// A `1Password` stand-in that answers both ways the real one is asked —
    /// `op read <reference>` for one, `op inject` for a template naming many —
    /// and writes down every invocation.
    ///
    /// Counting invocations is the point rather than an aside: a process is the
    /// unit of authorization on a desktop 1Password, so the number of times
    /// this script runs is the number of dialogues the operator is shown.
    ///
    /// `millis` makes it take as long as the real one does, for the tests where
    /// the shape of the cost is what is being asserted.
    #[cfg(unix)]
    fn fake_op(dir: &std::path::Path, millis: u32) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let op = dir.join("op");
        let calls = dir.join("op-calls");
        std::fs::write(
            &op,
            format!(
                "#!/bin/sh\n\
                 echo \"$1\" >> {}\n\
                 sleep {}\n\
                 case \"$1\" in\n\
                 read) printf 'value-for-%s' \"$3\" ;;\n\
                 inject) sed -E 's/\\{{\\{{ ([^}}]*) \\}}\\}}/value-for-\\1/g' ;;\n\
                 *) exit 2 ;;\n\
                 esac\n",
                calls.display(),
                millis as f64 / 1000.0
            ),
        )
        .unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
        (op, calls)
    }

    /// Every way `op` was invoked, in order — one line per process.
    #[cfg(unix)]
    fn invocations(calls: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(calls)
            .map(|text| text.lines().map(str::to_string).collect())
            .unwrap_or_default()
    }

    /// The bug the batching closes: a policy naming six vault-backed services
    /// asked 1Password six times.
    ///
    /// Each `op` is a separate client asking the desktop app for CLI access,
    /// and they were forked together, so the grant the operator gave the first
    /// dialogue could not cover the five already stacked behind it. Answering
    /// an `ask` stopped doing this in SIRI-205; startup, `SIGHUP`, `r` and `c`
    /// still did, which is the half of the report that was still open.
    #[cfg(unix)]
    #[test]
    fn many_references_are_one_1password_process_rather_than_one_each() {
        let dir = tempfile::tempdir().unwrap();
        let (op, calls) = fake_op(dir.path(), 0);
        let resolver = SecretResolver::new(op.to_str().unwrap());

        let references: Vec<String> = (0..6)
            .map(|n| format!("op://Private/item-{n}/credential"))
            .collect();

        let answers = resolver.refresh_all(&references);
        assert!(answers.iter().all(|answer| answer.is_ok()), "{answers:?}");

        assert_eq!(
            invocations(&calls),
            vec!["inject"],
            "six references, six authorization dialogues"
        );
        // And each value went to the reference it belongs to. A mis-split here
        // would hand one service's credential to another.
        for reference in &references {
            assert_eq!(
                resolver.resolve(reference).unwrap().expose(),
                format!("value-for-{reference}")
            );
        }
    }

    /// A reference this process already holds is not part of the question.
    ///
    /// `resolve_all` is what a reload nobody asked for uses, and the template
    /// it builds names only what it has never read — otherwise an edit that
    /// added one service would go back to the vault for all of them, which is
    /// the prompt SIRI-205 is about wearing a different hat.
    #[cfg(unix)]
    #[test]
    fn a_cache_first_read_only_asks_about_references_it_has_never_seen() {
        let dir = tempfile::tempdir().unwrap();
        let (op, calls) = fake_op(dir.path(), 0);
        let resolver = SecretResolver::new(op.to_str().unwrap());

        let first: Vec<String> = (0..3)
            .map(|n| format!("op://Private/item-{n}/credential"))
            .collect();
        assert!(resolver.resolve_all(&first).iter().all(Result::is_ok));
        assert_eq!(invocations(&calls), vec!["inject"]);

        // The edit adds one service and leaves the other three alone.
        let mut then = first.clone();
        then.push("op://Private/new-one/credential".to_string());
        assert!(resolver.resolve_all(&then).iter().all(Result::is_ok));

        assert_eq!(
            invocations(&calls),
            vec!["inject", "read"],
            "one new reference is one lookup, and `read` is what one reference costs"
        );
        assert_eq!(
            resolver
                .resolve("op://Private/new-one/credential")
                .unwrap()
                .expose(),
            "value-for-op://Private/new-one/credential"
        );
    }

    /// The fallback, and why it is worth having.
    ///
    /// `op inject` fails a template whole and names one cause, so a batch that
    /// will not run — an `op` too old to have `inject`, a vault that refused —
    /// must not become "one of your six references is wrong, work out which".
    /// Every reference is read the old way and answered on its own terms.
    #[cfg(unix)]
    #[test]
    fn a_batch_that_will_not_run_leaves_every_reference_answered_on_its_own() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let op = dir.path().join("op");
        std::fs::write(
            &op,
            "#!/bin/sh\n\
             [ \"$1\" = read ] || { echo 'unknown command \"inject\"' >&2; exit 1; }\n\
             case \"$3\" in\n\
             *broken*) echo \"could not read $3\" >&2; exit 1 ;;\n\
             *) printf 'value-for-%s' \"$3\" ;;\n\
             esac\n",
        )
        .unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
        let resolver = SecretResolver::new(op.to_str().unwrap());

        let references = vec![
            "op://Private/fine/credential".to_string(),
            "op://Private/broken/credential".to_string(),
            "op://Private/also-fine/credential".to_string(),
        ];
        let answers = resolver.refresh_all(&references);

        assert!(answers[0].is_ok(), "{:?}", answers[0]);
        assert!(answers[2].is_ok(), "{:?}", answers[2]);
        let error = answers[1].as_ref().expect_err("the broken one");
        assert!(
            error.contains("op://Private/broken/credential"),
            "the failure has to name the line of the file to fix: {error}"
        );
        assert_eq!(
            resolver
                .resolve("op://Private/fine/credential")
                .unwrap()
                .expose(),
            "value-for-op://Private/fine/credential"
        );
    }

    /// The bug the fallback introduced, reported against a real policy: eight
    /// vault-backed services, one dismissed dialogue, and then eight more.
    ///
    /// `op inject` cannot be authorized without the human who dismissed the
    /// prompt, so reading the eight references one at a time after it fails is
    /// putting the identical question in front of the identical person eight
    /// more times. Dismissing a dialogue is an answer. It is taken as one.
    #[cfg(unix)]
    #[test]
    fn a_dismissed_authorization_prompt_is_not_asked_again_once_per_reference() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let op = dir.path().join("op");
        let calls = dir.path().join("op-calls");
        // What the real `op` says, verbatim from the report.
        std::fs::write(
            &op,
            format!(
                "#!/bin/sh\n\
                 echo \"$1\" >> {}\n\
                 echo \"[ERROR] could not read secret: error initializing client: \
                 authorization prompt dismissed, please try again\" >&2\n\
                 exit 1\n",
                calls.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
        let resolver = SecretResolver::new(op.to_str().unwrap());

        let references: Vec<String> = (0..8)
            .map(|n| format!("op://Private/item-{n}/credential"))
            .collect();
        let answers = resolver.refresh_all(&references);

        assert_eq!(
            invocations(&calls),
            vec!["inject"],
            "the dialogue the operator dismissed was put back in front of them"
        );
        assert_eq!(answers.len(), 8);
        assert!(answers.iter().all(Result::is_err), "{answers:?}");
        // One reason, said once. Eight copies of the same sentence is a wall
        // an operator has to read all of to learn there is one thing wrong.
        assert!(
            answers[0]
                .as_ref()
                .unwrap_err()
                .contains("authorization prompt dismissed"),
            "{:?}",
            answers[0]
        );
        for answer in &answers[1..] {
            assert_eq!(answer.as_ref().unwrap_err(), NOT_ASKED_AGAIN);
        }
    }

    /// The same rule one layer down: if the batch was not the thing that failed,
    /// the first reference to be refused is the last one that asks.
    ///
    /// Reached when `op inject` is unusable for a reason that is not the vault
    /// — an `op` too old to have it — and the vault then refuses anyway. The
    /// references after the refusal are not broken and are not described as
    /// though they were; nothing was asked about them.
    #[cfg(unix)]
    #[test]
    fn a_refusal_partway_through_stops_the_rest_of_the_reads() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let op = dir.path().join("op");
        let calls = dir.path().join("op-calls");
        std::fs::write(
            &op,
            format!(
                "#!/bin/sh\n\
                 echo \"$1 $3\" >> {}\n\
                 [ \"$1\" = read ] || {{ echo 'unknown command \"inject\"' >&2; exit 1; }}\n\
                 case \"$3\" in\n\
                 *item-0*) printf 'value-for-%s' \"$3\" ;;\n\
                 *) echo 'error initializing client: authorization prompt dismissed' >&2; \
                 exit 1 ;;\n\
                 esac\n",
                calls.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
        let resolver = SecretResolver::new(op.to_str().unwrap());

        let references: Vec<String> = (0..5)
            .map(|n| format!("op://Private/item-{n}/credential"))
            .collect();
        let answers = resolver.refresh_all(&references);

        assert_eq!(
            invocations(&calls).len(),
            3,
            "one `inject`, one read that worked, one that was refused — and then it stopped"
        );
        assert!(answers[0].is_ok(), "{:?}", answers[0]);
        assert!(answers[1]
            .as_ref()
            .unwrap_err()
            .contains("authorization prompt dismissed"));
        for answer in &answers[2..] {
            assert_eq!(
                answer.as_ref().unwrap_err(),
                NOT_ASKED_AGAIN,
                "a reference nothing was asked about must not read as a broken one"
            );
        }
    }

    /// The reload cost that made the console unusable: every `op://` reference
    /// in the file was read one after another, so a policy with eight of them
    /// paid eight vault round trips in a row — on startup, on every `SIGHUP`,
    /// and on `r`, where it was seconds of a console that had stopped drawing.
    ///
    /// The bound is deliberately loose. What is being asserted is that the cost
    /// no longer scales with the number of references, not a particular number
    /// of milliseconds on a particular machine.
    #[cfg(unix)]
    #[test]
    fn many_references_cost_about_one_lookup_rather_than_one_each() {
        let dir = tempfile::tempdir().unwrap();
        let (op, _) = fake_op(dir.path(), 200);
        let resolver = SecretResolver::new(op.to_str().unwrap());

        let references: Vec<String> = (0..8)
            .map(|n| format!("op://Private/item-{n}/credential"))
            .collect();

        let started = std::time::Instant::now();
        let answers = resolver.refresh_all(&references);
        let took = started.elapsed();

        assert!(answers.iter().all(|answer| answer.is_ok()), "{answers:?}");
        // The stand-in really did sleep, so the bound below means something.
        assert!(
            took >= std::time::Duration::from_millis(150),
            "the stand-in did not run: {took:?}"
        );
        assert!(
            took < std::time::Duration::from_millis(800),
            "eight 200ms lookups took {took:?} — they are still happening one at a time"
        );
        // And every value actually landed in the cache, under its own reference.
        for (n, reference) in references.iter().enumerate() {
            assert_eq!(
                resolver.resolve(reference).unwrap().expose(),
                format!("value-for-op://Private/item-{n}/credential")
            );
        }
    }

    /// Reading them at once must not reorder the answers. The list of failures
    /// is what an operator reads to find the line of the file that is wrong, so
    /// it is paired with the references by position.
    #[test]
    fn an_answer_comes_back_beside_the_reference_it_belongs_to() {
        std::env::set_var("AGENT_IAP_ORDER_TEST", "sk-not-real");
        let resolver = SecretResolver::new("op-not-installed");
        let references: Vec<String> = (0..12)
            .map(|n| match n % 3 {
                0 => "env:AGENT_IAP_ORDER_TEST".to_string(),
                1 => format!("env:AGENT_IAP_UNSET_{n}"),
                _ => format!("literal:value-{n}"),
            })
            .collect();

        let answers = resolver.refresh_all(&references);
        assert_eq!(answers.len(), references.len());
        for (index, answer) in answers.iter().enumerate() {
            match index % 3 {
                1 => {
                    let error = answer.as_ref().expect_err("an unset variable");
                    assert!(
                        error.contains(&format!("AGENT_IAP_UNSET_{index}")),
                        "answer {index} names the wrong reference: {error}"
                    );
                }
                _ => assert!(answer.is_ok(), "answer {index}: {answer:?}"),
            }
        }
    }

    #[test]
    fn a_managed_reference_names_a_credential_and_is_not_one() {
        assert_eq!(
            SecretRef::parse("iap://github-readonly").unwrap(),
            SecretRef::Managed("github-readonly".into())
        );
        // It is a pointer, so it trims like one and prints like one.
        assert_eq!(
            SecretRef::parse(" iap://github-readonly\n").unwrap(),
            SecretRef::Managed("github-readonly".into())
        );
        assert_eq!(
            display_ref(" iap://github-readonly "),
            "iap://github-readonly"
        );

        // And the value it points at is not in the policy file, which is the
        // whole reason it is allowed where `literal:` is refused.
        assert!(!SecretRef::parse("iap://github-readonly")
            .unwrap()
            .is_inline());
        assert!(SecretRef::parse("literal:hunter2").unwrap().is_inline());
    }

    /// A name that cannot be stored cannot be referenced either — caught here,
    /// where it is typed, rather than as a resolution failure at startup.
    #[test]
    fn a_managed_reference_with_an_unstorable_name_is_refused_at_the_reference() {
        for raw in ["iap://", "iap://has spaces", "iap://has/slashes"] {
            assert!(SecretRef::parse(raw).is_err(), "`{raw}` parsed");
        }
    }

    /// The refusal that had no way out: the message used to offer `literal:`,
    /// which every enrolment surface then refused for a different reason. What
    /// it offers has to be something a credential can actually be enrolled as.
    #[test]
    fn the_refusal_offers_a_spelling_that_is_not_refused_again() {
        let error = SecretRef::parse("ghp_pasted_token")
            .unwrap_err()
            .to_string();
        assert!(error.contains("iap://NAME"), "{error}");
        assert!(error.contains("agent-iap secret set"), "{error}");
        assert!(
            !error.contains("literal:"),
            "offering `literal:` sends the operator to the next refusal: {error}"
        );
    }

    #[test]
    fn rejects_bare_values_so_a_pasted_key_is_never_silently_accepted() {
        let err = SecretRef::parse("sk-ant-secret").unwrap_err().to_string();
        assert!(err.contains("unrecognised secret reference"));
        assert!(
            !err.contains("sk-ant-secret"),
            "error leaked the value: {err}"
        );
    }

    #[test]
    fn errors_never_echo_the_value_after_the_scheme() {
        let err = SecretRef::parse("bogus:sk-ant-secret")
            .unwrap_err()
            .to_string();
        assert!(err.contains("bogus:***"));
        assert!(!err.contains("sk-ant-secret"));
    }

    #[test]
    fn debug_never_reveals_the_secret() {
        let s = Secret::new("sk-ant-supersecret".into());
        assert_eq!(format!("{s:?}"), "Secret(***)");
        assert_eq!(s.expose(), "sk-ant-supersecret");
    }

    #[test]
    fn env_and_file_resolve_and_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "from-file\n").unwrap();

        let resolver = SecretResolver::new("op");
        std::env::set_var("LLM_IAP_TEST_SECRET", "from-env");

        assert_eq!(
            resolver
                .resolve("env:LLM_IAP_TEST_SECRET")
                .unwrap()
                .expose(),
            "from-env"
        );
        assert_eq!(
            resolver
                .resolve(&format!("file:{}", path.display()))
                .unwrap()
                .expose(),
            "from-file",
            "trailing newline should be trimmed"
        );

        // Cached: removing the source still resolves.
        std::env::remove_var("LLM_IAP_TEST_SECRET");
        assert_eq!(
            resolver
                .resolve("env:LLM_IAP_TEST_SECRET")
                .unwrap()
                .expose(),
            "from-env"
        );
    }

    /// The store behind `iap://`, through the resolver the proxy uses — and
    /// through `refresh`, which is what a reload calls, so `secret set` against
    /// a running proxy takes effect on the next reload rather than on a restart.
    #[test]
    fn a_managed_reference_resolves_from_the_store_and_refreshes_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.toml");
        let store = crate::store::Store::at(&path);
        store.set("readonly", "ghp_v1").unwrap();

        let resolver = SecretResolver::new("op-not-installed").with_store(&path);
        assert_eq!(
            resolver.resolve("iap://readonly").unwrap().expose(),
            "ghp_v1"
        );

        // Rotated behind an unchanged reference, exactly as `file:` and `op://`
        // can be.
        store.set("readonly", "ghp_v2").unwrap();
        assert_eq!(
            resolver.resolve("iap://readonly").unwrap().expose(),
            "ghp_v1",
            "resolve keeps serving the cached value"
        );
        assert_eq!(
            resolver.refresh("iap://readonly").unwrap().expose(),
            "ghp_v2"
        );

        // A name nobody stored fails saying how to store it, and never by
        // blaming 1Password — `op` was never going to be asked.
        let error = resolver.resolve("iap://absent").unwrap_err().to_string();
        assert!(error.contains("agent-iap secret"), "{error}");
        assert!(!error.contains("1Password"), "{error}");
    }

    #[test]
    fn refresh_picks_up_a_rotated_source_that_resolve_still_caches() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "v1\n").unwrap();
        let reference = format!("file:{}", path.display());

        let resolver = SecretResolver::new("op");
        assert_eq!(resolver.resolve(&reference).unwrap().expose(), "v1");

        // The value behind the reference changes; the reference string does not.
        std::fs::write(&path, "v2\n").unwrap();
        assert_eq!(
            resolver.resolve(&reference).unwrap().expose(),
            "v1",
            "resolve keeps serving the cached value"
        );
        assert_eq!(
            resolver.refresh(&reference).unwrap().expose(),
            "v2",
            "refresh re-reads the source"
        );
        assert_eq!(
            resolver.resolve(&reference).unwrap().expose(),
            "v2",
            "and the fresh value is what the cache now holds"
        );
    }

    #[test]
    fn a_failed_refresh_keeps_the_last_good_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "v1\n").unwrap();
        let reference = format!("file:{}", path.display());

        let resolver = SecretResolver::new("op");
        assert_eq!(resolver.resolve(&reference).unwrap().expose(), "v1");

        // The source is gone: a refresh cannot read it…
        std::fs::remove_file(&path).unwrap();
        assert!(resolver.refresh(&reference).is_err());

        // …and must not have evicted the value the proxy is still serving.
        assert_eq!(
            resolver.resolve(&reference).unwrap().expose(),
            "v1",
            "a failed refresh leaves the last good value in place"
        );
    }

    #[test]
    fn the_account_is_taken_off_a_reference_and_every_other_parameter_kept() {
        for (raw, reference, account) in [
            (
                "op://Private/GitHub/token",
                "op://Private/GitHub/token",
                None,
            ),
            (
                "op://Private/GitHub/token?account=my.1password.com",
                "op://Private/GitHub/token",
                Some("my.1password.com"),
            ),
            // 1Password's own parameters change what `op` returns, so they
            // reach it — in the order they were written.
            (
                "op://Private/GitHub/one-time password?attribute=otp",
                "op://Private/GitHub/one-time password?attribute=otp",
                None,
            ),
            (
                "op://Private/Deploy key/private key?account=ABCDEF123&ssh-format=openssh",
                "op://Private/Deploy key/private key?ssh-format=openssh",
                Some("ABCDEF123"),
            ),
            (
                " op://Private/GitHub/token?attribute=otp&account=my.1password.com ",
                "op://Private/GitHub/token?attribute=otp",
                Some("my.1password.com"),
            ),
        ] {
            assert_eq!(
                SecretRef::parse(raw).unwrap(),
                SecretRef::OnePassword {
                    reference: reference.into(),
                    account: account.map(str::to_string),
                },
                "`{raw}`"
            );
        }
    }

    #[test]
    fn an_account_parameter_that_names_no_single_account_is_refused() {
        for raw in [
            "op://Private/GitHub/token?account=",
            "op://Private/GitHub/token?account",
            "op://Private/GitHub/token?account=a.1password.com&account=b.1password.com",
        ] {
            assert!(SecretRef::parse(raw).is_err(), "`{raw}`");
        }
    }

    #[test]
    fn the_reference_names_its_account_over_the_policy_and_the_policy_over_the_default() {
        let mut accounts = OpAccounts::new(Some("default.1password.com".into()));
        accounts.assign("op://Private/GitHub/token", "my.1password.com");
        accounts.assign(
            "op://Ops/Pinned/token?account=ops.1password.com",
            "my.1password.com",
        );

        assert_eq!(
            accounts
                .account_for(" op://Private/GitHub/token ")
                .as_deref(),
            Some("my.1password.com")
        );
        assert_eq!(
            accounts
                .account_for("op://Ops/Pinned/token?account=ops.1password.com")
                .as_deref(),
            Some("ops.1password.com")
        );
        assert_eq!(
            accounts.account_for("op://Work/API/token").as_deref(),
            Some("default.1password.com")
        );
        assert_eq!(accounts.account_for("env:HOME"), None);
        assert_eq!(
            OpAccounts::new(None).account_for("op://Work/API/token"),
            None
        );
    }

    /// A stand-in `op` that writes down its whole command line, and answers
    /// with the account it was told to read from — so a value read from the
    /// wrong account is visibly the wrong value.
    #[cfg(unix)]
    fn account_aware_op(dir: &std::path::Path) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let op = dir.join("op");
        let calls = dir.join("op-calls");
        std::fs::write(
            &op,
            format!(
                "#!/bin/sh\n\
                 echo \"$*\" >> {calls}\n\
                 account=default\n\
                 command=$1; shift\n\
                 reference=\n\
                 while [ $# -gt 0 ]; do\n\
                   case \"$1\" in\n\
                   --account) account=$2; shift 2 ;;\n\
                   --no-newline) shift ;;\n\
                   *) reference=$1; shift ;;\n\
                   esac\n\
                 done\n\
                 case \"$account\" in\n\
                 locked.example.com) echo '[ERROR] account is not signed in' >&2; exit 1 ;;\n\
                 esac\n\
                 case \"$command\" in\n\
                 read) printf '%s@%s' \"$reference\" \"$account\" ;;\n\
                 inject) sed -E \"s/\\{{\\{{ ([^}}]*) \\}}\\}}/\\1@$account/g\" ;;\n\
                 *) exit 2 ;;\n\
                 esac\n",
                calls = calls.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
        (op, calls)
    }

    /// The report: most credentials in the company account, one in a personal
    /// one. One pass is one `op inject` per account, each told which, and every
    /// value comes back from the account it was meant to.
    #[cfg(unix)]
    #[test]
    fn references_in_two_accounts_are_one_batch_per_account() {
        let dir = tempfile::tempdir().unwrap();
        let (op, calls) = account_aware_op(dir.path());
        let mut accounts = OpAccounts::new(None);
        accounts.assign("op://Private/Pinned/token", "my.1password.com");
        let resolver = SecretResolver::new(op.to_str().unwrap()).with_op_accounts(accounts);

        let references: Vec<String> = [
            "op://Work/one/token",
            "op://Private/GitHub classic/token?account=my.1password.com",
            "op://Work/two/token",
            "op://Private/Pinned/token",
        ]
        .map(str::to_string)
        .to_vec();
        let answers = resolver.refresh_all(&references);
        assert!(answers.iter().all(Result::is_ok), "{answers:?}");

        assert_eq!(
            invocations(&calls),
            vec!["inject", "inject --account my.1password.com"],
            "one process per account, in the order the file first names them"
        );
        for (raw, wanted) in [
            (&references[0], "op://Work/one/token@default"),
            (
                &references[1],
                "op://Private/GitHub classic/token@my.1password.com",
            ),
            (&references[2], "op://Work/two/token@default"),
            (&references[3], "op://Private/Pinned/token@my.1password.com"),
        ] {
            assert_eq!(resolver.resolve(raw).unwrap().expose(), wanted, "`{raw}`");
        }

        // One reference alone is `op read`, told its account the same way.
        let single = "op://Private/Other/token?account=my.1password.com";
        assert_eq!(
            resolver.resolve(single).unwrap().expose(),
            "op://Private/Other/token@my.1password.com"
        );
        assert_eq!(
            invocations(&calls).last().map(String::as_str),
            Some("read --no-newline op://Private/Other/token --account my.1password.com")
        );
    }

    /// Being signed out of one account says nothing about another: the
    /// account that refused is named, and is the only one that stops.
    #[cfg(unix)]
    #[test]
    fn a_refusal_names_its_account_and_stops_only_that_account() {
        let dir = tempfile::tempdir().unwrap();
        let (op, calls) = account_aware_op(dir.path());
        let resolver = SecretResolver::new(op.to_str().unwrap());

        let references: Vec<String> = [
            "op://Work/one/token",
            "op://Private/a/token?account=locked.example.com",
            "op://Work/two/token",
            "op://Private/b/token?account=locked.example.com",
        ]
        .map(str::to_string)
        .to_vec();
        let answers = resolver.refresh_all(&references);

        assert!(answers[0].is_ok(), "{:?}", answers[0]);
        assert!(answers[2].is_ok(), "{:?}", answers[2]);
        let first = answers[1].as_ref().unwrap_err();
        assert!(first.contains("`locked.example.com`"), "{first}");
        assert!(is_authorization_failure(first), "{first}");
        assert_eq!(
            answers[3].as_ref().unwrap_err(),
            &not_asked_again(Some("locked.example.com"))
        );
        assert_eq!(
            invocations(&calls),
            vec!["inject", "inject --account locked.example.com"],
            "the refusing account was asked once, and nothing was retried one by one"
        );
    }

    /// A reload that moves a reference to another account is a different
    /// credential under the same spelling, and must not be served the value
    /// the old account gave.
    #[cfg(unix)]
    #[test]
    fn a_value_is_cached_per_account_not_only_per_spelling() {
        let dir = tempfile::tempdir().unwrap();
        let (op, _) = account_aware_op(dir.path());
        let resolver = SecretResolver::new(op.to_str().unwrap());
        let raw = "op://Private/GitHub/token";
        assert_eq!(
            resolver.resolve(raw).unwrap().expose(),
            "op://Private/GitHub/token@default"
        );

        let mut accounts = OpAccounts::new(None);
        accounts.assign(raw, "my.1password.com");
        resolver.set_op_accounts(accounts);
        assert_eq!(
            resolver.resolve(raw).unwrap().expose(),
            "op://Private/GitHub/token@my.1password.com"
        );
    }
}
