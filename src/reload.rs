//! Noticing that the policy file changed, wherever the proxy is running.
//!
//! `AppState::reload` is what *applies* an edited policy. This is what decides
//! there is one to apply. It lives in the daemon rather than in the console
//! because the deployment least able to take a restart — a unit file, a
//! container, twenty agents on one proxy — is exactly the one with no console
//! attached, and a reload that only worked where somebody was watching would be
//! a reload for the case that needed it least.
//!
//! Two triggers, and they are the same code path:
//!
//! - the file changing on disk, which is what `agent-iap acl add` and an editor
//!   both do, and what a human expects to be enough;
//! - `SIGHUP`, which is what every other daemon on the box answers to, and the
//!   one thing a config-management tool knows how to send after it writes.
//!
//! They differ in one thing, and `Trigger::rereads_credentials` is where that
//! is argued: `SIGHUP` says *read it all again*, and a file that merely changed
//! does not.
//!
//! What this deliberately does *not* do is decide whether the new policy is
//! acceptable. `AppState::reload` is all-or-nothing and refuses anything it
//! cannot serve, so the worst a bad edit does here is get logged and ignored.

use anyhow::{Context, Result};
use parking_lot::Mutex;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::config::{Config, Overrides};
use crate::state::AppState;

/// How long the file has to stop changing before it is read.
///
/// A rewrite is a truncate followed by a write, so there is a moment when the
/// file on disk is half a policy. Reading it then reports a broken file that is
/// not broken — and the operator who just ran `agent-iap acl add` would be told
/// their edit was rejected.
pub const SETTLE: Duration = Duration::from_millis(250);

/// How often the file is asked whether it changed.
///
/// A `stat` is cheap enough that this could be far quicker, and there is no
/// reason for it to be: the event it is waiting for happens a few times a day,
/// and the cost of noticing it a moment later is nothing.
pub const POLL: Duration = Duration::from_millis(500);

/// Enough of a file's identity to notice it changing, without reading it.
///
/// Not a hash: this question is asked twice a second forever, and digesting the
/// whole policy file to find out that nothing happened is a cost paid
/// continuously for an event that is rare. Length and modification time miss an
/// edit only if it changed neither, which for a TOML file rewritten by hand or
/// by `enroll` does not come up.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    modified: Option<SystemTime>,
    len: u64,
}

fn stamp(path: &Path) -> Option<Stamp> {
    let metadata = std::fs::metadata(path).ok()?;
    Some(Stamp {
        modified: metadata.modified().ok(),
        len: metadata.len(),
    })
}

/// Why the policy was re-read, for the log and the audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// The file changed under a running proxy.
    Edited,
    /// `SIGHUP`.
    Signal,
    /// The console's `r` — somebody asked for the file to be re-read.
    Asked,
    /// A write the console just made, which reloads itself so that a rule
    /// granted from the approval dialogue governs the next call.
    Wrote,
}

impl Trigger {
    pub fn as_str(self) -> &'static str {
        match self {
            Trigger::Edited => "edited",
            Trigger::Signal => "sighup",
            Trigger::Asked => "asked",
            Trigger::Wrote => "wrote",
        }
    }

    /// Does this reload go back to the vault, or serve the values this process
    /// already holds?
    ///
    /// A credential rotated behind an unchanged reference is invisible in the
    /// file — nothing about the bytes says the value moved — so the only honest
    /// answer is to read it again, and the only honest moment to do that is
    /// when somebody said so. `SIGHUP` is what a config-management tool sends
    /// after writing a renewed certificate or a rotated key, and `r` is an
    /// operator asking for exactly this; both re-read everything.
    ///
    /// The other two did not ask. A watched file that changed and a rule the
    /// console just wrote are both usually `[[acl]]` edits, which say nothing
    /// about any credential — and making them a vault lookup per reference is
    /// how answering an `ask` came to raise a 1Password authorization prompt
    /// every time (SIRI-205). References the edit *added* are still read, being
    /// ones this process has never resolved.
    pub fn rereads_credentials(self) -> bool {
        match self {
            Trigger::Signal | Trigger::Asked => true,
            Trigger::Edited | Trigger::Wrote => false,
        }
    }
}

/// Watches one policy file, and is the only thing that reads it.
///
/// Shared: the daemon's task polls it and the console forces it, and both go
/// through here so that the console pressing `r` does not leave the watcher
/// believing there is still an edit outstanding — which would reload a second
/// time and report a change nobody made.
pub struct Watcher {
    path: PathBuf,
    /// What the command line said, re-applied on top of every read. Without
    /// this a reload would quietly undo `--listen` and move the proxy off the
    /// address its agents are connected to.
    overrides: Overrides,
    /// The mark on the file the running policy was read from.
    seen: Mutex<Option<Stamp>>,
    /// When the file was first seen to differ. `None` while it matches.
    settling: Mutex<Option<Instant>>,
}

impl Watcher {
    pub fn new(path: impl Into<PathBuf>, overrides: Overrides) -> Self {
        let path = path.into();
        let seen = stamp(&path);
        Watcher {
            path,
            overrides,
            seen: Mutex::new(seen),
            settling: Mutex::new(None),
        }
    }

    /// Read the policy file the way this proxy was started: the file, plus
    /// whatever the command line said on top.
    pub fn read(&self) -> Result<Config> {
        let mut config = Config::load(&self.path)
            .with_context(|| format!("reading `{}`", self.path.display()))?;
        self.overrides.apply(&mut config)?;
        Ok(config)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Has somebody written to the policy file since it was last read?
    pub fn edited(&self) -> bool {
        match stamp(&self.path) {
            // Unreadable is not "changed": a file briefly absent mid-rename
            // would otherwise be reported as an edit and then as an error.
            None => false,
            current => current != *self.seen.lock(),
        }
    }

    /// Read the file and put it in charge, whatever the file's mark says.
    ///
    /// The mark is taken *before* the read: a write landing between the two
    /// would otherwise leave the proxy holding the old contents under the new
    /// file's mark, and never looking again. And it is recorded even when the
    /// reload fails, because re-reading the same broken bytes twice a second
    /// would fill the log with one mistake.
    pub fn reload(&self, state: &Arc<AppState>, why: Trigger) -> Result<Arc<Config>> {
        let stamp = stamp(&self.path);
        *self.settling.lock() = None;

        let result = self.read().and_then(|config| state.reload(config, why));

        *self.seen.lock() = stamp;
        result
    }

    /// Reload if the file has changed and then stopped changing.
    ///
    /// `None` means there was nothing to do, which is almost always.
    pub fn poll(&self, state: &Arc<AppState>) -> Option<Result<Arc<Config>>> {
        if !self.edited() {
            *self.settling.lock() = None;
            return None;
        }
        let waited = {
            let mut settling = self.settling.lock();
            settling.get_or_insert_with(Instant::now).elapsed()
        };
        if waited < SETTLE {
            return None;
        }
        Some(self.reload(state, Trigger::Edited))
    }

    /// The daemon's own reload loop: the file, and `SIGHUP`.
    ///
    /// Runs whether or not a console is attached, which is the point. Never
    /// returns — a failed reload is logged and the proxy carries on serving the
    /// policy it already had, because the alternative is a proxy that stops
    /// holding the line the moment somebody fat-fingers a TOML file.
    pub async fn run(self: Arc<Self>, state: Arc<AppState>) {
        let mut hangup = hangups();
        let mut tick = tokio::time::interval(POLL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            let why = tokio::select! {
                _ = tick.tick() => None,
                _ = hangup.next() => Some(Trigger::Signal),
            };

            let outcome = match why {
                Some(why) => Some(self.reload(&state, why)),
                None => self.poll(&state),
            };

            match outcome {
                None => {}
                Some(Ok(config)) => tracing::info!(
                    agents = config.agents.len(),
                    rules = config.acl.len(),
                    upstreams = config.upstreams.len(),
                    mcp_servers = config.mcp_servers.len(),
                    "policy reloaded"
                ),
                // Loud, and not fatal. The running policy is untouched — see
                // `AppState::reload` — so this is a proxy that is still doing
                // its job and an edit that did not take.
                Some(Err(error)) => tracing::error!(
                    ?error,
                    path = %self.path.display(),
                    "refused an edited policy; still serving the previous one"
                ),
            }
        }
    }
}

/// `SIGHUP`, where there is such a thing.
fn hangups() -> Hangups {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(stream) => Hangups(Some(stream)),
            // Nothing here is worth refusing to start over: the file is still
            // watched, and that is the trigger a human reaches for anyway.
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "no SIGHUP handler; the policy file is still watched"
                );
                Hangups(None)
            }
        }
    }
    #[cfg(not(unix))]
    {
        Hangups(None)
    }
}

/// A `SIGHUP` stream, or a stand-in that never fires.
struct Hangups(
    #[cfg(unix)] Option<tokio::signal::unix::Signal>,
    #[cfg(not(unix))] Option<()>,
);

impl Hangups {
    async fn next(&mut self) {
        match &mut self.0 {
            #[cfg(unix)]
            Some(stream) => {
                stream.recv().await;
            }
            #[cfg(not(unix))]
            Some(()) => std::future::pending().await,
            None => std::future::pending().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(dir: &Path, extra: &str) -> String {
        format!(
            r#"
[audit]
path = "{}"
stderr = false

[[agents]]
id = "claude"
token_sha256 = "{}"
{extra}
"#,
            dir.join("audit.jsonl").display(),
            crate::identity::token_hash("iap_test"),
        )
    }

    fn started(dir: &Path) -> (Arc<AppState>, Arc<Watcher>, PathBuf) {
        let path = dir.join("iap.toml");
        std::fs::write(&path, policy(dir, "")).unwrap();
        let watcher = Watcher::new(&path, Overrides::default());
        let state = AppState::build(watcher.read().unwrap(), false).unwrap();
        (state, Arc::new(watcher), path)
    }

    /// The whole point: no console, no restart, and the edit is in force.
    #[test]
    fn an_edit_is_picked_up_without_anybody_watching() {
        let dir = tempfile::tempdir().unwrap();
        let (state, watcher, path) = started(dir.path());
        assert_eq!(state.acl.rule_count(), 0);

        std::fs::write(
            &path,
            policy(
                dir.path(),
                r#"
[[acl]]
name = "added-behind-its-back"
target = "gh"
action = "allow"
"#,
            ),
        )
        .unwrap();

        // Not yet: the writer might still be writing.
        assert!(watcher.poll(&state).is_none());
        assert_eq!(state.acl.rule_count(), 0);

        *watcher.settling.lock() = Instant::now().checked_sub(SETTLE);
        watcher.poll(&state).expect("settled").unwrap();

        assert_eq!(state.acl.rule_count(), 1);
        assert!(
            watcher.poll(&state).is_none(),
            "and it does not reload twice"
        );
    }

    #[test]
    fn a_signal_reloads_without_waiting_for_the_file_to_look_different() {
        // The file is written and `SIGHUP` arrives immediately after — which is
        // what a config-management tool does, and is too soon for a poll that
        // is waiting for the write to settle.
        let dir = tempfile::tempdir().unwrap();
        let (state, watcher, path) = started(dir.path());
        std::fs::write(
            &path,
            policy(
                dir.path(),
                r#"
[[acl]]
name = "by-signal"
target = "gh"
action = "allow"
"#,
            ),
        )
        .unwrap();

        watcher.reload(&state, Trigger::Signal).unwrap();
        assert_eq!(state.acl.rule_count(), 1);
    }

    /// A daemon reloading itself must not be a way to take the daemon down.
    #[test]
    fn a_broken_edit_is_refused_once_and_leaves_the_proxy_serving() {
        let dir = tempfile::tempdir().unwrap();
        let (state, watcher, path) = started(dir.path());

        std::fs::write(&path, "this is not toml {{{").unwrap();
        *watcher.settling.lock() = Instant::now().checked_sub(SETTLE);

        let error = watcher.poll(&state).expect("settled").unwrap_err();
        assert!(format!("{error:#}").contains("iap.toml"), "{error:#}");

        // Still the agent it started with, and no second complaint about the
        // same bytes.
        assert!(state.agents.by_id("claude").is_some());
        assert!(
            watcher.poll(&state).is_none(),
            "the same broken file must not be re-read twice a second"
        );
    }

    /// A reload must not quietly undo the command line.
    ///
    /// `--listen` is a deliberate divergence for the life of the run. Dropping
    /// it on somebody else's unrelated edit would move the proxy off the
    /// address its agents are connected to, which is an outage caused by a
    /// rule being added.
    #[test]
    fn a_reload_keeps_the_addresses_the_command_line_chose() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iap.toml");
        std::fs::write(&path, policy(dir.path(), "")).unwrap();

        let watcher = Watcher::new(
            &path,
            Overrides {
                listen: Some("127.0.0.1:19999".into()),
                admin_listen: Some("127.0.0.1:19998".into()),
                ..Default::default()
            },
        );
        let state = AppState::build(watcher.read().unwrap(), false).unwrap();
        assert_eq!(state.config().server.listen.port(), 19999);

        // An edit that says nothing about addresses at all.
        std::fs::write(
            &path,
            policy(
                dir.path(),
                r#"
[[acl]]
name = "unrelated"
target = "gh"
action = "allow"
"#,
            ),
        )
        .unwrap();
        let state = Arc::new(state);
        Arc::new(watcher).reload(&state, Trigger::Signal).unwrap();

        assert_eq!(state.acl.rule_count(), 1, "the edit landed");
        assert_eq!(
            state.config().server.listen.port(),
            19999,
            "and the proxy stayed where it was told to listen"
        );
        assert_eq!(state.config().server.admin_listen.unwrap().port(), 19998);
    }

    #[test]
    fn a_file_that_cannot_be_stat_ed_is_not_an_edit() {
        // Mid-rename, or a mount that blinked. Reporting it as a change would
        // mean reading a file that is not there and logging that it is not.
        let dir = tempfile::tempdir().unwrap();
        let (state, watcher, path) = started(dir.path());
        std::fs::remove_file(&path).unwrap();

        assert!(!watcher.edited());
        assert!(watcher.poll(&state).is_none());
    }
}
