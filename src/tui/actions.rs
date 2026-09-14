//! What the console does to the policy file, and what the running proxy makes
//! of it afterwards.
//!
//! Every write here goes through `enroll` or `profiles` — the same functions
//! the CLI calls, with the same validation and the same refusal to put a
//! credential in the file. The console adds no way to write something
//! `agent-iap upstream add` would have rejected.
//!
//! The second half is the part a one-shot CLI never had to think about: this
//! process is *running* against the policy it just edited. Rules and agents are
//! re-read into the live proxy immediately, because those are the edits an
//! operator makes in the middle of something — a rule written from the approval
//! dialogue that only took effect after a restart would be a rule that did not
//! work. Services and server settings cannot be swapped under an open
//! connection, so those are named as needing a restart rather than silently
//! not applying.
//!
//! The console is not the only thing that writes this file. `agent-iap acl add`
//! in the next terminal over, or an editor, edits the same policy the console
//! is displaying — so it watches the file rather than assuming it is the only
//! author, and a pane showing a rule list that is no longer the rule list is a
//! pane worth distrusting.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use crate::config::Config;
use crate::enroll::{self, McpTransportSpec};
use crate::list::{Inventory, ListOptions, What};
use crate::profiles;
use crate::state::AppState;

use super::form::{Form, Intent};
use super::views::CredentialStatus;

/// The policy file as the console currently understands it.
pub struct Policy {
    pub path: PathBuf,
    pub config: Config,
    /// The file as it was when this process read it at startup.
    ///
    /// The comparison is against *this* rather than against the config the
    /// proxy is running, because the two legitimately differ: `--listen` is a
    /// deliberate divergence for the life of the run, and reporting it as an
    /// unapplied edit would put a restart banner on screen that no restart
    /// would ever clear.
    baseline: Config,
    pub inventory: Inventory,
    pub credentials: Vec<CredentialStatus>,
    /// Edits made since startup that this process cannot adopt without one.
    /// Empty is the normal state and says nothing on screen.
    pub restart_needed: Vec<String>,
    /// The mark on the file the current view was read from. What the console
    /// compares against to notice somebody else editing the policy.
    seen: Option<Stamp>,
}

/// Enough of a file's identity to notice it changing, cheaply enough to ask
/// every frame.
///
/// Not a hash: the console asks this question eight times a second, and reading
/// and digesting the whole policy file to find out that nothing happened is a
/// cost paid continuously for an event that happens twice a day. Length and
/// modification time miss an edit only if it changed neither, which for a TOML
/// file rewritten by hand or by `enroll` does not come up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    modified: Option<SystemTime>,
    len: u64,
}

/// The file's current mark, or `None` if it cannot be stat'd at all.
pub fn stamp(path: &Path) -> Option<Stamp> {
    let metadata = std::fs::metadata(path).ok()?;
    Some(Stamp {
        modified: metadata.modified().ok(),
        len: metadata.len(),
    })
}

impl Policy {
    pub fn load(path: &Path, state: &Arc<AppState>) -> Result<Self> {
        let config = Config::load(path)?;
        let mut policy = Policy {
            path: path.to_path_buf(),
            baseline: config.clone(),
            config,
            inventory: Inventory::default(),
            credentials: Vec::new(),
            restart_needed: Vec::new(),
            seen: None,
        };
        policy.rebuild(state)?;
        Ok(policy)
    }

    /// Has somebody else written to the policy file since the console read it?
    pub fn edited_on_disk(&self) -> bool {
        match stamp(&self.path) {
            // Unreadable is not "changed": a file briefly absent mid-rename
            // would otherwise be reported as an edit and then as an error.
            None => false,
            current => current != self.seen,
        }
    }

    /// Stop reporting the file as edited, whatever it currently says.
    ///
    /// For the one case `rebuild` cannot cover: it refused to load, and asking
    /// it again every frame would put the same error on screen eight times a
    /// second. The next edit produces a new mark and is tried again.
    pub fn accept_on_disk(&mut self) {
        self.seen = stamp(&self.path);
    }

    /// Re-read the file and push what can be pushed into the running proxy.
    pub fn rebuild(&mut self, state: &Arc<AppState>) -> Result<()> {
        // Marked before the read rather than after. A write landing between the
        // two would otherwise leave the console holding the old contents under
        // the new file's mark, and never looking at the file again.
        let stamp = stamp(&self.path);
        let config = Config::load(&self.path)?;

        // Compiled and enrolled before either is swapped: a file that no longer
        // makes a policy must leave the proxy on the one it is already running.
        state.acl.reload(&config).context(
            "the edited rule list would not compile — the proxy is still on the old one",
        )?;
        state
            .agents
            .reload(&config, &state.resolver)
            .context("the edited agent list would not enrol — the proxy is still on the old one")?;

        self.restart_needed = needs_restart(&self.baseline, &config);
        self.inventory = Inventory::build(&config, &ListOptions::default())
            .context("reading the policy file back")?;
        self.credentials = credential_statuses(&config, &self.credentials);
        self.config = config;
        self.seen = stamp;
        Ok(())
    }

    /// Resolve every credential reference and record what happened.
    ///
    /// Deliberately on a keystroke rather than on a timer: an `op://` reference
    /// is a subprocess and a network call, and a console that ran one every
    /// frame would be a console that rate-limits a vault.
    pub fn check_credentials(&mut self, state: &Arc<AppState>) {
        for row in &mut self.credentials {
            row.resolves = Some(
                state
                    .resolver
                    .resolve(&row.reference)
                    .map(|_| ())
                    .map_err(|error| format!("{error:#}")),
            );
        }
    }
}

/// Which sections changed in a way this process cannot adopt while running.
///
/// Rules and agents are absent on purpose: those *are* reloaded, so naming them
/// here would tell an operator to restart for something already in effect.
fn needs_restart(started_with: &Config, edited: &Config) -> Vec<String> {
    let mut stale = Vec::new();
    if differs(&started_with.upstreams, &edited.upstreams) {
        stale.push("upstreams".into());
    }
    if differs(&started_with.mcp_servers, &edited.mcp_servers) {
        stale.push("mcp servers".into());
    }
    if differs(&started_with.server, &edited.server) {
        stale.push("server settings".into());
    }
    if differs(&started_with.audit, &edited.audit) {
        stale.push("audit settings".into());
    }
    stale
}

/// Compared as serialised values rather than field by field, so a field added
/// to the config schema later is covered without anyone remembering to add it
/// to a list here — the failure mode being an operator told nothing about a
/// change that did not take effect.
fn differs<T: serde::Serialize>(started_with: &T, edited: &T) -> bool {
    serde_json::to_string(started_with).ok() != serde_json::to_string(edited).ok()
}

/// Every credential the file names, carrying forward any status already known.
fn credential_statuses(config: &Config, previous: &[CredentialStatus]) -> Vec<CredentialStatus> {
    let inventory = Inventory::build(
        config,
        &ListOptions {
            what: What::Credentials,
            agent: None,
        },
    );
    inventory
        .map(|inventory| {
            inventory
                .credentials
                .unwrap_or_default()
                .into_iter()
                .map(|row| CredentialStatus {
                    resolves: previous
                        .iter()
                        .find(|old| old.reference == row.reference && old.field == row.field)
                        .and_then(|old| old.resolves.clone()),
                    owner: row.owner,
                    field: row.field,
                    reference: row.reference,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// What a completed form did, in the words the console puts on screen.
pub struct Effect {
    pub message: String,
    /// A minted token. Shown once, in a modal of its own, because this is the
    /// only moment it exists outside the agent that will hold it.
    pub token: Option<(String, String)>,
    /// A preview rather than a write — the dry run.
    pub preview: Option<String>,
}

impl Effect {
    fn said(message: impl Into<String>) -> Self {
        Effect {
            message: message.into(),
            token: None,
            preview: None,
        }
    }
}

/// Apply a filled-in form to the policy file.
pub fn submit(policy: &Policy, form: &Form) -> Result<Effect> {
    let path = policy.path.as_path();
    match form.intent {
        Intent::Agent => {
            let id = required(form, "id")?;
            let agent = enroll::add_agent(
                path,
                &id,
                form.opt("name").as_deref(),
                &form.list("targets"),
            )?;
            Ok(Effect {
                message: format!("enrolled `{id}` — its token is live now, no restart needed"),
                token: Some((agent.id, agent.token)),
                preview: None,
            })
        }
        Intent::Upstream => {
            let name = required(form, "name")?;
            let base_url = required(form, "base-url")?;
            let headers = form.pairs("set-header")?;
            enroll::add_upstream(path, &name, &base_url, &form.auth().to_spec()?, &headers)?;
            Ok(Effect::said(format!(
                "added upstream `{name}` — restart agent-iap to start serving it"
            )))
        }
        Intent::McpServer => {
            let name = required(form, "name")?;
            let transport = match form.text("transport").as_str() {
                "http" => McpTransportSpec::Http {
                    url: required(form, "url")?,
                },
                _ => McpTransportSpec::Stdio {
                    command: required(form, "command")?,
                    args: form.list("args"),
                    env: form.pairs("env")?,
                    cwd: form.opt("cwd"),
                },
            };
            enroll::add_mcp_server(path, &name, &transport, &form.auth().to_spec()?)?;
            Ok(Effect::said(format!(
                "added MCP server `{name}` — restart agent-iap to start serving it"
            )))
        }
        Intent::Rule => {
            let methods = non_empty(form.list("methods"), "*");
            let paths = non_empty(form.list("paths"), "**");
            let target = default_to(form.text("target"), "*");
            let agent = default_to(form.text("agent"), "*");
            let kind = form.text("kind");
            let action = form.text("action");

            let landed = match form.opt("position") {
                Some(position) => {
                    let index: usize = position
                        .parse()
                        .with_context(|| format!("`{position}` is not a rule number"))?;
                    enroll::insert_rule(
                        path,
                        index,
                        form.opt("name").as_deref(),
                        &agent,
                        &kind,
                        &target,
                        &methods,
                        &paths,
                        &action,
                    )?
                }
                None => enroll::add_rule(
                    path,
                    form.opt("name").as_deref(),
                    &agent,
                    &kind,
                    &target,
                    &methods,
                    &paths,
                    &action,
                )?,
            };
            Ok(Effect::said(format!(
                "rule #{landed}: {action} {} {} on `{target}` for `{agent}` — live now",
                methods.join(","),
                paths.join(",")
            )))
        }
        Intent::Profile => {
            let id = required(form, "id")?;
            let profile = profiles::get(&id)?;
            let dry_run = form.flag("dry-run");
            let added = profiles::add(
                path,
                &profile,
                &profiles::AddOptions {
                    name: form.opt("as"),
                    secret: form.opt("secret"),
                    access: form.opt("access"),
                    vars: form
                        .pairs("var")?
                        .into_iter()
                        .map(|(name, value)| format!("{name}={value}"))
                        .collect(),
                    agent: form.opt("agent"),
                    dry_run,
                },
            )?;
            if let Some(plan) = added.plan {
                return Ok(Effect {
                    message: format!("`{id}` — nothing written"),
                    token: None,
                    preview: Some(plan),
                });
            }
            Ok(Effect::said(format!(
                "added `{}` ({}) at access `{}`, {} rules — restart agent-iap to serve it",
                added.name,
                added.kind,
                added.access,
                added.rules.len()
            )))
        }
    }
}

fn required(form: &Form, key: &str) -> Result<String> {
    form.opt(key)
        .with_context(|| format!("`{key}` is required"))
}

fn default_to(value: String, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value
    }
}

fn non_empty(values: Vec<String>, fallback: &str) -> Vec<String> {
    if values.is_empty() {
        vec![fallback.to_string()]
    } else {
        values
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(text: &str) -> Config {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn a_new_rule_is_not_something_to_restart_for() {
        // The whole point of reloading the ACL: a rule written from the
        // approval dialogue is in force before the operator looks away.
        let running = config("");
        let edited = config(
            r#"
[[acl]]
target = "gh"
action = "allow"
"#,
        );
        assert!(needs_restart(&running, &edited).is_empty());
    }

    #[test]
    fn a_new_upstream_is() {
        let running = config("");
        let edited = config(
            r#"
[[upstreams]]
name = "gh"
base_url = "https://api.github.com"
"#,
        );
        assert_eq!(needs_restart(&running, &edited), vec!["upstreams"]);
    }

    #[test]
    fn a_credential_keeps_its_last_known_status_across_a_reload() {
        // Otherwise every unrelated edit blanks the column an operator is
        // using to decide whether the vault is still unlocked.
        let config = config(
            r#"
[[upstreams]]
name = "gh"
base_url = "https://api.github.com"
auth = { type = "bearer", secret = "env:GH_TOKEN" }
"#,
        );
        let first = credential_statuses(&config, &[]);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].reference, "env:GH_TOKEN");
        assert!(first[0].resolves.is_none());

        let checked = vec![CredentialStatus {
            resolves: Some(Ok(())),
            ..credential_statuses(&config, &[]).pop().unwrap()
        }];
        let again = credential_statuses(&config, &checked);
        assert_eq!(again[0].resolves, Some(Ok(())));
    }
}
