//! What the console does to the policy file, and what the running proxy makes
//! of it afterwards.
//!
//! Every write here goes through `enroll` or `profiles` — the same functions
//! the CLI calls, with the same validation and the same refusal to put a
//! credential in the file. The console adds no way to write something
//! `agent-iap upstream add` would have rejected.
//!
//! The second half is the part a one-shot CLI never had to think about: this
//! process is *running* against the policy it just edited. Every write here is
//! followed by `AppState::reload`, which puts the whole edited file in charge —
//! rules, agents, upstreams, MCP servers, credentials, timeouts, the audit log,
//! and the listeners. There is nothing the console can write that takes effect
//! only after a restart, because an operator who wrote a rule from the approval
//! dialogue is answering a request that is still parked.
//!
//! The console is not the only thing that writes this file. `agent-iap acl add`
//! in the next terminal over, or an editor, edits the same policy the console
//! is displaying — and a pane showing a rule list that is no longer the rule
//! list is a pane worth distrusting. The watching itself belongs to the daemon
//! (`crate::reload`), which does it whether or not anyone is looking; the
//! console shares that watcher, so pressing `r` does not leave it believing an
//! edit is still outstanding, and it hears about every reload either of them
//! causes.

use anyhow::{Context, Result};
use chrono::Utc;
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::Config;
use crate::enroll::{self, McpTransportSpec};
use crate::list::{Inventory, ListOptions, What};
use crate::profiles;
use crate::reload::Watcher;
use crate::state::AppState;

use super::form::{Form, Intent};
use super::views::CredentialStatus;

/// The policy file as the console currently understands it.
pub struct Policy {
    pub path: PathBuf,
    pub config: Arc<Config>,
    pub inventory: Inventory,
    pub credentials: Vec<CredentialStatus>,
    /// The daemon's watcher, shared. The console does not read the file itself.
    watcher: Arc<Watcher>,
}

impl Policy {
    pub fn load(watcher: Arc<Watcher>, state: &Arc<AppState>) -> Result<Self> {
        let mut policy = Policy {
            path: watcher.path().to_path_buf(),
            config: state.config(),
            inventory: Inventory::default(),
            credentials: Vec::new(),
            watcher,
        };
        policy.show(state.config())?;
        Ok(policy)
    }

    /// The watcher the daemon is running, shared with this console.
    ///
    /// Handed out because the reload itself happens on a thread of its own —
    /// reading the file can be a vault lookup per credential, which is not
    /// something the console can stop drawing for. See `spawn_reloader`.
    pub fn watcher(&self) -> &Arc<Watcher> {
        &self.watcher
    }

    /// Catch the panes up to a policy that is already in force — the daemon's
    /// watcher having reloaded it, or the console itself a moment ago.
    pub fn show(&mut self, config: Arc<Config>) -> Result<()> {
        self.inventory = Inventory::build(&config, &ListOptions::default())
            .context("reading the policy file back")?;
        self.credentials = credential_statuses(&config, &self.credentials);
        self.config = config;
        Ok(())
    }

    /// Record what a re-read of the credential references found.
    ///
    /// Answers arrive by reference rather than by row number: the check runs
    /// off the thread that draws, and the policy can be replaced while it is
    /// out. A row that is no longer in the file is simply not found, and a row
    /// that arrived while it was out keeps saying `not checked`, which is what
    /// it is.
    pub fn checked(&mut self, answers: &[(String, Result<(), String>)]) {
        for (reference, answer) in answers {
            for row in self
                .credentials
                .iter_mut()
                .filter(|row| row.reference == *reference)
            {
                row.resolves = Some(answer.clone());
            }
        }
    }
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
    /// The service to call now that it is written, when the form asked for it.
    /// Carried back rather than done here: the call is a network round trip and
    /// sometimes a child process, and this function runs on the thread that
    /// draws.
    pub verify: Option<String>,
}

impl Effect {
    fn said(message: impl Into<String>) -> Self {
        Effect {
            message: message.into(),
            token: None,
            preview: None,
            verify: None,
        }
    }

    /// The same, for a service the form offered to verify.
    fn wrote(form: &Form, name: &str, message: impl Into<String>) -> Self {
        Effect {
            verify: form.flag("verify").then(|| name.to_string()),
            ..Effect::said(message)
        }
    }
}

/// Apply a filled-in form to the policy file.
pub fn submit(policy: &Policy, form: &Form) -> Result<Effect> {
    let path = policy.path.as_path();
    match &form.intent {
        Intent::Agent => {
            let id = required(form, "id")?;
            let targets = form.list("targets");
            let agent = enroll::add_agent(
                path,
                &id,
                form.opt("name").as_deref(),
                match form.flag("any-target") {
                    true => enroll::Reach::Any,
                    false => enroll::Reach::Only(&targets),
                },
            )?;
            Ok(Effect {
                message: format!("enrolled `{id}` — its token is live now, no restart needed"),
                token: Some((agent.id, agent.token)),
                preview: None,
                verify: None,
            })
        }
        Intent::Upstream => {
            let name = required(form, "name")?;
            let base_url = required(form, "base-url")?;
            let headers = form.pairs("set-header")?;
            enroll::add_upstream(path, &name, &base_url, &form.auth().to_spec()?, &headers)?;
            Ok(Effect::wrote(
                form,
                &name,
                format!("added upstream `{name}` — {}", ungranted(policy)),
            ))
        }
        Intent::EditUpstream(name) => {
            let base_url = required(form, "base-url")?;
            let headers = form.pairs("set-header")?;
            enroll::edit_upstream(path, name, &base_url, &form.auth().to_spec()?, &headers)?;
            Ok(Effect::wrote(
                form,
                name,
                format!("updated upstream `{name}` — the next call through it uses this"),
            ))
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
            Ok(Effect::wrote(
                form,
                &name,
                format!("added MCP server `{name}` — {}", ungranted(policy)),
            ))
        }
        Intent::Rule => {
            let methods = non_empty(form.list("methods"), "*");
            let paths = non_empty(form.list("paths"), "**");
            let target = default_to(form.text("target"), "*");
            let agent = default_to(form.text("agent"), "*");
            let kind = form.text("kind");
            let action = form.text("action");
            let expires = form
                .opt("expires-in")
                .map(|ttl| enroll::parse_ttl(&ttl).map(|delta| Utc::now() + delta))
                .transpose()?;

            let name = form.opt("name");
            let spec = enroll::RuleSpec {
                name: name.as_deref(),
                agent: &agent,
                kind: &kind,
                target: &target,
                methods: &methods,
                paths: &paths,
                action: &action,
                expires,
            };

            let landed = match form.opt("position") {
                Some(position) => {
                    let index: usize = position
                        .parse()
                        .with_context(|| format!("`{position}` is not a rule number"))?;
                    enroll::insert_rule(path, index, &spec)?
                }
                None => enroll::add_rule(path, &spec)?,
            };
            let until = match expires {
                Some(at) => format!(", for {}", enroll::remaining(at, Utc::now())),
                None => String::new(),
            };
            Ok(Effect::said(format!(
                "rule #{landed}: {action} {} {} on `{target}` for `{agent}`{until} — live now",
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
                        .prefixed("var:")
                        .into_iter()
                        .map(|(name, value)| format!("{name}={value}"))
                        .collect(),
                    agent: form.opt("agent"),
                    grant: form.flag("grant"),
                    dry_run,
                },
            )?;
            if let Some(plan) = added.plan {
                return Ok(Effect {
                    message: format!("`{id}` — nothing written"),
                    token: None,
                    preview: Some(plan),
                    verify: None,
                });
            }
            let permitted = match added.granted {
                true => format!("{} rules — live now", added.rules.len()),
                // Not "0 rules": what happened is a policy decision, and a
                // count of zero reads as one the form failed to make.
                false => "nothing granted — the first call stops here".to_string(),
            };
            Ok(Effect::wrote(
                form,
                &added.name,
                format!(
                    "added `{}` ({}) at access `{}`, {permitted}",
                    added.name, added.kind, added.access,
                ),
            ))
        }
    }
}

/// The footer line for a service just enrolled with nothing permitting it.
///
/// "agents can reach it now" is what this said, on a console whose whole
/// purpose is that they cannot until somebody says so. The rules have not
/// changed — nothing above writes one — so the policy in hand is the one the
/// next call will be decided against.
fn ungranted(policy: &Policy) -> String {
    let default = policy.config.acl_default.action;
    // Before anything about the fallthrough: a standing `allow` that names no
    // target covers the service written a moment ago, so "nothing grants it
    // yet" would be false as it was printed — and this is the exact moment an
    // operator finds out, or does not, that the next call will not stop here.
    if let Some(&index) = crate::verify::blanket_allows(&policy.config.acl).first() {
        return format!(
            "rule #{index} allows every target, so this is granted already and no call to it \
             will stop here. `x` on the acl pane (5) takes that rule out"
        );
    }
    match crate::verify::cannot_ask_warning(&policy.config.acl, default) {
        Some(_) => format!(
            "nothing grants it, and nothing in this policy can ask: a call {}. `a` on the acl              pane writes a rule",
            crate::verify::fallthrough_clause(default)
        ),
        None => format!(
            "nothing grants it yet — a call {}",
            crate::verify::fallthrough_clause(default)
        ),
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
