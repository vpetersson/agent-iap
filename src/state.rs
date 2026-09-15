//! Everything the request path needs — assembled at startup, and replaceable
//! without one.
//!
//! The policy file is edited while this process is running: from the console,
//! from `agent-iap acl add` in the next terminal, from an editor. Nothing here
//! is therefore assembled once and owned forever. `reload` swaps the lot, and
//! its contract is the one that matters: everything that can fail is tried
//! before anything is swapped, so a policy file edited into something that will
//! not load leaves the proxy running the one it already had. A proxy serving
//! half of one policy and half of another is serving a policy nobody wrote.

use anyhow::{bail, Context, Result};
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

use crate::acl::Acl;
use crate::approval::ApprovalBroker;
use crate::audit::{AuditLog, AuditRecord};
use crate::config::Config;
use crate::config::WorkloadMode;
use crate::credentials::CredentialInjector;
use crate::identity::{AgentRegistry, AuthFailure, Caller};
use crate::secrets::{SecretRef, SecretResolver};
use crate::workload::{WorkloadError, WorkloadIssuer};

pub struct AppState {
    /// The policy this process is serving right now. Read through `config()`,
    /// which hands out a snapshot — one request is weighed against one version
    /// of the file, even if it is replaced halfway through.
    config: RwLock<Arc<Config>>,
    pub agents: AgentRegistry,
    pub acl: Acl,
    pub audit: Arc<AuditLog>,
    pub injector: CredentialInjector,
    pub broker: Arc<ApprovalBroker>,
    /// Rebuilt when the upstream timeouts change, which are baked into a client
    /// rather than read per request. Cloning one is an `Arc` bump.
    http: RwLock<reqwest::Client>,
    pub resolver: Arc<SecretResolver>,
    pub admin_token: String,
    pub workload: WorkloadIssuer,
    /// Announced after every successful reload, for the parts that cannot be
    /// swapped behind a lock because they are holding a socket open.
    reloads: broadcast::Sender<Arc<Config>>,
}

/// The client the proxy forwards with. Its timeouts cannot be changed after it
/// is built, so a reload that changes them builds another.
fn build_http_client(config: &Config) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        // `read_timeout` bounds the gap between chunks; `timeout` would bound
        // the whole response, silently truncating any stream that ran longer
        // than it — which for streamed LLM output is the normal case.
        .read_timeout(Duration::from_secs(config.server.upstream_timeout_secs))
        .connect_timeout(Duration::from_secs(
            config.server.upstream_connect_timeout_secs,
        ))
        .user_agent(crate::USER_AGENT)
        .build()
        .context("building the upstream HTTP client")
}

fn timeouts_changed(current: &Config, edited: &Config) -> bool {
    current.server.upstream_timeout_secs != edited.server.upstream_timeout_secs
        || current.server.upstream_connect_timeout_secs
            != edited.server.upstream_connect_timeout_secs
}

/// Re-read every reference the policy file names, before anything binds a port.
///
/// Reports all of the failures rather than the first: a proxy fronting twenty
/// upstreams should not need twenty restarts to discover that three of its
/// references are wrong.
///
/// `refresh` rather than `resolve`, so this both warms the cache at startup and
/// re-reads it on reload — a credential rotated behind an unchanged reference
/// takes effect the moment the file is reloaded, not only on a full restart.
/// A reference that no longer resolves fails the reload, which leaves the proxy
/// on the policy it already had (`AppState::reload` resolves before it swaps).
fn preload_secrets(config: &Config, resolver: &SecretResolver) -> Result<()> {
    let references = config.secret_refs();
    let mut failures = Vec::new();
    for reference in &references {
        if let Err(error) = resolver.refresh(reference) {
            failures.push((reference.clone(), format!("{error:#}")));
        }
    }
    if failures.is_empty() {
        return Ok(());
    }

    // Only mention `op` when an `op://` reference is one of the ones that
    // actually failed. Blaming 1Password for an unset environment variable
    // sends the operator to sign into a vault this config never mentions —
    // and `op` is never even invoked unless a reference asks for it.
    let hint = if failures
        .iter()
        .any(|(reference, _)| matches!(SecretRef::parse(reference), Ok(SecretRef::OnePassword(_))))
    {
        " — is `op` signed in?"
    } else {
        ""
    };

    let detail = failures
        .iter()
        .map(|(reference, error)| format!("  {reference}: {error}"))
        .collect::<Vec<_>>()
        .join("\n");

    bail!(
        "{} of {} secret references could not be resolved{hint}\n{detail}",
        failures.len(),
        references.len(),
    )
}

impl AppState {
    pub fn build(config: Config, audit_to_stderr: bool) -> Result<Arc<Self>> {
        let resolver = Arc::new(SecretResolver::new(config.server.op_binary.clone()));

        // Resolve everything now: a missing key or a locked 1Password vault should
        // stop startup, not surface as a mystery 502 on the first real request.
        preload_secrets(&config, &resolver)?;

        let agents = AgentRegistry::build(&config, &resolver)?;
        let acl = Acl::compile(&config)?;
        let audit = Arc::new(AuditLog::open(&config.audit, audit_to_stderr)?);

        let http = build_http_client(&config)?;

        let injector = CredentialInjector::new(
            Arc::clone(&resolver),
            http.clone(),
            Some(Arc::clone(&audit)),
        );

        // Parse every service-account key now. A malformed key should stop the
        // process here, not turn into a 502 the first time an agent calls.
        for upstream in &config.upstreams {
            injector.warm(&upstream.name, &upstream.auth)?;
        }
        for server in &config.mcp_servers {
            injector.warm(&server.name, &server.auth)?;
        }
        let broker = Arc::new(ApprovalBroker::new(Duration::from_secs(
            config.server.approval_timeout_secs,
        )));

        let admin_token = match &config.server.admin_token {
            Some(reference) => resolver
                .resolve(reference)
                .context("resolving server.admin_token")?
                .expose()
                .to_string(),
            None => crate::identity::generate_token()?,
        };

        let workload = WorkloadIssuer::new(&config.server.workload_identity)?;
        let (reloads, _) = broadcast::channel(16);

        Ok(Arc::new(AppState {
            config: RwLock::new(Arc::new(config)),
            agents,
            acl,
            audit,
            injector,
            broker,
            http: RwLock::new(http),
            resolver,
            admin_token,
            workload,
            reloads,
        }))
    }

    /// The policy as of right now.
    ///
    /// A snapshot rather than a borrow: a request that read the upstream list
    /// from one version of the file and the body limit from the next would be
    /// deciding by a policy that never existed. Callers take this once and use
    /// it throughout.
    pub fn config(&self) -> Arc<Config> {
        Arc::clone(&self.config.read())
    }

    /// The client to forward with. Cloned rather than borrowed so a reload can
    /// replace it without waiting for in-flight requests to finish with it.
    pub fn http(&self) -> reqwest::Client {
        self.http.read().clone()
    }

    /// Told about every reload, for the listeners — a socket bound to one
    /// address cannot be swapped behind a lock.
    pub fn subscribe_reloads(&self) -> broadcast::Receiver<Arc<Config>> {
        self.reloads.subscribe()
    }

    /// Serve this policy instead of the one currently loaded.
    ///
    /// Every fallible step happens first, against locals: the secrets resolve,
    /// the rules compile, the agents enrol, the credential schemes parse, the
    /// client builds, the log opens. Only then is anything installed, and the
    /// installs cannot fail. An edit that would not have started this process
    /// therefore does not stop it either — it is refused, with the reason, and
    /// the proxy carries on serving what it was already serving.
    pub fn reload(&self, config: Config, why: crate::reload::Trigger) -> Result<Arc<Config>> {
        // 1. Everything that can say no.
        preload_secrets(&config, &self.resolver)?;
        let rules = Acl::prepare(&config)?;
        let roster = AgentRegistry::prepare(&config, &self.resolver)?;

        // A credential edited in place keeps the name it is cached under, so
        // the tidying by name below cannot see it. Forget what this process is
        // holding for those targets *before* warming, or a changed
        // service-account key would be "parsed" from the copy of the old one
        // and a malformed new key would sail through this reload. Dropped even
        // if a later step refuses the policy, which costs one re-parse from the
        // config still in force — the safe direction.
        let current = self.config();
        for (target, auth) in config
            .upstreams
            .iter()
            .map(|upstream| (&upstream.name, &upstream.auth))
            .chain(config.mcp_servers.iter().map(|s| (&s.name, &s.auth)))
        {
            let was = current
                .upstream(target)
                .map(|upstream| &upstream.auth)
                .or_else(|| current.mcp_server(target).map(|server| &server.auth));
            if was.is_some_and(|was| was != auth) {
                self.injector.forget(target);
            }
        }

        // Warming parses each service-account key. Done before the swap so a
        // malformed one is a refused reload rather than a 502 on first use.
        for upstream in &config.upstreams {
            self.injector.warm(&upstream.name, &upstream.auth)?;
        }
        for server in &config.mcp_servers {
            self.injector.warm(&server.name, &server.auth)?;
        }

        let http = match timeouts_changed(&current, &config) {
            true => Some(build_http_client(&config)?),
            false => None,
        };

        // 2. Nothing below here can fail.
        self.acl.install(rules);
        self.agents.install(roster);
        if let Some(http) = http {
            *self.http.write() = http;
        }
        self.broker
            .set_timeout(Duration::from_secs(config.server.approval_timeout_secs));
        self.workload.reconfigure(&config.server.workload_identity);

        // A log that cannot be reopened is worth saying out loud, but it is not
        // worth refusing the whole policy over: the records keep going to the
        // file that is already open, which is the safe direction.
        if let Err(error) = self.audit.reopen(&config.audit) {
            tracing::error!(?error, "keeping the audit log where it is");
        }

        // A credential reference that was removed, or repointed at a different
        // vault item, must not keep being served from the token this process
        // minted for the old one.
        self.injector.retain_targets(
            config
                .upstreams
                .iter()
                .map(|up| up.name.as_str())
                .chain(config.mcp_servers.iter().map(|server| server.name.as_str())),
        );

        let config = Arc::new(config);
        *self.config.write() = Arc::clone(&config);

        // A policy change is a thing this proxy did, and the audit log is where
        // those go. Without it the log says an agent was allowed something and
        // nothing says the rule that allowed it appeared ten seconds earlier.
        // Best-effort on purpose: the policy is already in force, and refusing
        // to serve it because the log is full would be the wrong way round.
        let mut record = AuditRecord::new("proxy", "reload");
        record.target = self.config.read().server.listen.to_string();
        record.decision = Some(why.as_str().to_string());
        record.detail = Some(serde_json::json!({
            "agents": config.agents.len(),
            "upstreams": config.upstreams.len(),
            "mcp_servers": config.mcp_servers.len(),
            "acl_rules": config.acl.len(),
            "acl_default": config.acl_default.action.to_string(),
        }));
        self.audit.write_best_effort(record);

        let _ = self.reloads.send(Arc::clone(&config));
        Ok(config)
    }

    /// Resolve whatever credential a caller presented on the data plane.
    ///
    /// A workload token is tried first and only when it *is* one: `NotAToken`
    /// falls through to the agent registry, so an agent token is never reported
    /// as a malformed JWT and a malformed JWT is never reported as an unknown
    /// agent. In `required` mode a perfectly good agent token stops here — it
    /// mints, and that is all it does.
    pub fn authenticate(&self, presented: &str) -> Result<Caller, AuthFailure> {
        if self.workload.mode().enabled() {
            match self.workload.verify(presented) {
                Ok(token) => {
                    let Some(agent) = self.agents.by_id(&token.agent) else {
                        // The token is ours and still valid, but the agent it
                        // names has been removed from the policy file since.
                        return Err(AuthFailure::Workload(WorkloadError::UnknownAgent(
                            token.agent.clone(),
                        )));
                    };
                    return Ok(Caller::Workload { agent, token });
                }
                Err(WorkloadError::NotAToken) => {}
                Err(error) => return Err(AuthFailure::Workload(error)),
            }
        }

        match self.agents.authenticate(presented) {
            Some(_) if self.workload.mode() == WorkloadMode::Required => {
                Err(AuthFailure::WorkloadRequired)
            }
            Some(agent) => Ok(Caller::Agent(agent)),
            None => Err(AuthFailure::UnknownAgent),
        }
    }

    /// Record that the proxy came up, so every log begins with its own provenance.
    ///
    /// Fallible: a proxy that cannot write its own startup line will not be able
    /// to record anything it allows either, and should not come up at all.
    pub fn log_startup(&self) -> Result<()> {
        let mut record = AuditRecord::new("proxy", "startup");
        let config = self.config();
        record.target = config.server.listen.to_string();
        record.detail = Some(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            // Whether this process came up in cleartext is evidence, and the
            // log is where evidence goes.
            "tls": config.server.tls.is_some(),
            "admin_tls": config.server.admin_tls_material().is_some(),
            "agents": self.agents.len(),
            "upstreams": config.upstreams.len(),
            "mcp_servers": config.mcp_servers.len(),
            "acl_rules": self.acl.rule_count(),
            "acl_default": self.acl.default_action().to_string(),
            // Whether this process came up handing out standing grants or
            // short-lived ones is evidence, and the log is where evidence goes.
            "workload_identity": self.workload.mode().to_string(),
            "workload_lifetime_secs": self.workload.lifetime_secs(),
        }));
        self.audit
            .write(record)
            .context("writing the first audit record — is the log path writable?")?;
        Ok(())
    }
}

impl AppState {
    /// `reload` without naming a trigger, for tests that are not about one.
    #[cfg(test)]
    pub fn reload_for_test(&self, config: Config) -> Result<Arc<Config>> {
        self.reload(config, crate::reload::Trigger::Asked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config whose every secret reference is broken, so startup has to
    /// report on all of them.
    fn config_with(refs: &[&str]) -> Config {
        let upstreams: String = refs
            .iter()
            .enumerate()
            .map(|(index, reference)| {
                format!(
                    r#"
[[upstreams]]
name = "up{index}"
base_url = "https://example.invalid"
auth = {{ type = "bearer", secret = "{reference}" }}
"#
                )
            })
            .collect();
        toml::from_str(&format!(
            r#"
[[agents]]
id = "a"
token_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
{upstreams}"#
        ))
        .unwrap()
    }

    /// The whole contract of `reload`, on the thing a reload is usually for.
    #[test]
    fn an_upstream_added_by_a_reload_is_routable_and_carries_its_credential() {
        std::env::set_var("AGENT_IAP_RELOAD_TEST", "sk-not-real");
        let dir = tempfile::tempdir().unwrap();
        let policy = |extra: &str| -> Config {
            toml::from_str(&format!(
                r#"
[audit]
path = "{}"
stderr = false

[[agents]]
id = "claude"
token_sha256 = "{}"
{extra}
"#,
                dir.path().join("audit.jsonl").display(),
                crate::identity::token_hash("iap_test"),
            ))
            .unwrap()
        };

        let state = AppState::build(policy(""), false).unwrap();
        assert!(state.config().upstream("linear").is_none());

        state
            .reload_for_test(policy(
                r#"
[[upstreams]]
name = "linear"
base_url = "https://api.linear.app"
auth = { type = "bearer", secret = "env:AGENT_IAP_RELOAD_TEST" }

[[acl]]
name = "linear-reads"
target = "linear"
action = "allow"
"#,
            ))
            .unwrap();

        // Routable…
        assert_eq!(
            state
                .config()
                .upstream("linear")
                .map(|up| up.base_url.clone()),
            Some("https://api.linear.app".to_string())
        );
        // …and decided on by the new rules, in the same reload.
        assert_eq!(
            state
                .acl
                .evaluate(&crate::acl::AccessRequest::http(
                    "claude", "linear", "GET", "/x"
                ))
                .action,
            crate::config::Action::Allow
        );
    }

    /// A credential whose *value* moved behind an unchanged reference is
    /// re-read on reload. This used to take a full restart: the resolver cached
    /// the first read for the life of the process, so a rotated secret behind
    /// `file:`/`op://` kept serving the old value until the proxy was bounced.
    #[tokio::test]
    async fn a_reload_re_reads_a_rotated_credential() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("token");
        std::fs::write(&token, "old-token").unwrap();

        let policy = || -> Config {
            toml::from_str(&format!(
                r#"
[audit]
path = "{}"
stderr = false

[[agents]]
id = "claude"
token_sha256 = "{}"

[[upstreams]]
name = "gh"
base_url = "https://api.github.com"
auth = {{ type = "bearer", secret = "file:{}" }}
"#,
                dir.path().join("audit.jsonl").display(),
                crate::identity::token_hash("iap_test"),
                token.display(),
            ))
            .unwrap()
        };

        let state = AppState::build(policy(), false).unwrap();

        // Rotate the credential behind the same reference, then reload.
        std::fs::write(&token, "new-token").unwrap();
        state.reload_for_test(policy()).unwrap();

        let mut req = reqwest::Request::new(
            http::Method::GET,
            "https://api.github.com/user".parse().unwrap(),
        );
        let auth = state.config().upstream("gh").unwrap().auth.clone();
        state.injector.apply("gh", &auth, &mut req).await.unwrap();
        assert_eq!(
            req.headers()["authorization"],
            "Bearer new-token",
            "the reload re-read the rotated secret, no restart needed"
        );
    }

    /// The rule that makes a live reload safe to run against a proxy holding
    /// credentials: an edit that would not have started this process does not
    /// stop it either.
    #[test]
    fn a_policy_that_will_not_load_is_refused_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let good: Config = toml::from_str(&format!(
            r#"
[audit]
path = "{}"
stderr = false

[[agents]]
id = "claude"
token_sha256 = "{}"

[[acl]]
name = "keep-me"
target = "gh"
action = "allow"
"#,
            dir.path().join("audit.jsonl").display(),
            crate::identity::token_hash("iap_test"),
        ))
        .unwrap();

        let state = AppState::build(good, false).unwrap();

        // An upstream whose credential reference does not resolve. Nothing in
        // here is malformed; it simply could not be served.
        let broken: Config = toml::from_str(&format!(
            r#"
[audit]
path = "{}"
stderr = false

[[upstreams]]
name = "gh"
base_url = "https://api.github.com"
auth = {{ type = "bearer", secret = "env:AGENT_IAP_DEFINITELY_NOT_SET" }}
"#,
            dir.path().join("audit.jsonl").display(),
        ))
        .unwrap();

        let error = state.reload_for_test(broken).unwrap_err().to_string();
        assert!(error.contains("AGENT_IAP_DEFINITELY_NOT_SET"), "{error}");

        // Still serving what it was serving: the agent, and the rule.
        assert!(state.agents.by_id("claude").is_some());
        assert_eq!(state.acl.rule_count(), 1);
        assert!(state.config().upstreams.is_empty());
    }

    /// The half `retain_targets` cannot see: an upstream whose credential was
    /// edited keeps its name, so a token minted from the old one is cached
    /// under a key that still looks current. That token outlives the grant
    /// that justified it, which is the thing this proxy exists to stop.
    #[test]
    fn a_reload_that_repoints_a_credential_drops_the_token_minted_for_the_old_one() {
        std::env::set_var("AGENT_IAP_RELOAD_SECRET_ONE", "client-secret-one");
        std::env::set_var("AGENT_IAP_RELOAD_SECRET_TWO", "client-secret-two");
        let dir = tempfile::tempdir().unwrap();
        let policy = |reference: &str| -> Config {
            toml::from_str(&format!(
                r#"
[audit]
path = "{}"
stderr = false

[[upstreams]]
name = "gh"
base_url = "https://api.github.com"
auth = {{ type = "oauth2_client_credentials", token_url = "https://id.example.com/token", client_id = "iap", client_secret = "{reference}" }}
"#,
                dir.path().join("audit.jsonl").display(),
            ))
            .unwrap()
        };

        let state = AppState::build(policy("env:AGENT_IAP_RELOAD_SECRET_ONE"), false).unwrap();
        state
            .injector
            .remember("gh", "access-token-from-the-old-client");

        // A reload that changed something else entirely must not throw the
        // token away — that is a round trip to the token endpoint on every
        // unrelated edit.
        state
            .reload_for_test(policy("env:AGENT_IAP_RELOAD_SECRET_ONE"))
            .unwrap();
        assert_eq!(
            state.injector.holds("gh").as_deref(),
            Some("access-token-from-the-old-client"),
            "an unrelated reload re-minted a perfectly good token"
        );

        state
            .reload_for_test(policy("env:AGENT_IAP_RELOAD_SECRET_TWO"))
            .unwrap();
        assert_eq!(
            state.injector.holds("gh"),
            None,
            "the token minted from the credential that was just replaced is still being served"
        );
    }

    #[test]
    fn every_broken_reference_is_reported_not_just_the_first() {
        // Twenty upstreams should not mean twenty restarts to find three typos.
        let config = config_with(&["env:AGENT_IAP_NOT_SET_ONE", "env:AGENT_IAP_NOT_SET_TWO"]);
        let resolver = SecretResolver::new("op");
        let error = preload_secrets(&config, &resolver).unwrap_err().to_string();

        assert!(error.contains("2 of 2"), "{error}");
        assert!(error.contains("AGENT_IAP_NOT_SET_ONE"), "{error}");
        assert!(error.contains("AGENT_IAP_NOT_SET_TWO"), "{error}");
    }

    #[test]
    fn an_unset_environment_variable_is_never_blamed_on_1password() {
        // The whole defect: `op` is not invoked unless a reference asks for it,
        // so naming it here sends the operator to sign into a vault this config
        // does not mention.
        let config = config_with(&["env:AGENT_IAP_NOT_SET_ONE"]);
        let resolver = SecretResolver::new("op");
        let error = preload_secrets(&config, &resolver).unwrap_err().to_string();

        assert!(!error.contains("op"), "{error}");
        assert!(error.contains("is not set"), "{error}");
    }

    #[test]
    fn the_1password_hint_appears_when_an_op_reference_is_the_one_failing() {
        let config = config_with(&["env:AGENT_IAP_NOT_SET_ONE", "op://Vault/Item/field"]);
        // A binary that cannot exist, so the `op` branch fails without needing
        // the real CLI installed or signed in.
        let resolver = SecretResolver::new("agent-iap-no-such-op-binary");
        let error = preload_secrets(&config, &resolver).unwrap_err().to_string();

        assert!(error.contains("is `op` signed in?"), "{error}");
        assert!(error.contains("op://Vault/Item/field"), "{error}");
    }

    #[test]
    fn a_config_whose_references_all_resolve_preloads_cleanly() {
        let config = config_with(&["literal:sk-test"]);
        let resolver = SecretResolver::new("op");
        preload_secrets(&config, &resolver).unwrap();
    }
}
