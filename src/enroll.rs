//! Enrolling and retiring agents, upstreams and rules in a policy file from
//! the CLI.
//!
//! `init` used to be the only way to get a usable file, which forced it to
//! guess: it minted a token nobody asked for and wrote an Anthropic upstream
//! that may not be the one you wanted. The alternative was editing TOML by
//! hand, and a policy file is exactly the kind of file where a typo is a
//! security bug rather than a parse error.
//!
//! So these commands append to the file instead. Two properties matter and
//! both are load-bearing:
//!
//! * **Comments survive.** The generated file is mostly comments explaining
//!   what each block does, and a round-trip through `toml::to_string` would
//!   delete every one of them. `toml_edit` keeps the document as written.
//! * **The result is validated before it is saved.** Every edit is applied to
//!   an in-memory document, parsed back through `Config` and run through the
//!   same `validate()` the proxy uses at startup. A rejected edit leaves the
//!   file untouched, so a bad flag can never be the reason the proxy stops
//!   coming up.
//!
//! Editing earns it for the same reason adding does — `edit_upstream` is the
//! console's `e`, and has no CLI command behind it yet: a flag left off a
//! command line has to mean either "leave it alone" or "set it to nothing", and
//! for a credential those differ by an upstream that stops being protected. The
//! console has no such ambiguity, because the form opens on the entry and sends
//! the whole of it back.
//!
//! Removal earns the same treatment, and for a sharper reason. The pitch for
//! this proxy is that a leaked agent token is revoked by deleting one line and
//! nothing real rotates — but "delete one line" was a hand-edit of the file,
//! performed under time pressure, on the one operation nobody rehearses. So
//! `rm` and `rotate` are commands too, with two properties of their own:
//!
//! * **A removal cannot leave a file the proxy would refuse.** Removing a
//!   service an agent still lists in `targets`, or an agent id a rule still
//!   names, is caught here rather than at the next restart.
//! * **A removal says what it orphaned.** A rule that matches nothing is how a
//!   policy file rots, so the rules naming the thing that just left are either
//!   pruned with it or reported by number.

use anyhow::{bail, Context, Result};
use std::path::Path;
use toml_edit::{Array, DocumentMut, Item, Table, Value};

use crate::config::{AclRuleConfig, Action, AuthConfig, Config};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};

use crate::identity;
use crate::secrets::SecretRef;

/// An agent enrolled into the file, and the token that proves it is that agent.
pub struct EnrolledAgent {
    pub id: String,
    /// Plaintext, existing only here and in the one line that prints it — the
    /// file got the hash.
    pub token: String,
}

/// Redacted for the same reason `init::Initialized` is: a `{:?}` in a test
/// failure or an error chain must not be what spills the token.
impl std::fmt::Debug for EnrolledAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrolledAgent")
            .field("id", &self.id)
            .field("token", &"***")
            .finish()
    }
}

/// How an upstream authenticates, in the shape the CLI accepts it.
#[derive(Debug, Clone)]
pub enum AuthSpec {
    None,
    Bearer {
        secret: String,
    },
    Header {
        header: String,
        secret: String,
        prefix: Option<String>,
    },
    Basic {
        /// A plain user field, or `None` when the user field is itself the
        /// credential and `username_secret` carries the reference.
        username: Option<String>,
        username_secret: Option<String>,
        secret: String,
    },
    Query {
        param: String,
        secret: String,
    },
    /// The two schemes that mint a short-lived token instead of forwarding a
    /// long-lived secret. They were reachable only by hand-editing the file,
    /// which meant the credential the proxy handles best — a Google service
    /// account — was the one the CLI could not enrol.
    Oauth2ClientCredentials {
        token_url: String,
        client_id: String,
        client_secret: String,
        scope: Option<String>,
        audience: Option<String>,
    },
    ServiceAccountJwt {
        key_file: Option<String>,
        issuer: Option<String>,
        private_key: Option<String>,
        key_id: Option<String>,
        token_url: Option<String>,
        audience: Option<String>,
        scopes: Vec<String>,
        subject: Option<String>,
        lifetime_secs: Option<u64>,
    },
}

/// Every credential scheme there is, spelled as the CLI's `--auth` takes them.
///
/// The console offers the same list from the same constant: a scheme the CLI
/// can enrol and the console cannot is a reason to keep a terminal open beside
/// the terminal, which is what the console exists to stop.
pub const AUTH_SCHEMES: &[&str] = &[
    "none",
    "bearer",
    "header",
    "basic",
    "query",
    "oauth2-client-credentials",
    "service-account-jwt",
];

/// Everything the credential schemes take, in the shape a human supplies it —
/// a flag on the command line, a field in the console's form.
///
/// One struct for both because each scheme needs a different subset, and the
/// rule about which subset is the difference between a credential that is
/// injected and one that silently is not. Two copies of that rule would be two
/// chances to get it wrong.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthInput {
    /// One of `AUTH_SCHEMES`. `-` and `_` are interchangeable.
    pub scheme: String,
    pub secret: Option<String>,
    pub header: Option<String>,
    pub prefix: Option<String>,
    pub username: Option<String>,
    pub username_secret: Option<String>,
    pub param: Option<String>,
    pub key_file: Option<String>,
    pub private_key: Option<String>,
    pub issuer: Option<String>,
    pub key_id: Option<String>,
    pub token_url: Option<String>,
    pub audience: Option<String>,
    pub scopes: Vec<String>,
    pub subject: Option<String>,
    pub lifetime_secs: Option<u64>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

impl AuthInput {
    /// Which fields this scheme reads. The console shows these and hides the
    /// rest, so a form for `bearer` does not ask for a token endpoint.
    pub fn fields_for(scheme: &str) -> &'static [&'static str] {
        match normalise_scheme(scheme) {
            "none" => &[],
            "bearer" => &["secret"],
            "header" => &["header", "secret", "prefix"],
            "basic" => &["username", "username-secret", "secret"],
            "query" => &["param", "secret"],
            "oauth2-client-credentials" => &[
                "token-url",
                "client-id",
                "client-secret",
                "scope",
                "audience",
            ],
            "service-account-jwt" => &[
                "key-file",
                "private-key",
                "issuer",
                "key-id",
                "token-url",
                "audience",
                "scope",
                "subject",
                "lifetime-secs",
            ],
            _ => &[],
        }
    }

    /// Which of `fields_for`'s keys hold a secret *reference* — `env:NAME`,
    /// `file:/path`, `op://vault/item/field` — rather than a plain value.
    ///
    /// `--header x-api-key` is a header name and `--issuer` is a JWT claim;
    /// neither is resolved against anything. These five are, which is why the
    /// console offers its file picker on exactly these and why an error about
    /// one of them has to be redacted before it is printed. The list is
    /// checked against `AuthConfig::secret_fields` in the tests, so a scheme
    /// that grows a sixth cannot quietly be left off it.
    pub fn is_reference(key: &str) -> bool {
        matches!(
            key,
            "secret" | "username-secret" | "client-secret" | "key-file" | "private-key"
        )
    }

    /// A credential already in the file, read back as the fields a human would
    /// have typed to produce it.
    ///
    /// The inverse of `to_spec`, and the reason an edit form can open on what
    /// the file says rather than on blanks: a form that starts empty is one
    /// where changing a base URL quietly drops the `prefix` nobody remembered
    /// was there.
    pub fn of(auth: &AuthConfig) -> AuthInput {
        let scheme = |scheme: &str| AuthInput {
            scheme: scheme.to_string(),
            ..AuthInput::default()
        };
        match auth {
            AuthConfig::None => scheme("none"),
            AuthConfig::Bearer { secret } => AuthInput {
                secret: Some(secret.clone()),
                ..scheme("bearer")
            },
            AuthConfig::Header {
                header,
                secret,
                prefix,
            } => AuthInput {
                header: Some(header.clone()),
                secret: Some(secret.clone()),
                prefix: prefix.clone(),
                ..scheme("header")
            },
            AuthConfig::Basic {
                username,
                username_secret,
                secret,
            } => AuthInput {
                username: username.clone(),
                username_secret: username_secret.clone(),
                secret: Some(secret.clone()),
                ..scheme("basic")
            },
            AuthConfig::Query { param, secret } => AuthInput {
                param: Some(param.clone()),
                secret: Some(secret.clone()),
                ..scheme("query")
            },
            AuthConfig::Oauth2ClientCredentials {
                token_url,
                client_id,
                client_secret,
                scope,
                audience,
            } => AuthInput {
                token_url: Some(token_url.clone()),
                client_id: Some(client_id.clone()),
                client_secret: Some(client_secret.clone()),
                // One space-delimited parameter in the file, a repeatable flag
                // here — the same split `to_spec` joins back.
                scopes: scope
                    .iter()
                    .flat_map(|scope| scope.split_whitespace())
                    .map(String::from)
                    .collect(),
                audience: audience.clone(),
                ..scheme("oauth2-client-credentials")
            },
            AuthConfig::ServiceAccountJwt {
                key_file,
                issuer,
                private_key,
                key_id,
                token_url,
                audience,
                scopes,
                subject,
                lifetime_secs,
            } => AuthInput {
                key_file: key_file.clone(),
                issuer: issuer.clone(),
                private_key: private_key.clone(),
                key_id: key_id.clone(),
                token_url: token_url.clone(),
                audience: audience.clone(),
                scopes: scopes.clone(),
                subject: subject.clone(),
                lifetime_secs: *lifetime_secs,
                ..scheme("service-account-jwt")
            },
        }
    }

    /// One field's value, by the key `fields_for` names it with — the same key
    /// the CLI flag and the console's field share, so a form can fill itself in
    /// without a second table mapping fields to values.
    pub fn value(&self, key: &str) -> Option<String> {
        match key {
            "secret" => self.secret.clone(),
            "header" => self.header.clone(),
            "prefix" => self.prefix.clone(),
            "username" => self.username.clone(),
            "username-secret" => self.username_secret.clone(),
            "param" => self.param.clone(),
            "key-file" => self.key_file.clone(),
            "private-key" => self.private_key.clone(),
            "issuer" => self.issuer.clone(),
            "key-id" => self.key_id.clone(),
            "token-url" => self.token_url.clone(),
            "audience" => self.audience.clone(),
            "scope" => (!self.scopes.is_empty()).then(|| self.scopes.join(" ")),
            "subject" => self.subject.clone(),
            "lifetime-secs" => self.lifetime_secs.map(|secs| secs.to_string()),
            "client-id" => self.client_id.clone(),
            "client-secret" => self.client_secret.clone(),
            _ => None,
        }
    }

    /// Each scheme needs a different subset of the fields, and silently ignoring
    /// one that was supplied is how a credential ends up not being sent.
    pub fn to_spec(&self) -> Result<AuthSpec> {
        let need_secret = || -> Result<String> {
            self.secret.clone().context(
                "this `--auth` scheme needs `--secret <REF>` — the credential reference to inject",
            )
        };
        let spec = match normalise_scheme(&self.scheme) {
            "none" => AuthSpec::None,
            "bearer" => AuthSpec::Bearer {
                secret: need_secret()?,
            },
            "header" => AuthSpec::Header {
                header: self.header.clone().context(
                    "`--auth header` needs `--header <NAME>`, e.g. `--header x-api-key`",
                )?,
                secret: need_secret()?,
                prefix: self.prefix.clone(),
            },
            "basic" => {
                if self.username.is_none() && self.username_secret.is_none() {
                    bail!(
                        "`--auth basic` needs `--username <NAME>`, or `--username-secret <REF>` \
                         for an API like Graylog whose user field is the credential"
                    );
                }
                if self.username.is_some() && self.username_secret.is_some() {
                    bail!("`--username` and `--username-secret` are two spellings of the same field — pass one");
                }
                AuthSpec::Basic {
                    username: self.username.clone(),
                    username_secret: self.username_secret.clone(),
                    secret: need_secret()?,
                }
            }
            "query" => AuthSpec::Query {
                param: self
                    .param
                    .clone()
                    .context("`--auth query` needs `--param <NAME>`, e.g. `--param key`")?,
                secret: need_secret()?,
            },
            "oauth2-client-credentials" => AuthSpec::Oauth2ClientCredentials {
                token_url: self
                    .token_url
                    .clone()
                    .context("`--auth oauth2-client-credentials` needs `--token-url <URL>`")?,
                client_id: self
                    .client_id
                    .clone()
                    .context("`--auth oauth2-client-credentials` needs `--client-id <ID>`")?,
                client_secret: self
                    .client_secret
                    .clone()
                    .context("`--auth oauth2-client-credentials` needs `--client-secret <REF>`")?,
                // One space-delimited `scope` parameter, which is how the grant
                // spells a list; the flag is repeatable so the caller does not
                // have to know that.
                scope: (!self.scopes.is_empty()).then(|| self.scopes.join(" ")),
                audience: self.audience.clone(),
            },
            "service-account-jwt" => {
                if self.key_file.is_none() && self.private_key.is_none() {
                    bail!(
                        "`--auth service-account-jwt` needs `--key-file <REF>` (the JSON key \
                         Google issues) or `--private-key <REF>` with `--issuer` and `--token-url`"
                    );
                }
                if self.key_file.is_some() && self.private_key.is_some() {
                    bail!("`--key-file` already carries the private key — pass one or the other");
                }
                AuthSpec::ServiceAccountJwt {
                    key_file: self.key_file.clone(),
                    issuer: self.issuer.clone(),
                    private_key: self.private_key.clone(),
                    key_id: self.key_id.clone(),
                    token_url: self.token_url.clone(),
                    audience: self.audience.clone(),
                    scopes: self.scopes.clone(),
                    subject: self.subject.clone(),
                    lifetime_secs: self.lifetime_secs,
                }
            }
            other => bail!(
                "`{other}` is not a credential scheme — it is one of {}",
                AUTH_SCHEMES.join(", ")
            ),
        };
        if matches!(spec, AuthSpec::None) && self.secret.is_some() {
            bail!("`--secret` was given but `--auth` is `none`, so nothing would be injected");
        }
        Ok(spec)
    }
}

/// `service_account_jwt` as the config file spells it and `service-account-jwt`
/// as the flag does are the same scheme, and an operator reading one and typing
/// the other should not be told it does not exist.
fn normalise_scheme(scheme: &str) -> &str {
    match scheme.trim() {
        "oauth2_client_credentials" => "oauth2-client-credentials",
        "service_account_jwt" => "service-account-jwt",
        "" => "none",
        other => other,
    }
}

/// Add `[[agents]]`, minting the token and writing only its hash.
/// What an agent may address at all, as the operator spelled it out.
///
/// An enum rather than "the list, and empty means everything", because that
/// is the shape the bug had: `targets` is the coarse gate in front of the ACL,
/// an omitted one reads as *any* upstream and *any* MCP server this proxy
/// fronts, and "I did not say" and "I meant everything" are one missing flag
/// apart. Here they are two different values, and `add_agent` will not take a
/// guess at which was meant.
///
/// The *file* is unchanged: an absent `targets` key still means any, so every
/// policy already written goes on meaning what it meant. What changed is that
/// a command can no longer write one by saying nothing.
#[derive(Debug, Clone, Copy)]
pub enum Reach<'a> {
    /// These upstreams and MCP servers, and nothing else.
    Only(&'a [String]),
    /// Everything the proxy fronts, including services added later. The
    /// blanket grant — available, and asked for by name.
    Any,
}

impl<'a> Reach<'a> {
    /// The targets to write, which is nothing at all for `Any`: an absent
    /// `targets` key is how the file spells the blanket grant, and there is
    /// no second spelling to drift from it.
    pub fn targets(self) -> &'a [String] {
        match self {
            Reach::Only(targets) => targets,
            Reach::Any => &[],
        }
    }

    pub fn is_any(self) -> bool {
        matches!(self, Reach::Any)
    }
}

pub fn add_agent(
    path: &Path,
    id: &str,
    name: Option<&str>,
    reach: Reach<'_>,
) -> Result<EnrolledAgent> {
    check_id(id, "agent id")?;

    // The default grant, refused. Every other flag on `agent add` defaults to
    // the narrowest thing it can mean; this one defaulted to the widest, and
    // silently — a bare `agent add` enrolled a token good against every
    // upstream and every MCP server the proxy fronts, now and in future, with
    // only the ACL between it and all of them. The blanket grant is still
    // available; it is no longer what you get for not mentioning it.
    let targets = reach.targets();
    if targets.is_empty() && !reach.is_any() {
        bail!(
            "`{id}` was given no targets, which in the file means *every* upstream and MCP \
             server — say which it is:\n  --target <name>   the services it may address, \
             repeatable\n  --any-target      all of them, including ones added later"
        );
    }

    let mut document = read(path)?;
    let existing = document_config(&document)?;
    if existing.agents.iter().any(|agent| agent.id == id) {
        bail!(
            "`{}` already has an agent `{id}` — ids are how a request is attributed, \
             so two of them would make the audit log ambiguous",
            path.display()
        );
    }

    // Targets that name nothing are the failure this command exists to catch:
    // the file stays valid, the agent looks scoped, and every call it makes is
    // denied by a rule that never mentions the target it was pointed at.
    let reachable: Vec<&str> = existing
        .upstreams
        .iter()
        .map(|up| up.name.as_str())
        .chain(
            existing
                .mcp_servers
                .iter()
                .map(|server| server.name.as_str()),
        )
        .collect();
    for target in targets {
        if !reachable.iter().any(|name| *name == target) {
            bail!(
                "no upstream or MCP server named `{target}` in `{}` — add it first with \
                 `agent-iap upstream add {target} --base-url <url>`, or `--any-target` for \
                 all of them",
                path.display()
            );
        }
    }

    let token = identity::generate_token()?;

    let mut entry = Table::new();
    entry["id"] = toml_edit::value(id);
    if let Some(name) = name {
        entry["name"] = toml_edit::value(name);
    }
    entry["token_sha256"] = toml_edit::value(identity::token_hash(&token));
    // `Any` writes no key at all, which is how the file has always spelled the
    // blanket grant. One spelling, so a reader of the file cannot be told two
    // different things by the same absence.
    if !targets.is_empty() {
        entry["targets"] = toml_edit::value(string_array(targets));
    }

    append(&mut document, "agents", entry);
    save(path, document)?;

    Ok(EnrolledAgent {
        id: id.to_string(),
        token,
    })
}

/// Remove `[[agents]]`, and with `prune` the rules that name it outright.
///
/// This is the revocation path: after it, the agent's token hashes to nothing
/// in the file and the next start of the proxy will not know it. Rules are
/// pruned only on an exact `agent = "<id>"`; a glob like `ci-*` covers a fleet,
/// and one member leaving is not that rule ending.
pub fn remove_agent(path: &Path, id: &str, prune: bool) -> Result<Removal> {
    let mut document = read(path)?;
    let existing = document_config(&document)?;
    let index = agent_index(&existing, id, path)?;

    let named = rules_matching(&existing, |rule| rule.agent == id);

    remove_table(&mut document, "agents", index, path)?;
    let removal = take_rules(&mut document, named, prune, path)?;
    save(path, document)?;
    Ok(removal)
}

/// Mint the agent a new token and replace the hash in place.
///
/// The other half of revocation, and the one with a deadline: a token that
/// leaked belongs to an agent that still has work to do, so the answer is a new
/// token rather than an entry deleted and re-added under a name the audit log
/// would have to be told about.
pub fn rotate_agent(path: &Path, id: &str) -> Result<EnrolledAgent> {
    let mut document = read(path)?;
    let existing = document_config(&document)?;
    let index = agent_index(&existing, id, path)?;

    // `token_ref` means the token lives in 1Password, a file or the
    // environment, and the file only points at it. Writing a hash here would
    // rotate the token *and* silently move where the agent's credential comes
    // from — two changes, one of them unasked for.
    if let Some(reference) = &existing.agents[index].token_ref {
        bail!(
            "agent `{id}` authenticates with `token_ref = \"{reference}\"`, so its token lives \
             in that store and not in this file — rotate it there and restart the proxy. \
             Writing a hash here would also change where the agent's credential comes from."
        );
    }

    let token = identity::generate_token()?;
    entry_mut(&mut document, "agents", index, path)?["token_sha256"] =
        toml_edit::value(identity::token_hash(&token));
    save(path, document)?;

    Ok(EnrolledAgent {
        id: id.to_string(),
        token,
    })
}

/// Add `[[upstreams]]`: a base URL and the credential to attach on the way out.
pub fn add_upstream(
    path: &Path,
    name: &str,
    base_url: &str,
    auth: &AuthSpec,
    headers: &[(String, String)],
) -> Result<()> {
    add_upstream_probing(path, name, base_url, auth, headers, None)
}

/// The same, for an enrolment that knows how this service proves a credential.
///
/// `verify_path` is written to the entry so that every later `verify` — the
/// one on the enrolment, the `v` key in the console, `agent-iap verify
/// upstream` months from now — calls the endpoint the vendor documents for
/// the purpose rather than the root. It is a property of the service, so it
/// belongs in the file next to the base URL rather than in the argv of
/// whoever happens to be asking.
pub fn add_upstream_probing(
    path: &Path,
    name: &str,
    base_url: &str,
    auth: &AuthSpec,
    headers: &[(String, String)],
    verify_path: Option<&str>,
) -> Result<()> {
    check_id(name, "upstream name")?;
    check_base_url(base_url)?;
    check_secret_refs(auth)?;

    let mut document = read(path)?;
    let existing = document_config(&document)?;
    if existing.upstreams.iter().any(|up| up.name == name) {
        bail!("`{}` already has an upstream `{name}`", path.display());
    }
    // The routing prefix is the name, and an MCP server sharing it would make
    // `/{name}/...` ambiguous.
    if existing
        .mcp_servers
        .iter()
        .any(|server| server.name == name)
    {
        bail!(
            "`{}` already has an MCP server named `{name}`, and both are addressed \
             as `/{name}/…`",
            path.display()
        );
    }

    append(
        &mut document,
        "upstreams",
        upstream_entry(name, base_url, auth, headers, verify_path),
    );
    save(path, document)
}

fn upstream_entry(
    name: &str,
    base_url: &str,
    auth: &AuthSpec,
    headers: &[(String, String)],
    verify_path: Option<&str>,
) -> Table {
    let mut entry = Table::new();
    entry["name"] = toml_edit::value(name);
    entry["base_url"] = toml_edit::value(base_url);
    entry["auth"] = toml_edit::value(auth_value(auth));
    if !headers.is_empty() {
        let mut table = toml_edit::InlineTable::new();
        for (key, value) in headers {
            table.insert(key, Value::from(value.as_str()));
        }
        entry["headers"] = toml_edit::value(table);
    }
    if let Some(probe) = verify_path {
        entry["verify_path"] = toml_edit::value(probe);
    }
    entry
}

/// Rewrite an existing `[[upstreams]]`: where it points, the credential it
/// attaches, the static headers it sends.
///
/// The alternative was `rm` and `add`, which is not the same operation: it
/// takes the entry's ACL rules with it or strands the agents scoped to it,
/// moves the block to the end of the file, and leaves a window where the proxy
/// fronts nothing under that name. This edits the block in place, so the rules
/// and the `targets` that name it keep naming the same thing — and the whole
/// file is validated before it is written, exactly as an add is.
///
/// Whole rather than field by field: the caller supplies the entry it wants to
/// exist, and what it leaves out is left out. A credential is the field where
/// "unset means keep" and "unset means none" differ by an unprotected upstream,
/// so the console fills the form in from the file first and sends all of it
/// back.
///
/// The name is not editable here. It is the routing prefix, and ACL rules,
/// agents' `targets` and the audit log all name it — changing it is a rename of
/// something other blocks point at rather than an edit of this one.
pub fn edit_upstream(
    path: &Path,
    name: &str,
    base_url: &str,
    auth: &AuthSpec,
    headers: &[(String, String)],
) -> Result<()> {
    check_base_url(base_url)?;
    check_secret_refs(auth)?;

    let mut document = read(path)?;
    let existing = document_config(&document)?;
    let index = existing
        .upstreams
        .iter()
        .position(|up| up.name == name)
        .with_context(|| {
            format!(
                "no upstream `{name}` in `{}`{}",
                path.display(),
                known(existing.upstreams.iter().map(|up| up.name.as_str()))
            )
        })?;

    let entry = entry_mut(&mut document, "upstreams", index, path)?;
    entry["base_url"] = toml_edit::value(base_url);
    entry["auth"] = toml_edit::value(auth_value(auth));
    match headers.is_empty() {
        // Removed rather than written as an empty table: `headers = {}` says
        // the same thing while reading like something that was meant.
        true => {
            entry.remove("headers");
        }
        false => {
            let mut table = toml_edit::InlineTable::new();
            for (key, value) in headers {
                table.insert(key, Value::from(value.as_str()));
            }
            entry["headers"] = toml_edit::value(table);
        }
    }
    save(path, document)
}

/// Remove `[[upstreams]]`, and with `prune` everything that pointed at it.
pub fn remove_upstream(path: &Path, name: &str, prune: bool) -> Result<Removal> {
    remove_service(path, name, prune, ServiceKind::Upstream)
}

/// An MCP server as the CLI accepts it: a child process to spawn, or a remote
/// endpoint to relay to.
#[derive(Debug, Clone)]
pub enum McpTransportSpec {
    Stdio {
        command: String,
        args: Vec<String>,
        /// Child environment. Values are secret *references*, resolved inside
        /// the proxy — the same rule the rest of the file follows.
        env: Vec<(String, String)>,
        cwd: Option<String>,
    },
    Http {
        url: String,
    },
}

/// Add `[[mcp_servers]]`. Without this an MCP server could only be enrolled by
/// hand-editing TOML, which is the one thing the enrolment commands exist to
/// avoid — and MCP is where most of the interesting credentials now live.
pub fn add_mcp_server(
    path: &Path,
    name: &str,
    transport: &McpTransportSpec,
    auth: &AuthSpec,
) -> Result<()> {
    check_id(name, "mcp server name")?;
    check_secret_refs(auth)?;
    if let McpTransportSpec::Stdio { env, .. } = transport {
        for (key, reference) in env {
            let parsed = SecretRef::parse(reference)
                .with_context(|| format!("`--env {key}=…` takes a credential reference"))?;
            if parsed.is_inline() {
                bail!(
                    "`literal:` puts the credential in the policy file itself — use `op://`, \
                     `env:` or `file:` so the file stays safe to commit"
                );
            }
        }
    }
    if let McpTransportSpec::Http { url } = transport {
        check_base_url(url)?;
    }

    let mut document = read(path)?;
    let existing = document_config(&document)?;
    if existing
        .mcp_servers
        .iter()
        .any(|server| server.name == name)
    {
        bail!("`{}` already has an MCP server `{name}`", path.display());
    }
    // One namespace: `/{name}/…` routes to an upstream, and the ACL `target`
    // and the agent's `targets` are matched against the same set of names.
    if existing.upstreams.iter().any(|up| up.name == name) {
        bail!(
            "`{}` already has an upstream named `{name}`, and both share one namespace",
            path.display()
        );
    }

    append(
        &mut document,
        "mcp_servers",
        mcp_entry(name, transport, auth),
    );
    save(path, document)
}

fn mcp_entry(name: &str, transport: &McpTransportSpec, auth: &AuthSpec) -> Table {
    let mut entry = Table::new();
    entry["name"] = toml_edit::value(name);
    match transport {
        McpTransportSpec::Stdio {
            command,
            args,
            env,
            cwd,
        } => {
            entry["transport"] = toml_edit::value("stdio");
            entry["command"] = toml_edit::value(command.as_str());
            if !args.is_empty() {
                entry["args"] = toml_edit::value(string_array(args));
            }
            if !env.is_empty() {
                let mut table = toml_edit::InlineTable::new();
                for (key, reference) in env {
                    table.insert(key, Value::from(reference.as_str()));
                }
                entry["env"] = toml_edit::value(table);
            }
            if let Some(cwd) = cwd {
                entry["cwd"] = toml_edit::value(cwd.as_str());
            }
        }
        McpTransportSpec::Http { url } => {
            entry["transport"] = toml_edit::value("http");
            entry["url"] = toml_edit::value(url.as_str());
        }
    }
    if !matches!(auth, AuthSpec::None) {
        entry["auth"] = toml_edit::value(auth_value(auth));
    }
    entry
}

/// Remove `[[mcp_servers]]`, and with `prune` everything that pointed at it.
pub fn remove_mcp_server(path: &Path, name: &str, prune: bool) -> Result<Removal> {
    remove_service(path, name, prune, ServiceKind::McpServer)
}

/// One ACL rule, as a caller spells it out.
///
/// A struct rather than eight positional arguments: they are all strings and
/// string lists, four of them default to `*`, and the difference between a rule
/// that grants what was meant and one that grants everything is which order
/// they went in.
#[derive(Debug, Clone, Default)]
pub struct RuleSpec<'a> {
    pub name: Option<&'a str>,
    pub agent: &'a str,
    pub kind: &'a str,
    pub target: &'a str,
    pub methods: &'a [String],
    pub paths: &'a [String],
    pub action: &'a str,
    /// When the rule stops applying. `None` is the grant with no end.
    pub expires: Option<DateTime<Utc>>,
}

/// Add `[[acl]]`. Appended last, because first match wins and an earlier rule
/// would silently take precedence over everything already in the file.
pub fn add_rule(path: &Path, spec: &RuleSpec<'_>) -> Result<usize> {
    let mut document = read(path)?;
    append(&mut document, "acl", rule_entry(spec));
    let landed = document_config(&document)?.acl.len().saturating_sub(1);
    save(path, document)?;
    Ok(landed)
}

/// Put a rule *before* the one at `index`, rather than after everything.
///
/// The one edit `add_rule` cannot express, and the one the approval console
/// needs: an operator answering "allow this from now on" is overriding the
/// `ask` rule that just stopped them, and first match wins — appended after it,
/// the new rule would never be reached and the same question would come back on
/// the next call. An `index` past the end appends, which is what a decision
/// taken by the *default* action means.
pub fn insert_rule(path: &Path, index: usize, spec: &RuleSpec<'_>) -> Result<usize> {
    let mut document = read(path)?;
    let entry = rule_entry(spec);

    let existing = document_config(&document)?.acl.len();
    if index >= existing {
        append(&mut document, "acl", entry);
        save(path, document)?;
        return Ok(existing);
    }

    array_of_tables(&mut document, "acl", path)?.insert(index, entry);
    save(path, document)?;
    Ok(index)
}

/// How long a grant lasts, as an operator types it: `30s`, `5m`, `1h`, `7d`.
///
/// Deliberately not a bare number. "Allow this for 5" is a question about units
/// that an operator answering a security prompt should not have to stop and
/// ask, and getting it wrong by a factor of sixty is the direction that hurts.
pub fn parse_ttl(text: &str) -> Result<TimeDelta> {
    let text = text.trim();
    let (count, unit) = text.split_at(
        text.find(|c: char| !c.is_ascii_digit())
            .with_context(|| format!("`{text}` has no unit — try `30s`, `5m`, `1h` or `7d`"))?,
    );
    let count: i64 = count
        .parse()
        .with_context(|| format!("`{text}` does not start with a number of them"))?;

    let delta = match unit {
        "s" | "sec" | "secs" => TimeDelta::try_seconds(count),
        "m" | "min" | "mins" => TimeDelta::try_minutes(count),
        "h" | "hr" | "hrs" | "hour" | "hours" => TimeDelta::try_hours(count),
        "d" | "day" | "days" => TimeDelta::try_days(count),
        "w" | "week" | "weeks" => TimeDelta::try_weeks(count),
        other => bail!("`{other}` is not a unit of time — use s, m, h, d or w"),
    }
    .with_context(|| format!("`{text}` is longer than a duration can be"))?;

    if delta <= TimeDelta::zero() {
        bail!("`{text}` is not a length of time — a grant that has already run out grants nothing");
    }
    Ok(delta)
}

/// How much of a grant is left, in the words a human reads it back in.
pub fn remaining(expires: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let left = expires - now;
    if left <= TimeDelta::zero() {
        return "expired".to_string();
    }
    let seconds = left.num_seconds();
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m", left.num_minutes())
    } else if seconds < 86_400 {
        format!("{}h{}m", left.num_hours(), left.num_minutes() % 60)
    } else {
        format!("{}d{}h", left.num_days(), left.num_hours() % 24)
    }
}

fn rule_entry(spec: &RuleSpec<'_>) -> Table {
    let mut entry = Table::new();
    if let Some(name) = spec.name {
        entry["name"] = toml_edit::value(name);
    }
    entry["agent"] = toml_edit::value(spec.agent);
    entry["kind"] = toml_edit::value(spec.kind);
    entry["target"] = toml_edit::value(spec.target);
    entry["methods"] = toml_edit::value(string_array(spec.methods));
    entry["paths"] = toml_edit::value(string_array(spec.paths));
    entry["action"] = toml_edit::value(spec.action);
    if let Some(expires) = spec.expires {
        // Seconds and UTC: a deadline is evidence, and evidence a reader has to
        // convert out of a local timezone to compare is evidence they will get
        // wrong at least once.
        entry["expires"] = toml_edit::value(expires.to_rfc3339_opts(SecondsFormat::Secs, true));
    }
    entry
}

/// The positional spelling of a rule, for tests that do not care about expiry.
#[cfg(test)]
fn rule<'a>(
    name: Option<&'a str>,
    agent: &'a str,
    kind: &'a str,
    target: &'a str,
    methods: &'a [String],
    paths: &'a [String],
    action: &'a str,
) -> RuleSpec<'a> {
    RuleSpec {
        name,
        agent,
        kind,
        target,
        methods,
        paths,
        action,
        expires: None,
    }
}

/// What `remove_rule` took out, and what the list looks like afterwards.
#[derive(Debug)]
pub struct RuleRemoval {
    /// The rule as it was, so the command can print what it just deleted
    /// rather than the number the operator typed.
    pub rule: AclRuleConfig,
    pub index: usize,
    /// Rules left. Everything after `index` has shifted down by one, which is
    /// the whole reason this is worth saying out loud.
    pub remaining: usize,
}

/// Remove the `[[acl]]` rule at `index` — the `#` column of `agent-iap list acl`.
///
/// By number rather than by name because a rule need not have one, and two may
/// share it. Position is the ACL's semantics: first match wins, so the number
/// is the only thing that identifies a rule unambiguously.
pub fn remove_rule(path: &Path, index: usize) -> Result<RuleRemoval> {
    let mut document = read(path)?;
    let existing = document_config(&document)?;
    let rule = existing
        .acl
        .get(index)
        .cloned()
        .with_context(|| match existing.acl.len() {
            0 => format!("`{}` has no `[[acl]]` rules to remove", path.display()),
            count => format!(
                "no rule {index} in `{}` — the rules are numbered 0 to {}, as `agent-iap list acl` \
                 prints them",
                path.display(),
                count - 1
            ),
        })?;

    remove_table(&mut document, "acl", index, path)?;
    save(path, document)?;
    Ok(RuleRemoval {
        rule,
        index,
        remaining: existing.acl.len() - 1,
    })
}

/// What a reset leaves deciding once the rules are gone.
///
/// Two values rather than an `Action`, because `allow` is not one of the
/// things a reset can mean: emptying the rule list and then letting everything
/// through is the one outcome nobody reaches for this command to get.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetTo {
    /// Back to asking — what `agent-iap acl reset` means, and the behaviour
    /// this proxy is modelled on. No rule matches, so every request stops on a
    /// human at the console, who answers it once or answers it for good. An
    /// unanswered one still denies; what changes is that somebody is given the
    /// chance to answer at all.
    Ask,
    /// Strict mode — `--deny`. Nothing matches and nothing asks, so every
    /// request is refused without a prompt, for keeps and across restarts.
    /// `agent-iap run --lockdown` is the same state for right now.
    Deny,
}

impl ResetTo {
    pub fn action(self) -> Action {
        match self {
            ResetTo::Ask => Action::Ask,
            ResetTo::Deny => Action::Deny,
        }
    }
}

/// What `reset_acl` took out, and what the policy said before it did.
#[derive(Debug)]
pub struct AclReset {
    /// Every rule that was in the file, so the command can print what it just
    /// deleted rather than a number. This is the destructive one of the ACL
    /// edits — the others take out a rule the operator named — so the record
    /// of what was there is the whole of what makes it recoverable.
    pub removed: Vec<RuleRef>,
    /// What `acl_default` was, so the command can say whether the reset moved
    /// the fall-through or only emptied the list above it.
    pub was_default: Action,
    /// And what it is now: `ask` for a plain reset, `deny` for a strict one.
    pub now_default: Action,
}

/// Delete every `[[acl]]` rule and write `acl_default` — `ask` by default.
///
/// Starting over, written down. Every other edit in this module is a
/// considered change to one entry; this is the one an operator reaches for
/// when the rule list has stopped being something they can reason about and
/// they want to build it back from what actually shows up.
///
/// It leaves the state this proxy is modelled on: no rule matches, so every
/// request falls through to an `ask` and stops on a human, who allows it once,
/// allows it from now on, or says no. A `deny` default there would be quieter
/// and worse — the requests would still be refused, but nobody would be asked,
/// and an operator who had just wiped the rule list on purpose would have no
/// way to put back the ones they actually wanted short of reading the audit
/// log for 403s. `ResetTo::Deny` is that quieter state, and it is a flag
/// because it is a different decision.
///
/// Both halves matter either way, and neither is enough alone: rules under a
/// permissive default grant everything, and a tightened default under a
/// surviving `allow` rule at the top grants everything too. So this writes
/// both, and is the only edit here that touches `acl_default`.
///
/// It does not stop what is already running: an in-flight request has been
/// cleared, and a "remember for this session" answer lives in the process
/// rather than the file. `agent-iap run --lockdown` is the switch for those.
pub fn reset_acl(path: &Path, to: ResetTo) -> Result<AclReset> {
    let mut document = read(path)?;
    let existing = document_config(&document)?;
    let removed = rules_matching(&existing, |_| true);

    // The whole key, rather than the entries one at a time: `[[acl]]` blocks
    // and one inline `acl = [...]` array are two spellings of the same data,
    // and a reset that silently skipped the second would report that
    // everything was blocked while leaving every rule in force. Removing the
    // key is unambiguous in both spellings, which is what this edit — alone
    // among the edits here — has to be.
    document.remove("acl");
    set_default_action(&mut document, &to.action().to_string());

    save(path, document)?;
    Ok(AclReset {
        removed,
        was_default: existing.acl_default.action,
        now_default: to.action(),
    })
}

/// Write `acl_default.action`, however the file happens to spell the table.
fn set_default_action(document: &mut DocumentMut, action: &str) {
    match document.get_mut("acl_default") {
        Some(Item::Table(table)) => table["action"] = toml_edit::value(action),
        Some(Item::Value(Value::InlineTable(table))) => {
            table.insert("action", action.into());
        }
        // Absent, or written as something that is not a table at all. The
        // second cannot have loaded, since `document_config` has already
        // parsed this file against the schema — so this is the first.
        _ => {
            let mut table = Table::new();
            table["action"] = toml_edit::value(action);
            document["acl_default"] = Item::Table(table);
        }
    }
}

/// A service to render without writing it, for `profile add --dry-run`.
pub enum ServiceSpec<'a> {
    Upstream {
        base_url: &'a str,
        verify_path: Option<&'a str>,
    },
    McpHttp {
        url: &'a str,
    },
    McpStdio {
        command: &'a str,
        args: &'a [String],
        env: &'a [(String, String)],
    },
}

/// The exact TOML `add_upstream` / `add_mcp_server` would append. Built from
/// the same entry builders they use, so a dry run cannot promise one thing and
/// the write produce another.
pub fn render_service(name: &str, spec: ServiceSpec<'_>, auth: &AuthSpec) -> String {
    let (key, entry) = match spec {
        ServiceSpec::Upstream {
            base_url,
            verify_path,
        } => (
            "upstreams",
            upstream_entry(name, base_url, auth, &[], verify_path),
        ),
        ServiceSpec::McpHttp { url } => (
            "mcp_servers",
            mcp_entry(
                name,
                &McpTransportSpec::Http {
                    url: url.to_string(),
                },
                auth,
            ),
        ),
        ServiceSpec::McpStdio { command, args, env } => (
            "mcp_servers",
            mcp_entry(
                name,
                &McpTransportSpec::Stdio {
                    command: command.to_string(),
                    args: args.to_vec(),
                    env: env.to_vec(),
                    cwd: None,
                },
                auth,
            ),
        ),
    };
    render(key, entry)
}

/// The exact TOML `add_rule` would append.
#[allow(clippy::too_many_arguments)]
pub fn render_rule(spec: &RuleSpec<'_>) -> String {
    render("acl", rule_entry(spec))
}

fn render(key: &str, entry: Table) -> String {
    let mut document = DocumentMut::new();
    append(&mut document, key, entry);
    document.to_string()
}

/// Position in the rule list, so the caller can say where a new rule landed —
/// "rule 3 of 3" is the difference between a rule that applies and one that an
/// earlier `deny` already shadowed.
pub fn rule_count(path: &Path) -> Result<usize> {
    Ok(policy(path)?.acl.len())
}

/// What an unmatched request falls through to, as the file has it.
///
/// The companion to `rule_count`, and needed by everything that says what an
/// empty rule list means: "no rules" only reads as "denied" while the default
/// denies, and `reset_acl` can leave it asking. A message that assumed one
/// would be confidently wrong in exactly the state an operator reached for a
/// reset to get into.
pub fn acl_default(path: &Path) -> Result<Action> {
    Ok(policy(path)?.acl_default.action)
}

/// The policy as the file has it, parsed.
///
/// For the caller that has to describe what the file it just wrote will now do
/// and needs the rules as well as the default — `verify::cannot_ask_warning`
/// reads both. The two accessors above are this call, narrowed, so there is
/// still only one answer to "what does this file say".
pub fn policy(path: &Path) -> Result<Config> {
    document_config(&read(path)?)
}

/// A rule as `agent-iap list acl` identifies it: the number `acl rm` takes, and
/// the name the audit log prints beside a decision.
#[derive(Debug)]
pub struct RuleRef {
    pub index: usize,
    pub name: Option<String>,
}

impl std::fmt::Display for RuleRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.name {
            Some(name) => write!(f, "acl[{}] `{name}`", self.index),
            None => write!(f, "acl[{}]", self.index),
        }
    }
}

/// What a removal took out, and what it deliberately left behind.
///
/// Both halves are the answer to the same question. An operator revoking a
/// leaked token needs to know which rules still name the agent; an operator
/// retiring a service needs to know which agents stopped being scoped to it.
#[derive(Debug, Default)]
pub struct Removal {
    /// Rules deleted alongside the subject, because `prune` was set.
    pub pruned_rules: Vec<RuleRef>,
    /// Rules that name the subject and are still in the file, matching nothing.
    pub orphaned_rules: Vec<RuleRef>,
    /// Agents whose `targets` no longer name the removed service.
    pub detached_agents: Vec<String>,
}

/// Upstreams and MCP servers are removed the same way — one namespace, one set
/// of things that can point at a name — and differ only in which array the
/// entry lives in and what to call it in an error.
#[derive(Copy, Clone)]
enum ServiceKind {
    Upstream,
    McpServer,
}

impl ServiceKind {
    fn key(self) -> &'static str {
        match self {
            ServiceKind::Upstream => "upstreams",
            ServiceKind::McpServer => "mcp_servers",
        }
    }

    fn noun(self) -> &'static str {
        match self {
            ServiceKind::Upstream => "upstream",
            ServiceKind::McpServer => "MCP server",
        }
    }
}

fn remove_service(path: &Path, name: &str, prune: bool, kind: ServiceKind) -> Result<Removal> {
    let mut document = read(path)?;
    let existing = document_config(&document)?;
    let index = match kind {
        ServiceKind::Upstream => existing.upstreams.iter().position(|up| up.name == name),
        ServiceKind::McpServer => existing
            .mcp_servers
            .iter()
            .position(|server| server.name == name),
    }
    .with_context(|| {
        let noun = kind.noun();
        format!(
            "no {noun} `{name}` in `{}`{}",
            path.display(),
            match kind {
                ServiceKind::Upstream =>
                    known(existing.upstreams.iter().map(|up| up.name.as_str())),
                ServiceKind::McpServer => known(
                    existing
                        .mcp_servers
                        .iter()
                        .map(|server| server.name.as_str())
                ),
            }
        )
    })?;

    // Agents hard-scoped to this service. `validate()` rejects a `targets`
    // entry naming nothing, so leaving one behind is not an untidy file — it is
    // a proxy that will not come back up, discovered at the restart.
    let scoped: Vec<(usize, &str)> = existing
        .agents
        .iter()
        .enumerate()
        .filter(|(_, agent)| agent.targets.iter().any(|target| target == name))
        .map(|(index, agent)| (index, agent.id.as_str()))
        .collect();
    if !scoped.is_empty() {
        let ids: Vec<&str> = scoped.iter().map(|(_, id)| *id).collect();
        if !prune {
            bail!(
                "{} `{name}` is still in the `targets` of {} — removing it would leave a policy \
                 file the proxy refuses to load. Re-run with `--prune` to drop it from them too.",
                kind.noun(),
                list(&ids)
            );
        }
        // Emptying `targets` does not narrow an agent, it widens it: no
        // `targets` at all means *any* target, subject only to the ACL. A
        // removal must not hand out a grant on its way past. Asked of every
        // entry rather than of the length, so `["github", "github"]` counts.
        let widened: Vec<&str> = scoped
            .iter()
            .filter(|(index, _)| {
                existing.agents[*index]
                    .targets
                    .iter()
                    .all(|target| target == name)
            })
            .map(|(_, id)| *id)
            .collect();
        if !widened.is_empty() {
            bail!(
                "`{name}` is the only target of {} — dropping it would leave `targets` empty, \
                 which means *any* target rather than none. Remove {} first with \
                 `agent-iap agent rm`.",
                list(&widened),
                if widened.len() == 1 { "it" } else { "them" }
            );
        }
    }
    let detached: Vec<String> = scoped.iter().map(|(_, id)| id.to_string()).collect();
    let scoped_indices: Vec<usize> = scoped.iter().map(|(index, _)| *index).collect();

    // Rules aimed at this service by name. A `target = "*"` rule is left alone:
    // it covers whatever is configured, and one service leaving does not orphan
    // it.
    let named = rules_matching(&existing, |rule| rule.target == name);

    remove_table(&mut document, kind.key(), index, path)?;
    for agent_index in scoped_indices {
        if let Some(Item::Value(Value::Array(targets))) =
            entry_mut(&mut document, "agents", agent_index, path)?.get_mut("targets")
        {
            targets.retain(|target| target.as_str() != Some(name));
        }
    }
    let mut removal = take_rules(&mut document, named, prune, path)?;
    removal.detached_agents = detached;
    save(path, document)?;
    Ok(removal)
}

/// Where an agent sits in the file, or an error naming the ones that are in it.
fn agent_index(existing: &Config, id: &str, path: &Path) -> Result<usize> {
    existing
        .agents
        .iter()
        .position(|agent| agent.id == id)
        .with_context(|| {
            format!(
                "no agent `{id}` in `{}`{}",
                path.display(),
                known(existing.agents.iter().map(|agent| agent.id.as_str()))
            )
        })
}

/// Every rule the predicate picks out, by position in the file.
fn rules_matching(config: &Config, predicate: impl Fn(&AclRuleConfig) -> bool) -> Vec<RuleRef> {
    config
        .acl
        .iter()
        .enumerate()
        .filter(|(_, rule)| predicate(rule))
        .map(|(index, rule)| RuleRef {
            index,
            name: rule.name.clone(),
        })
        .collect()
}

/// Delete the rules the caller identified, or report them as orphans.
fn take_rules(
    document: &mut DocumentMut,
    named: Vec<RuleRef>,
    prune: bool,
    path: &Path,
) -> Result<Removal> {
    if !prune {
        return Ok(Removal {
            orphaned_rules: named,
            ..Default::default()
        });
    }
    // Back to front: removing rule 2 renumbers rule 5, and taking the indices
    // in the order they were collected would delete the wrong ones.
    for rule in named.iter().rev() {
        remove_table(document, "acl", rule.index, path)?;
    }
    Ok(Removal {
        pruned_rules: named,
        ..Default::default()
    })
}

/// The nth `[[key]]` block, to edit in place.
fn entry_mut<'a>(
    document: &'a mut DocumentMut,
    key: &str,
    index: usize,
    path: &Path,
) -> Result<&'a mut Table> {
    array_of_tables(document, key, path)?
        .get_mut(index)
        .with_context(|| format!("`[[{key}]]` block {index} is not in `{}`", path.display()))
}

/// Delete the nth `[[key]]` block.
fn remove_table(document: &mut DocumentMut, key: &str, index: usize, path: &Path) -> Result<()> {
    let tables = array_of_tables(document, key, path)?;
    if index >= tables.len() {
        bail!("`[[{key}]]` block {index} is not in `{}`", path.display());
    }
    tables.remove(index);
    Ok(())
}

/// TOML lets the same data be written as `[[key]]` blocks or as one inline
/// array, and these commands edit the first. Refusing the second is the point:
/// a removal that quietly matched nothing would report success and leave the
/// credential live.
fn array_of_tables<'a>(
    document: &'a mut DocumentMut,
    key: &str,
    path: &Path,
) -> Result<&'a mut toml_edit::ArrayOfTables> {
    match document.get_mut(key) {
        Some(Item::ArrayOfTables(tables)) => Ok(tables),
        Some(_) => bail!(
            "`{key}` in `{}` is written as an inline array rather than as `[[{key}]]` blocks, \
             which is what these commands edit — this one needs an editor",
            path.display()
        ),
        None => bail!("`{}` has no `[[{key}]]` blocks", path.display()),
    }
}

/// The names that *are* in the file. A typo is the common reason a removal
/// finds nothing, and the answer is nearly always in this list.
fn known<'a>(names: impl Iterator<Item = &'a str>) -> String {
    let mut names: Vec<&str> = names.collect();
    if names.is_empty() {
        return String::new();
    }
    names.sort_unstable();
    format!(" — the file has: {}", names.join(", "))
}

/// `a`, `a and b`, `a, b and c` — an error naming three agents should read
/// like a sentence.
fn list(names: &[&str]) -> String {
    let quoted: Vec<String> = names.iter().map(|name| format!("`{name}`")).collect();
    match quoted.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

fn read(path: &Path) -> Result<DocumentMut> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "reading `{}` — `agent-iap init` writes one if you have not yet",
            path.display()
        )
    })?;
    text.parse::<DocumentMut>()
        .with_context(|| format!("parsing `{}`", path.display()))
}

/// Parse the in-memory document as a `Config`, so an edit is checked against
/// the real schema rather than against what this module believes it wrote.
fn document_config(document: &DocumentMut) -> Result<Config> {
    toml::from_str(&document.to_string()).context("the policy file does not match the schema")
}

fn append(document: &mut DocumentMut, key: &str, entry: Table) {
    let array = document
        .entry(key)
        .or_insert_with(|| Item::ArrayOfTables(Default::default()));
    if let Item::ArrayOfTables(tables) = array {
        tables.push(entry);
    }
}

/// Validate before writing, and write whole: a half-written policy file is a
/// proxy that will not restart.
fn save(path: &Path, document: DocumentMut) -> Result<()> {
    let text = document.to_string();
    let config: Config =
        toml::from_str(&text).context("the edit produced a policy file that does not parse")?;
    config
        .validate()
        .context("the edit produced a policy file the proxy would reject")?;
    std::fs::write(path, text).with_context(|| format!("writing `{}`", path.display()))
}

/// Every credential *reference* the spec carries. All of them are checked, not
/// just the first: `--username-secret op://… --secret literal:token` would
/// otherwise slip a literal past the check that exists to stop exactly that.
fn auth_secrets(auth: &AuthSpec) -> Vec<&str> {
    match auth {
        AuthSpec::None => vec![],
        AuthSpec::Bearer { secret }
        | AuthSpec::Header { secret, .. }
        | AuthSpec::Query { secret, .. } => vec![secret.as_str()],
        AuthSpec::Basic {
            username_secret,
            secret,
            ..
        } => username_secret
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(secret.as_str()))
            .collect(),
        AuthSpec::Oauth2ClientCredentials { client_secret, .. } => vec![client_secret.as_str()],
        AuthSpec::ServiceAccountJwt {
            key_file,
            private_key,
            ..
        } => key_file
            .iter()
            .chain(private_key.iter())
            .map(String::as_str)
            .collect(),
    }
}

/// Reject a credential where a *reference* belongs, before anything is written.
fn check_secret_refs(auth: &AuthSpec) -> Result<()> {
    // `<token>:token` — Graylog, and Graylog's session variant — puts the
    // credential in the user field and a documented constant in the password.
    // That constant is not a secret, and refusing `literal:token` here would
    // leave the scheme expressible only by writing the real token into the
    // file: the exact outcome this check exists to prevent.
    if let AuthSpec::Basic {
        username_secret: Some(reference),
        secret,
        ..
    } = auth
    {
        let parsed = SecretRef::parse(reference)
            .context("`--username-secret` takes a credential *reference*, not the credential")?;
        if parsed.is_inline() {
            bail!(
                "`literal:` in `--username-secret` puts the credential in the policy file \
                 itself — use `op://`, `env:` or `file:`"
            );
        }
        // The password is still parsed, so a bare word is still caught.
        SecretRef::parse(secret)
            .context("`--secret` takes a credential *reference*, not the credential")?;
        return Ok(());
    }

    for reference in auth_secrets(auth) {
        // Catch `--secret ANTHROPIC_API_KEY` — a bare name is not a reference,
        // and left alone it would be resolved as a literal and sent upstream.
        // Deliberately not echoing the value: `--secret sk-live-…` is exactly
        // the mistake this catches, and `SecretRef::parse` redacts it for the
        // same reason. Naming the flag is as much as can be said safely.
        let parsed = SecretRef::parse(reference)
            .context("`--secret` takes a credential *reference*, not the credential")?;
        if parsed.is_inline() {
            // Same refusal `init` makes: the policy file is meant to be
            // committable, and `literal:` is the one thing that would stop it.
            bail!(
                "`literal:` puts the credential in the policy file itself — use `op://`, \
                 `env:` or `file:` so the file stays safe to commit"
            );
        }
    }
    Ok(())
}

fn auth_value(auth: &AuthSpec) -> Value {
    let mut table = toml_edit::InlineTable::new();
    match auth {
        AuthSpec::None => {
            table.insert("type", "none".into());
        }
        AuthSpec::Bearer { secret } => {
            table.insert("type", "bearer".into());
            table.insert("secret", secret.as_str().into());
        }
        AuthSpec::Header {
            header,
            secret,
            prefix,
        } => {
            table.insert("type", "header".into());
            table.insert("header", header.as_str().into());
            table.insert("secret", secret.as_str().into());
            if let Some(prefix) = prefix {
                table.insert("prefix", prefix.as_str().into());
            }
        }
        AuthSpec::Basic {
            username,
            username_secret,
            secret,
        } => {
            table.insert("type", "basic".into());
            if let Some(username) = username {
                table.insert("username", username.as_str().into());
            }
            if let Some(reference) = username_secret {
                table.insert("username_secret", reference.as_str().into());
            }
            table.insert("secret", secret.as_str().into());
        }
        AuthSpec::Query { param, secret } => {
            table.insert("type", "query".into());
            table.insert("param", param.as_str().into());
            table.insert("secret", secret.as_str().into());
        }
        AuthSpec::Oauth2ClientCredentials {
            token_url,
            client_id,
            client_secret,
            scope,
            audience,
        } => {
            table.insert("type", "oauth2_client_credentials".into());
            table.insert("token_url", token_url.as_str().into());
            table.insert("client_id", client_id.as_str().into());
            table.insert("client_secret", client_secret.as_str().into());
            if let Some(scope) = scope {
                table.insert("scope", scope.as_str().into());
            }
            if let Some(audience) = audience {
                table.insert("audience", audience.as_str().into());
            }
        }
        AuthSpec::ServiceAccountJwt {
            key_file,
            issuer,
            private_key,
            key_id,
            token_url,
            audience,
            scopes,
            subject,
            lifetime_secs,
        } => {
            table.insert("type", "service_account_jwt".into());
            if let Some(value) = key_file {
                table.insert("key_file", value.as_str().into());
            }
            if let Some(value) = issuer {
                table.insert("issuer", value.as_str().into());
            }
            if let Some(value) = private_key {
                table.insert("private_key", value.as_str().into());
            }
            if let Some(value) = key_id {
                table.insert("key_id", value.as_str().into());
            }
            if let Some(value) = token_url {
                table.insert("token_url", value.as_str().into());
            }
            if let Some(value) = audience {
                table.insert("audience", value.as_str().into());
            }
            if !scopes.is_empty() {
                table.insert("scopes", Value::Array(string_array(scopes)));
            }
            if let Some(value) = subject {
                table.insert("subject", value.as_str().into());
            }
            if let Some(value) = lifetime_secs {
                table.insert("lifetime_secs", Value::from(*value as i64));
            }
        }
    }
    Value::InlineTable(table)
}

fn string_array(values: &[String]) -> Array {
    values.iter().map(|value| value.as_str()).collect()
}

/// Same rule `init` applies to `--agent`: these names become URL path segments
/// and audit-log fields, and anything exotic here is a problem somewhere else.
fn check_id(id: &str, what: &str) -> Result<()> {
    if id.is_empty() {
        bail!("{what} must not be empty");
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("{what} `{id}` must be ASCII letters, digits, `-`, `_` or `.`");
    }
    Ok(())
}

fn check_base_url(url: &str) -> Result<()> {
    let parsed = url
        .parse::<http::Uri>()
        .with_context(|| format!("`{url}` is not a valid base URL"))?;
    match parsed.scheme_str() {
        Some("http") | Some("https") => {}
        Some(scheme) => bail!("base URL scheme `{scheme}` is not supported — use http or https"),
        None => bail!("base URL `{url}` needs a scheme, e.g. `https://{url}`"),
    }
    if parsed.authority().is_none() {
        bail!("base URL `{url}` has no host");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::{self, InitOptions, Template};

    /// A fresh minimal policy file — the state an operator is actually in when
    /// they reach for these commands.
    fn empty_policy() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iap.toml");
        init::init(&InitOptions {
            path: path.clone(),
            template: Template::Minimal,
            ..Default::default()
        })
        .unwrap();
        (dir, path)
    }

    fn load(path: &Path) -> Config {
        toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    /// How `init` spells the default. Held here so a template that changes
    /// its mind breaks the tests that edit it rather than silently appending
    /// a second `[acl_default]` and producing a file that does not parse.
    const DEFAULT_TABLE: &str = "[acl_default]\naction = \"ask\"";

    /// Edit `acl_default` in a written policy file, the way an operator
    /// reaching for a reset got there.
    fn set_default(path: &Path, action: &str) {
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.contains(DEFAULT_TABLE), "the template moved");
        std::fs::write(
            path,
            text.replace(
                DEFAULT_TABLE,
                &format!("[acl_default]\naction = \"{action}\""),
            ),
        )
        .unwrap();
    }

    /// `is_reference` is a list, and a list beside a `match` is a list that
    /// goes stale. `AuthConfig::secret_fields` is the one that decides what
    /// gets resolved, so it is the one this is held against: every scheme,
    /// every field it fills, both ways.
    #[test]
    fn the_fields_that_hold_a_reference_are_the_ones_that_get_resolved() {
        for auth in [
            AuthConfig::Bearer {
                secret: "env:A".into(),
            },
            AuthConfig::Header {
                header: "x-api-key".into(),
                secret: "env:B".into(),
                prefix: Some("Token ".into()),
            },
            AuthConfig::Basic {
                username: Some("someone".into()),
                username_secret: Some("env:C".into()),
                secret: "env:D".into(),
            },
            AuthConfig::Query {
                param: "key".into(),
                secret: "env:E".into(),
            },
            AuthConfig::Oauth2ClientCredentials {
                token_url: "https://id.example.com/token".into(),
                client_id: "iap".into(),
                client_secret: "env:F".into(),
                scope: Some("read".into()),
                audience: Some("https://example.com".into()),
            },
            AuthConfig::ServiceAccountJwt {
                key_file: Some("env:G".into()),
                issuer: Some("iap@example.iam.gserviceaccount.com".into()),
                private_key: Some("env:H".into()),
                key_id: Some("abc".into()),
                token_url: Some("https://oauth2.example.com/token".into()),
                audience: None,
                scopes: vec!["https://example.com/auth".into()],
                subject: Some("person@example.com".into()),
                lifetime_secs: Some(600),
            },
        ] {
            let input = AuthInput::of(&auth);
            let mut claimed: Vec<&str> = AuthInput::fields_for(&input.scheme)
                .iter()
                .copied()
                .filter(|key| AuthInput::is_reference(key) && input.value(key).is_some())
                .collect();
            // `auth.username_secret` as the config file spells it is
            // `username-secret` as a flag and a field.
            let mut resolved: Vec<String> = auth
                .secret_fields()
                .into_iter()
                .map(|(field, _)| field.trim_start_matches("auth.").replace('_', "-"))
                .collect();
            claimed.sort_unstable();
            resolved.sort_unstable();
            assert_eq!(claimed, resolved, "for `{}`", input.scheme);
        }
    }

    /// The whole point of the change: `init` then three commands, no editor.
    #[test]
    fn a_proxy_can_be_built_from_nothing_without_touching_the_file() {
        let (_dir, path) = empty_policy();

        add_upstream(
            &path,
            "anthropic",
            "https://api.anthropic.com",
            &AuthSpec::Header {
                header: "x-api-key".into(),
                secret: "env:ANTHROPIC_API_KEY".into(),
                prefix: None,
            },
            &[("anthropic-version".into(), "2023-06-01".into())],
        )
        .unwrap();
        add_rule(
            &path,
            &rule(
                Some("inference"),
                "*",
                "http",
                "anthropic",
                &["POST".to_string()],
                &["/v1/messages".to_string()],
                "allow",
            ),
        )
        .unwrap();
        let agent = add_agent(
            &path,
            "claude-code",
            None,
            Reach::Only(&["anthropic".to_string()]),
        )
        .unwrap();

        let config = load(&path);
        config
            .validate()
            .expect("the assembled file must start a proxy");
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.acl.len(), 1);
        assert_eq!(config.agents.len(), 1);
        assert_eq!(config.agents[0].targets, vec!["anthropic".to_string()]);
        assert_eq!(
            config.agents[0].token_sha256.as_deref(),
            Some(identity::token_hash(&agent.token).as_str()),
            "the file gets the hash, the operator gets the token"
        );
    }

    /// The file is mostly comments explaining itself; a round-trip that ate
    /// them would make every later edit harder than the one it saved.
    #[test]
    fn editing_preserves_the_comments_the_template_wrote() {
        let (_dir, path) = empty_policy();
        let before = std::fs::read_to_string(&path).unwrap();
        add_upstream(
            &path,
            "github",
            "https://api.github.com",
            &AuthSpec::None,
            &[],
        )
        .unwrap();
        let after = std::fs::read_to_string(&path).unwrap();

        for line in before.lines().filter(|l| l.starts_with('#')) {
            assert!(after.contains(line), "comment was dropped: {line}");
        }
    }

    /// Plaintext must never reach the file, and `Debug` must not be the hole.
    #[test]
    fn the_token_is_never_written_and_never_printed_by_debug() {
        let (_dir, path) = empty_policy();
        let agent = add_agent(&path, "ci", None, Reach::Any).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&agent.token));
        assert!(text.contains(&identity::token_hash(&agent.token)));
        assert!(!format!("{agent:?}").contains(&agent.token));
    }

    /// The default grant, refused. A bare `agent add` used to enrol an agent
    /// with no `targets` — which the file reads as *every* upstream and every
    /// MCP server, now and in future. Saying nothing can no longer be how that
    /// is asked for.
    #[test]
    fn enrolling_an_agent_without_saying_what_it_may_reach_is_refused() {
        let (_dir, path) = empty_policy();

        let error = add_agent(&path, "ci", None, Reach::Only(&[]))
            .unwrap_err()
            .to_string();

        assert!(error.contains("--target"), "{error}");
        assert!(error.contains("--any-target"), "{error}");
        assert!(
            load(&path).agents.is_empty(),
            "and nothing was written — a refused enrolment must not mint a token either"
        );
    }

    /// The blanket grant is still available. It is a decision now, not a
    /// default, and the file spells it the way it always has.
    #[test]
    fn the_blanket_grant_is_still_there_when_it_is_asked_for() {
        let (_dir, path) = empty_policy();

        add_agent(&path, "ci", None, Reach::Any).unwrap();

        let agents = load(&path).agents;
        assert_eq!(agents.len(), 1);
        assert!(
            agents[0].targets.is_empty(),
            "an absent `targets` is how the file says `any`, and there is only one spelling"
        );
        assert!(
            !std::fs::read_to_string(&path).unwrap().contains("targets"),
            "in particular, no empty `targets = []`, which would read as a scope that is not one"
        );
    }

    /// Reading is unchanged. Every policy file already written goes on meaning
    /// what it meant — only the command that writes a new one got stricter.
    #[test]
    fn an_absent_targets_key_still_reads_as_any() {
        let (_dir, path) = empty_policy();
        add_agent(&path, "ci", None, Reach::Any).unwrap();

        let config = load(&path);
        assert!(crate::identity::agent_may_address(
            &config.agents[0],
            "anything-at-all"
        ));
    }

    #[test]
    fn a_duplicate_agent_id_is_refused() {
        let (_dir, path) = empty_policy();
        add_agent(&path, "ci", None, Reach::Any).unwrap();
        let error = add_agent(&path, "ci", None, Reach::Any)
            .unwrap_err()
            .to_string();
        assert!(error.contains("already has an agent"), "{error}");
    }

    /// `--target` naming nothing reads like a grant and denies every call, so
    /// it is refused at the point it is typed rather than discovered in a log.
    #[test]
    fn a_target_that_names_nothing_is_refused() {
        let (_dir, path) = empty_policy();
        let error = add_agent(&path, "ci", None, Reach::Only(&["githbu".to_string()]))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("no upstream or MCP server named `githbu`"),
            "{error}"
        );
        assert!(
            load(&path).agents.is_empty(),
            "a refused edit must not half-apply"
        );
    }

    /// `--secret ANTHROPIC_API_KEY` instead of `--secret env:ANTHROPIC_API_KEY`
    /// would otherwise be stored and sent upstream as the literal string.
    #[test]
    fn a_bare_name_is_not_accepted_as_a_credential_reference() {
        let (_dir, path) = empty_policy();
        let error = add_upstream(
            &path,
            "anthropic",
            "https://api.anthropic.com",
            &AuthSpec::Bearer {
                secret: "ANTHROPIC_API_KEY".into(),
            },
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("credential *reference*"), "{error}");
    }

    /// The error that reports a bad `--secret` must not be the thing that
    /// prints the credential someone passed by mistake.
    #[test]
    fn a_mistyped_secret_is_not_echoed_back_in_the_error() {
        let (_dir, path) = empty_policy();
        let error = format!(
            "{:#}",
            add_upstream(
                &path,
                "stripe",
                "https://api.stripe.com",
                &AuthSpec::Bearer {
                    secret: "sk-live-REALKEY123".into(),
                },
                &[],
            )
            .unwrap_err()
        );
        assert!(
            !error.contains("sk-live-REALKEY123"),
            "the error leaked the credential: {error}"
        );
    }

    #[test]
    fn a_literal_credential_is_refused_as_it_is_by_init() {
        let (_dir, path) = empty_policy();
        let error = add_upstream(
            &path,
            "anthropic",
            "https://api.anthropic.com",
            &AuthSpec::Bearer {
                secret: "literal:sk-real-key".into(),
            },
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("literal:"), "{error}");
        assert!(!error.contains("sk-real-key"), "the error must not echo it");
    }

    #[test]
    fn a_base_url_without_a_scheme_is_refused() {
        let (_dir, path) = empty_policy();
        let error = add_upstream(&path, "gh", "api.github.com", &AuthSpec::None, &[])
            .unwrap_err()
            .to_string();
        assert!(error.contains("scheme"), "{error}");
    }

    /// First match wins, so a rule appended last cannot change what an existing
    /// rule already decides. Inserting would have made this silently possible.
    #[test]
    fn rules_are_appended_so_existing_ones_keep_precedence() {
        let (_dir, path) = empty_policy();
        add_upstream(
            &path,
            "github",
            "https://api.github.com",
            &AuthSpec::None,
            &[],
        )
        .unwrap();
        add_rule(
            &path,
            &rule(
                Some("first"),
                "*",
                "http",
                "github",
                &["GET".into()],
                &["/**".into()],
                "deny",
            ),
        )
        .unwrap();
        add_rule(
            &path,
            &rule(
                Some("second"),
                "*",
                "http",
                "github",
                &["GET".into()],
                &["/**".into()],
                "allow",
            ),
        )
        .unwrap();

        let config = load(&path);
        assert_eq!(config.acl[0].name.as_deref(), Some("first"));
        assert_eq!(config.acl[1].name.as_deref(), Some("second"));
        assert_eq!(rule_count(&path).unwrap(), 2);
    }

    /// An upstream and an MCP server are both addressed as `/<name>/…`.
    #[test]
    fn a_name_already_taken_by_an_mcp_server_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iap.toml");
        init::init(&InitOptions {
            path: path.clone(),
            template: Template::Full,
            ..Default::default()
        })
        .unwrap();
        let taken = load(&path).mcp_servers[0].name.clone();

        let error = add_upstream(&path, &taken, "https://example.com", &AuthSpec::None, &[])
            .unwrap_err()
            .to_string();
        assert!(error.contains("MCP server"), "{error}");
    }

    #[test]
    fn a_service_account_can_be_enrolled_without_editing_the_file() {
        // The scheme the proxy handles best used to be the one the CLI could
        // not express, so a Google upstream meant hand-writing TOML.
        let (_dir, path) = empty_policy();
        add_upstream(
            &path,
            "gsc",
            "https://searchconsole.googleapis.com",
            &AuthSpec::ServiceAccountJwt {
                key_file: Some("op://Private/GCP/credential".into()),
                issuer: None,
                private_key: None,
                key_id: None,
                token_url: None,
                audience: None,
                scopes: vec!["https://www.googleapis.com/auth/webmasters.readonly".into()],
                subject: Some("person@example.com".into()),
                lifetime_secs: None,
            },
            &[],
        )
        .unwrap();

        let config = load(&path);
        config.validate().unwrap();
        match &config.upstreams[0].auth {
            crate::config::AuthConfig::ServiceAccountJwt {
                key_file,
                scopes,
                subject,
                ..
            } => {
                assert_eq!(key_file.as_deref(), Some("op://Private/GCP/credential"));
                assert_eq!(scopes.len(), 1);
                assert_eq!(subject.as_deref(), Some("person@example.com"));
            }
            other => panic!("expected a service account, got {other:?}"),
        }
    }

    #[test]
    fn an_mcp_server_can_be_enrolled_without_editing_the_file() {
        let (_dir, path) = empty_policy();
        add_mcp_server(
            &path,
            "posthog",
            &McpTransportSpec::Http {
                url: "https://mcp.posthog.com/mcp".into(),
            },
            &AuthSpec::Bearer {
                secret: "op://Private/PostHog/key".into(),
            },
        )
        .unwrap();
        add_mcp_server(
            &path,
            "local-notes",
            &McpTransportSpec::Stdio {
                command: "notes-mcp".into(),
                args: vec!["--stdio".into()],
                env: vec![("NOTES_TOKEN".into(), "env:NOTES_TOKEN".into())],
                cwd: None,
            },
            &AuthSpec::None,
        )
        .unwrap();

        let config = load(&path);
        config.validate().unwrap();
        assert_eq!(config.mcp_servers.len(), 2);
        assert_eq!(
            config.mcp_servers[0].url.as_deref(),
            Some("https://mcp.posthog.com/mcp")
        );
        assert_eq!(
            config.mcp_servers[1]
                .env
                .get("NOTES_TOKEN")
                .map(String::as_str),
            Some("env:NOTES_TOKEN")
        );
    }

    #[test]
    fn an_mcp_name_already_taken_by_an_upstream_is_refused() {
        // Both are addressed as `/{name}/…` and both are matched by the same
        // ACL `target`, so the collision is not cosmetic.
        let (_dir, path) = empty_policy();
        add_upstream(
            &path,
            "github",
            "https://api.github.com",
            &AuthSpec::None,
            &[],
        )
        .unwrap();
        let error = add_mcp_server(
            &path,
            "github",
            &McpTransportSpec::Http {
                url: "https://example.com/mcp".into(),
            },
            &AuthSpec::None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("upstream"), "{error}");
    }

    #[test]
    fn a_credential_in_an_mcp_child_environment_must_be_a_reference() {
        let (_dir, path) = empty_policy();
        let error = add_mcp_server(
            &path,
            "leaky",
            &McpTransportSpec::Stdio {
                command: "server".into(),
                args: vec![],
                env: vec![("TOKEN".into(), "literal:ghp_realtoken".into())],
                cwd: None,
            },
            &AuthSpec::None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("literal:"), "{error}");
        assert!(
            !error.contains("ghp_realtoken"),
            "the error echoed the credential: {error}"
        );
    }

    #[test]
    fn basic_auth_can_put_the_credential_in_the_user_field() {
        // Graylog's `<token>:token`. The token stays a reference; the password
        // is a documented constant and is allowed to be a literal.
        let (_dir, path) = empty_policy();
        add_upstream(
            &path,
            "graylog",
            "https://graylog.example.com/api",
            &AuthSpec::Basic {
                username: None,
                username_secret: Some("op://Private/Graylog/token".into()),
                secret: "literal:token".into(),
            },
            &[],
        )
        .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("username_secret = \"op://Private/Graylog/token\""));
        load(&path).validate().unwrap();
    }

    #[test]
    fn a_literal_in_the_user_field_is_still_refused() {
        // The exception is narrow: the *password* may be a scheme constant.
        // The user field is where the credential actually is.
        let (_dir, path) = empty_policy();
        let error = add_upstream(
            &path,
            "graylog",
            "https://graylog.example.com/api",
            &AuthSpec::Basic {
                username: None,
                username_secret: Some("literal:the-real-token".into()),
                secret: "literal:token".into(),
            },
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("--username-secret"), "{error}");
        assert!(!error.contains("the-real-token"), "{error}");
    }

    #[test]
    fn basic_auth_with_neither_user_field_is_rejected_by_validate() {
        let (_dir, path) = empty_policy();
        let error = add_upstream(
            &path,
            "broken",
            "https://example.com",
            &AuthSpec::Basic {
                username: None,
                username_secret: None,
                secret: "env:PASSWORD".into(),
            },
            &[],
        )
        .unwrap_err();
        // The refusal comes from `validate()`, so it is in the cause chain
        // rather than the top-level "the edit produced a policy file…".
        let error = format!("{error:#}");
        assert!(error.contains("username"), "{error}");
    }

    #[test]
    fn a_rule_can_be_put_in_front_of_the_one_it_overrides() {
        // The approval console's "from now on": an `ask` rule already matches,
        // so an allow appended after it would never be reached and the operator
        // would be asked the same question forever.
        let (_dir, path) = empty_policy();
        add_rule(
            &path,
            &rule(
                Some("writes-need-a-human"),
                "*",
                "http",
                "github",
                &["POST".into()],
                &["**".into()],
                "ask",
            ),
        )
        .unwrap();

        let landed = insert_rule(
            &path,
            0,
            &rule(
                Some("console-allow"),
                "claude",
                "http",
                "github",
                &["POST".into()],
                &["/repos/acme/api/issues".into()],
                "allow",
            ),
        )
        .unwrap();
        assert_eq!(landed, 0);

        let config = document_config(&read(&path).unwrap()).unwrap();
        assert_eq!(config.acl[0].name.as_deref(), Some("console-allow"));
        assert_eq!(config.acl[1].name.as_deref(), Some("writes-need-a-human"));
    }

    #[test]
    fn a_grant_can_be_written_with_a_deadline_on_it() {
        let (_dir, path) = empty_policy();
        let expires = Utc::now() + parse_ttl("1h").unwrap();
        add_rule(
            &path,
            &RuleSpec {
                name: Some("for-the-migration"),
                agent: "claude",
                kind: "http",
                target: "github",
                methods: &["POST".into()],
                paths: &["/repos/**".into()],
                action: "allow",
                expires: Some(expires),
            },
        )
        .unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        // UTC and to the second: a deadline a reader has to convert out of a
        // local timezone is one they will read wrong at least once.
        assert!(written.contains("expires = \""), "{written}");
        assert!(written.contains('Z'), "{written}");

        let config = document_config(&read(&path).unwrap()).unwrap();
        assert!(!config.acl[0].expired_at(Utc::now()));
        assert!(config.acl[0].expired_at(expires + TimeDelta::try_seconds(1).unwrap()));
    }

    #[test]
    fn a_duration_needs_its_unit_spelled_out() {
        assert_eq!(
            parse_ttl("30s").unwrap(),
            TimeDelta::try_seconds(30).unwrap()
        );
        assert_eq!(parse_ttl("5m").unwrap(), TimeDelta::try_minutes(5).unwrap());
        assert_eq!(parse_ttl(" 1h ").unwrap(), TimeDelta::try_hours(1).unwrap());
        assert_eq!(parse_ttl("7d").unwrap(), TimeDelta::try_days(7).unwrap());

        // "Allow this for 5" is a question about units that an operator
        // answering a security prompt should not have to stop and ask, and
        // being wrong by a factor of sixty is the direction that hurts.
        let error = parse_ttl("5").unwrap_err().to_string();
        assert!(error.contains("no unit"), "{error}");
        assert!(parse_ttl("5y").is_err(), "years are not offered");
        assert!(parse_ttl("0h").is_err(), "a grant that has already run out");
        assert!(parse_ttl("-1h").is_err());
    }

    #[test]
    fn time_left_reads_as_time_left() {
        let now = Utc::now();
        let left = |delta: TimeDelta| remaining(now + delta, now);
        assert_eq!(left(TimeDelta::try_seconds(45).unwrap()), "45s");
        assert_eq!(left(TimeDelta::try_minutes(47).unwrap()), "47m");
        assert_eq!(left(TimeDelta::try_minutes(90).unwrap()), "1h30m");
        assert_eq!(left(TimeDelta::try_hours(30).unwrap()), "1d6h");
        assert_eq!(left(-TimeDelta::try_seconds(1).unwrap()), "expired");
    }

    #[test]
    fn inserting_past_the_end_appends_rather_than_failing() {
        // The default action did the asking, so there is no rule to get in
        // front of — and "nowhere to insert" must not be an error path the
        // console has to have a second answer for.
        let (_dir, path) = empty_policy();
        let landed = insert_rule(
            &path,
            7,
            &rule(
                Some("only-rule"),
                "*",
                "*",
                "*",
                &["*".into()],
                &["**".into()],
                "deny",
            ),
        )
        .unwrap();

        assert_eq!(landed, 0);
        assert_eq!(rule_count(&path).unwrap(), 1);
    }

    #[test]
    fn the_dry_run_renderer_matches_what_would_be_written() {
        // If these drift, `--dry-run` becomes a promise the write does not keep.
        let (_dir, path) = empty_policy();
        let auth = AuthSpec::Bearer {
            secret: "env:TOKEN".into(),
        };
        let rendered = render_service(
            "svc",
            ServiceSpec::Upstream {
                base_url: "https://x.example.com",
                verify_path: None,
            },
            &auth,
        );
        add_upstream(&path, "svc", "https://x.example.com", &auth, &[]).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        for line in rendered.lines().filter(|line| !line.trim().is_empty()) {
            assert!(
                written.contains(line),
                "`--dry-run` printed a line the write did not produce: {line}"
            );
        }
    }

    /// A file with something in every array — the state a removal has anything
    /// to say about.
    fn populated_policy() -> (tempfile::TempDir, std::path::PathBuf) {
        let (dir, path) = empty_policy();
        add_upstream(
            &path,
            "github",
            "https://api.github.com",
            &AuthSpec::Bearer {
                secret: "env:GITHUB_TOKEN".into(),
            },
            &[],
        )
        .unwrap();
        add_upstream(
            &path,
            "anthropic",
            "https://api.anthropic.com",
            &AuthSpec::None,
            &[],
        )
        .unwrap();
        // acl[0] names the agent outright, acl[1] is every agent, acl[2] is a
        // glob over a fleet. Only the first is orphaned by removing `ci`.
        add_rule(
            &path,
            &rule(
                Some("gh-read"),
                "ci",
                "http",
                "github",
                &["GET".into()],
                &["/repos/**".into()],
                "allow",
            ),
        )
        .unwrap();
        add_rule(
            &path,
            &rule(
                None,
                "*",
                "http",
                "anthropic",
                &["POST".into()],
                &["/v1/messages".into()],
                "allow",
            ),
        )
        .unwrap();
        add_rule(
            &path,
            &rule(
                Some("gh-write"),
                "ci-*",
                "http",
                "github",
                &["POST".into()],
                &["/repos/**".into()],
                "ask",
            ),
        )
        .unwrap();
        add_agent(
            &path,
            "ci",
            None,
            Reach::Only(&["github".into(), "anthropic".into()]),
        )
        .unwrap();
        (dir, path)
    }

    /// The revocation the README promises, as a command rather than an editor.
    #[test]
    fn removing_an_agent_takes_its_token_hash_with_it() {
        let (_dir, path) = populated_policy();
        let hash = load(&path).agents[0].token_sha256.clone().unwrap();

        remove_agent(&path, "ci", false).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains(&hash),
            "the hash that authenticated it is still in the file"
        );
        let config = load(&path);
        assert!(config.agents.is_empty());
        config
            .validate()
            .expect("what is left must still start a proxy");
    }

    /// A rule that matches nothing is how a policy file rots, so the ones left
    /// behind are named rather than left for the operator to notice.
    #[test]
    fn removing_an_agent_reports_the_rules_that_still_name_it() {
        let (_dir, path) = populated_policy();

        let removal = remove_agent(&path, "ci", false).unwrap();

        assert_eq!(
            load(&path).acl.len(),
            3,
            "nothing is pruned without the flag"
        );
        assert_eq!(removal.orphaned_rules.len(), 1);
        assert_eq!(removal.orphaned_rules[0].index, 0);
        assert_eq!(removal.orphaned_rules[0].to_string(), "acl[0] `gh-read`");
    }

    /// `--prune` takes the rules that name the agent outright. A glob covers a
    /// fleet, so one member leaving must not delete it.
    #[test]
    fn pruning_spares_the_glob_that_covers_a_fleet() {
        let (_dir, path) = populated_policy();

        let removal = remove_agent(&path, "ci", true).unwrap();

        assert_eq!(removal.pruned_rules.len(), 1);
        let acl = load(&path).acl;
        assert_eq!(acl.len(), 2);
        assert_eq!(acl[0].agent, "*");
        assert_eq!(acl[1].agent, "ci-*");
    }

    #[test]
    fn removing_an_agent_that_is_not_there_changes_nothing() {
        let (_dir, path) = populated_policy();
        let before = std::fs::read_to_string(&path).unwrap();

        let error = remove_agent(&path, "cl", true).unwrap_err().to_string();

        assert!(error.contains("no agent `cl`"), "{error}");
        assert!(error.contains("the file has: ci"), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    /// The leaked-token path: a new token, the same agent, and nothing
    /// upstream touched.
    #[test]
    fn rotating_replaces_the_hash_and_leaves_everything_else() {
        let (_dir, path) = populated_policy();
        let before = load(&path);
        let old_hash = before.agents[0].token_sha256.clone().unwrap();

        let rotated = rotate_agent(&path, "ci").unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains(&old_hash),
            "the leaked token still authenticates"
        );
        assert!(
            !text.contains(&rotated.token),
            "plaintext must never reach the file"
        );
        assert!(text.contains(&identity::token_hash(&rotated.token)));

        let after = load(&path);
        assert_eq!(after.agents.len(), 1);
        assert_eq!(after.agents[0].id, "ci");
        assert_eq!(after.agents[0].targets, before.agents[0].targets);
        assert_eq!(after.acl.len(), before.acl.len());
        assert_eq!(after.upstreams.len(), before.upstreams.len());
        after.validate().unwrap();
    }

    /// `token_ref` points at 1Password, a file or the environment. Rotating
    /// here would move where the credential comes from — a second change
    /// nobody asked for, on the one command run under time pressure.
    #[test]
    fn rotating_an_agent_whose_token_lives_elsewhere_is_refused() {
        let (_dir, path) = populated_policy();
        let before = format!(
            "{}\n[[agents]]\nid = \"vault\"\ntoken_ref = \"op://Private/Agent/token\"\n",
            std::fs::read_to_string(&path).unwrap()
        );
        std::fs::write(&path, &before).unwrap();

        let error = rotate_agent(&path, "vault").unwrap_err().to_string();

        assert!(error.contains("token_ref"), "{error}");
        assert!(error.contains("rotate it there"), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    /// `agent add --target` refuses a target that names nothing; this is the
    /// same check from the other end, and without it the file would only fail
    /// at the next restart.
    #[test]
    fn removing_a_service_an_agent_is_scoped_to_is_refused() {
        let (_dir, path) = populated_policy();
        let before = std::fs::read_to_string(&path).unwrap();

        let error = remove_upstream(&path, "github", false)
            .unwrap_err()
            .to_string();

        assert!(error.contains("`ci`"), "{error}");
        assert!(error.contains("--prune"), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn pruning_a_service_detaches_the_agents_scoped_to_it() {
        let (_dir, path) = populated_policy();

        let removal = remove_upstream(&path, "github", true).unwrap();

        assert_eq!(removal.detached_agents, vec!["ci".to_string()]);
        assert_eq!(removal.pruned_rules.len(), 2, "both rules aimed at github");
        let config = load(&path);
        assert!(config.upstreams.iter().all(|up| up.name != "github"));
        assert_eq!(config.agents[0].targets, vec!["anthropic".to_string()]);
        assert_eq!(config.acl.len(), 1);
        config.validate().unwrap();
    }

    /// An empty `targets` is not "no targets", it is *any* target. Pruning the
    /// last one would hand out a grant on the way to a removal.
    #[test]
    fn a_removal_never_widens_an_agent_to_every_target() {
        let (_dir, path) = empty_policy();
        add_upstream(
            &path,
            "anthropic",
            "https://api.anthropic.com",
            &AuthSpec::None,
            &[],
        )
        .unwrap();
        add_agent(&path, "ci", None, Reach::Only(&["anthropic".into()])).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();

        let error = remove_upstream(&path, "anthropic", true)
            .unwrap_err()
            .to_string();

        assert!(error.contains("only target of `ci`"), "{error}");
        assert!(error.contains("any"), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn an_mcp_server_is_removed_the_same_way() {
        let (_dir, path) = empty_policy();
        add_mcp_server(
            &path,
            "notes",
            &McpTransportSpec::Stdio {
                command: "notes-mcp".into(),
                args: vec!["--stdio".into()],
                env: vec![("NOTES_TOKEN".into(), "op://Private/Notes/token".into())],
                cwd: None,
            },
            &AuthSpec::None,
        )
        .unwrap();
        add_rule(
            &path,
            &rule(
                None,
                "*",
                "mcp",
                "notes",
                &["tools/call".into()],
                &["get_*".into()],
                "allow",
            ),
        )
        .unwrap();

        let removal = remove_mcp_server(&path, "notes", true).unwrap();

        assert_eq!(removal.pruned_rules.len(), 1);
        let config = load(&path);
        assert!(config.mcp_servers.is_empty());
        assert!(config.acl.is_empty());
        assert!(
            !std::fs::read_to_string(&path)
                .unwrap()
                .contains("NOTES_TOKEN"),
            "the child's credential reference went with it"
        );
    }

    /// Position is the ACL's whole semantics, so a removal by number has to be
    /// the number the operator was shown.
    #[test]
    fn removing_a_rule_renumbers_the_ones_after_it() {
        let (_dir, path) = populated_policy();

        let removed = remove_rule(&path, 0).unwrap();

        assert_eq!(removed.rule.name.as_deref(), Some("gh-read"));
        assert_eq!(removed.remaining, 2);
        let acl = load(&path).acl;
        assert_eq!(acl.len(), 2);
        assert_eq!(acl[0].target, "anthropic", "rule 1 is now rule 0");
        assert_eq!(acl[1].name.as_deref(), Some("gh-write"));
    }

    #[test]
    fn a_reset_takes_out_every_rule_and_leaves_the_default_asking() {
        let (_dir, path) = populated_policy();
        // The state a reset is for: a file that has been edited into saying
        // yes by default, with rules on top that say yes some more.
        set_default(&path, "allow");
        assert_eq!(load(&path).acl_default.action, Action::Allow);

        let reset = reset_acl(&path, ResetTo::Ask).unwrap();

        assert_eq!(reset.removed.len(), 3);
        assert_eq!(reset.was_default, Action::Allow);
        assert_eq!(reset.now_default, Action::Ask);
        // Both halves: rules under an `allow` default still grant everything,
        // and an `ask` default under a surviving `allow` rule never asks.
        let config = load(&path);
        assert!(config.acl.is_empty());
        assert_eq!(config.acl_default.action, Action::Ask);
        // And nothing else went with them — a reset that also revoked the
        // agents is one nobody reaches for.
        assert_eq!(config.upstreams.len(), 2);
        assert!(!config.agents.is_empty());
    }

    /// The other half of the same command: same wipe, but nothing is asked.
    #[test]
    fn a_strict_reset_writes_the_default_that_does_not_ask() {
        let (_dir, path) = populated_policy();
        set_default(&path, "allow");

        let reset = reset_acl(&path, ResetTo::Deny).unwrap();

        assert_eq!(reset.now_default, Action::Deny);
        let config = load(&path);
        assert!(config.acl.is_empty());
        assert_eq!(config.acl_default.action, Action::Deny);
    }

    #[test]
    fn the_names_of_what_a_reset_removed_come_back_with_it() {
        // The only record of a rule list that no longer exists, so the
        // command can print it rather than a count.
        let (_dir, path) = populated_policy();

        let reset = reset_acl(&path, ResetTo::Ask).unwrap();

        let named: Vec<_> = reset
            .removed
            .iter()
            .filter_map(|rule| rule.name.as_deref())
            .collect();
        assert_eq!(named, vec!["gh-read", "gh-write"]);
        assert_eq!(reset.removed[0].index, 0);
        assert_eq!(reset.removed[2].index, 2);
    }

    #[test]
    fn a_reset_of_a_file_with_no_rules_still_writes_the_default() {
        // `remove_rule` refuses a file with no `[[acl]]` blocks, and is right
        // to: there is no rule 0 to take out. A reset is not asking for a
        // rule, it is asking for a state, and the file is not in it until
        // `acl_default` says so.
        let (_dir, path) = empty_policy();
        set_default(&path, "deny");

        let reset = reset_acl(&path, ResetTo::Ask).unwrap();

        assert!(reset.removed.is_empty());
        assert_eq!(reset.was_default, Action::Deny);
        assert_eq!(load(&path).acl_default.action, Action::Ask);
    }

    #[test]
    fn a_reset_finds_an_inline_default_table_too() {
        // `acl_default = { action = "allow" }` is the same policy written the
        // other way, and a reset that added a second `[acl_default]` table
        // beside it would produce a file that does not parse.
        // Written out rather than edited from the template: an inline table
        // has to sit above the first `[table]` header, or TOML reads it as a
        // key of that table instead of a top-level one.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iap.toml");
        std::fs::write(
            &path,
            "acl_default = { action = \"allow\" }\n\n[[acl]]\ntarget = \"*\"\naction = \"allow\"\n",
        )
        .unwrap();
        assert_eq!(load(&path).acl_default.action, Action::Allow);

        let reset = reset_acl(&path, ResetTo::Ask).unwrap();
        assert_eq!(reset.removed.len(), 1);

        assert_eq!(load(&path).acl_default.action, Action::Ask);
    }

    #[test]
    fn a_reset_keeps_the_comments_the_template_wrote() {
        let (_dir, path) = populated_policy();
        let before = std::fs::read_to_string(&path).unwrap();

        reset_acl(&path, ResetTo::Ask).unwrap();

        let after = std::fs::read_to_string(&path).unwrap();
        for line in before.lines().filter(|line| line.starts_with('#')) {
            assert!(after.contains(line), "lost the comment: {line}");
        }
    }

    #[test]
    fn a_rule_number_that_is_not_there_names_the_range() {
        let (_dir, path) = populated_policy();
        let before = std::fs::read_to_string(&path).unwrap();

        let error = remove_rule(&path, 7).unwrap_err().to_string();

        assert!(error.contains("numbered 0 to 2"), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    /// Removals go through the same document as the adds, so the comments the
    /// template wrote have to survive them too.
    #[test]
    fn removing_preserves_the_comments_the_template_wrote() {
        let (_dir, path) = populated_policy();
        let before = std::fs::read_to_string(&path).unwrap();

        remove_agent(&path, "ci", true).unwrap();
        remove_upstream(&path, "github", true).unwrap();

        let after = std::fs::read_to_string(&path).unwrap();
        for line in before.lines().filter(|line| line.starts_with('#')) {
            assert!(after.contains(line), "comment was dropped: {line}");
        }
    }

    /// TOML admits `agents = [{…}]` as well as `[[agents]]`, and these
    /// commands edit the second. Matching nothing and reporting success would
    /// leave a revoked token live.
    #[test]
    fn an_inline_array_is_refused_rather_than_silently_missed() {
        let (_dir, path) = empty_policy();
        let text = std::fs::read_to_string(&path).unwrap();
        // Before the first table header, so the key is top-level rather than
        // swallowed by whichever section the template ends with.
        std::fs::write(
            &path,
            format!(
                "agents = [{{ id = \"ci\", token_sha256 = \"{}\" }}]\n{text}",
                "0".repeat(64)
            ),
        )
        .unwrap();

        let error = remove_agent(&path, "ci", false).unwrap_err().to_string();

        assert!(error.contains("inline array"), "{error}");
    }

    /// Every scheme a policy file can hold, one of each — the set an edit has
    /// to be able to read back and write out again untouched.
    fn every_scheme() -> Vec<AuthConfig> {
        vec![
            AuthConfig::None,
            AuthConfig::Bearer {
                secret: "env:GITHUB_TOKEN".into(),
            },
            AuthConfig::Header {
                header: "x-api-key".into(),
                secret: "op://Private/Anthropic/key".into(),
                prefix: Some("Token ".into()),
            },
            AuthConfig::Basic {
                username: None,
                username_secret: Some("op://Private/Graylog/token".into()),
                secret: "literal:token".into(),
            },
            AuthConfig::Query {
                param: "key".into(),
                secret: "env:MAPS_KEY".into(),
            },
            AuthConfig::Oauth2ClientCredentials {
                token_url: "https://id.example.com/oauth2/token".into(),
                client_id: "iap".into(),
                client_secret: "op://Private/Example/client-secret".into(),
                scope: Some("read:things write:things".into()),
                audience: Some("https://api.example.com".into()),
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
        ]
    }

    /// The edit the console is: repoint a service, or swap the credential it
    /// attaches, without the entry ever leaving the file.
    #[test]
    fn an_upstream_can_be_repointed_without_being_removed_and_re_added() {
        let (_dir, path) = populated_policy();
        let before_text = std::fs::read_to_string(&path).unwrap();
        let before = load(&path);
        assert_eq!(before.acl.len(), 3);

        edit_upstream(
            &path,
            "github",
            "https://github.example.com/api/v3",
            &AuthSpec::Header {
                header: "authorization".into(),
                secret: "op://Private/GHE/token".into(),
                prefix: Some("token ".into()),
            },
            &[("accept".into(), "application/vnd.github+json".into())],
        )
        .unwrap();

        let after = load(&path);
        after
            .validate()
            .expect("an edit cannot leave a file the proxy would refuse");
        let upstream = after
            .upstream("github")
            .expect("it is still there, under its own name");
        assert_eq!(upstream.base_url, "https://github.example.com/api/v3");
        assert_eq!(
            upstream.headers.get("accept").map(String::as_str),
            Some("application/vnd.github+json")
        );
        assert!(
            matches!(&upstream.auth, AuthConfig::Header { secret, .. } if secret == "op://Private/GHE/token")
        );

        // The half `rm` and `add` could not have done: the rules aimed at it
        // and the agent scoped to it are pointing at the same entry, in the
        // same place in the file.
        assert_eq!(
            after.acl.len(),
            before.acl.len(),
            "no rule was taken with it"
        );
        assert_eq!(after.agents[0].targets, before.agents[0].targets);
        assert_eq!(
            after
                .upstreams
                .iter()
                .map(|up| up.name.as_str())
                .collect::<Vec<_>>(),
            before
                .upstreams
                .iter()
                .map(|up| up.name.as_str())
                .collect::<Vec<_>>(),
            "and it did not move to the end of the file"
        );

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains("env:GITHUB_TOKEN"),
            "the old credential reference is still there:\n{text}"
        );
        for line in before_text.lines().filter(|line| line.starts_with('#')) {
            assert!(text.contains(line), "comment was dropped: {line}");
        }
    }

    /// What the console's edit form does when it is opened and saved: read the
    /// credential out of the file, and put it back. Anything this loses is a
    /// credential an operator dropped by editing a base URL.
    #[test]
    fn a_credential_read_out_of_the_file_goes_back_in_unchanged() {
        let (_dir, path) = populated_policy();
        for auth in every_scheme() {
            let spec = AuthInput::of(&auth)
                .to_spec()
                .unwrap_or_else(|error| panic!("{auth:?} could not be read back: {error:#}"));
            edit_upstream(&path, "github", "https://api.github.com", &spec, &[]).unwrap();

            assert_eq!(
                load(&path).upstream("github").unwrap().auth,
                auth,
                "a round trip through the form's fields changed the credential"
            );
        }
    }

    /// Clearing the headers has to clear them, not leave the last set in place.
    #[test]
    fn an_edit_that_drops_the_headers_drops_them() {
        let (_dir, path) = populated_policy();
        edit_upstream(
            &path,
            "github",
            "https://api.github.com",
            &AuthSpec::None,
            &[("accept".into(), "application/json".into())],
        )
        .unwrap();
        edit_upstream(
            &path,
            "github",
            "https://api.github.com",
            &AuthSpec::None,
            &[],
        )
        .unwrap();

        assert!(load(&path).upstream("github").unwrap().headers.is_empty());
    }

    /// An edit is checked exactly as an add is, and a refused one leaves the
    /// file as it was — including the credential it is refusing to overwrite.
    #[test]
    fn an_edit_is_validated_like_an_add() {
        let (_dir, path) = populated_policy();
        let before = std::fs::read_to_string(&path).unwrap();

        for spec in [
            AuthSpec::Bearer {
                secret: "ghp_the_token_itself".into(),
            },
            AuthSpec::Bearer {
                secret: "literal:ghp_the_token_itself".into(),
            },
        ] {
            edit_upstream(&path, "github", "https://api.github.com", &spec, &[]).unwrap_err();
        }
        edit_upstream(&path, "github", "api.github.com", &AuthSpec::None, &[]).unwrap_err();

        let error = edit_upstream(
            &path,
            "gihtub",
            "https://api.github.com",
            &AuthSpec::None,
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("no upstream `gihtub`"), "{error}");
        assert!(
            error.contains("anthropic"),
            "and says what is there: {error}"
        );

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            before,
            "a refused edit rewrote the file anyway"
        );
    }

    /// TLS is configured by hand in `[server.tls]`; enrolment is done by these
    /// commands. A rewrite that dropped the block would take the proxy off
    /// HTTPS as a side effect of adding an agent.
    #[test]
    fn enrolling_does_not_disturb_a_tls_block() {
        let (_dir, path) = empty_policy();
        let text = std::fs::read_to_string(&path).unwrap();
        let text = text.replace(
            "[audit]",
            "[server.tls]\ncert = \"file:/etc/agent-iap/fullchain.pem\"\nkey = \"file:/etc/agent-iap/key.pem\"\n\n[audit]",
        );
        std::fs::write(&path, &text).unwrap();

        add_upstream(
            &path,
            "github",
            "https://api.github.com",
            &AuthSpec::None,
            &[],
        )
        .unwrap();
        add_rule(
            &path,
            &rule(
                None,
                "*",
                "http",
                "github",
                &["GET".into()],
                &["/**".into()],
                "allow",
            ),
        )
        .unwrap();
        add_agent(&path, "ci", None, Reach::Only(&["github".to_string()])).unwrap();

        let config = load(&path);
        let tls = config
            .server
            .tls
            .expect("`[server.tls]` must survive enrolment");
        assert_eq!(tls.cert, "file:/etc/agent-iap/fullchain.pem");
        assert_eq!(tls.key, "file:/etc/agent-iap/key.pem");
    }
}
