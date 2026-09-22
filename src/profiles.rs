//! Helper profiles: a service the proxy can front, already spelled out.
//!
//! `upstream add` and `mcp-server add` can express any service, which means
//! they ask you for everything — the base URL, the scheme, the header name, the
//! OAuth scopes, and a set of paths narrow enough to be worth calling a policy.
//! Getting a service wrong in that list does not fail loudly: a scope typo is a
//! 403 an hour later, and `--paths '/**'` is a grant nobody reviews.
//!
//! A profile is that answer, written down once. `agent-iap profile add graylog`
//! knows Graylog authenticates an access token as `<token>:token`, that its API
//! hangs off `/api`, and which of its routes are reads. What it does *not* know
//! is your credential, and it never asks for one: `--secret` takes the same
//! reference every other command takes.
//!
//! Profiles are a starting point, not a ceiling. Everything one writes is
//! ordinary TOML in the policy file, and `--dry-run` prints it before anything
//! is written, because a policy you did not read is not a policy you can rely
//! on.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

use crate::enroll::{self, AuthSpec, McpTransportSpec};

/// What credential the profile needs, so `profile show` can say what to fetch
/// before the first call fails with a 401 that names nothing.
#[derive(Debug, Clone)]
pub struct Credential {
    /// One line: what the thing is called where you go to create it.
    pub about: String,
    /// Where to create it.
    pub url: String,
}

/// A value the caller has to supply because it is theirs, not the vendor's —
/// a self-hosted host name, a data region, an account login.
#[derive(Debug, Clone)]
pub struct Var {
    pub name: String,
    pub about: String,
    pub default: Option<String>,
}

/// The credential scheme, minus the reference the caller supplies as `--secret`.
#[derive(Debug, Clone)]
pub enum AuthTemplate {
    None,
    Bearer,
    Header {
        header: String,
        prefix: Option<String>,
    },
    /// Ordinary basic auth; the user half comes from a profile variable.
    Basic {
        username_var: String,
    },
    /// Basic auth where the *user* field is the credential and the password is
    /// a documented constant — Graylog's `<token>:token`.
    BasicSecretUser {
        password: String,
    },
    /// The credential goes in the query string, because the vendor takes it
    /// nowhere else — Semrush's v3 `?key=`. Worth naming as its own template so
    /// nobody reaches for `Bearer` and gets a 401 that says nothing.
    Query {
        param: String,
    },
    /// Google and anything else doing RFC 7523. Scopes come from the access
    /// level, because "read" and "write" are different scopes, not just
    /// different paths.
    ServiceAccountJwt,
}

/// What the profile adds to the policy file.
#[derive(Debug, Clone)]
pub enum Service {
    Http {
        base_url: String,
        auth: AuthTemplate,
    },
    McpHttp {
        url: String,
        auth: AuthTemplate,
    },
    /// A child process. Used for vendors whose remote MCP server speaks OAuth
    /// rather than a bearer token: `mcp-remote` does the browser flow and
    /// caches the result, and the proxy still sees every JSON-RPC message.
    McpStdio {
        command: String,
        args: Vec<String>,
        /// Child environment. Values are secret references; `{secret}` is
        /// substituted with whatever `--secret` was given.
        env: Vec<(String, String)>,
    },
}

impl Service {
    pub fn kind(&self) -> &'static str {
        match self {
            Service::Http { .. } => "http",
            Service::McpHttp { .. } | Service::McpStdio { .. } => "mcp",
        }
    }

    fn endpoint(&self) -> String {
        match self {
            Service::Http { base_url, .. } => base_url.clone(),
            Service::McpHttp { url, .. } => url.clone(),
            Service::McpStdio { command, args, .. } => {
                format!("{command} {}", args.join(" "))
            }
        }
    }
}

/// One ACL rule the access level contributes.
#[derive(Debug, Clone)]
pub struct RuleTemplate {
    pub suffix: String,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
    pub action: String,
}

/// A named bundle of scopes and rules: what "read" means for this service.
#[derive(Debug, Clone)]
pub struct Access {
    pub name: String,
    pub about: String,
    /// OAuth scopes this level needs. Empty for schemes that have none.
    pub scopes: Vec<String>,
    pub rules: Vec<RuleTemplate>,
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub id: String,
    pub title: String,
    pub vendor: String,
    pub summary: String,
    pub default_name: String,
    pub credential: Credential,
    pub vars: Vec<Var>,
    pub service: Service,
    pub access: Vec<Access>,
    /// Anything true about this profile that would otherwise be found out the
    /// hard way — an auth flow the proxy cannot do, a call that costs money.
    pub note: Option<String>,
    /// The endpoint `--verify` should call to prove the credential, `{var}`
    /// expansion and all. `None` where the vendor documents nothing cheap,
    /// safe and available to every plan — a probe that 403s on half the
    /// accounts that hold a good token is worse than no probe at all.
    pub probe: Option<String>,
}

impl Profile {
    /// Declare the endpoint `verify` should call. For the profiles built by a
    /// shared constructor, which has no literal to put it in.
    fn probing(mut self, probe: &str) -> Self {
        self.probe = Some(probe.to_string());
        self
    }

    pub fn default_access(&self) -> &Access {
        &self.access[0]
    }

    pub fn find_access(&self, name: &str) -> Result<&Access> {
        self.access
            .iter()
            .find(|level| level.name == name)
            .with_context(|| {
                format!(
                    "profile `{}` has no access level `{name}` — it has {}",
                    self.id,
                    self.access
                        .iter()
                        .map(|level| level.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }

    pub fn endpoint(&self) -> String {
        self.service.endpoint()
    }
}

/// The probe belonging to whatever profile fronts this base URL, for an
/// upstream that has no `verify_path` of its own.
///
/// The fallback exists because `verify_path` is written at enrolment: every
/// upstream added before a profile had a probe — or added by hand, or by an
/// editor — carries none, and would go on being verified against its root
/// forever. Matching on the base URL is what is available, since the policy
/// file records no profile id; that is deliberate, and it is what makes a
/// profile a starting point rather than something you are stuck inside.
///
/// A probe still holding a `{var}` is skipped: it was never expanded, so the
/// path would be nonsense. Those upstreams need the real `verify_path` the
/// enrolment writes.
pub fn probe_for(base_url: &str) -> Option<String> {
    let wanted = base_url.trim_end_matches('/');
    catalog().into_iter().find_map(|profile| {
        let Service::Http { base_url, .. } = &profile.service else {
            return None;
        };
        if !is_the_same_service(base_url.trim_end_matches('/'), wanted) {
            return None;
        }
        profile.probe.filter(|probe| !probe.contains('{'))
    })
}

/// Whether an enrolled base URL is the one this profile writes.
///
/// A regional or self-hosted profile spells its base URL with the var still in
/// it — PostHog's is `https://{region}.posthog.com` — while the upstream holds
/// what the operator's answer expanded it to. Comparing the two as strings
/// therefore declines exactly the profiles whose upstreams most need the
/// fallback, so a var matches here the way it was filled in: one non-empty run
/// of a single URL component. It never spans a `/`, which is what stops a
/// template from claiming a path that belongs to some other service.
fn is_the_same_service(template: &str, concrete: &str) -> bool {
    let mut literals = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let Some(close) = rest[open..].find('}').map(|at| at + open) else {
            // An unterminated `{` is a bug in the catalogue, not a wildcard.
            return false;
        };
        literals.push(&rest[..open]);
        rest = &rest[close + 1..];
    }
    literals.push(rest);

    let (first, later) = literals.split_first().expect("a trailing literal");
    let Some(mut left) = concrete.strip_prefix(*first) else {
        return false;
    };
    let Some((last, between)) = later.split_last() else {
        // No vars at all: the base URLs are the same service or they are not.
        return left.is_empty();
    };
    for literal in between {
        let Some(at) = left.find(literal).filter(|at| *at > 0) else {
            return false;
        };
        if left[..at].contains('/') {
            return false;
        }
        left = &left[at + literal.len()..];
    }
    // Whatever is left over is the last var, held to the same two rules.
    match left.strip_suffix(last) {
        Some(value) => !value.is_empty() && !value.contains('/'),
        None => false,
    }
}

/// The MCP methods that carry the session rather than doing anything with it.
///
/// These name no tool and no resource, so they match a rule only when it places
/// no constraint on `paths`. Any tool-scoped rule therefore leaves `initialize`
/// falling through to the default — and the default is deny, so the handshake
/// fails and the agent sees a server that never came up. Every MCP profile
/// emits this rule first, before the rule that scopes the tools.
pub const MCP_SESSION_METHODS: &[&str] = &[
    "initialize",
    "notifications/*",
    "ping",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
    "completion/complete",
    "logging/setLevel",
];

/// Options for materialising a profile into a policy file.
pub struct AddOptions {
    /// Name the service takes in the policy file. Defaults to the profile's.
    pub name: Option<String>,
    /// Credential reference. Required unless the profile needs none.
    pub secret: Option<String>,
    /// Access level; defaults to the profile's first, which is the narrowest.
    ///
    /// It decides the OAuth scopes the credential is minted with whether or not
    /// anything is granted, and it decides the rules `grant` writes.
    pub access: Option<String>,
    pub vars: Vec<String>,
    /// Restrict the rules to one agent. Defaults to every agent. Read only
    /// when `grant` is set — without it there are no rules to scope.
    pub agent: Option<String>,
    /// Write the access level's ACL rules along with the service.
    ///
    /// Off, because enrolling a service is not the same act as granting an
    /// agent standing access to it, and doing both on one command is how a
    /// proxy whose whole point is `ask` came to answer its first real request
    /// with `allow` and nobody asked (SIRI-197). Left off, the service is
    /// enrolled and nothing is permitted: the first call falls through to
    /// `acl_default`, stops on a human at the console, and the rule is written
    /// from the answer — for the agent that actually asked and the path it
    /// actually asked for. On, this writes the reviewed bundle up front, which
    /// is a standing `allow` and therefore something a human has to type.
    pub grant: bool,
    /// Print what would be written and write nothing.
    pub dry_run: bool,
}

/// A rule the profile is about to write, with the name and target it will
/// actually carry — resolved from `--as`, not from the profile id.
struct PlannedRule {
    name: String,
    kind: String,
    methods: Vec<String>,
    paths: Vec<String>,
    action: String,
}

/// What `profile add` did, so the caller can print it without re-deriving it.
pub struct Added {
    pub name: String,
    pub kind: &'static str,
    pub endpoint: String,
    pub access: String,
    /// The rules written, which is nothing at all unless `grant` was asked for.
    pub rules: Vec<String>,
    /// Whether `grant` was asked for — so a caller can tell "you asked for the
    /// rules and here they are" from "nothing is permitted yet", rather than
    /// inferring it from an empty list an access level could also produce.
    pub granted: bool,
    pub scopes: Vec<String>,
    pub note: Option<String>,
    /// The TOML a `dry_run` would have written. Returned rather than printed
    /// so the approval console can show the same preview the CLI does — a
    /// `println!` into a drawn terminal is a corrupted screen.
    pub plan: Option<String>,
}

pub fn get(id: &str) -> Result<Profile> {
    catalog()
        .into_iter()
        .find(|profile| profile.id == id)
        .with_context(|| {
            format!("no profile `{id}` — `agent-iap profile list` shows every one there is")
        })
}

/// Add a profile to the policy file: the service, then its rules.
pub fn add(path: &Path, profile: &Profile, options: &AddOptions) -> Result<Added> {
    let name = options
        .name
        .clone()
        .unwrap_or_else(|| profile.default_name.clone());
    let access = match &options.access {
        Some(level) => profile.find_access(level)?,
        None => profile.default_access(),
    };
    let vars = resolve_vars(profile, &options.vars)?;

    let needs_secret = !matches!(
        service_auth(&profile.service),
        Some(AuthTemplate::None) | None
    );
    let secret = match (&options.secret, needs_secret) {
        (Some(secret), _) => secret.clone(),
        (None, true) => bail!(
            "profile `{}` needs `--secret <REF>`: {} — create one at {}",
            profile.id,
            profile.credential.about,
            profile.credential.url
        ),
        (None, false) => String::new(),
    };

    let service = substitute_service(&profile.service, &vars, &secret)?;
    let auth = build_auth(&service, &secret, &vars, &access.scopes)?;
    // The probe names the same vars the service does — Cloudflare's is
    // `/accounts/{account_id}/tokens/verify` — so it is expanded here, with
    // the account already resolved, rather than left for `verify` to guess at.
    let probe = profile
        .probe
        .as_deref()
        .map(|probe| expand(probe, &vars, &secret))
        .transpose()?;

    // Rules are named after the service as it was actually added, not after the
    // profile: two PostHog accounts on one proxy would otherwise produce two
    // sets of rules with identical names in the audit log.
    let agent = options.agent.clone().unwrap_or_else(|| "*".to_string());
    // Empty unless `grant` was asked for. The access level still decided the
    // scopes above either way — what it no longer decides on its own is
    // whether an agent may call.
    let rules = match options.grant {
        true => planned_rules(&name, &service, access),
        false => Vec::new(),
    };

    let added = Added {
        name: name.clone(),
        kind: service.kind(),
        endpoint: service.endpoint(),
        access: access.name.clone(),
        rules: rules.iter().map(|rule| rule.name.clone()).collect(),
        granted: options.grant,
        scopes: access.scopes.clone(),
        note: profile.note.clone(),
        plan: None,
    };

    if options.dry_run {
        return Ok(Added {
            plan: Some(render_plan(
                &name,
                &service,
                &auth,
                &rules,
                &agent,
                probe.as_deref(),
            )),
            ..added
        });
    }

    match &service {
        Service::Http { base_url, .. } => {
            enroll::add_upstream_probing(path, &name, base_url, &auth, &[], probe.as_deref())?;
        }
        Service::McpHttp { url, .. } => {
            enroll::add_mcp_server(
                path,
                &name,
                &McpTransportSpec::Http { url: url.clone() },
                &auth,
            )?;
        }
        Service::McpStdio { command, args, env } => {
            enroll::add_mcp_server(
                path,
                &name,
                &McpTransportSpec::Stdio {
                    command: command.clone(),
                    args: args.clone(),
                    env: env.clone(),
                    cwd: None,
                },
                &auth,
            )?;
        }
    }

    for rule in &rules {
        enroll::add_rule(path, &planned_spec(rule, &agent, &name))?;
    }

    Ok(added)
}

fn render_plan(
    name: &str,
    service: &Service,
    auth: &AuthSpec,
    rules: &[PlannedRule],
    agent: &str,
    probe: Option<&str>,
) -> String {
    let mut plan = String::from("# would append to the policy file:\n");
    plan.push_str(&enroll::render_service(
        name,
        service_spec(service, probe),
        auth,
    ));
    plan.push('\n');
    if rules.is_empty() {
        // An empty `[[acl]]` section is the whole point of the default, and a
        // plan that just stops after the service looks like one that forgot to
        // print the rest.
        plan.push_str(
            "# no `[[acl]]` rules: nothing is permitted yet, and the first call\n\
             # falls through to `acl_default`. `--grant` writes the access\n\
             # level's rules here instead.\n",
        );
        return plan;
    }
    for rule in rules {
        plan.push_str(&enroll::render_rule(&planned_spec(rule, agent, name)));
        plan.push('\n');
    }
    plan
}

/// The access level's rules, named after the service as it was actually added.
///
/// Only ever called for a `--grant`: these are standing `allow` rules, and
/// nothing but a human asking writes one.
fn planned_rules(name: &str, service: &Service, access: &Access) -> Vec<PlannedRule> {
    let mut rules: Vec<PlannedRule> = Vec::new();
    if service.kind() == "mcp" {
        // First, so it is matched before any tool-scoped rule can shadow it.
        // `initialize` names no tool, so a file holding only the tool-scoped
        // rules below is one where the session never opens.
        rules.push(PlannedRule {
            name: format!("{name}-session"),
            kind: "mcp".to_string(),
            methods: MCP_SESSION_METHODS.iter().map(|m| m.to_string()).collect(),
            paths: vec!["**".to_string()],
            action: "allow".to_string(),
        });
    }
    for rule in &access.rules {
        rules.push(PlannedRule {
            name: format!("{name}-{}", rule.suffix),
            kind: service.kind().to_string(),
            methods: rule.methods.clone(),
            paths: rule.paths.clone(),
            action: rule.action.clone(),
        });
    }
    rules
}

/// A profile's rule, in the shape `enroll` writes. Profiles grant standing
/// access, so nothing here expires — a profile is the policy, not a loan.
fn planned_spec<'a>(
    rule: &'a PlannedRule,
    agent: &'a str,
    target: &'a str,
) -> enroll::RuleSpec<'a> {
    enroll::RuleSpec {
        name: Some(&rule.name),
        agent,
        kind: &rule.kind,
        target,
        methods: &rule.methods,
        paths: &rule.paths,
        action: &rule.action,
        expires: None,
    }
}

fn service_spec<'a>(service: &'a Service, probe: Option<&'a str>) -> enroll::ServiceSpec<'a> {
    match service {
        Service::Http { base_url, .. } => enroll::ServiceSpec::Upstream {
            base_url,
            verify_path: probe,
        },
        Service::McpHttp { url, .. } => enroll::ServiceSpec::McpHttp { url },
        Service::McpStdio { command, args, env } => {
            enroll::ServiceSpec::McpStdio { command, args, env }
        }
    }
}

fn service_auth(service: &Service) -> Option<AuthTemplate> {
    match service {
        Service::Http { auth, .. } | Service::McpHttp { auth, .. } => Some(auth.clone()),
        // A stdio server takes its credential through the environment, which is
        // still a `--secret` reference — just not an `auth` block.
        Service::McpStdio { env, .. } => {
            if env.is_empty() {
                Some(AuthTemplate::None)
            } else {
                None
            }
        }
    }
}

fn resolve_vars(profile: &Profile, given: &[String]) -> Result<BTreeMap<String, String>> {
    let mut supplied = BTreeMap::new();
    for entry in given {
        let (key, value) = entry
            .split_once('=')
            .with_context(|| format!("`--var {entry}` should be `name=value`"))?;
        if !profile.vars.iter().any(|var| var.name == key) {
            bail!(
                "profile `{}` has no variable `{key}` — it takes {}",
                profile.id,
                if profile.vars.is_empty() {
                    "none".to_string()
                } else {
                    profile
                        .vars
                        .iter()
                        .map(|var| var.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            );
        }
        supplied.insert(key.to_string(), value.to_string());
    }

    let mut resolved = BTreeMap::new();
    for var in &profile.vars {
        let value = supplied
            .get(&var.name)
            .cloned()
            .or_else(|| var.default.clone())
            .with_context(|| {
                format!(
                    "profile `{}` needs `--var {}=…` ({})",
                    profile.id, var.name, var.about
                )
            })?;
        resolved.insert(var.name.clone(), value);
    }
    Ok(resolved)
}

/// `{var}` and `{secret}` substitution. An unresolved placeholder is an error
/// rather than a literal brace in a base URL nobody notices until the 404.
fn expand(template: &str, vars: &BTreeMap<String, String>, secret: &str) -> Result<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = rest[open..]
            .find('}')
            .with_context(|| format!("unterminated `{{` in `{template}`"))?
            + open;
        let key = &rest[open + 1..close];
        let value = if key == "secret" {
            secret.to_string()
        } else {
            vars.get(key)
                .cloned()
                .with_context(|| format!("`{{{key}}}` in `{template}` has no value"))?
        };
        out.push_str(&value);
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn substitute_service(
    service: &Service,
    vars: &BTreeMap<String, String>,
    secret: &str,
) -> Result<Service> {
    Ok(match service {
        Service::Http { base_url, auth } => Service::Http {
            base_url: expand(base_url, vars, secret)?,
            auth: auth.clone(),
        },
        Service::McpHttp { url, auth } => Service::McpHttp {
            url: expand(url, vars, secret)?,
            auth: auth.clone(),
        },
        Service::McpStdio { command, args, env } => Service::McpStdio {
            command: command.clone(),
            args: args
                .iter()
                .map(|arg| expand(arg, vars, secret))
                .collect::<Result<_>>()?,
            env: env
                .iter()
                .map(|(key, value)| Ok((key.clone(), expand(value, vars, secret)?)))
                .collect::<Result<_>>()?,
        },
    })
}

fn build_auth(
    service: &Service,
    secret: &str,
    vars: &BTreeMap<String, String>,
    scopes: &[String],
) -> Result<AuthSpec> {
    let template = match service {
        Service::Http { auth, .. } | Service::McpHttp { auth, .. } => auth.clone(),
        Service::McpStdio { .. } => return Ok(AuthSpec::None),
    };
    Ok(match template {
        AuthTemplate::None => AuthSpec::None,
        AuthTemplate::Bearer => AuthSpec::Bearer {
            secret: secret.to_string(),
        },
        AuthTemplate::Header { header, prefix } => AuthSpec::Header {
            header,
            secret: secret.to_string(),
            prefix,
        },
        AuthTemplate::Basic { username_var } => AuthSpec::Basic {
            username: Some(
                vars.get(&username_var)
                    .cloned()
                    .with_context(|| format!("basic auth needs `--var {username_var}=…`"))?,
            ),
            username_secret: None,
            secret: secret.to_string(),
        },
        AuthTemplate::BasicSecretUser { password } => AuthSpec::Basic {
            username: None,
            username_secret: Some(secret.to_string()),
            secret: format!("literal:{password}"),
        },
        AuthTemplate::Query { param } => AuthSpec::Query {
            param,
            secret: secret.to_string(),
        },
        AuthTemplate::ServiceAccountJwt => AuthSpec::ServiceAccountJwt {
            key_file: Some(secret.to_string()),
            issuer: None,
            private_key: None,
            key_id: None,
            token_url: None,
            audience: None,
            scopes: scopes.to_vec(),
            subject: None,
            lifetime_secs: None,
        },
    })
}

// ---------------------------------------------------------------------------
// The catalog
// ---------------------------------------------------------------------------

fn v(name: &str, about: &str, default: Option<&str>) -> Var {
    Var {
        name: name.into(),
        about: about.into(),
        default: default.map(Into::into),
    }
}

fn rule(suffix: &str, methods: &[&str], paths: &[&str], action: &str) -> RuleTemplate {
    RuleTemplate {
        suffix: suffix.into(),
        methods: methods.iter().map(|m| m.to_string()).collect(),
        paths: paths.iter().map(|p| p.to_string()).collect(),
        action: action.into(),
    }
}

fn access(name: &str, about: &str, scopes: &[&str], rules: Vec<RuleTemplate>) -> Access {
    Access {
        name: name.into(),
        about: about.into(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        rules,
    }
}

/// A Google API fronted by one service account. Read and write differ by scope
/// as well as by path, which is why the scopes live on the access level.
fn google(id: &str, title: &str, summary: &str, base_url: &str, levels: Vec<Access>) -> Profile {
    Profile {
        id: id.into(),
        title: title.into(),
        vendor: "Google".into(),
        summary: summary.into(),
        default_name: id.into(),
        credential: Credential {
            about: "the service-account JSON key, exactly as Google issues it".into(),
            url: "https://console.cloud.google.com/iam-admin/serviceaccounts".into(),
        },
        vars: vec![],
        service: Service::Http {
            base_url: base_url.into(),
            auth: AuthTemplate::ServiceAccountJwt,
        },
        access: levels,
        note: Some(
            "Grant the service account access to the property itself — a key with no \
             binding authenticates fine and then 403s. For Search Console add the \
             service-account email as a user on the site; for GA4 add it to the property. \
             `--subject` on the upstream turns on domain-wide delegation if you need to \
             act as a person instead."
                .into(),
        ),
        probe: None,
    }
}

fn cloudflare_mcp(slug: &str, host: &str, title: &str, summary: &str) -> Profile {
    Profile {
        id: format!("cloudflare-mcp-{slug}"),
        title: title.into(),
        vendor: "Cloudflare".into(),
        summary: summary.into(),
        default_name: format!("cf-{slug}"),
        credential: Credential {
            about: "nothing up front — `mcp-remote` opens a browser for Cloudflare's OAuth \
                    flow on first use and caches the grant"
                .into(),
            url: "https://developers.cloudflare.com/agents/model-context-protocol/".into(),
        },
        vars: vec![],
        service: Service::McpStdio {
            command: "npx".into(),
            args: vec![
                "-y".into(),
                "mcp-remote".into(),
                format!("https://{host}/mcp"),
            ],
            env: vec![],
        },
        access: vec![
            access(
                "read",
                "read-only tools",
                &[],
                vec![
                    // Cloudflare's MCP tools are underscore-named — `zones_list`,
                    // `workers_get_worker`, `query_worker_observability`.
                    rule(
                        "reads",
                        &["tools/call"],
                        &[
                            "get_*",
                            "*_get",
                            "*_get_*",
                            "list_*",
                            "*_list",
                            "search_*",
                            "*_search",
                            "query_*",
                            "*_query",
                            "*_read",
                            "*_analytics",
                        ],
                        "allow",
                    ),
                    rule("other-tools", &["tools/call"], &["**"], "ask"),
                ],
            ),
            access(
                "write",
                "every tool the server exposes",
                &[],
                vec![rule("tools", &["tools/call"], &["**"], "allow")],
            ),
            access(
                "ask",
                "prompt for every tool call",
                &[],
                vec![rule("tools", &["tools/call"], &["**"], "ask")],
            ),
        ],
        note: Some(
            "Cloudflare's hosted MCP servers authenticate with an interactive OAuth flow, \
             not an API token, so this profile runs them through `mcp-remote` rather than \
             fronting the endpoint directly. That means the OAuth grant lives in the \
             child's cache, outside the proxy — the proxy still sees and rules on every \
             JSON-RPC message, but it is not what holds the credential. For a credential \
             the proxy does hold, use the `cloudflare` REST profile."
                .into(),
        ),
        probe: None,
    }
}

/// A plain bearer-token REST API: the shape most vendors ship.
/// The shape most vendors ship: one base URL, one bearer token, three levels.
struct BearerApi<'a> {
    id: &'a str,
    title: &'a str,
    vendor: &'a str,
    summary: &'a str,
    base_url: &'a str,
    credential: Credential,
    read_paths: &'a [&'a str],
    write_paths: &'a [&'a str],
}

fn bearer_api(spec: BearerApi<'_>) -> Profile {
    let BearerApi {
        id,
        title,
        vendor,
        summary,
        base_url,
        credential,
        read_paths,
        write_paths,
    } = spec;
    Profile {
        id: id.into(),
        title: title.into(),
        vendor: vendor.into(),
        summary: summary.into(),
        default_name: id.into(),
        credential,
        vars: vec![],
        service: Service::Http {
            base_url: base_url.into(),
            auth: AuthTemplate::Bearer,
        },
        access: vec![
            access(
                "read",
                "GET only",
                &[],
                vec![rule("reads", &["GET"], read_paths, "allow")],
            ),
            access(
                "write",
                "every method",
                &[],
                vec![rule("all", &["*"], write_paths, "allow")],
            ),
            access(
                "ask-writes",
                "reads allowed, anything else prompts, DELETE denied",
                &[],
                vec![
                    rule("reads", &["GET"], read_paths, "allow"),
                    rule("deletes", &["DELETE"], write_paths, "deny"),
                    rule("writes", &["*"], write_paths, "ask"),
                ],
            ),
        ],
        note: None,
        probe: None,
    }
}

/// What `read`, `triage` and `write` mean for the Sentry REST API.
///
/// Shared by the hosted and self-hosted profiles because it is one API: the
/// deployment decides the host, not the paths, and a level that meant something
/// different depending on where Sentry runs would be a level nobody could
/// reason about.
fn sentry_rest_access() -> Vec<Access> {
    // Sentry's issue endpoints come in three spellings and always have: the
    // organization-wide one, the project-scoped one that predates it and is all
    // a 9.x install has, and the bare `/issues/<id>/` an issue's own URL
    // resolves to. A rule naming only the first works on sentry.io and covers
    // nothing on an older self-hosted instance.
    const ISSUES: &[&str] = &[
        "/organizations/*/issues/**",
        "/projects/*/*/issues/**",
        "/issues/**",
    ];
    vec![
        access(
            "read",
            "GET across the whole v0 API — `org:read`, `project:read` and `event:read`",
            &[],
            vec![rule("reads", &["GET"], &["/**"], "allow")],
        ),
        access(
            "triage",
            "reads, plus resolving, ignoring and assigning issues; DELETE denied, \
             anything else prompts",
            &[],
            vec![
                rule("reads", &["GET"], &["/**"], "allow"),
                // Resolve, ignore, assign and mute are one PUT with different
                // bodies, and they are the whole of what an agent watching
                // errors needs to write. `event:write` on the token; the ACL is
                // what keeps the same token from editing a project.
                rule("triage", &["PUT"], ISSUES, "allow"),
                rule("deletes", &["DELETE"], &["/**"], "deny"),
                rule("writes", &["*"], &["/**"], "ask"),
            ],
        ),
        access(
            "write",
            "every method across the whole API",
            &[],
            vec![rule("all", &["*"], &["/**"], "allow")],
        ),
    ]
}

/// The same three levels for the MCP server, so `--access triage` means the
/// same thing whichever of the four Sentry profiles it is given to.
fn sentry_mcp_access() -> Vec<Access> {
    // The catalog moves — tools arrive with products — so `read` allows the
    // read-shaped verbs and sends the rest to `ask` rather than denying them.
    // `analyze_issue_with_seer` matches none of these on purpose: it is the one
    // read here that spends, so it prompts with the writes.
    const READS: &[&str] = &["whoami", "find_*", "get_*", "search_*", "*_details"];
    vec![
        access(
            "read",
            "the tools that look things up; everything else prompts",
            &[],
            vec![
                rule("reads", &["tools/call"], READS, "allow"),
                rule("other-tools", &["tools/call"], &["**"], "ask"),
            ],
        ),
        access(
            "triage",
            "also `update_issue` — resolve, ignore and assign — and nothing else",
            &[],
            vec![
                rule("reads", &["tools/call"], READS, "allow"),
                rule("triage", &["tools/call"], &["update_issue"], "allow"),
                rule("other-tools", &["tools/call"], &["**"], "ask"),
            ],
        ),
        access(
            "write",
            "every tool the server exposes",
            &[],
            vec![rule("tools", &["tools/call"], &["**"], "allow")],
        ),
    ]
}

pub fn catalog() -> Vec<Profile> {
    let mut profiles = vec![
        // ---------------- Google ----------------
        google(
            "google-search-console",
            "Google Search Console",
            "Search analytics, sitemaps and URL inspection for a verified property.",
            "https://searchconsole.googleapis.com",
            vec![
                access(
                    "read",
                    "search analytics and site listings; the query endpoints are POST",
                    &["https://www.googleapis.com/auth/webmasters.readonly"],
                    vec![
                        rule("reads", &["GET"], &["/webmasters/v3/**", "/v1/**"], "allow"),
                        // `searchAnalytics.query` and `urlInspection` are reads
                        // that happen to be POSTs, so a GET-only rule would make
                        // the read-only level unable to read anything.
                        rule(
                            "queries",
                            &["POST"],
                            &[
                                "/webmasters/v3/sites/*/searchAnalytics/query",
                                "/v1/urlInspection/index:inspect",
                            ],
                            "allow",
                        ),
                    ],
                ),
                access(
                    "write",
                    "also sitemap submission and site management",
                    &["https://www.googleapis.com/auth/webmasters"],
                    vec![rule("all", &["*"], &["/webmasters/v3/**", "/v1/**"], "allow")],
                ),
            ],
        )
        .probing("/webmasters/v3/sites"),
        google(
            "google-analytics-data",
            "Google Analytics 4 — Data API",
            "runReport, runRealtimeReport and the rest of the GA4 reporting surface.",
            "https://analyticsdata.googleapis.com",
            vec![access(
                "read",
                "the whole Data API, which has no mutations — its reads are POSTs",
                &["https://www.googleapis.com/auth/analytics.readonly"],
                vec![rule("reports", &["GET", "POST"], &["/v1beta/**"], "allow")],
            )],
        ),
        google(
            "google-analytics-admin",
            "Google Analytics 4 — Admin API",
            "Accounts, properties, data streams and custom dimensions.",
            "https://analyticsadmin.googleapis.com",
            vec![
                access(
                    "read",
                    "list and get",
                    &["https://www.googleapis.com/auth/analytics.readonly"],
                    vec![rule("reads", &["GET"], &["/v1beta/**", "/v1alpha/**"], "allow")],
                ),
                access(
                    "write",
                    "also create, update and delete",
                    &["https://www.googleapis.com/auth/analytics.edit"],
                    vec![rule("all", &["*"], &["/v1beta/**", "/v1alpha/**"], "allow")],
                ),
            ],
        )
        .probing("/v1beta/accounts"),
        google(
            "google-indexing",
            "Google Indexing API",
            "Notify Google that a URL was updated or deleted.",
            "https://indexing.googleapis.com",
            vec![access(
                "write",
                "publish notifications — the API has no read surface worth scoping",
                &["https://www.googleapis.com/auth/indexing"],
                vec![rule(
                    "publish",
                    &["POST"],
                    &["/v3/urlNotifications:publish"],
                    "allow",
                )],
            )],
        ),
        google(
            "google-bigquery",
            "Google BigQuery",
            "Run queries and read datasets, tables and job results.",
            "https://bigquery.googleapis.com",
            vec![
                access(
                    "read",
                    "list metadata and run queries",
                    &["https://www.googleapis.com/auth/bigquery.readonly"],
                    vec![
                        rule("reads", &["GET"], &["/bigquery/v2/**"], "allow"),
                        rule(
                            "queries",
                            &["POST"],
                            &["/bigquery/v2/projects/*/queries", "/bigquery/v2/projects/*/jobs"],
                            "allow",
                        ),
                    ],
                ),
                access(
                    "write",
                    "also create and delete datasets and tables",
                    &["https://www.googleapis.com/auth/bigquery"],
                    vec![rule("all", &["*"], &["/bigquery/v2/**"], "allow")],
                ),
            ],
        )
        .probing("/bigquery/v2/projects"),
        google(
            "google-drive",
            "Google Drive",
            "List, search and download files.",
            "https://www.googleapis.com",
            vec![
                access(
                    "read",
                    "list, get and download",
                    &["https://www.googleapis.com/auth/drive.readonly"],
                    vec![rule("reads", &["GET"], &["/drive/v3/**"], "allow")],
                ),
                access(
                    "write",
                    "also upload, update and delete",
                    &["https://www.googleapis.com/auth/drive"],
                    vec![rule("all", &["*"], &["/drive/v3/**", "/upload/drive/v3/**"], "allow")],
                ),
            ],
        )
        .probing("/drive/v3/about?fields=user"),
        google(
            "google-sheets",
            "Google Sheets",
            "Read and write spreadsheet values.",
            "https://sheets.googleapis.com",
            vec![
                access(
                    "read",
                    "get values and metadata",
                    &["https://www.googleapis.com/auth/spreadsheets.readonly"],
                    vec![rule("reads", &["GET"], &["/v4/spreadsheets/**"], "allow")],
                ),
                access(
                    "write",
                    "also update and append",
                    &["https://www.googleapis.com/auth/spreadsheets"],
                    vec![rule("all", &["*"], &["/v4/spreadsheets/**"], "allow")],
                ),
            ],
        ),
        google(
            "google-cloud-logging",
            "Google Cloud Logging",
            "Read log entries out of Cloud Logging.",
            "https://logging.googleapis.com",
            vec![access(
                "read",
                "list entries — `entries:list` is a POST",
                &["https://www.googleapis.com/auth/logging.read"],
                vec![
                    rule("reads", &["GET"], &["/v2/**"], "allow"),
                    rule("list-entries", &["POST"], &["/v2/entries:list"], "allow"),
                ],
            )],
        ),
        google(
            "google-cloud-storage",
            "Google Cloud Storage",
            "Read objects and bucket metadata.",
            "https://storage.googleapis.com",
            vec![
                access(
                    "read",
                    "get objects and list buckets",
                    &["https://www.googleapis.com/auth/devstorage.read_only"],
                    vec![rule("reads", &["GET"], &["/**"], "allow")],
                ),
                access(
                    "write",
                    "also upload and delete",
                    &["https://www.googleapis.com/auth/devstorage.read_write"],
                    vec![rule("all", &["*"], &["/**"], "allow")],
                ),
            ],
        ),
        // ---------------- PostHog ----------------
        Profile {
            id: "posthog".into(),
            title: "PostHog REST API".into(),
            vendor: "PostHog".into(),
            summary: "Projects, insights, events, feature flags and HogQL queries.".into(),
            default_name: "posthog".into(),
            credential: Credential {
                about: "a personal API key, scoped to the projects you want reachable".into(),
                url: "https://app.posthog.com/settings/user-api-keys".into(),
            },
            vars: vec![v(
                "region",
                "PostHog cloud region: `us` or `eu`",
                Some("us"),
            )],
            service: Service::Http {
                base_url: "https://{region}.posthog.com".into(),
                auth: AuthTemplate::Bearer,
            },
            access: vec![
                access(
                    "read",
                    "GET the API, plus the HogQL query endpoint, which is a POST",
                    &[],
                    vec![
                        rule("reads", &["GET"], &["/api/**"], "allow"),
                        rule(
                            "queries",
                            &["POST"],
                            &["/api/projects/*/query", "/api/projects/*/query/", "/api/environments/*/query/"],
                            "allow",
                        ),
                    ],
                ),
                access(
                    "write",
                    "every method",
                    &[],
                    vec![rule("all", &["*"], &["/api/**"], "allow")],
                ),
            ],
            note: Some(
                "One proxy fronts as many PostHog accounts as you have keys — add the \
                 profile once per account with `--as posthog-<account> --secret <that \
                 account's key>`. Each gets its own rules, its own audit rows and its own \
                 line in `agent-iap list`, and an agent scoped to one cannot reach the other."
                    .into(),
            ),
            // The route PostHog's own docs name for checking a personal API
            // key. The base URL is the app, whose root answers a browser
            // redirect to the login page however good the key is — so without
            // this the only thing `verify` could report was `redirected`, which
            // reads as a wrong base URL and is not one. A key scoped away from
            // `user:read` answers 403 here, which `verify` names as a scope
            // problem rather than a bad credential.
            probe: Some("/api/users/@me/".into()),
        },
        Profile {
            id: "posthog-mcp".into(),
            title: "PostHog MCP server".into(),
            vendor: "PostHog".into(),
            summary: "PostHog's hosted MCP server, fronted with a personal API key.".into(),
            default_name: "posthog-mcp".into(),
            credential: Credential {
                about: "a personal API key — the MCP server takes it as a bearer token".into(),
                url: "https://app.posthog.com/settings/user-api-keys".into(),
            },
            vars: vec![],
            service: Service::McpHttp {
                url: "https://mcp.posthog.com/mcp".into(),
                auth: AuthTemplate::Bearer,
            },
            access: vec![
                access(
                    "read",
                    "read-shaped tools; everything else prompts",
                    &[],
                    vec![
                        // PostHog names over a thousand tools by verb, and the
                        // read verbs are a closed set: `-get`, `-list`,
                        // `-retrieve`, `-search`, `query-`. Anything outside it
                        // falls to the `ask` rule below rather than being
                        // denied, because a catalog this size will always have
                        // a read this list has not met yet.
                        rule(
                            "reads",
                            &["tools/call"],
                            &[
                                "get-*",
                                "*-get",
                                "*-get-*",
                                "list-*",
                                "*-list",
                                "*-retrieve",
                                "*-search",
                                "*-describe",
                                "query-*",
                                "*-query",
                                "*-stats",
                                "*-count",
                                "*-summary",
                                "*-status",
                                "*-history",
                                "*-logs",
                                "*-reference",
                                "read-*",
                            ],
                            "allow",
                        ),
                        rule("other-tools", &["tools/call"], &["**"], "ask"),
                    ],
                ),
                access(
                    "write",
                    "every tool",
                    &[],
                    vec![rule("tools", &["tools/call"], &["**"], "allow")],
                ),
            ],
            note: Some(
                "PostHog exposes well over a thousand tools, so the `read` level allows the \
                 read verbs and sends everything else to `ask` rather than denying it — an \
                 unrecognised tool prompts instead of failing silently. Watch the audit log \
                 for `ask` rows and turn the ones you want into their own rule. One proxy \
                 fronts several accounts: add the profile once per account with `--as \
                 posthog-<account>` and its own key."
                    .into(),
            ),
            probe: None,
        },
        // ---------------- Cloudflare ----------------
        Profile {
            id: "cloudflare".into(),
            title: "Cloudflare REST API".into(),
            vendor: "Cloudflare".into(),
            summary: "The whole client/v4 surface: DNS, zones, Workers, R2, WAF, Access."
                .into(),
            default_name: "cloudflare".into(),
            credential: Credential {
                about: "an API token, scoped to the zones and permissions you want reachable"
                    .into(),
                url: "https://dash.cloudflare.com/profile/api-tokens".into(),
            },
            vars: vec![v(
                "account_id",
                "your Cloudflare account ID — the 32-hex string in the dashboard URL, or \
                 under Manage Account",
                None,
            )],
            service: Service::Http {
                base_url: "https://api.cloudflare.com/client/v4".into(),
                auth: AuthTemplate::Bearer,
            },
            access: vec![
                access(
                    "read",
                    "GET across every service",
                    &[],
                    vec![
                        rule("reads", &["GET"], &["/**"], "allow"),
                        // GraphQL analytics is a POST to one path, and it is a read.
                        rule("graphql", &["POST"], &["/graphql"], "allow"),
                    ],
                ),
                access(
                    "write",
                    "every method across every service",
                    &[],
                    vec![rule("all", &["*"], &["/**"], "allow")],
                ),
                access(
                    "ask-writes",
                    "reads allowed, writes prompt, DELETE denied outright",
                    &[],
                    vec![
                        rule("reads", &["GET"], &["/**"], "allow"),
                        rule("graphql", &["POST"], &["/graphql"], "allow"),
                        rule("deletes", &["DELETE"], &["/**"], "deny"),
                        rule("writes", &["POST", "PUT", "PATCH"], &["/**"], "ask"),
                    ],
                ),
            ],
            note: Some(
                "This is the profile that gives full coverage of Cloudflare's services: \
                 one base URL and one token reach all of them, and the token's own scopes \
                 are a second limit under the ACL. The account ID is asked for because a \
                 Cloudflare token is only half an address: most of the API lives under \
                 `/accounts/<id>/…`, and an account-owned token (`cfat_`, the durable \
                 service-principal kind) can only be verified at that account's own \
                 endpoint — `/user/tokens/verify` is for user tokens and rejects it. \
                 Cloudflare's MCP servers are separate profiles (`cloudflare-mcp-*`) and \
                 authenticate differently."
                    .into(),
            ),
            // Documented as *the* "is this token good" call, and the reason the
            // account ID is a var: without it the only path this profile could
            // probe is the root, which answers `7000 No route for that URI` to
            // a good token and a bad one alike.
            probe: Some("/accounts/{account_id}/tokens/verify".into()),
        },
        // ---------------- DataForSEO ----------------
        Profile {
            id: "dataforseo".into(),
            title: "DataForSEO API".into(),
            vendor: "DataForSEO".into(),
            summary: "SERP, Keywords Data, Backlinks, On-Page and the rest of v3.".into(),
            default_name: "dataforseo".into(),
            credential: Credential {
                about: "the API password that pairs with your API login".into(),
                url: "https://app.dataforseo.com/api-access".into(),
            },
            vars: vec![v("login", "your DataForSEO API login (an email)", None)],
            service: Service::Http {
                base_url: "https://api.dataforseo.com".into(),
                auth: AuthTemplate::Basic {
                    username_var: "login".into(),
                },
            },
            access: vec![
                access(
                    "queued",
                    "task_post / task_get and every GET; the `live` endpoints prompt",
                    &[],
                    vec![
                        rule("reads", &["GET"], &["/v3/**"], "allow"),
                        // `live` bills per call at a higher rate than the queued
                        // equivalent, and nothing in method or path shape tells
                        // an agent that. Making it prompt is the whole point of
                        // having an `ask` action.
                        rule("live", &["POST"], &["/v3/**/live/**"], "ask"),
                        rule("tasks", &["POST"], &["/v3/**"], "allow"),
                    ],
                ),
                access(
                    "all",
                    "every endpoint including the live ones, no prompt",
                    &[],
                    vec![rule("all", &["GET", "POST"], &["/v3/**"], "allow")],
                ),
            ],
            note: Some(
                "DataForSEO bills per call and its `live` endpoints cost more than the \
                 queued ones, so the default level makes those prompt. `agent-iap audit tail \
                 --target dataforseo` is the per-agent spend trail."
                    .into(),
            ),
            // Free, and the one call that tells a wrong password from a wrong
            // login: DataForSEO answers a bad pair with `40100 You are not
            // authorized` rather than a 401 shaped like a routing mistake.
            probe: Some("/v3/appendix/user_data".into()),
        },
        Profile {
            id: "dataforseo-mcp".into(),
            title: "DataForSEO MCP server".into(),
            vendor: "DataForSEO".into(),
            summary: "DataForSEO's hosted MCP server, over the same login and password."
                .into(),
            default_name: "dataforseo-mcp".into(),
            credential: Credential {
                about: "the API password that pairs with your API login".into(),
                url: "https://app.dataforseo.com/api-access".into(),
            },
            vars: vec![v("login", "your DataForSEO API login (an email)", None)],
            service: Service::McpHttp {
                url: "https://mcp.dataforseo.com/mcp".into(),
                auth: AuthTemplate::Basic {
                    username_var: "login".into(),
                },
            },
            access: vec![
                access(
                    "read",
                    "every tool, since the API has no mutations — only charges",
                    &[],
                    vec![rule("tools", &["tools/call"], &["**"], "allow")],
                ),
                access(
                    "ask",
                    "prompt for every tool call, because every call bills",
                    &[],
                    vec![rule("tools", &["tools/call"], &["**"], "ask")],
                ),
            ],
            note: None,
            probe: None,
        },
        // ---------------- Graylog ----------------
        Profile {
            id: "graylog".into(),
            title: "Graylog REST API".into(),
            vendor: "Graylog".into(),
            summary: "Search messages, and read streams, dashboards and system state."
                .into(),
            default_name: "graylog".into(),
            credential: Credential {
                about: "a REST API access token (User → Edit tokens), *not* your password"
                    .into(),
                url: "https://go2docs.graylog.org/current/setting_up_graylog/rest_api_access_tokens.htm"
                    .into(),
            },
            vars: vec![v(
                "host",
                "your Graylog host and port, e.g. `graylog.example.com:9000`",
                None,
            )],
            service: Service::Http {
                base_url: "https://{host}/api".into(),
                auth: AuthTemplate::BasicSecretUser {
                    // Graylog authenticates `<token>:token`: the token goes in
                    // the user field and the password is this fixed word. It is
                    // documented and public, so it is a `literal:` on purpose —
                    // the credential is the user half, and that stays a
                    // reference.
                    password: "token".into(),
                },
            },
            access: vec![
                access(
                    "read",
                    "search and read; searches are POSTs",
                    &[],
                    vec![
                        rule("reads", &["GET"], &["/**"], "allow"),
                        rule(
                            "searches",
                            &["POST"],
                            &["/views/search", "/views/search/**", "/search/**"],
                            "allow",
                        ),
                    ],
                ),
                access(
                    "write",
                    "every method",
                    &[],
                    vec![rule("all", &["*"], &["/**"], "allow")],
                ),
            ],
            note: Some(
                "Graylog authenticates an access token as basic `<token>:token` — the \
                 credential is the *user* field. This profile puts it in `username_secret`, \
                 so the token stays a reference and the policy file stays committable. \
                 A session token works the same way with `session` as the password."
                    .into(),
            ),
            probe: None,
        },
        // ---------------- Semrush ----------------
        Profile {
            id: "semrush".into(),
            title: "Semrush API (v3)".into(),
            vendor: "Semrush".into(),
            summary: "Domain, keyword and backlink reports, Trends traffic data, and Projects."
                .into(),
            default_name: "semrush".into(),
            credential: Credential {
                about: "the v3 API key — a different key from the v4 one, and not \
                        interchangeable with it"
                    .into(),
                url: "https://www.semrush.com/accounts/api-keys/active".into(),
            },
            vars: vec![],
            service: Service::Http {
                base_url: "https://api.semrush.com".into(),
                // v3 takes the key nowhere but the query string. The proxy
                // appends it on the way out, which is the only reason an agent
                // can call this API without ever holding the key — a scheme
                // that would otherwise put the credential in every URL the
                // agent writes, and every log that URL passes through.
                auth: AuthTemplate::Query {
                    param: "key".into(),
                },
            },
            access: vec![
                access(
                    "read",
                    "every report: analytics, backlinks, Trends, and Projects reads",
                    &[],
                    vec![rule(
                        "reads",
                        &["GET"],
                        &[
                            // The SEO/analytics reports are all one path with a
                            // `type=` parameter — `/?type=domain_ranks`. There
                            // is nothing else at the root.
                            "/",
                            // Backlinks v3, documented with the trailing slash;
                            // both spellings reach the same handler.
                            "/analytics/v1",
                            "/analytics/v1/**",
                            // Trends: `/analytics/ta/api/v3/summary` and friends.
                            "/analytics/ta/api/**",
                            // Position Tracking and Site Audit reads.
                            "/management/v1/**",
                        ],
                        "allow",
                    )],
                ),
                access(
                    "ask-writes",
                    "reads allowed, Projects mutations prompt, DELETE denied",
                    &[],
                    vec![
                        rule(
                            "reads",
                            &["GET"],
                            &[
                                "/",
                                "/analytics/v1",
                                "/analytics/v1/**",
                                "/analytics/ta/api/**",
                                "/management/v1/**",
                            ],
                            "allow",
                        ),
                        rule("deletes", &["DELETE"], &["/management/v1/**"], "deny"),
                        rule("writes", &["*"], &["/management/v1/**"], "ask"),
                    ],
                ),
                access(
                    "write",
                    "the reads, plus every method on the Projects API",
                    &[],
                    vec![
                        rule(
                            "reads",
                            &["GET"],
                            &[
                                "/",
                                "/analytics/v1",
                                "/analytics/v1/**",
                                "/analytics/ta/api/**",
                                "/management/v1/**",
                            ],
                            "allow",
                        ),
                        // Projects is the only part of v3 that mutates
                        // anything: creating a campaign, launching a crawl,
                        // adding tracked keywords. The report surface is GET
                        // and stays GET at every level.
                        rule("projects", &["*"], &["/management/v1/**"], "allow"),
                    ],
                ),
            ],
            note: Some(
                "Semrush v3 authenticates with `?key=` in the query string, so this profile \
                 enrols it as `query` auth and the proxy appends the key on the way out — \
                 the agent's own URLs never carry it. Two things the ACL cannot do here: \
                 every analytics report lives at the same path (`/?type=domain_ranks`), so \
                 rules cannot tell one report from another, and every report bills API \
                 units, which no method or path reveals — `agent-iap audit tail --target \
                 semrush` is the per-agent spend trail. The unit-balance endpoints are not \
                 reachable through this upstream: one is on `www.semrush.com` and the other \
                 wants the key as a path segment. The v4 surface is a separate key and a \
                 separate profile (`semrush-v4`)."
                    .into(),
            ),
            probe: None,
        },
        Profile {
            id: "semrush-trends".into(),
            title: "Semrush Trends API".into(),
            vendor: "Semrush".into(),
            summary: "Traffic Analytics: visits, sources, audience overlap and market share."
                .into(),
            default_name: "semrush-trends".into(),
            credential: Credential {
                about: "the v3 API key — the same key `semrush` uses, on an account with a \
                        Trends subscription"
                    .into(),
                url: "https://www.semrush.com/accounts/api-keys/active".into(),
            },
            vars: vec![],
            service: Service::Http {
                base_url: "https://api.semrush.com/analytics/ta/api/v3".into(),
                auth: AuthTemplate::Query {
                    param: "key".into(),
                },
            },
            access: vec![
                access(
                    "read",
                    "every Trends report — the API has no mutations",
                    &[],
                    vec![rule("reads", &["GET"], &["/**"], "allow")],
                ),
                access(
                    "ask",
                    "prompt for every report, because every report bills",
                    &[],
                    vec![rule("reports", &["GET"], &["/**"], "ask")],
                ),
            ],
            note: Some(
                "Trends reports are reachable through `semrush` too — this profile exists \
                 for the budget rather than the paths. Trends bills against its own monthly \
                 allowance rather than Standard API units, so an agent can exhaust one \
                 without touching the other, and only a separate upstream makes that \
                 visible in the audit log and grantable on its own: one agent can be given \
                 Trends and not the reports. Same v3 key, different endpoint."
                    .into(),
            ),
            probe: None,
        },
        Profile {
            id: "semrush-v4".into(),
            title: "Semrush API (v4)".into(),
            vendor: "Semrush".into(),
            summary: "Backlinks, Projects and the Local APIs — listings, reviews, map rank."
                .into(),
            default_name: "semrush-v4".into(),
            credential: Credential {
                about: "a v4 API key, with its own permissions and expiry; shown once when \
                        you create it"
                    .into(),
                url: "https://www.semrush.com/accounts/api-keys/active".into(),
            },
            vars: vec![],
            service: Service::Http {
                base_url: "https://api.semrush.com/apis/v4".into(),
                auth: AuthTemplate::Header {
                    header: "authorization".into(),
                    // `Apikey`, not `Bearer` — Semrush rejects the latter.
                    prefix: Some("Apikey ".into()),
                },
            },
            access: vec![
                access(
                    "read",
                    "GET across every v4 API",
                    &[],
                    vec![rule("reads", &["GET"], &["/**"], "allow")],
                ),
                access(
                    "ask-writes",
                    "reads allowed, writes prompt, DELETE denied outright",
                    &[],
                    vec![
                        rule("reads", &["GET"], &["/**"], "allow"),
                        rule("deletes", &["DELETE"], &["/**"], "deny"),
                        rule("writes", &["POST", "PUT", "PATCH"], &["/**"], "ask"),
                    ],
                ),
                access(
                    "write",
                    "every method across every v4 API",
                    &[],
                    vec![rule("all", &["*"], &["/**"], "allow")],
                ),
            ],
            note: Some(
                "v4 keys are separate from the v3 key and the two are not interchangeable, \
                 so a working `semrush` upstream tells you nothing about this one. Unlike \
                 v3, a v4 key carries its own permissions and expiry — set them narrow at \
                 Semrush as well, since that limit holds even where the ACL is wide. The \
                 Local APIs write: `ask-writes` is the level to start from if listings or \
                 reviews are in scope."
                    .into(),
            ),
            probe: None,
        },
        Profile {
            id: "semrush-mcp".into(),
            title: "Semrush MCP server".into(),
            vendor: "Semrush".into(),
            summary: "Semrush's hosted MCP server: discover a report, then run it.".into(),
            default_name: "semrush-mcp".into(),
            credential: Credential {
                about: "a v4 API key — the server's OAuth flow is the alternative, and the \
                        one the proxy cannot hold"
                    .into(),
                url: "https://www.semrush.com/accounts/api-keys/active".into(),
            },
            vars: vec![],
            service: Service::McpHttp {
                url: "https://mcp.semrush.com/v2/mcp".into(),
                auth: AuthTemplate::Header {
                    header: "authorization".into(),
                    prefix: Some("Apikey ".into()),
                },
            },
            access: vec![
                access(
                    "read",
                    "every tool: the surface is read-only, and only bills",
                    &[],
                    vec![rule("tools", &["tools/call"], &["**"], "allow")],
                ),
                access(
                    "discovery",
                    "browsing the catalog is free; running a report prompts",
                    &[],
                    vec![
                        // Unusually for an MCP server, the tool that costs
                        // money is the one you can name: `execute_report` runs
                        // the report and bills for it, and everything else only
                        // describes what is available.
                        rule("run", &["tools/call"], &["execute_report"], "ask"),
                        rule("catalog", &["tools/call"], &["**"], "allow"),
                    ],
                ),
                access(
                    "ask",
                    "prompt for every tool call",
                    &[],
                    vec![rule("tools", &["tools/call"], &["**"], "ask")],
                ),
            ],
            note: Some(
                "This server prefers OAuth, which would put the grant in the agent's own \
                 client rather than in the proxy; the profile uses the API-key header \
                 instead, so the credential stays on this side of the boundary. The tools \
                 are two-step — a discovery tool names a report, `get_report_schema` gives \
                 its parameters, `execute_report` runs it — and only the last one bills, \
                 which is what the `discovery` level is for. Everything reachable here is a \
                 read: the MCP server exposes the SEO and Trends APIs plus the read-only \
                 Projects methods, and nothing that mutates."
                    .into(),
            ),
            probe: None,
        },
        // ---------------- Sentry ----------------
        Profile {
            id: "sentry".into(),
            title: "Sentry API (sentry.io)".into(),
            vendor: "Sentry".into(),
            summary: "Issues, events, releases, alerts and Discover, on Sentry's own cloud."
                .into(),
            default_name: "sentry".into(),
            credential: Credential {
                about: "a user auth token (`sntryu_…`), or an internal-integration token, \
                        with the scopes you want reachable"
                    .into(),
                url: "https://sentry.io/settings/account/api/auth-tokens/".into(),
            },
            vars: vec![v(
                "region",
                "the region your organization is in: `us` or `de` — its settings page says which",
                Some("us"),
            )],
            service: Service::Http {
                base_url: "https://{region}.sentry.io/api/0".into(),
                auth: AuthTemplate::Bearer,
            },
            access: sentry_rest_access(),
            note: Some(
                "Sentry has shipped one version of this API and the `0` in `/api/0` is it — \
                 there is no `v1` to move to, which is why the same rules front sentry.io \
                 and an install of your own. What does differ is the region. Every \
                 organization lives in one, `us` or `de`, and an organization auth token \
                 (`sntrys_…`) carries its own region inside it, so pointing one at the \
                 other host is a 401 or a redirect from a token that is perfectly good. \
                 Plain `sentry.io` routes to either; the region host is what this profile \
                 writes because it is the one that does not, and a wrong region is better \
                 found by `verify` than by an agent. Organization tokens are CI \
                 credentials — releases and source maps — so a token for reading issues \
                 should be a user one. For an install of your own, use \
                 `sentry-self-hosted`."
                    .into(),
            ),
            // Free, on every plan and every version, and the call that separates
            // a rejected token from an unentitled one: a good token with no
            // `org:read` gets a 403 here, which `verify` reports as a warning
            // rather than a failure.
            probe: Some("/organizations/".into()),
        },
        Profile {
            id: "sentry-self-hosted".into(),
            title: "Sentry API (self-hosted)".into(),
            vendor: "Sentry".into(),
            summary: "The same v0 API on an install of your own — no regions, and whatever \
                      endpoints your version has."
                .into(),
            default_name: "sentry".into(),
            credential: Credential {
                about: "an auth token from *your* install — a sentry.io token is not valid \
                        against it"
                    .into(),
                url: "https://develop.sentry.dev/self-hosted/".into(),
            },
            vars: vec![
                v(
                    "host",
                    "your Sentry host, e.g. `sentry.example.com` — no scheme, no `/api/0`",
                    None,
                ),
                v(
                    "scheme",
                    "`https`, or `http` for an install that terminates TLS nowhere — the \
                     token crosses that wire in a header",
                    Some("https"),
                ),
            ],
            service: Service::Http {
                base_url: "{scheme}://{host}/api/0".into(),
                auth: AuthTemplate::Bearer,
            },
            access: sentry_rest_access(),
            note: Some(
                "Self-hosted Sentry has been on calendar versions since 20.6.0 — `YY.MM.PATCH`, \
                 cut monthly — and the API you get is that release's, not sentry.io's. The \
                 paths these rules name have been there throughout, but what answers them \
                 has not: anything sentry.io shipped after the version you run 404s rather \
                 than being denied, and Seer is not in self-hosted at all. Older than the \
                 calendar versions, a 9.x install predates the organization-wide issue and \
                 event endpoints and has only the project-scoped ones \
                 (`/projects/{org}/{project}/issues/`); both spellings are inside the rules \
                 here, so the access level means the same thing on either — only the \
                 answers change. There are no regions and no `sntrys_` organization tokens \
                 here: the token comes from your own instance, under Settings → Auth Tokens \
                 (Settings → Account → API → Auth Tokens on the 9.x line)."
                    .into(),
            ),
            probe: Some("/organizations/".into()),
        },
        Profile {
            id: "sentry-mcp".into(),
            title: "Sentry MCP server".into(),
            vendor: "Sentry".into(),
            summary: "Sentry's hosted MCP server, fronted with a token instead of a browser."
                .into(),
            default_name: "sentry-mcp".into(),
            credential: Credential {
                about: "a user auth token (`sntryu_…`) — the same one the REST profile takes"
                    .into(),
                url: "https://sentry.io/settings/account/api/auth-tokens/".into(),
            },
            vars: vec![],
            service: Service::McpHttp {
                url: "https://mcp.sentry.dev/mcp".into(),
                // The remote server's documented alternative to its OAuth flow:
                // `Sentry-Bearer`, not `Bearer`, in the ordinary authorization
                // header. It is what lets the proxy hold this credential rather
                // than hand the whole exchange to `mcp-remote`.
                auth: AuthTemplate::Header {
                    header: "authorization".into(),
                    prefix: Some("Sentry-Bearer ".into()),
                },
            },
            access: sentry_mcp_access(),
            note: Some(
                "Sentry's hosted MCP server offers OAuth first, and every client that takes \
                 the plain URL does the browser flow. It also accepts a token in the \
                 authorization header as `Sentry-Bearer <token>`, and that is what this \
                 profile enrols — so the credential stays in the proxy, the way it does for \
                 the REST profiles, rather than in a child process's cache the way the \
                 `cloudflare-mcp-*` profiles have to. `analyze_issue_with_seer` is left out \
                 of the `read` level's allow list on purpose: Seer is the one tool here \
                 that spends against the organization's budget, so it lands on `ask` with \
                 the writes. The server can be scoped to one organization or project by \
                 adding it to the URL (`/mcp/<org>/<project>`); edit the `url` this writes \
                 if you want that. Self-hosted Sentry has no hosted MCP — use \
                 `sentry-mcp-self-hosted`."
                    .into(),
            ),
            probe: None,
        },
        Profile {
            id: "sentry-mcp-self-hosted".into(),
            title: "Sentry MCP server (self-hosted)".into(),
            vendor: "Sentry".into(),
            summary: "The same MCP server as a child process, pointed at an install of your own."
                .into(),
            default_name: "sentry-mcp".into(),
            credential: Credential {
                about: "an auth token from your own install, with `org:read`, `project:read` \
                        and `event:write`"
                    .into(),
                url: "https://develop.sentry.dev/self-hosted/".into(),
            },
            vars: vec![v(
                "host",
                "your Sentry host, e.g. `sentry.example.com` — no scheme, no `/api/0`",
                None,
            )],
            service: Service::McpStdio {
                command: "npx".into(),
                args: vec![
                    "-y".into(),
                    "@sentry/mcp-server@latest".into(),
                    "--host={host}".into(),
                    // Seer is not part of self-hosted, and a skill whose tools
                    // 404 on every call is worse than one that is not offered.
                    "--disable-skills=seer".into(),
                ],
                env: vec![("SENTRY_ACCESS_TOKEN".into(), "{secret}".into())],
            },
            access: sentry_mcp_access(),
            note: Some(
                "There is no hosted MCP endpoint for an install of your own, so this one runs \
                 `@sentry/mcp-server` as a child and points it at your host. The token goes \
                 to the child in `SENTRY_ACCESS_TOKEN` as the same `--secret` reference every \
                 other profile takes, and the proxy still rules on and logs every JSON-RPC \
                 message. Two things the flags cover and the rules cannot: Seer is disabled \
                 because self-hosted does not have it, and an install that terminates TLS \
                 nowhere needs `--insecure-http` added to `args` by hand. Tools that name a \
                 product your version predates fail as tool errors, not as denials."
                    .into(),
            ),
            probe: None,
        },
        // ---------------- Common neighbours ----------------
        Profile {
            id: "anthropic".into(),
            title: "Anthropic API".into(),
            vendor: "Anthropic".into(),
            summary: "Messages, batches and models.".into(),
            default_name: "anthropic".into(),
            credential: Credential {
                about: "an API key".into(),
                url: "https://console.anthropic.com/settings/keys".into(),
            },
            vars: vec![],
            service: Service::Http {
                base_url: "https://api.anthropic.com".into(),
                auth: AuthTemplate::Header {
                    header: "x-api-key".into(),
                    prefix: None,
                },
            },
            access: vec![
                access(
                    "inference",
                    "messages and token counting",
                    &[],
                    vec![rule(
                        "messages",
                        &["POST"],
                        &["/v1/messages", "/v1/messages/count_tokens"],
                        "allow",
                    ), rule("models", &["GET"], &["/v1/models", "/v1/models/*"], "allow")],
                ),
                access(
                    "all",
                    "every endpoint",
                    &[],
                    vec![rule("all", &["*"], &["/v1/**"], "allow")],
                ),
            ],
            note: None,
            probe: Some("/v1/models".into()),
        },
        Profile {
            id: "openai".into(),
            title: "OpenAI API".into(),
            vendor: "OpenAI".into(),
            summary: "Responses, chat completions, embeddings and models.".into(),
            default_name: "openai".into(),
            credential: Credential {
                about: "an API key".into(),
                url: "https://platform.openai.com/api-keys".into(),
            },
            vars: vec![],
            service: Service::Http {
                base_url: "https://api.openai.com".into(),
                auth: AuthTemplate::Bearer,
            },
            access: vec![
                access(
                    "inference",
                    "the endpoints that generate, and nothing that manages the account",
                    &[],
                    vec![
                        rule(
                            "generate",
                            &["POST"],
                            &["/v1/responses", "/v1/chat/completions", "/v1/embeddings"],
                            "allow",
                        ),
                        rule("models", &["GET"], &["/v1/models", "/v1/models/*"], "allow"),
                    ],
                ),
                access(
                    "all",
                    "every endpoint",
                    &[],
                    vec![rule("all", &["*"], &["/v1/**"], "allow")],
                ),
            ],
            note: None,
            probe: Some("/v1/models".into()),
        },
        bearer_api(BearerApi {
            id: "github",
            title: "GitHub REST API",
            vendor: "GitHub",
            summary: "Repos, issues, pull requests and actions.",
            base_url: "https://api.github.com",
            credential: Credential {
                about: "a fine-grained personal access token".into(),
                url: "https://github.com/settings/personal-access-tokens".into(),
            },
            read_paths: &["/**"],
            write_paths: &["/**"],
        })
        .probing("/user"),
        bearer_api(BearerApi {
            id: "linear",
            title: "Linear API",
            vendor: "Linear",
            summary: "Issues and projects, over GraphQL.",
            base_url: "https://api.linear.app",
            credential: Credential {
                about: "a personal API key".into(),
                url: "https://linear.app/settings/api".into(),
            },
            read_paths: &["/graphql"],
            write_paths: &["/graphql"],
        }),
        bearer_api(BearerApi {
            id: "slack",
            title: "Slack Web API",
            vendor: "Slack",
            summary: "Post messages and read channel history.",
            base_url: "https://slack.com/api",
            credential: Credential {
                about: "a bot user OAuth token (`xoxb-…`)".into(),
                url: "https://api.slack.com/apps".into(),
            },
            read_paths: &["/conversations.*", "/users.*", "/team.info"],
            write_paths: &["/**"],
        }),
        bearer_api(BearerApi {
            id: "stripe",
            title: "Stripe API",
            vendor: "Stripe",
            summary: "Customers, subscriptions, invoices and charges.",
            base_url: "https://api.stripe.com",
            credential: Credential {
                about: "a restricted API key — not the live secret key".into(),
                url: "https://dashboard.stripe.com/apikeys".into(),
            },
            read_paths: &["/v1/**"],
            write_paths: &["/v1/**"],
        }),
    ];

    // Cloudflare ships a remote MCP server per product area, and "full coverage"
    // means all of them rather than the two everyone remembers.
    for (slug, host, title, summary) in [
        (
            "api",
            "mcp.cloudflare.com",
            "Cloudflare API MCP",
            "The account-wide API surface as MCP tools.",
        ),
        (
            "docs",
            "docs.mcp.cloudflare.com",
            "Cloudflare Documentation MCP",
            "Search Cloudflare's documentation. No account access.",
        ),
        (
            "bindings",
            "bindings.mcp.cloudflare.com",
            "Workers Bindings MCP",
            "KV, R2, D1 and Durable Object bindings for Workers.",
        ),
        (
            "builds",
            "builds.mcp.cloudflare.com",
            "Workers Builds MCP",
            "Inspect Workers build history and logs.",
        ),
        (
            "observability",
            "observability.mcp.cloudflare.com",
            "Workers Observability MCP",
            "Query Workers logs and analytics.",
        ),
        (
            "radar",
            "radar.mcp.cloudflare.com",
            "Cloudflare Radar MCP",
            "Global internet traffic and routing insights.",
        ),
        (
            "containers",
            "containers.mcp.cloudflare.com",
            "Cloudflare Containers MCP",
            "Run a sandboxed container.",
        ),
        (
            "browser",
            "browser.mcp.cloudflare.com",
            "Browser Rendering MCP",
            "Fetch and render pages in a managed browser.",
        ),
        (
            "logs",
            "logs.mcp.cloudflare.com",
            "Logpush MCP",
            "Manage and inspect Logpush jobs.",
        ),
        (
            "ai-gateway",
            "ai-gateway.mcp.cloudflare.com",
            "AI Gateway MCP",
            "Inspect AI Gateway logs and configuration.",
        ),
        (
            "autorag",
            "autorag.mcp.cloudflare.com",
            "AI Search (AutoRAG) MCP",
            "Query AutoRAG indexes.",
        ),
        (
            "auditlogs",
            "auditlogs.mcp.cloudflare.com",
            "Audit Logs MCP",
            "Read Cloudflare account audit logs.",
        ),
        (
            "dns-analytics",
            "dns-analytics.mcp.cloudflare.com",
            "DNS Analytics MCP",
            "DNS query analytics and reporting.",
        ),
        (
            "dex",
            "dex.mcp.cloudflare.com",
            "Digital Experience Monitoring MCP",
            "Cloudflare One endpoint and network insights.",
        ),
        (
            "casb",
            "casb.mcp.cloudflare.com",
            "Cloudflare One CASB MCP",
            "SaaS security posture findings.",
        ),
        (
            "graphql",
            "graphql.mcp.cloudflare.com",
            "Cloudflare GraphQL MCP",
            "Run GraphQL analytics queries.",
        ),
    ] {
        profiles.push(cloudflare_mcp(slug, host, title, summary));
    }

    profiles.sort_by(|a, b| a.id.cmp(&b.id));
    profiles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_profile_is_internally_consistent() {
        for profile in catalog() {
            assert!(
                !profile.access.is_empty(),
                "{}: no access levels",
                profile.id
            );
            assert!(
                !profile.default_name.is_empty(),
                "{}: no default name",
                profile.id
            );
            for level in &profile.access {
                assert!(
                    !level.rules.is_empty(),
                    "{}/{}: no rules",
                    profile.id,
                    level.name
                );
                for rule in &level.rules {
                    assert!(
                        matches!(rule.action.as_str(), "allow" | "deny" | "ask"),
                        "{}/{}: bad action `{}`",
                        profile.id,
                        level.name,
                        rule.action
                    );
                    assert!(!rule.methods.is_empty() && !rule.paths.is_empty());
                }
            }
        }
    }

    #[test]
    fn profile_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for profile in catalog() {
            assert!(
                seen.insert(profile.id.clone()),
                "duplicate id {}",
                profile.id
            );
        }
    }

    #[test]
    fn google_read_and_write_ask_for_different_scopes() {
        let gsc = get("google-search-console").unwrap();
        let read = gsc.find_access("read").unwrap();
        let write = gsc.find_access("write").unwrap();
        assert!(read.scopes[0].ends_with("webmasters.readonly"));
        assert!(write.scopes[0].ends_with("/webmasters"));
    }

    #[test]
    fn expand_substitutes_vars_and_the_secret() {
        let vars = BTreeMap::from([("host".to_string(), "graylog.example.com".to_string())]);
        assert_eq!(
            expand("https://{host}/api", &vars, "op://x/y/z").unwrap(),
            "https://graylog.example.com/api"
        );
        assert_eq!(expand("{secret}", &vars, "env:TOKEN").unwrap(), "env:TOKEN");
        assert!(expand("{nope}", &vars, "").is_err());
        assert!(expand("{unterminated", &vars, "").is_err());
    }

    #[test]
    fn graylog_puts_the_token_in_the_user_field() {
        let profile = get("graylog").unwrap();
        let vars = BTreeMap::from([("host".to_string(), "g.example.com".to_string())]);
        let service = substitute_service(&profile.service, &vars, "op://P/Graylog/token").unwrap();
        let auth = build_auth(&service, "op://P/Graylog/token", &vars, &[]).unwrap();
        match auth {
            AuthSpec::Basic {
                username,
                username_secret,
                secret,
            } => {
                assert!(username.is_none());
                assert_eq!(username_secret.as_deref(), Some("op://P/Graylog/token"));
                assert_eq!(secret, "literal:token");
            }
            other => panic!("expected basic, got {other:?}"),
        }
    }

    #[test]
    fn semrush_keeps_the_two_key_versions_on_two_schemes() {
        // The keys are version-specific and Semrush does not accept one for the
        // other, so the profiles differ in the credential scheme itself — not
        // merely in which paths they allow.
        let v3 = get("semrush").unwrap();
        let vars = BTreeMap::new();
        match build_auth(&v3.service, "env:SEMRUSH_V3", &vars, &[]).unwrap() {
            AuthSpec::Query { param, secret } => {
                assert_eq!(param, "key");
                assert_eq!(secret, "env:SEMRUSH_V3");
            }
            other => panic!("expected query auth, got {other:?}"),
        }

        let v4 = get("semrush-v4").unwrap();
        match build_auth(&v4.service, "env:SEMRUSH_V4", &vars, &[]).unwrap() {
            AuthSpec::Header {
                header,
                secret,
                prefix,
            } => {
                assert_eq!(header, "authorization");
                assert_eq!(secret, "env:SEMRUSH_V4");
                // The trailing space is load-bearing: the prefix is
                // concatenated verbatim, and `ApikeyKEY` is not a credential.
                assert_eq!(prefix.as_deref(), Some("Apikey "));
            }
            other => panic!("expected header auth, got {other:?}"),
        }
    }

    #[test]
    fn the_semrush_reports_are_reachable_at_the_root_path() {
        // Every v3 report is `/` with a `type=` parameter, so a read level that
        // only lists sub-paths would be a profile that can read nothing.
        let read = get("semrush").unwrap().default_access().clone();
        assert!(
            read.rules
                .iter()
                .any(|rule| rule.paths.iter().any(|path| path == "/")),
            "the v3 read level does not allow the root path"
        );
    }

    /// A probe is a request fired at somebody's account on a keystroke, so the
    /// table has rules. Two of them a machine can check: it is a path under the
    /// profile's own base URL, and it is a GET the profile's *narrowest* access
    /// level already allows — so the operator is verifying a call the agent
    /// they are enrolling could also make. The third, that it is free and has
    /// no side effect, is a judgement recorded beside each entry.
    #[test]
    fn every_declared_probe_is_a_get_the_narrowest_access_level_allows() {
        for profile in catalog() {
            let Some(probe) = &profile.probe else {
                continue;
            };
            assert!(
                probe.starts_with('/'),
                "`{}`: a probe is relative to the base URL — `{probe}`",
                profile.id
            );
            assert!(
                matches!(profile.service, Service::Http { .. }),
                "`{}`: only an HTTP upstream has a path to probe",
                profile.id
            );

            // `{var}` stands in for a value the operator supplies, and a glob
            // has to see something concrete to match a path segment.
            let path = probe.split('?').next().unwrap_or(probe);
            let concrete = regex_free_expand(path);
            let allowed = profile.default_access().rules.iter().any(|rule| {
                rule.action == "allow"
                    && rule.methods.iter().any(|m| m == "GET" || m == "*")
                    && rule.paths.iter().any(|pattern| {
                        globset::Glob::new(pattern)
                            .map(|glob| glob.compile_matcher().is_match(&concrete))
                            .unwrap_or(false)
                    })
            });
            assert!(
                allowed,
                "`{}`: probe `{concrete}` is not a GET the `{}` level allows, so an agent \
                 could not make the call the operator just verified",
                profile.id,
                profile.default_access().name
            );
        }
    }

    /// `{account_id}` → a value, so the path can be matched against a glob.
    fn regex_free_expand(path: &str) -> String {
        let mut out = String::new();
        let mut rest = path;
        while let Some(open) = rest.find('{') {
            let close = rest[open..].find('}').map(|at| open + at).unwrap_or(open);
            out.push_str(&rest[..open]);
            out.push_str("VALUE");
            rest = &rest[close + 1..];
        }
        out.push_str(rest);
        out
    }

    /// The fallback, and the two cases it has to decline.
    #[test]
    fn a_probe_is_found_by_base_url_but_never_an_unexpanded_one() {
        assert_eq!(
            probe_for("https://api.github.com").as_deref(),
            Some("/user")
        );
        // A trailing slash is the same service.
        assert_eq!(
            probe_for("https://api.github.com/").as_deref(),
            Some("/user")
        );
        // Cloudflare's probe names an account the catalogue does not know, so
        // the fallback cannot supply it — only the enrolment, which expanded it.
        assert!(get("cloudflare").unwrap().probe.unwrap().contains('{'));
        assert_eq!(probe_for("https://api.cloudflare.com/client/v4"), None);
        // A known service with no free read-only route stays unprobed.
        assert_eq!(probe_for("https://api.semrush.com/apis/v4"), None);
        assert_eq!(probe_for("https://api.example.com"), None);
        // The regional profiles: the upstream holds the expanded URL, and the
        // catalogue holds the template it came from.
        assert_eq!(
            probe_for("https://us.posthog.com").as_deref(),
            Some("/api/users/@me/")
        );
        assert_eq!(
            probe_for("https://eu.posthog.com/").as_deref(),
            Some("/api/users/@me/")
        );
        assert_eq!(
            probe_for("https://us.sentry.io/api/0").as_deref(),
            Some("/organizations/")
        );
        // A var fills one component and never reaches across a `/`, so
        // `https://{region}.posthog.com` does not claim somebody else's path.
        assert_eq!(probe_for("https://us.posthog.com/api"), None);
        assert_eq!(probe_for("https://posthog.com"), None);
    }

    /// The matching a templated base URL needs, and the ways it says no.
    #[test]
    fn a_var_in_a_base_url_matches_one_component_of_the_enrolled_one() {
        assert!(is_the_same_service(
            "https://{region}.posthog.com",
            "https://us.posthog.com"
        ));
        assert!(is_the_same_service(
            "{scheme}://{host}/api/0",
            "https://sentry.example.com/api/0"
        ));
        assert!(is_the_same_service(
            "https://{host}/api",
            "https://g.lan/api"
        ));
        // A var is never empty: the template names a component, and an
        // upstream that has not got one is not this service.
        assert!(!is_the_same_service(
            "https://{region}.posthog.com",
            "https://.posthog.com"
        ));
        assert!(!is_the_same_service("https://{host}/api", "https:///api"));
        // ...and never spans a `/`.
        assert!(!is_the_same_service(
            "https://{region}.posthog.com",
            "https://evil.example.com/us.posthog.com"
        ));
        assert!(!is_the_same_service(
            "https://{host}/api",
            "https://g.lan/nested/api"
        ));
        // A literal template is still an equality test.
        assert!(is_the_same_service(
            "https://api.github.com",
            "https://api.github.com"
        ));
        assert!(!is_the_same_service(
            "https://api.github.com",
            "https://api.github.com/v3"
        ));
    }

    /// The reason there is a Sentry MCP profile at all rather than another
    /// `mcp-remote` child: the hosted server takes a token in the ordinary
    /// authorization header, so the proxy can hold the credential.
    #[test]
    fn sentry_mcp_holds_the_token_instead_of_delegating_the_oauth_flow() {
        let profile = get("sentry-mcp").unwrap();
        let auth = build_auth(
            &profile.service,
            "op://Private/Sentry/token",
            &BTreeMap::new(),
            &[],
        )
        .unwrap();
        match auth {
            AuthSpec::Header {
                header,
                secret,
                prefix,
            } => {
                assert_eq!(header, "authorization");
                assert_eq!(secret, "op://Private/Sentry/token");
                // `Sentry-Bearer`, not `Bearer` — the plain one is the OAuth
                // access token's scheme and this is not that.
                assert_eq!(prefix.as_deref(), Some("Sentry-Bearer "));
            }
            other => panic!("sentry-mcp should front the hosted server directly: {other:?}"),
        }
    }

    /// Self-hosted has no hosted endpoint, so the credential goes to a child
    /// process — still as the reference the operator gave, never as a value.
    #[test]
    fn the_self_hosted_mcp_passes_a_reference_to_the_child_and_points_it_at_the_host() {
        let profile = get("sentry-mcp-self-hosted").unwrap();
        let vars = BTreeMap::from([("host".to_string(), "sentry.example.com".to_string())]);
        let service = substitute_service(&profile.service, &vars, "env:SENTRY_TOKEN").unwrap();
        let Service::McpStdio { args, env, .. } = service else {
            panic!("self-hosted Sentry has no hosted MCP endpoint to front");
        };
        assert!(args.contains(&"--host=sentry.example.com".to_string()));
        // Seer is not part of a self-hosted install, and a skill whose every
        // tool fails is worse than one that was never offered.
        assert!(args.contains(&"--disable-skills=seer".to_string()));
        assert_eq!(
            env,
            vec![(
                "SENTRY_ACCESS_TOKEN".to_string(),
                "env:SENTRY_TOKEN".to_string()
            )]
        );
    }

    /// Seer is the one tool on the MCP server that spends, so it sits with the
    /// writes rather than with the reads whose shape it otherwise shares.
    #[test]
    fn the_sentry_mcp_read_level_holds_back_the_tool_that_bills() {
        let read = get("sentry-mcp").unwrap().default_access().clone();
        let matches = |tool: &str| {
            read.rules
                .iter()
                .find(|rule| {
                    rule.paths.iter().any(|pattern| {
                        globset::Glob::new(pattern)
                            .map(|glob| glob.compile_matcher().is_match(tool))
                            .unwrap_or(false)
                    })
                })
                .map(|rule| rule.action.as_str())
        };
        assert_eq!(matches("whoami"), Some("allow"));
        assert_eq!(matches("find_organizations"), Some("allow"));
        assert_eq!(matches("search_issues"), Some("allow"));
        assert_eq!(matches("get_issue_details"), Some("allow"));
        assert_eq!(matches("analyze_issue_with_seer"), Some("ask"));
        assert_eq!(matches("update_issue"), Some("ask"));
        // The generic escape hatch runs whatever it is handed, so it cannot be
        // read-shaped however it is spelled.
        assert_eq!(matches("execute_sentry_tool"), Some("ask"));
    }

    /// Four profiles, one vocabulary: `--access triage` has to mean the same
    /// thing whichever Sentry you are pointing at, or it means nothing.
    #[test]
    fn every_sentry_profile_offers_the_same_three_levels() {
        for id in [
            "sentry",
            "sentry-self-hosted",
            "sentry-mcp",
            "sentry-mcp-self-hosted",
        ] {
            let names: Vec<_> = get(id)
                .unwrap()
                .access
                .iter()
                .map(|level| level.name.clone())
                .collect();
            assert_eq!(names, ["read", "triage", "write"], "`{id}`");
        }
    }

    /// The issue endpoint has three spellings and a self-hosted install may
    /// only have the oldest of them.
    #[test]
    fn sentry_triage_covers_the_issue_paths_every_version_has() {
        let triage = get("sentry-self-hosted")
            .unwrap()
            .find_access("triage")
            .unwrap()
            .clone();
        let put = triage
            .rules
            .iter()
            .find(|rule| rule.methods == ["PUT"])
            .expect("`triage` is the level that writes to issues");
        for path in [
            // sentry.io and a current self-hosted install
            "/organizations/acme/issues/4242/",
            // the project-scoped one a 9.x install has instead
            "/projects/acme/web/issues/4242/",
            // and the one an issue's own URL resolves to
            "/issues/4242/",
        ] {
            assert!(
                put.paths.iter().any(|pattern| {
                    globset::Glob::new(pattern)
                        .map(|glob| glob.compile_matcher().is_match(path))
                        .unwrap_or(false)
                }),
                "`triage` does not reach `{path}`"
            );
        }
    }

    #[test]
    fn an_unknown_var_is_rejected_rather_than_ignored() {
        let profile = get("posthog").unwrap();
        let err = resolve_vars(&profile, &["regoin=eu".to_string()]).unwrap_err();
        assert!(err.to_string().contains("no variable `regoin`"));
    }

    #[test]
    fn a_var_without_a_default_must_be_supplied() {
        let profile = get("graylog").unwrap();
        assert!(resolve_vars(&profile, &[]).is_err());
        assert!(resolve_vars(&profile, &["host=g.example.com".to_string()]).is_ok());
    }
}
