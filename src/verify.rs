//! The verify step: does this upstream or MCP server actually work?
//!
//! `check` answers a question about the file — does it parse, do the references
//! resolve, do the rules make sense. That is not the question an operator has
//! just after adding an upstream. Theirs is "did I get the base URL right, is
//! that token the one this API wants, and will an agent be let through" — and
//! the first two of those are answered by the service at the other end, not by
//! the file.
//!
//! So this makes the call. One request for an HTTP upstream, one `initialize`
//! handshake for an MCP server, with the real credential attached exactly the
//! way the proxy would attach it — the same `CredentialInjector` against the
//! same `build_url`, which for an OAuth or service-account scheme means the
//! token is really minted rather than assumed mintable. What comes back is
//! reported step by step, because "it failed" and "it failed at the credential"
//! are different afternoons.
//!
//! Two things it deliberately is not. It is not an agent: the call is made by
//! the operator's own process, under no agent identity, so it is not recorded
//! as traffic an agent caused — though where a log is open a token *mint* is
//! still written, because a credential that came into existence is an event
//! whoever asked for it. And it is not a gate: nothing here writes the policy
//! file and nothing here undoes a write. `upstream add --verify` adds the
//! upstream and then says what it found, because the fix for a mistyped base
//! URL is `upstream edit`, not doing the whole enrolment again.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::audit::AuditLog;
use crate::config::{
    AclRuleConfig, Action, AuthConfig, Config, McpServerConfig, McpTransportKind, UpstreamConfig,
};
use crate::credentials::CredentialInjector;
use crate::secrets::{display_ref, SecretResolver};

/// How long any one call gets. Long enough for a cold start at the other end,
/// short enough that verifying a whole policy file is still something you wait
/// for rather than walk away from.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// What gets probed when nobody named a path: the root, which is the one path
/// every base URL has.
const ROOT: &str = "/";

/// How many tool names a report prints before it starts counting.
const TOOLS_NAMED: usize = 8;

/// How much of a child's stderr is worth quoting back.
const STDERR_KEPT: usize = 400;

/// How much of a response body an error quotes.
const CLIP: usize = 160;

/// Step names, so the reader of a report and the code agree on them.
const ENDPOINT: &str = "endpoint";
const CREDENTIAL: &str = "credential";
const REACH: &str = "reach";
const HANDSHAKE: &str = "handshake";
const TOOLS: &str = "tools";
const POLICY: &str = "policy";

/// How a step turned out.
///
/// Ordered worst-last, so a report's verdict is the maximum of its steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    Passed,
    /// It answered, but not with what a working service answers. A 404 on the
    /// base URL says the host is real and says nothing about the credential; an
    /// upstream no rule reaches is enrolled and unreachable. Neither of those
    /// is a failure and neither of them is fine.
    Warned,
    Failed,
}

impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Outcome::Passed => "ok",
            Outcome::Warned => "warn",
            Outcome::Failed => "FAILED",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Step {
    pub name: &'static str,
    pub outcome: Outcome,
    pub detail: String,
}

/// What one verification found, in the order it found it.
#[derive(Debug, Clone)]
pub struct Report {
    pub target: String,
    /// `upstream` or `mcp server`, for a line that has to say which.
    pub kind: &'static str,
    pub endpoint: String,
    pub steps: Vec<Step>,
}

impl Report {
    fn new(target: &str, kind: &'static str, endpoint: &str) -> Self {
        Report {
            target: target.to_string(),
            kind,
            endpoint: endpoint.to_string(),
            steps: Vec::new(),
        }
    }

    fn step(&mut self, name: &'static str, outcome: Outcome, detail: impl Into<String>) {
        self.steps.push(Step {
            name,
            outcome,
            detail: detail.into(),
        });
    }

    fn passed(&mut self, name: &'static str, detail: impl Into<String>) {
        self.step(name, Outcome::Passed, detail);
    }

    fn warned(&mut self, name: &'static str, detail: impl Into<String>) {
        self.step(name, Outcome::Warned, detail);
    }

    fn failed(&mut self, name: &'static str, detail: impl Into<String>) {
        self.step(name, Outcome::Failed, detail);
    }

    fn find(&self, name: &str) -> Option<&Step> {
        self.steps.iter().find(|step| step.name == name)
    }

    /// The worst thing that happened.
    pub fn verdict(&self) -> Outcome {
        self.steps
            .iter()
            .map(|step| step.outcome)
            .max()
            .unwrap_or(Outcome::Passed)
    }

    /// Nothing failed. Warnings are still worth reading, which is why they do
    /// not make this false.
    pub fn ok(&self) -> bool {
        self.verdict() != Outcome::Failed
    }

    /// One line, for a footer or a table cell: the first thing that went wrong,
    /// or — when nothing did — what the service actually said.
    pub fn headline(&self) -> String {
        let worst = self.verdict();
        if worst != Outcome::Passed {
            if let Some(step) = self.steps.iter().find(|step| step.outcome == worst) {
                return format!("{}: {}", step.name, step.detail);
            }
        }
        match self.find(REACH).or_else(|| self.find(HANDSHAKE)) {
            Some(step) => step.detail.clone(),
            None => "ok".to_string(),
        }
    }
}

pub struct Options {
    pub timeout: Duration,
    /// Path to probe on an HTTP upstream, relative to its base URL, query
    /// string and all. The root when omitted — which for most APIs is a 404,
    /// so an upstream whose credential you want actually exercised wants a real
    /// endpoint here.
    pub path: Option<String>,
    /// The daemon's audit log, when this is running inside one. Only the
    /// credential injector writes to it, and only for a token it minted.
    pub audit: Option<Arc<AuditLog>>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            timeout: DEFAULT_TIMEOUT,
            path: None,
            audit: None,
        }
    }
}

/// Verify one upstream by name.
pub async fn upstream(
    config: &Config,
    resolver: &Arc<SecretResolver>,
    name: &str,
    options: &Options,
) -> Result<Report> {
    let upstream = config
        .upstream(name)
        .with_context(|| format!("`{name}` is not a configured upstream"))?;
    Ok(probe_upstream(config, upstream, resolver, options).await)
}

/// Verify one MCP server by name.
pub async fn mcp_server(
    config: &Config,
    resolver: &Arc<SecretResolver>,
    name: &str,
    options: &Options,
) -> Result<Report> {
    let server = config
        .mcp_server(name)
        .with_context(|| format!("`{name}` is not a configured MCP server"))?;
    Ok(probe_mcp(config, server, resolver, options).await)
}

/// Verify whatever that name is — an upstream, or an MCP server.
///
/// The console has a name and the pane it came from; a caller holding only the
/// name should not have to guess which list to look in.
pub async fn target(
    config: &Config,
    resolver: &Arc<SecretResolver>,
    name: &str,
    options: &Options,
) -> Result<Report> {
    if config.upstream(name).is_some() {
        return upstream(config, resolver, name, options).await;
    }
    mcp_server(config, resolver, name, options)
        .await
        .with_context(|| format!("`{name}` is neither an upstream nor an MCP server"))
}

// ---- http upstreams -------------------------------------------------------

async fn probe_upstream(
    config: &Config,
    upstream: &UpstreamConfig,
    resolver: &Arc<SecretResolver>,
    options: &Options,
) -> Report {
    let mut report = Report::new(&upstream.name, "upstream", &upstream.base_url);

    let (path, query) = split_query(options.path.as_deref().unwrap_or(ROOT));
    let url = match crate::proxy::build_url(&upstream.base_url, &path, query.as_deref()) {
        Ok(url) => url,
        Err(error) => {
            report.failed(ENDPOINT, format!("{error:#}"));
            http_policy(config, &upstream.name, &mut report);
            return report;
        }
    };

    let http = match client(options) {
        Ok(http) => http,
        Err(error) => {
            report.failed(ENDPOINT, format!("{error:#}"));
            http_policy(config, &upstream.name, &mut report);
            return report;
        }
    };

    let mut request = reqwest::Request::new(http::Method::GET, url.clone());
    let mut unusable = Vec::new();
    for (name, value) in &upstream.headers {
        match (
            name.parse::<http::HeaderName>(),
            value.parse::<http::HeaderValue>(),
        ) {
            (Ok(name), Ok(value)) => {
                request.headers_mut().insert(name, value);
            }
            _ => unusable.push(name.clone()),
        }
    }
    if unusable.is_empty() {
        report.passed(ENDPOINT, format!("GET {url}"));
    } else {
        // The proxy drops these silently on every call, so an upstream that
        // needs one is broken in a way nothing else in the tooling says aloud.
        report.warned(
            ENDPOINT,
            format!(
                "GET {url} — but the static header(s) {} are not valid headers and are dropped",
                unusable.join(", ")
            ),
        );
    }

    // The same injector the proxy uses, so an OAuth or service-account scheme
    // is verified by minting the token rather than by reading the fields that
    // would be used to mint one.
    let injector = CredentialInjector::new(
        Arc::clone(resolver),
        http.clone(),
        options.audit.as_ref().map(Arc::clone),
    );
    match injector
        .apply(&upstream.name, &upstream.auth, &mut request)
        .await
    {
        Ok(()) => report.passed(CREDENTIAL, describe_auth(&upstream.auth)),
        Err(error) => {
            report.failed(CREDENTIAL, format!("{error:#}"));
            http_policy(config, &upstream.name, &mut report);
            return report;
        }
    }

    let started = Instant::now();
    match http.execute(request).await {
        Ok(response) => {
            let (outcome, detail) = classify(&response, started.elapsed(), options.path.is_some());
            report.step(REACH, outcome, detail);
        }
        Err(error) => report.failed(REACH, describe(&error)),
    }

    http_policy(config, &upstream.name, &mut report);
    report
}

/// What the status code says about the two things being verified: that the host
/// is the one that was meant, and that the credential is one it accepts.
fn classify(
    response: &reqwest::Response,
    elapsed: Duration,
    path_was_given: bool,
) -> (Outcome, String) {
    let status = response.status();
    let took = format!("in {}ms", elapsed.as_millis());

    if status.is_success() {
        return (Outcome::Passed, format!("answered {status} {took}"));
    }
    if status.is_redirection() {
        let to = response
            .headers()
            .get(http::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("somewhere it did not name");
        // Not followed, on purpose: a 302 to a login page reads as a 200 to a
        // client that follows it, and "the credential works" is the one
        // conclusion that must never be drawn from a redirect.
        return (
            Outcome::Warned,
            format!("answered {status} → {to} — the base URL may be the wrong one"),
        );
    }
    match status.as_u16() {
        401 => (
            Outcome::Failed,
            format!("the service rejected the credential — {status} {took}"),
        ),
        // Authenticated and not entitled. The credential got in; what it may do
        // is a scope question, and on a probe of the root it is usually not
        // even a real one.
        403 => (
            Outcome::Warned,
            format!(
                "answered {status} {took} — the credential was accepted but is not allowed here"
            ),
        ),
        404 | 405 if !path_was_given => (
            Outcome::Warned,
            format!(
                "the host answered {status} {took} — reachable, but its root says nothing \
                 about the credential. Pass --path with a real endpoint to exercise it."
            ),
        ),
        429 => (
            Outcome::Warned,
            format!("the service is rate-limiting this credential — {status} {took}"),
        ),
        _ => (
            Outcome::Warned,
            format!("the service answered {status} {took}"),
        ),
    }
}

// ---- mcp servers ----------------------------------------------------------

async fn probe_mcp(
    config: &Config,
    server: &McpServerConfig,
    resolver: &Arc<SecretResolver>,
    options: &Options,
) -> Report {
    let mut report = Report::new(&server.name, "mcp server", &endpoint_of(server));

    match server.transport {
        McpTransportKind::Http => probe_mcp_http(server, resolver, options, &mut report).await,
        McpTransportKind::Stdio => probe_mcp_stdio(server, resolver, options, &mut report).await,
    }

    mcp_policy(config, server, &mut report);
    report
}

/// One JSON-RPC exchange with a remote MCP server, credential attached.
async fn post(
    http: &reqwest::Client,
    injector: &CredentialInjector,
    server: &McpServerConfig,
    url: &url::Url,
    session: Option<&str>,
    message: &Value,
) -> Result<(http::StatusCode, Option<String>, String), Refused> {
    let mut request = reqwest::Request::new(http::Method::POST, url.clone());
    request.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    request.headers_mut().insert(
        http::header::ACCEPT,
        http::HeaderValue::from_static("application/json, text/event-stream"),
    );
    if let Some(session) = session {
        if let Ok(value) = session.parse() {
            request.headers_mut().insert("mcp-session-id", value);
        }
    }
    *request.body_mut() = Some(reqwest::Body::from(
        serde_json::to_vec(message).unwrap_or_default(),
    ));

    injector
        .apply(&server.name, &server.auth, &mut request)
        .await
        .map_err(|error| Refused {
            at: CREDENTIAL,
            why: format!("{error:#}"),
        })?;

    let response = http.execute(request).await.map_err(|error| Refused {
        at: HANDSHAKE,
        why: describe(&error),
    })?;
    let status = response.status();
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = response.text().await.unwrap_or_default();
    Ok((status, session, body))
}

async fn probe_mcp_http(
    server: &McpServerConfig,
    resolver: &Arc<SecretResolver>,
    options: &Options,
    report: &mut Report,
) {
    let url = match server.url.as_deref().map(str::parse::<url::Url>) {
        Some(Ok(url)) => url,
        Some(Err(error)) => {
            report.failed(
                ENDPOINT,
                format!("`{}` is not a URL: {error}", endpoint_of(server)),
            );
            return;
        }
        None => {
            report.failed(ENDPOINT, "http transport with no url");
            return;
        }
    };
    report.passed(ENDPOINT, format!("POST {url}"));

    let http = match client(options) {
        Ok(http) => http,
        Err(error) => {
            report.failed(ENDPOINT, format!("{error:#}"));
            return;
        }
    };
    let injector = CredentialInjector::new(
        Arc::clone(resolver),
        http.clone(),
        options.audit.as_ref().map(Arc::clone),
    );

    let started = Instant::now();
    let (status, session, body) =
        match post(&http, &injector, server, &url, None, &initialize_request()).await {
            Ok(answer) => {
                report.passed(CREDENTIAL, describe_auth(&server.auth));
                answer
            }
            Err(refused) => {
                report.failed(refused.at, refused.why);
                return;
            }
        };

    match rpc_result(&body, 1) {
        Some(Ok(result)) => report.passed(
            HANDSHAKE,
            format!(
                "{} in {}ms",
                describe_server(&result),
                started.elapsed().as_millis()
            ),
        ),
        other => {
            report.failed(
                HANDSHAKE,
                match (status.as_u16(), other) {
                    (401 | 403, _) => format!("the server rejected the credential — {status}"),
                    (_, Some(Err(error))) => format!("the server refused `initialize`: {error}"),
                    _ => format!(
                        "the server answered {status} to `initialize` with {}",
                        clip(&body)
                    ),
                },
            );
            return;
        }
    }

    // `initialized` is a notification: the server owes it no answer, and by the
    // spec the session is not open until it has been sent.
    let _ = post(
        &http,
        &injector,
        server,
        &url,
        session.as_deref(),
        &initialized_notification(),
    )
    .await;

    match post(
        &http,
        &injector,
        server,
        &url,
        session.as_deref(),
        &tools_request(),
    )
    .await
    {
        Ok((_, _, body)) => match rpc_result(&body, 2) {
            Some(Ok(result)) => report.passed(TOOLS, describe_tools(&result)),
            Some(Err(error)) => report.warned(
                TOOLS,
                format!("the handshake worked, but `tools/list` returned an error: {error}"),
            ),
            None => report.warned(
                TOOLS,
                format!(
                    "the handshake worked, but `tools/list` returned {}",
                    clip(&body)
                ),
            ),
        },
        Err(refused) => report.warned(TOOLS, refused.why),
    }
}

async fn probe_mcp_stdio(
    server: &McpServerConfig,
    resolver: &Arc<SecretResolver>,
    options: &Options,
    report: &mut Report,
) {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let Some(command_name) = server.command.clone() else {
        report.failed(ENDPOINT, "stdio transport with no command");
        return;
    };
    report.passed(ENDPOINT, format!("spawn {}", endpoint_of(server)));

    // Nothing is minted for a stdio child — its credential is an environment
    // entry — so resolving the references *is* the credential step.
    let injector = CredentialInjector::new(Arc::clone(resolver), crate::http_client(), None);
    let env = match injector.resolve_env(&server.env) {
        Ok(env) => {
            report.passed(CREDENTIAL, describe_env(server));
            env
        }
        Err(error) => {
            report.failed(CREDENTIAL, format!("{error:#}"));
            return;
        }
    };

    let mut command = tokio::process::Command::new(&command_name);
    command
        .args(&server.args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    if let Some(cwd) = &server.cwd {
        command.current_dir(cwd);
    }
    for (key, secret) in &env {
        command.env(key, secret.expose());
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            report.failed(
                HANDSHAKE,
                format!("could not spawn `{command_name}`: {error}"),
            );
            return;
        }
    };
    let mut stdin = child.stdin.take().expect("stdin was piped");
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");

    // A server that will not start says why on stderr and then says nothing
    // else — so the complaint is collected while the handshake waits, and
    // quoted back only if the handshake is what goes wrong.
    let complaint = Arc::new(parking_lot::Mutex::new(String::new()));
    let collecting = Arc::clone(&complaint);
    let draining = tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let mut held = collecting.lock();
            if held.len() >= STDERR_KEPT {
                break;
            }
            held.push_str(line.trim());
            held.push(' ');
        }
    });

    let started = Instant::now();
    let mut lines = BufReader::new(stdout).lines();

    let opening = [initialize_request()];
    let handshake = exchange(&mut stdin, &mut lines, &opening, 1);
    let answered = tokio::time::timeout(options.timeout, handshake).await;

    let said = || {
        let held = complaint.lock().trim().to_string();
        match held.is_empty() {
            true => String::new(),
            false => format!(" — it said: {}", clip(&held)),
        }
    };

    match answered {
        Ok(Ok(Some(Ok(result)))) => {
            report.passed(
                HANDSHAKE,
                format!(
                    "{} in {}ms",
                    describe_server(&result),
                    started.elapsed().as_millis()
                ),
            );
            let asking = [initialized_notification(), tools_request()];
            let tools = exchange(&mut stdin, &mut lines, &asking, 2);
            match tokio::time::timeout(options.timeout, tools).await {
                Ok(Ok(Some(Ok(result)))) => report.passed(TOOLS, describe_tools(&result)),
                Ok(Ok(Some(Err(error)))) => report.warned(
                    TOOLS,
                    format!("the handshake worked, but `tools/list` returned an error: {error}"),
                ),
                _ => report.warned(
                    TOOLS,
                    "the handshake worked, but the server did not answer `tools/list`",
                ),
            }
        }
        Ok(Ok(Some(Err(error)))) => report.failed(
            HANDSHAKE,
            format!("`{command_name}` refused `initialize`: {error}"),
        ),
        Ok(Ok(None)) => report.failed(
            HANDSHAKE,
            format!(
                "`{command_name}` exited without answering `initialize`{}",
                said()
            ),
        ),
        Ok(Err(error)) => report.failed(
            HANDSHAKE,
            format!("talking to `{command_name}`: {error:#}{}", said()),
        ),
        Err(_) => report.failed(
            HANDSHAKE,
            format!(
                "`{command_name}` did not answer `initialize` within {}s{}",
                options.timeout.as_secs(),
                said()
            ),
        ),
    }

    // The child holds a real credential in its environment; it does not outlive
    // the question it was spawned to answer.
    drop(stdin);
    let _ = child.kill().await;
    draining.abort();
}

/// Write some frames to a child and read back the answer carrying `id`.
///
/// Servers put banners and log lines on stdout alongside the protocol, so the
/// answer is the frame with our id and everything ahead of it is noise.
async fn exchange(
    stdin: &mut tokio::process::ChildStdin,
    lines: &mut tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
    messages: &[Value],
    id: i64,
) -> Result<Option<Result<Value, String>>> {
    use tokio::io::AsyncWriteExt;

    for message in messages {
        let line = format!("{}\n", serde_json::to_string(message)?);
        stdin.write_all(line.as_bytes()).await?;
    }
    stdin.flush().await?;

    while let Some(line) = lines.next_line().await? {
        if let Some(result) = rpc_result(&line, id) {
            return Ok(Some(result));
        }
    }
    Ok(None)
}

/// A step that could not be taken, and the step it belonged to.
struct Refused {
    at: &'static str,
    why: String,
}

// ---- the policy half ------------------------------------------------------

/// Is there a rule that would let an agent through to this upstream?
///
/// An upstream nothing reaches is the failure mode of a successful enrolment:
/// the credential resolves, the host answers, and every agent call is denied by
/// `<default>` with no rule to point at.
fn http_policy(config: &Config, name: &str, report: &mut Report) {
    let (outcome, detail) = reachability(
        config,
        name,
        "http",
        &format!("agent-iap acl add --kind http --target {name} --methods GET --paths '/**'"),
    );
    report.step(POLICY, outcome, detail);
}

fn mcp_policy(config: &Config, server: &McpServerConfig, report: &mut Report) {
    // The narrower complaint first: rules that exist but leave `initialize` out
    // are the case that looks configured and is not. Worded for one line rather
    // than reusing `check`'s paragraph, which is laid out to be read as a block.
    if mcp_handshake_warning(config, server).is_some() {
        report.warned(
            POLICY,
            format!(
                "rules reach it, but none admits `initialize` — the handshake will be denied \
                 by `<default>` and the agent will see a server that never starts. Add a \
                 session rule in front of the tool rules: agent-iap acl add --kind mcp \
                 --target {} --paths '**' {}",
                server.name,
                session_methods()
            ),
        );
        return;
    }
    let fix = format!(
        "agent-iap acl add --kind mcp --target {} --paths '**' {}",
        server.name,
        session_methods()
    );
    let (outcome, detail) = reachability(config, &server.name, "mcp", &fix);
    report.step(POLICY, outcome, detail);
}

fn reachability(config: &Config, name: &str, kind: &str, fix: &str) -> (Outcome, String) {
    let now = chrono::Utc::now();
    let reaching: Vec<(usize, &AclRuleConfig)> = config
        .acl
        .iter()
        .enumerate()
        .filter(|(_, rule)| {
            (rule.kind == kind || rule.kind == "*")
                && glob_matches(&rule.target, name)
                && !rule.expired_at(now)
        })
        .collect();

    let admitting: Vec<String> = reaching
        .iter()
        .filter(|(_, rule)| rule.action != Action::Deny)
        .map(|(index, rule)| rule.name.clone().unwrap_or_else(|| format!("acl[{index}]")))
        .collect();

    if !admitting.is_empty() {
        return (
            Outcome::Passed,
            format!(
                "reached by {}: {}",
                plural(admitting.len()),
                admitting.join(", ")
            ),
        );
    }
    if config.acl_default.action != Action::Deny {
        return (
            Outcome::Passed,
            format!(
                "no rule names it, but the ACL default is `{}`",
                config.acl_default.action
            ),
        );
    }
    let had = match reaching.is_empty() {
        true => "no ACL rule reaches it",
        false => "every ACL rule that reaches it denies",
    };
    (
        Outcome::Warned,
        format!("{had} — agent calls will be denied by `<default>`. Add one: {fix}"),
    )
}

fn plural(count: usize) -> String {
    match count {
        1 => "1 rule".to_string(),
        many => format!("{many} rules"),
    }
}

/// MCP servers whose rules would deny the handshake.
///
/// `initialize` names no tool, so it matches only a rule that leaves `paths`
/// unconstrained. A policy whose every MCP rule scopes tool names therefore
/// looks complete, validates, starts — and then the agent's session never
/// opens, with a `<default>` deny that names no rule to go and fix. This is the
/// one misconfiguration in the file that produces no useful error at the point
/// it bites, so `check` and `mcp-server verify` both say it here instead.
pub fn mcp_handshake_warnings(config: &Config) -> Vec<String> {
    config
        .mcp_servers
        .iter()
        .filter_map(|server| mcp_handshake_warning(config, server))
        .collect()
}

fn mcp_handshake_warning(config: &Config, server: &McpServerConfig) -> Option<String> {
    let unconstrained = |paths: &[String]| {
        paths
            .iter()
            .any(|path| matches!(path.as_str(), "*" | "**" | "/**"))
    };

    // Only rules that could reach this server at all, and only ones that would
    // let `initialize` through: an unconstrained-path allow.
    let admits_handshake = config.acl.iter().any(|rule| {
        matches!(rule.kind.as_str(), "mcp" | "*")
            && glob_matches(&rule.target, &server.name)
            && rule.action == Action::Allow
            && unconstrained(&rule.paths)
            && rule
                .methods
                .iter()
                .any(|method| glob_matches(method, "initialize"))
    });
    if admits_handshake {
        return None;
    }
    let reachable = config.acl.iter().any(|rule| {
        matches!(rule.kind.as_str(), "mcp" | "*") && glob_matches(&rule.target, &server.name)
    });
    // A server with no rules at all is already obvious from `list`; the trap is
    // the one that looks configured.
    if !reachable || config.acl_default.action == Action::Allow {
        return None;
    }
    Some(format!(
        "mcp server `{name}` has rules, but none of them admits `initialize`.\n\
         The handshake will be denied by `<default>`, and the agent will see a\n\
         server that never starts. Add a session rule before the tool rules:\n\n\
         \x20 agent-iap acl add --kind mcp --target {name} --paths '**' \\\n\
         \x20   {fix}",
        name = server.name,
        fix = session_methods(),
    ))
}

fn session_methods() -> String {
    crate::profiles::MCP_SESSION_METHODS
        .iter()
        .map(|method| format!("--methods '{method}'"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The same `*`/`**` glob the ACL compiles, for names that contain no `/`.
pub fn glob_matches(pattern: &str, value: &str) -> bool {
    globset::Glob::new(pattern)
        .map(|glob| glob.compile_matcher().is_match(value))
        .unwrap_or(false)
}

// ---- shared plumbing ------------------------------------------------------

fn client(options: &Options) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(options.timeout)
        .redirect(reqwest::redirect::Policy::none())
        // The same name every other outbound call this process makes gives, so
        // an operator finding a probe in their access log can search for the
        // thing that made it.
        .user_agent(crate::USER_AGENT)
        .build()
        .context("building the client the verification calls with")
}

/// Split a probe path into the path and the query the proxy would send.
///
/// `build_url` insists the path survive normalisation unchanged, which a `?`
/// inside it would not — so the two halves are separated here the way a real
/// request arrives with them already separate.
fn split_query(raw: &str) -> (String, Option<String>) {
    let raw = raw.trim();
    let (path, query) = match raw.split_once('?') {
        Some((path, query)) => (path, Some(query.to_string())),
        None => (raw, None),
    };
    let path = match path {
        "" => ROOT.to_string(),
        path if path.starts_with('/') => path.to_string(),
        path => format!("/{path}"),
    };
    (path, query)
}

/// Name the credential that was attached, by reference and never by value.
fn describe_auth(auth: &AuthConfig) -> String {
    match auth {
        AuthConfig::None => "none — nothing is attached on the way out".to_string(),
        AuthConfig::Bearer { secret } => {
            format!("bearer token resolved from {}", display_ref(secret))
        }
        AuthConfig::Header { header, secret, .. } => {
            format!("`{header}` resolved from {}", display_ref(secret))
        }
        AuthConfig::Basic { secret, .. } => {
            format!("basic auth resolved from {}", display_ref(secret))
        }
        AuthConfig::Query { param, secret } => {
            format!("`?{param}` resolved from {}", display_ref(secret))
        }
        AuthConfig::Oauth2ClientCredentials { token_url, .. } => {
            format!("minted an access token at {token_url}")
        }
        AuthConfig::ServiceAccountJwt { .. } => {
            "signed an assertion and exchanged it for an access token".to_string()
        }
    }
}

fn describe_env(server: &McpServerConfig) -> String {
    if server.env.is_empty() {
        return "none — the child is given no credential".to_string();
    }
    format!(
        "resolved {}",
        server
            .env
            .iter()
            .map(|(name, reference)| format!("{name}={}", display_ref(reference)))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn endpoint_of(server: &McpServerConfig) -> String {
    match server.transport {
        McpTransportKind::Http => server.url.clone().unwrap_or_default(),
        McpTransportKind::Stdio => {
            let command = server.command.clone().unwrap_or_default();
            match server.args.is_empty() {
                true => command,
                false => format!("{command} {}", server.args.join(" ")),
            }
        }
    }
}

/// Describe a transport failure without printing the outbound URL.
///
/// `reqwest::Error`'s own `Display` embeds it, and with `query` auth that URL
/// carries the credential. The causes underneath it do not, so the actual
/// reason — a DNS miss, a refused connection, a certificate nobody signed — can
/// still be named.
fn describe(error: &reqwest::Error) -> String {
    let headline = crate::proxy::describe_upstream_error(error);
    let mut cause = None;
    let mut source = std::error::Error::source(error);
    while let Some(inner) = source {
        cause = Some(inner.to_string());
        source = inner.source();
    }
    match cause {
        Some(cause) => format!("{headline} — {cause}"),
        None => headline,
    }
}

fn initialize_request() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": crate::gateway::PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "agent-iap verify", "version": env!("CARGO_PKG_VERSION") },
        },
    })
}

fn initialized_notification() -> Value {
    json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
}

fn tools_request() -> Value {
    json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" })
}

/// The response carrying `id`, out of a body that may be one JSON frame, an SSE
/// stream, or a batch of either. `None` when no frame answers to that id.
fn rpc_result(body: &str, id: i64) -> Option<Result<Value, String>> {
    let mut frames: Vec<Value> = Vec::new();
    if let Ok(value) = serde_json::from_str::<Value>(body.trim()) {
        frames.push(value);
    }
    frames.extend(crate::mcp::parse_sse(body));

    frames
        .into_iter()
        .flat_map(|frame| match frame {
            Value::Array(batch) => batch,
            other => vec![other],
        })
        .find(|frame| frame.get("id").and_then(Value::as_i64) == Some(id))
        .map(|frame| match frame.get("error") {
            Some(error) => Err(error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("no message")
                .to_string()),
            None => Ok(frame.get("result").cloned().unwrap_or(Value::Null)),
        })
}

fn describe_server(result: &Value) -> String {
    let info = result.get("serverInfo");
    let name = info
        .and_then(|info| info.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("an unnamed server");
    let version = info
        .and_then(|info| info.get("version"))
        .and_then(Value::as_str)
        .map(|version| format!(" {version}"))
        .unwrap_or_default();
    let protocol = result
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or("an unstated revision");
    format!("{name}{version}, speaking MCP {protocol}")
}

fn describe_tools(result: &Value) -> String {
    let tools: Vec<&str> = result
        .get("tools")
        .and_then(Value::as_array)
        .map(|tools| {
            tools
                .iter()
                .filter_map(|tool| tool.get("name").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    match tools.len() {
        0 => "the server offers no tools".to_string(),
        count => {
            // Named rather than counted, up to a point: the ACL is written
            // against these names, and a `tools/call` rule for a tool spelled
            // differently is a rule that matches nothing.
            let shown: Vec<&str> = tools.iter().copied().take(TOOLS_NAMED).collect();
            let rest = count.saturating_sub(shown.len());
            let tail = match rest {
                0 => String::new(),
                rest => format!(" and {rest} more"),
            };
            format!("{count} tools: {}{tail}", shown.join(", "))
        }
    }
}

/// Break a line on word boundaries.
///
/// Deliberately not a dependency: a report is the only thing this tool wraps,
/// and both front ends have to wrap it the same way — the CLI to keep its
/// columns, the console because a modal sizes itself by counting lines and a
/// line it then wraps is a line drawn past the bottom of the box.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// A body quoted back in an error, kept to one line.
fn clip(body: &str) -> String {
    let body = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if body.is_empty() {
        return "an empty body".to_string();
    }
    match body.char_indices().nth(CLIP) {
        Some((at, _)) => format!("`{}…`", &body[..at]),
        None => format!("`{body}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16, headers: &[(&str, &str)]) -> reqwest::Response {
        let mut builder = http::Response::builder().status(status);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        reqwest::Response::from(builder.body("").unwrap())
    }

    fn verdict_of(status: u16, path_was_given: bool) -> Outcome {
        classify(
            &response(status, &[]),
            Duration::from_millis(1),
            path_was_given,
        )
        .0
    }

    /// The distinction the whole command rests on: a service that refused the
    /// credential is a failure, and a service that answered something other
    /// than yes is not. Getting this backwards makes `--verify` either useless
    /// (everything passes) or unusable (every 404 fails a deploy).
    #[test]
    fn a_rejected_credential_fails_and_an_unhelpful_answer_only_warns() {
        assert_eq!(verdict_of(200, false), Outcome::Passed);
        assert_eq!(verdict_of(204, false), Outcome::Passed);
        assert_eq!(verdict_of(401, false), Outcome::Failed);
        assert_eq!(verdict_of(403, false), Outcome::Warned);
        assert_eq!(verdict_of(404, false), Outcome::Warned);
        assert_eq!(verdict_of(429, false), Outcome::Warned);
        assert_eq!(verdict_of(503, false), Outcome::Warned);
    }

    #[test]
    fn a_redirect_is_reported_rather_than_followed() {
        let (outcome, detail) = classify(
            &response(302, &[("location", "https://login.example.com/")]),
            Duration::from_millis(1),
            false,
        );
        assert_eq!(outcome, Outcome::Warned);
        assert!(
            detail.contains("login.example.com"),
            "a redirect has to name where it went: {detail}"
        );
    }

    /// The suggestion only makes sense when nobody has taken it yet.
    #[test]
    fn a_404_stops_suggesting_a_path_once_one_was_given() {
        let asked = classify(&response(404, &[]), Duration::from_millis(1), true).1;
        let unasked = classify(&response(404, &[]), Duration::from_millis(1), false).1;
        assert!(!asked.contains("--path"), "{asked}");
        assert!(unasked.contains("--path"), "{unasked}");
    }

    #[test]
    fn a_probe_path_is_split_the_way_a_request_arrives() {
        assert_eq!(split_query("/user"), ("/user".into(), None));
        assert_eq!(split_query("user"), ("/user".into(), None));
        assert_eq!(split_query(""), ("/".into(), None));
        assert_eq!(
            split_query("/v1/models?limit=1&page=2"),
            ("/v1/models".into(), Some("limit=1&page=2".into()))
        );
    }

    #[test]
    fn a_response_is_found_in_plain_json_in_sse_and_in_a_batch() {
        let plain = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"x"}}"#;
        assert_eq!(
            rpc_result(plain, 1).unwrap().unwrap()["protocolVersion"],
            "x"
        );
        assert!(rpc_result(plain, 2).is_none(), "a different id is not ours");

        let sse = format!("event: message\ndata: {plain}\n\ndata: [DONE]\n");
        assert!(rpc_result(&sse, 1).unwrap().is_ok());

        let batch = format!("[{{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{{}}}},{plain}]");
        assert!(rpc_result(&batch, 1).unwrap().is_ok());
    }

    #[test]
    fn a_jsonrpc_error_is_the_servers_refusal_not_a_missing_answer() {
        let refused =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"no such method"}}"#;
        assert_eq!(rpc_result(refused, 1), Some(Err("no such method".into())));
    }

    fn config(text: &str) -> Config {
        toml::from_str(text).unwrap()
    }

    const UPSTREAM: &str = r#"
[[upstreams]]
name = "github"
base_url = "https://api.github.com"
"#;

    #[test]
    fn an_upstream_nothing_reaches_is_a_warning_and_one_with_a_rule_is_not() {
        let bare = config(UPSTREAM);
        let (outcome, detail) = reachability(&bare, "github", "http", "…");
        assert_eq!(outcome, Outcome::Warned);
        assert!(detail.contains("<default>"), "{detail}");

        let allowed = config(&format!(
            r#"{UPSTREAM}
[[acl]]
name = "github-reads"
kind = "http"
target = "gith*"
action = "allow"
"#
        ));
        let (outcome, detail) = reachability(&allowed, "github", "http", "…");
        assert_eq!(outcome, Outcome::Passed);
        assert!(detail.contains("github-reads"), "{detail}");
    }

    /// A rule that only says no is not a way in, and neither is one whose
    /// deadline has passed — both leave the call to `<default>`.
    #[test]
    fn a_deny_only_or_expired_rule_does_not_count_as_reaching_it() {
        for rule in [
            r#"action = "deny""#,
            r#"action = "allow"
expires = "2020-01-01T00:00:00Z""#,
        ] {
            let config = config(&format!(
                r#"{UPSTREAM}
[[acl]]
kind = "http"
target = "github"
{rule}
"#
            ));
            assert_eq!(
                reachability(&config, "github", "http", "…").0,
                Outcome::Warned,
                "`{rule}` is not a grant"
            );
        }
    }

    /// An `ask` rule reaches it: the call stops on a human rather than on
    /// `<default>`, which is the thing the warning is about.
    #[test]
    fn an_ask_rule_reaches_it() {
        let config = config(&format!(
            r#"{UPSTREAM}
[[acl]]
kind = "http"
target = "github"
action = "ask"
"#
        ));
        let (outcome, detail) = reachability(&config, "github", "http", "…");
        assert_eq!(outcome, Outcome::Passed);
        // Unnamed rules are numbered the way `agent-iap list` numbers them.
        assert!(detail.contains("acl[0]"), "{detail}");
    }

    /// The report is read, copied into a ticket and pasted into a chat. A
    /// `literal:` credential is the one reference that *is* the credential, and
    /// `display_ref` is what keeps it out — this is the test that says the
    /// report goes through it.
    #[test]
    fn a_report_names_a_credential_and_never_prints_one() {
        let described = describe_auth(&AuthConfig::Bearer {
            secret: "literal:sk-the-real-thing".into(),
        });
        assert!(!described.contains("sk-the-real-thing"), "{described}");

        let mut server: McpServerConfig = toml::from_str(
            r#"
name = "child"
transport = "stdio"
command = "server"
"#,
        )
        .unwrap();
        server
            .env
            .insert("TOKEN".into(), "literal:sk-the-real-thing".into());
        let described = describe_env(&server);
        assert!(!described.contains("sk-the-real-thing"), "{described}");
    }

    #[test]
    fn a_verdict_is_the_worst_step_and_the_headline_is_what_it_says() {
        let mut report = Report::new("github", "upstream", "https://api.github.com");
        report.passed(ENDPOINT, "GET https://api.github.com/");
        report.passed(REACH, "answered 200 OK in 9ms");
        assert_eq!(report.verdict(), Outcome::Passed);
        assert!(report.ok());
        // Nothing wrong, so the headline is the thing the caller wanted to
        // know: what the service actually said.
        assert_eq!(report.headline(), "answered 200 OK in 9ms");

        report.warned(POLICY, "no ACL rule reaches it");
        assert_eq!(report.verdict(), Outcome::Warned);
        assert!(report.ok(), "a warning is not a failure");
        assert_eq!(report.headline(), "policy: no ACL rule reaches it");

        report.failed(CREDENTIAL, "env:NOPE is not set");
        assert_eq!(report.verdict(), Outcome::Failed);
        assert!(!report.ok());
        assert_eq!(report.headline(), "credential: env:NOPE is not set");
    }

    #[test]
    fn tools_are_named_up_to_a_point_and_counted_after_it() {
        let tools = |count: usize| {
            json!({
                "tools": (0..count)
                    .map(|n| json!({ "name": format!("tool_{n}") }))
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(describe_tools(&tools(0)), "the server offers no tools");
        assert_eq!(describe_tools(&tools(2)), "2 tools: tool_0, tool_1");
        let many = describe_tools(&tools(TOOLS_NAMED + 3));
        assert!(
            many.starts_with(&format!("{} tools:", TOOLS_NAMED + 3)),
            "{many}"
        );
        assert!(many.ends_with("and 3 more"), "{many}");
    }

    #[test]
    fn wrapping_keeps_whole_words_and_never_loses_one() {
        let text = "the service rejected the credential — 401 Unauthorized in 12ms";
        let lines = wrap(text, 20);
        assert!(lines
            .iter()
            .all(|line| line.chars().count() <= 20 || !line.contains(' ')));
        assert_eq!(lines.join(" "), text);
    }
}
