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

/// What gets probed when nobody named a path and the upstream carries no
/// `verify_path`: the root, which is the one path every base URL has.
const ROOT: &str = "/";

/// What the probe was aimed at, which is what decides what its answer is worth.
///
/// The distinction the report lives or dies on. A 404 from an endpoint that
/// should exist means something is wrong. A 404 from the root of an API means
/// the API serves nothing at its root — true of very nearly all of them, and it
/// says nothing whatsoever about the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Aim {
    /// `/`, because there was nothing better to try.
    Root,
    /// A real endpoint: `--path`, or the upstream's own `verify_path`. A
    /// credential either works against one of those or it does not.
    Endpoint,
}

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

    /// The one character a table cell can afford. What the eye is actually
    /// scanning a status column for is which rows are not the shape of the
    /// others, and a glyph does that in a way a sentence cannot.
    pub fn glyph(self) -> char {
        match self {
            Outcome::Passed => '✓',
            Outcome::Warned => '!',
            Outcome::Failed => '✗',
        }
    }
}

#[derive(Debug, Clone)]
pub struct Step {
    pub name: &'static str,
    pub outcome: Outcome,
    /// The sentence, for a report somebody sat down to read.
    pub detail: String,
    /// Two or three words, for a table cell that has no room for the sentence.
    /// The step's own name when nothing better was given, which is already the
    /// most useful thing a cell can say: it names the line of the full report
    /// to go and read.
    brief: Option<String>,
}

impl Step {
    pub fn brief(&self) -> &str {
        self.brief.as_deref().unwrap_or(self.name)
    }
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
            brief: None,
        });
    }

    /// The same, with the short form a table cell gets.
    fn noted(
        &mut self,
        name: &'static str,
        outcome: Outcome,
        brief: &str,
        detail: impl Into<String>,
    ) {
        self.step(name, outcome, detail);
        if let Some(step) = self.steps.last_mut() {
            step.brief = Some(brief.to_string());
        }
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

    /// Two or three words and nothing else, for the status column.
    ///
    /// The column exists to be glanced at. Putting the whole sentence in it was
    /// the mistake: it ran off the side of the pane, it read as alarming when
    /// it was not, and it buried the one bit that matters — which of these
    /// rows is not like the others. The sentence still exists, one keystroke
    /// away in the report.
    pub fn brief(&self) -> &str {
        let worst = self.verdict();
        if worst != Outcome::Passed {
            if let Some(step) = self.steps.iter().find(|step| step.outcome == worst) {
                return step.brief();
            }
        }
        match self.find(REACH).or_else(|| self.find(HANDSHAKE)) {
            Some(step) => step.brief(),
            None => "ok",
        }
    }
}

pub struct Options {
    pub timeout: Duration,
    /// Path to probe on an HTTP upstream, relative to its base URL, query
    /// string and all. Omitted falls back to the upstream's own `verify_path`
    /// and then to the root — which for most APIs is a 404, so an upstream
    /// whose credential you want actually exercised wants one of the two.
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

    // What the caller named wins — `--path` is how you ask a question about one
    // endpoint. Then the upstream's own `verify_path`, which its enrolment
    // wrote. Then the catalogue, which is what covers an upstream enrolled
    // before its profile had a probe, or written by hand. Only then the root.
    let inherited;
    let (probe, aim) = match options.path.as_deref().or(upstream.verify_path.as_deref()) {
        Some(probe) => (probe, Aim::Endpoint),
        None => match crate::profiles::probe_for(&upstream.base_url) {
            Some(probe) => {
                inherited = probe;
                (inherited.as_str(), Aim::Endpoint)
            }
            None => (ROOT, Aim::Root),
        },
    };
    let (path, query) = split_query(probe);
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
            report.noted(
                CREDENTIAL,
                Outcome::Failed,
                "cannot resolve",
                format!("{error:#}"),
            );
            http_policy(config, &upstream.name, &mut report);
            return report;
        }
    }

    let started = Instant::now();
    match http.execute(request).await {
        Ok(response) => {
            let (outcome, brief, detail) = classify(&response, started.elapsed(), aim);
            report.noted(REACH, outcome, brief, detail);
        }
        Err(error) => report.noted(REACH, Outcome::Failed, "unreachable", describe(&error)),
    }

    http_policy(config, &upstream.name, &mut report);
    report
}

/// What the status code says about the two things being verified: that the host
/// is the one that was meant, and that the credential is one it accepts.
///
/// Only a probe of a real endpoint can speak to the second, and a report must
/// never claim more than its probe went and asked. Dressing a root probe up as
/// an answer about the credential turns every healthy upstream amber — and a
/// status column that is amber for a working fleet is one an operator learns
/// within a day to stop reading, which is worse than not having it.
fn classify(
    response: &reqwest::Response,
    elapsed: Duration,
    aim: Aim,
) -> (Outcome, &'static str, String) {
    let status = response.status();
    let took = format!("in {}ms", elapsed.as_millis());

    if status.is_success() {
        return match aim {
            Aim::Endpoint => (
                Outcome::Passed,
                "credential ok",
                format!("answered {status} {took} — the credential was accepted"),
            ),
            Aim::Root => (
                Outcome::Passed,
                REACHABLE,
                format!("the host answered {status} {took}{NOT_EXERCISED}"),
            ),
        };
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
            "redirected",
            format!("answered {status} → {to} — the base URL may be the wrong one"),
        );
    }
    match (status.as_u16(), aim) {
        // A credential the service actively rejected, wherever it was aimed. An
        // API that 401s its own root has still 401ed a request carrying this
        // key, and that is worth failing on.
        (401, _) => (
            Outcome::Failed,
            "rejected",
            format!("the service rejected the credential — {status} {took}"),
        ),
        // Authenticated and not entitled. Against a real endpoint that is a
        // scope problem worth naming — a service-account key with no binding to
        // the property is exactly this shape.
        (403, Aim::Endpoint) => (
            Outcome::Warned,
            "not entitled",
            format!(
                "answered {status} {took} — the credential is accepted but not entitled here. \
                 Check the scopes, and that the account has been granted the resource."
            ),
        ),
        // Every other 4xx from the root: it answered, which is the whole of
        // what the root was asked. Nothing is wrong, so nothing is amber.
        (_, Aim::Root) if status.is_client_error() => (
            Outcome::Passed,
            REACHABLE,
            format!("the host answered {status} {took}{NOT_EXERCISED}"),
        ),
        (404 | 405, Aim::Endpoint) => (
            Outcome::Warned,
            "no such endpoint",
            format!(
                "answered {status} {took} for an endpoint that should exist — the base URL \
                 may be wrong, or the API has moved"
            ),
        ),
        (429, _) => (
            Outcome::Warned,
            "rate limited",
            format!("the service is rate-limiting this credential — {status} {took}"),
        ),
        _ => (
            Outcome::Warned,
            "http error",
            format!("the service answered {status} {took}"),
        ),
    }
}

/// What the column says for a root probe that came back clean. Deliberately
/// not "ok": the host is there and the credential is untested, and those are
/// different claims.
const REACHABLE: &str = "reachable";

/// The sentence a root probe owes the reader. Without it a pass here would
/// imply the report proved something it never went near.
const NOT_EXERCISED: &str =
    " — reachable. The credential was attached but not exercised: this upstream has no \
     `verify_path`, so pass --path with a real endpoint to prove it.";

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
                let brief = match refused.at {
                    CREDENTIAL => "cannot resolve",
                    _ => "unreachable",
                };
                report.noted(refused.at, Outcome::Failed, brief, refused.why);
                return;
            }
        };

    match rpc_result(&body, 1) {
        Some(Ok(result)) => report.noted(
            HANDSHAKE,
            Outcome::Passed,
            "session ok",
            format!(
                "{} in {}ms",
                describe_server(&result),
                started.elapsed().as_millis()
            ),
        ),
        other => {
            report.noted(
                HANDSHAKE,
                Outcome::Failed,
                "no session",
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
            Some(Ok(result)) => report.noted(
                TOOLS,
                Outcome::Passed,
                &count_tools(&result),
                describe_tools(&result),
            ),
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
            report.noted(
                CREDENTIAL,
                Outcome::Failed,
                "cannot resolve",
                format!("{error:#}"),
            );
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
            report.noted(
                HANDSHAKE,
                Outcome::Failed,
                "no session",
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
            report.noted(
                HANDSHAKE,
                Outcome::Passed,
                "session ok",
                format!(
                    "{} in {}ms",
                    describe_server(&result),
                    started.elapsed().as_millis()
                ),
            );
            let asking = [initialized_notification(), tools_request()];
            let tools = exchange(&mut stdin, &mut lines, &asking, 2);
            match tokio::time::timeout(options.timeout, tools).await {
                Ok(Ok(Some(Ok(result)))) => report.noted(
                    TOOLS,
                    Outcome::Passed,
                    &count_tools(&result),
                    describe_tools(&result),
                ),
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
        Ok(Ok(Some(Err(error)))) => report.noted(
            HANDSHAKE,
            Outcome::Failed,
            "no session",
            format!("`{command_name}` refused `initialize`: {error}"),
        ),
        Ok(Ok(None)) => report.noted(
            HANDSHAKE,
            Outcome::Failed,
            "no session",
            format!(
                "`{command_name}` exited without answering `initialize`{}",
                said()
            ),
        ),
        Ok(Err(error)) => report.noted(
            HANDSHAKE,
            Outcome::Failed,
            "no session",
            format!("talking to `{command_name}`: {error:#}{}", said()),
        ),
        Err(_) => report.noted(
            HANDSHAKE,
            Outcome::Failed,
            "no session",
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
    let (outcome, brief, detail) = reachability(
        config,
        name,
        "http",
        &format!(
            "agent-iap acl add --kind http --target {name} --methods GET --paths '/**' \
             --action allow"
        ),
    );
    report.noted(POLICY, outcome, brief, detail);
}

fn mcp_policy(config: &Config, server: &McpServerConfig, report: &mut Report) {
    // The narrower complaint first: rules that exist but leave `initialize` out
    // are the case that looks configured and is not. Worded for one line rather
    // than reusing `check`'s paragraph, which is laid out to be read as a block.
    if mcp_handshake_warning(config, server).is_some() {
        report.noted(
            POLICY,
            Outcome::Warned,
            "no initialize rule",
            format!(
                "rules reach it, but none admits `initialize` — the handshake will be denied \
                 by `<default>` and the agent will see a server that never starts. Add a \
                 session rule in front of the tool rules: agent-iap acl add --kind mcp \
                 --target {} --paths '**' {} --action allow",
                server.name,
                session_methods()
            ),
        );
        return;
    }
    let fix = format!(
        "agent-iap acl add --kind mcp --target {} --paths '**' {} --action allow",
        server.name,
        session_methods()
    );
    let (outcome, brief, detail) = reachability(config, &server.name, "mcp", &fix);
    report.noted(POLICY, outcome, brief, detail);
}

fn reachability(
    config: &Config,
    name: &str,
    kind: &str,
    fix: &str,
) -> (Outcome, &'static str, String) {
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
            "reachable by acl",
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
            "acl default",
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
        "no acl rule",
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
    // What actually happens to the handshake is whatever `acl_default` says, so
    // name it rather than asserting a `deny` the file may not contain: under
    // `ask` the session does not fail, it stops on a human every time it opens,
    // which is its own thing to go and fix.
    let fallthrough = match config.acl_default.action {
        Action::Ask => {
            "The handshake will fall through to `<default>`, which is `ask`, so\n\
                        every session stops on a human — and denies outright wherever there\n\
                        is no console."
        }
        _ => {
            "The handshake will be denied by `<default>`, and the agent will see a\n\
              server that never starts."
        }
    };
    Some(format!(
        "mcp server `{name}` has rules, but none of them admits `initialize`.\n\
         {fallthrough} Add a session rule before the tool rules:\n\n\
         \x20 agent-iap acl add --kind mcp --target {name} --paths '**' \\\n\
         \x20   {fix} --action allow",
        name = server.name,
        fix = session_methods(),
    ))
}

/// A policy in which nothing can ever stop on a human.
///
/// No rule says `ask` and `acl_default` does not either, so every request the
/// rules do not cover is settled without anybody being asked. That is a
/// perfectly good deployment when it was chosen; it is the reported bug when it
/// was not — the console draws an empty queue, the audit log fills with
/// `<default>` decisions, and nothing on screen connects the two.
///
/// The diagnosis is shared by `check`, `run`'s headless banner and the console,
/// because three wordings of one state is how an operator ends up believing the
/// most optimistic of them. The way out is not: a console names the key it is
/// on, a terminal names the command.
pub fn cannot_ask_warning(rules: &[AclRuleConfig], default: Action) -> Option<String> {
    if default == Action::Ask || rules.iter().any(|rule| rule.action == Action::Ask) {
        return None;
    }
    let settled = match default {
        Action::Allow => "forwarded",
        _ => "refused",
    };
    let rule_list = match rules.len() {
        0 => "There are no rules at all.".to_string(),
        1 => "There is one rule.".to_string(),
        count => format!("The {count} rules cover what they cover."),
    };
    // One paragraph, unwrapped: every surface that shows this has its own idea
    // of how wide it is. `wrap` is here for the ones that have to decide.
    Some(format!(
        "nothing in this policy can ask. No rule says `ask` and `acl_default` is \
         `{default}`. {rule_list} A request no rule covers is {settled} by \
         `<default>`: a line in the audit log, an empty approval queue, and nothing \
         on screen joining the two."
    ))
}

/// What a request no rule covers meets, as one clause naming the reason.
///
/// Every surface that reports an enrolment has to say this, and until now each
/// one guessed: `init` said the proxy "denies everything", `upstream add` said
/// a service with no rule "is not reachable", and the console said "agents can
/// reach it now" — three different answers to one question `acl_default`
/// already answers, on a file where the answer is `ask`. The wording around it
/// is each surface's own (the way out of a bad default is a command in a
/// terminal and a key in the console); the clause is this.
pub fn fallthrough_clause(default: Action) -> &'static str {
    match default {
        Action::Ask => "stops at the `agent-iap run` console",
        Action::Allow => "is forwarded — `acl_default` is allow",
        Action::Deny => "is refused by `<default>`, with nobody asked",
    }
}

/// How a terminal fixes the state [`cannot_ask_warning`] describes. The console
/// has its own, because there the answer is a key rather than a command.
pub const CANNOT_ASK_FIX: &str = "`agent-iap acl reset` makes the fallthrough a question, and \
                                  clears the rules doing it. To keep them, one rule is enough:";

/// The command under [`CANNOT_ASK_FIX`], kept off the wrapping so it arrives as
/// one line somebody can paste.
pub const CANNOT_ASK_COMMAND: &str = "  agent-iap acl add --action ask";

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

/// `12 tools`, for a cell. The names belong in the report, not the column.
fn count_tools(result: &Value) -> String {
    match tool_names(result).len() {
        0 => "no tools".to_string(),
        1 => "1 tool".to_string(),
        many => format!("{many} tools"),
    }
}

fn tool_names(result: &Value) -> Vec<&str> {
    result
        .get("tools")
        .and_then(Value::as_array)
        .map(|tools| {
            tools
                .iter()
                .filter_map(|tool| tool.get("name").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default()
}

fn describe_tools(result: &Value) -> String {
    let tools = tool_names(result);
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

    fn rule(action: Action) -> AclRuleConfig {
        let action = match action {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Ask => "ask",
        };
        toml::from_str(&format!("target = \"github\"\naction = \"{action}\"")).unwrap()
    }

    /// The reported state: rules gone (or never written) and a fallthrough that
    /// settles every request without anybody seeing it.
    #[test]
    fn no_rules_and_a_deny_default_cannot_ask() {
        let warning = cannot_ask_warning(&[], Action::Deny).expect("this is the reported bug");
        assert!(
            warning.contains("nothing in this policy can ask"),
            "{warning}"
        );
        assert!(
            warning.contains("`deny`"),
            "it names the default: {warning}"
        );
        assert!(warning.contains("refused"), "{warning}");
    }

    /// An `allow` default asks nobody either — and the sentence has to stop
    /// saying "refused", because nothing is being refused.
    #[test]
    fn an_allow_default_cannot_ask_either_and_says_what_it_does() {
        let warning = cannot_ask_warning(&[rule(Action::Allow)], Action::Allow).unwrap();
        assert!(warning.contains("forwarded"), "{warning}");
        assert!(!warning.contains("refused"), "{warning}");
    }

    /// The two ways a policy *can* ask. Neither is warned about: a warning an
    /// operator sees on a healthy policy is one they learn to skip.
    #[test]
    fn a_policy_that_can_ask_is_not_warned_about() {
        assert!(
            cannot_ask_warning(&[], Action::Ask).is_none(),
            "the default asks"
        );
        assert!(
            cannot_ask_warning(&[rule(Action::Allow), rule(Action::Ask)], Action::Deny).is_none(),
            "a rule asks"
        );
    }

    fn response(status: u16, headers: &[(&str, &str)]) -> reqwest::Response {
        let mut builder = http::Response::builder().status(status);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        reqwest::Response::from(builder.body("").unwrap())
    }

    fn verdict_of(status: u16, aim: Aim) -> Outcome {
        classify(&response(status, &[]), Duration::from_millis(1), aim).0
    }

    /// The distinction the whole command rests on: a service that refused the
    /// credential is a failure, and a service that answered something other
    /// than yes is not. Getting this backwards makes `--verify` either useless
    /// (everything passes) or unusable (every 404 fails a deploy).
    #[test]
    fn a_rejected_credential_fails_and_an_unhelpful_answer_only_warns() {
        assert_eq!(verdict_of(200, Aim::Endpoint), Outcome::Passed);
        assert_eq!(verdict_of(204, Aim::Endpoint), Outcome::Passed);
        assert_eq!(verdict_of(401, Aim::Endpoint), Outcome::Failed);
        assert_eq!(verdict_of(403, Aim::Endpoint), Outcome::Warned);
        assert_eq!(verdict_of(404, Aim::Endpoint), Outcome::Warned);
        assert_eq!(verdict_of(429, Aim::Endpoint), Outcome::Warned);
        assert_eq!(verdict_of(503, Aim::Endpoint), Outcome::Warned);
    }

    /// The regression this exists for. Every upstream in the console showed
    /// amber and every one of them worked, because almost no API serves
    /// anything at its root — so the probe that had nowhere better to aim got a
    /// 404 and the column called it a warning. A status column that is amber
    /// for a healthy fleet teaches the operator to stop reading it, which is
    /// the one outcome worse than not having it.
    #[test]
    fn a_root_that_answers_at_all_is_a_pass_whatever_it_answers() {
        for status in [200, 400, 403, 404, 405, 410, 418] {
            assert_eq!(
                verdict_of(status, Aim::Root),
                Outcome::Passed,
                "a root probe answering {status}"
            );
        }
        // The exception: the service looked at this credential and said no.
        // Where it was pointed does not soften that.
        assert_eq!(verdict_of(401, Aim::Root), Outcome::Failed);
        // And a server-side fault is still worth an eyebrow.
        assert_eq!(verdict_of(503, Aim::Root), Outcome::Warned);
    }

    /// A pass from the root must not read as a pass for the credential.
    #[test]
    fn a_root_probe_says_what_it_did_not_prove() {
        for status in [200, 404] {
            let (outcome, _, detail) =
                classify(&response(status, &[]), Duration::from_millis(1), Aim::Root);
            assert_eq!(outcome, Outcome::Passed);
            assert!(detail.contains("not exercised"), "{detail}");
            assert!(detail.contains("--path"), "{detail}");
        }
        let (_, _, detail) = classify(&response(200, &[]), Duration::from_millis(1), Aim::Endpoint);
        assert!(detail.contains("credential was accepted"), "{detail}");
        assert!(!detail.contains("not exercised"), "{detail}");
    }

    #[test]
    fn a_redirect_is_reported_rather_than_followed() {
        let (outcome, _, detail) = classify(
            &response(302, &[("location", "https://login.example.com/")]),
            Duration::from_millis(1),
            Aim::Root,
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
        let asked = classify(&response(404, &[]), Duration::from_millis(1), Aim::Endpoint).2;
        let unasked = classify(&response(404, &[]), Duration::from_millis(1), Aim::Root).2;
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
        let (outcome, _, detail) = reachability(&bare, "github", "http", "…");
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
        let (outcome, _, detail) = reachability(&allowed, "github", "http", "…");
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
        let (outcome, _, detail) = reachability(&config, "github", "http", "…");
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
    fn a_verdict_is_the_worst_step_whatever_order_they_arrived_in() {
        let mut report = Report::new("github", "upstream", "https://api.github.com");
        report.passed(ENDPOINT, "GET https://api.github.com/");
        report.passed(REACH, "answered 200 OK in 9ms");
        assert_eq!(report.verdict(), Outcome::Passed);
        assert!(report.ok());

        report.warned(POLICY, "no ACL rule reaches it");
        assert_eq!(report.verdict(), Outcome::Warned);
        assert!(report.ok(), "a warning is not a failure");

        report.failed(CREDENTIAL, "env:NOPE is not set");
        assert_eq!(report.verdict(), Outcome::Failed);
        assert!(!report.ok());

        // And a pass arriving after the failure does not undo it.
        report.passed(TOOLS, "3 tools");
        assert_eq!(report.verdict(), Outcome::Failed);
    }

    /// What the status column says, for every shape of report. The rule it has
    /// to keep: short enough to sit in a table cell beside four other columns.
    #[test]
    fn the_short_form_stays_short_and_never_repeats_the_sentence() {
        let mut report = Report::new("api", "upstream", "https://api.example.com");
        report.noted(ENDPOINT, Outcome::Passed, "endpoint", "GET https://…/user");
        report.noted(
            REACH,
            Outcome::Passed,
            "credential ok",
            "answered 200 OK in 9ms — the credential was accepted",
        );
        report.noted(
            POLICY,
            Outcome::Passed,
            "reachable by acl",
            "reached by 1 rule: api-reads",
        );
        assert_eq!(report.verdict(), Outcome::Passed);
        // The network result, not the last step: "reachable by acl" is true and
        // is not what somebody scanning this column wants to know.
        assert_eq!(report.brief(), "credential ok");

        report.noted(
            POLICY,
            Outcome::Warned,
            "no acl rule",
            "no ACL rule reaches it — agent calls will be denied by `<default>`. Add one: …",
        );
        assert_eq!(report.brief(), "no acl rule");

        report.noted(
            CREDENTIAL,
            Outcome::Failed,
            "cannot resolve",
            "environment variable `NOPE` is not set",
        );
        assert_eq!(report.brief(), "cannot resolve");

        for step in &report.steps {
            assert!(
                step.brief().chars().count() <= 18,
                "`{}` is too long for a cell",
                step.brief()
            );
            assert!(!step.brief().contains('.'), "a cell is not a sentence");
        }
    }

    /// A step nobody gave a short form to still says something useful: its own
    /// name, which points at the line of the report to go and read.
    #[test]
    fn a_step_without_a_short_form_falls_back_to_its_name() {
        let mut report = Report::new("api", "upstream", "https://api.example.com");
        report.failed(ENDPOINT, "`nonsense` is not a URL");
        assert_eq!(report.brief(), ENDPOINT);
    }

    /// Every outcome has a glyph, and no two share one — the column is read by
    /// shape before it is read by colour, which is also what makes it work for
    /// anyone who cannot tell the red from the green.
    #[test]
    fn each_outcome_has_its_own_glyph() {
        let glyphs: Vec<char> = [Outcome::Passed, Outcome::Warned, Outcome::Failed]
            .iter()
            .map(|outcome| outcome.glyph())
            .collect();
        assert_eq!(glyphs.len(), 3);
        for (at, glyph) in glyphs.iter().enumerate() {
            assert!(!glyphs[at + 1..].contains(glyph), "`{glyph}` is used twice");
        }
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
