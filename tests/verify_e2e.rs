//! `verify` against services that really answer.
//!
//! The unit tests say what a status code means; these say that the credential
//! the policy file names is the one that arrives, that a service which refuses
//! it is reported as refusing it, and that nothing on the way back through a
//! report is the credential itself.

use agent_iap::config::Config;
use agent_iap::secrets::SecretResolver;
use agent_iap::verify::{self, Outcome};
use axum::extract::Request;
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use http::{HeaderMap, StatusCode};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;

const KEY: &str = "sk-upstream-real";

/// An upstream that wants `x-api-key` and says so when it does not get it.
async fn spawn_api() -> SocketAddr {
    async fn handle(request: Request) -> axum::response::Response {
        if request
            .headers()
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            != Some(KEY)
        {
            return (StatusCode::UNAUTHORIZED, "who are you").into_response();
        }
        match request.uri().path() {
            "/" => (StatusCode::NOT_FOUND, "no index here").into_response(),
            "/me" => axum::Json(json!({ "login": "agent" })).into_response(),
            _ => (StatusCode::NOT_FOUND, "no").into_response(),
        }
    }
    serve(Router::new().fallback(any(handle))).await
}

/// A remote MCP server that wants a bearer token, and streams its answers back
/// as SSE — the transport a real one is most likely to use.
async fn spawn_mcp() -> SocketAddr {
    async fn handle(headers: HeaderMap, body: String) -> axum::response::Response {
        if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some("Bearer sk-mcp") {
            return (StatusCode::UNAUTHORIZED, "no").into_response();
        }
        let message: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let Some(id) = message.get("id") else {
            // A notification: acknowledged with no payload.
            return StatusCode::ACCEPTED.into_response();
        };
        let result = match message["method"].as_str() {
            Some("initialize") => json!({
                "protocolVersion": "2025-06-18",
                "serverInfo": { "name": "test-mcp", "version": "1.2.3" },
            }),
            _ => json!({ "tools": [{ "name": "search" }, { "name": "fetch" }] }),
        };
        let frame = json!({ "jsonrpc": "2.0", "id": id, "result": result });
        (
            [
                ("content-type", "text/event-stream"),
                ("mcp-session-id", "session-1"),
            ],
            format!("event: message\ndata: {frame}\n\n"),
        )
            .into_response()
    }
    serve(Router::new().fallback(any(handle))).await
}

async fn serve(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    addr
}

fn config(text: &str) -> Config {
    toml::from_str(text).unwrap()
}

fn resolver() -> Arc<SecretResolver> {
    Arc::new(SecretResolver::new("op"))
}

fn options(path: Option<&str>) -> verify::Options {
    verify::Options {
        timeout: std::time::Duration::from_secs(5),
        path: path.map(str::to_string),
        audit: None,
    }
}

/// Every step of one report, as `name = outcome`, so an assertion can name the
/// step it is about.
fn steps(report: &verify::Report) -> Vec<(&str, Outcome)> {
    report
        .steps
        .iter()
        .map(|step| (step.name, step.outcome))
        .collect()
}

fn detail(report: &verify::Report, name: &str) -> String {
    report
        .steps
        .iter()
        .find(|step| step.name == name)
        .unwrap_or_else(|| panic!("no `{name}` step in {:?}", steps(report)))
        .detail
        .clone()
}

#[tokio::test]
async fn an_upstream_that_accepts_the_credential_verifies_end_to_end() {
    let api = spawn_api().await;
    std::env::set_var("AGENT_IAP_VERIFY_KEY", KEY);
    let config = config(&format!(
        r#"
[[upstreams]]
name = "api"
base_url = "http://{api}"
auth = {{ type = "header", header = "x-api-key", secret = "env:AGENT_IAP_VERIFY_KEY" }}

[[acl]]
name = "api-reads"
kind = "http"
target = "api"
methods = ["GET"]
paths = ["/**"]
action = "allow"
"#
    ));

    let report = verify::upstream(&config, &resolver(), "api", &options(Some("/me")))
        .await
        .unwrap();

    assert_eq!(
        steps(&report),
        vec![
            ("endpoint", Outcome::Passed),
            ("credential", Outcome::Passed),
            ("reach", Outcome::Passed),
            ("policy", Outcome::Passed),
        ],
        "{report:?}"
    );
    assert!(report.ok());
    assert!(detail(&report, "reach").contains("200 OK"));
    assert!(detail(&report, "policy").contains("api-reads"));
}

/// The case the command exists for: the file is valid, the reference resolves,
/// and the service still says no.
#[tokio::test]
async fn a_credential_the_service_rejects_is_a_failure_and_says_which_step() {
    let api = spawn_api().await;
    std::env::set_var("AGENT_IAP_VERIFY_WRONG", "sk-not-the-one");
    let config = config(&format!(
        r#"
[[upstreams]]
name = "api"
base_url = "http://{api}"
auth = {{ type = "header", header = "x-api-key", secret = "env:AGENT_IAP_VERIFY_WRONG" }}
"#
    ));

    let report = verify::upstream(&config, &resolver(), "api", &options(Some("/me")))
        .await
        .unwrap();

    assert!(!report.ok());
    assert_eq!(report.verdict(), Outcome::Failed);
    // Named as a rejection rather than as "something went wrong", because the
    // two have entirely different fixes.
    assert!(detail(&report, "reach").contains("rejected the credential"));
    assert!(
        report.headline().starts_with("reach:"),
        "{}",
        report.headline()
    );
}

/// A reference that does not resolve stops the report before the call — there
/// is nothing to attach, so a request would only prove the host is up.
#[tokio::test]
async fn a_credential_that_will_not_resolve_stops_before_the_call() {
    let api = spawn_api().await;
    let config = config(&format!(
        r#"
[[upstreams]]
name = "api"
base_url = "http://{api}"
auth = {{ type = "bearer", secret = "env:AGENT_IAP_VERIFY_DEFINITELY_UNSET" }}
"#
    ));

    let report = verify::upstream(&config, &resolver(), "api", &options(None))
        .await
        .unwrap();

    assert_eq!(report.verdict(), Outcome::Failed);
    assert_eq!(
        steps(&report),
        vec![
            ("endpoint", Outcome::Passed),
            ("credential", Outcome::Failed),
            // Still answered: an operator fixing the credential wants to know
            // the rules are wrong too, not to find out on the next run.
            ("policy", Outcome::Warned),
        ],
        "{report:?}"
    );
}

/// The base URL is right, the credential is right, and nothing can get through.
#[tokio::test]
async fn an_upstream_no_rule_reaches_still_reports_the_call_and_warns() {
    let api = spawn_api().await;
    std::env::set_var("AGENT_IAP_VERIFY_KEY", KEY);
    let config = config(&format!(
        r#"
[[upstreams]]
name = "api"
base_url = "http://{api}"
auth = {{ type = "header", header = "x-api-key", secret = "env:AGENT_IAP_VERIFY_KEY" }}
"#
    ));

    let report = verify::upstream(&config, &resolver(), "api", &options(Some("/me")))
        .await
        .unwrap();

    assert!(
        report.ok(),
        "the service answered; the policy is the problem"
    );
    assert_eq!(report.verdict(), Outcome::Warned);
    let policy = detail(&report, "policy");
    assert!(policy.contains("no ACL rule reaches it"), "{policy}");
    // And it says what to type, because "add a rule" is not an instruction.
    assert!(policy.contains("agent-iap acl add"), "{policy}");
}

#[tokio::test]
async fn nothing_is_reachable_at_a_port_nothing_is_listening_on() {
    // Bound and dropped, so the port is real and certainly closed.
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let config = config(&format!(
        r#"
[[upstreams]]
name = "gone"
base_url = "http://{dead}"
"#
    ));

    let report = verify::upstream(&config, &resolver(), "gone", &options(None))
        .await
        .unwrap();

    assert_eq!(report.verdict(), Outcome::Failed);
    assert!(detail(&report, "reach").contains("connect"), "{report:?}");
}

#[tokio::test]
async fn a_remote_mcp_server_is_verified_by_its_handshake_and_its_tool_list() {
    let mcp = spawn_mcp().await;
    std::env::set_var("AGENT_IAP_VERIFY_MCP", "sk-mcp");
    let config = config(&format!(
        r#"
[[mcp_servers]]
name = "remote"
transport = "http"
url = "http://{mcp}/mcp"
auth = {{ type = "bearer", secret = "env:AGENT_IAP_VERIFY_MCP" }}

[[acl]]
name = "remote-session"
kind = "mcp"
target = "remote"
methods = ["initialize", "tools/list"]
paths = ["**"]
action = "allow"
"#
    ));

    let report = verify::mcp_server(&config, &resolver(), "remote", &options(None))
        .await
        .unwrap();

    assert!(report.ok(), "{report:?}");
    assert_eq!(
        steps(&report),
        vec![
            ("endpoint", Outcome::Passed),
            ("credential", Outcome::Passed),
            ("handshake", Outcome::Passed),
            ("tools", Outcome::Passed),
            ("policy", Outcome::Passed),
        ],
        "{report:?}"
    );
    // The server identifies itself, so two `[[mcp_servers]]` entries pointed at
    // the same URL by mistake are distinguishable.
    let handshake = detail(&report, "handshake");
    assert!(handshake.contains("test-mcp 1.2.3"), "{handshake}");
    // And the tools are named: these are the strings the ACL matches on.
    assert_eq!(detail(&report, "tools"), "2 tools: search, fetch");
}

#[tokio::test]
async fn an_mcp_server_that_rejects_the_token_fails_at_the_handshake() {
    let mcp = spawn_mcp().await;
    std::env::set_var("AGENT_IAP_VERIFY_MCP_WRONG", "sk-nope");
    let config = config(&format!(
        r#"
[[mcp_servers]]
name = "remote"
transport = "http"
url = "http://{mcp}/mcp"
auth = {{ type = "bearer", secret = "env:AGENT_IAP_VERIFY_MCP_WRONG" }}
"#
    ));

    let report = verify::mcp_server(&config, &resolver(), "remote", &options(None))
        .await
        .unwrap();

    assert_eq!(report.verdict(), Outcome::Failed);
    assert!(
        detail(&report, "handshake").contains("rejected the credential"),
        "{report:?}"
    );
}

/// The `tools/call` rules look complete and the session never opens. Verifying
/// the server is where an operator would find out, so it is where it is said.
#[tokio::test]
async fn rules_that_scope_every_tool_are_reported_as_denying_the_handshake() {
    let mcp = spawn_mcp().await;
    std::env::set_var("AGENT_IAP_VERIFY_MCP", "sk-mcp");
    let config = config(&format!(
        r#"
[[mcp_servers]]
name = "remote"
transport = "http"
url = "http://{mcp}/mcp"
auth = {{ type = "bearer", secret = "env:AGENT_IAP_VERIFY_MCP" }}

[[acl]]
name = "remote-tools"
kind = "mcp"
target = "remote"
methods = ["tools/call"]
paths = ["search"]
action = "allow"
"#
    ));

    let report = verify::mcp_server(&config, &resolver(), "remote", &options(None))
        .await
        .unwrap();

    // The server itself is fine — this is only about the policy in front of it.
    assert_eq!(report.verdict(), Outcome::Warned);
    let policy = detail(&report, "policy");
    assert!(policy.contains("none admits `initialize`"), "{policy}");
}

/// A report is pasted into tickets and chat windows. `literal:` is the one
/// reference that is the credential, and it must survive nothing.
#[tokio::test]
async fn no_report_ever_carries_the_credential_it_used() {
    let api = spawn_api().await;
    let config = config(&format!(
        r#"
[[upstreams]]
name = "api"
base_url = "http://{api}"
auth = {{ type = "query", param = "key", secret = "literal:{KEY}" }}
"#
    ));

    let report = verify::upstream(&config, &resolver(), "api", &options(Some("/me")))
        .await
        .unwrap();

    let printed = format!("{report:?}");
    assert!(
        !printed.contains(KEY),
        "the credential reached a report: {printed}"
    );
}

/// `query` auth puts the credential in the URL, which is what reqwest's own
/// error message prints. A failure there has to be described without it.
#[tokio::test]
async fn a_transport_failure_under_query_auth_does_not_print_the_url() {
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let config = config(&format!(
        r#"
[[upstreams]]
name = "gone"
base_url = "http://{dead}"
auth = {{ type = "query", param = "key", secret = "literal:{KEY}" }}
"#
    ));

    let report = verify::upstream(&config, &resolver(), "gone", &options(None))
        .await
        .unwrap();

    assert_eq!(report.verdict(), Outcome::Failed);
    let printed = format!("{report:?}");
    assert!(!printed.contains(KEY), "{printed}");
}

#[tokio::test]
async fn verifying_something_the_file_does_not_have_says_so() {
    let config = config("");
    let error = verify::target(&config, &resolver(), "ghost", &options(None))
        .await
        .unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("neither an upstream nor an MCP server"),
        "{message}"
    );
}
