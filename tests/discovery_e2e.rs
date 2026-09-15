//! End-to-end tests for zero state: an agent that has a token and an address
//! and nothing else.
//!
//! The question each of these asks is the same one — *can it get from here to a
//! working call without a human explaining the proxy first* — and the answers
//! that matter are: it is told what it can reach, it is told nothing it could
//! not have learned from one refused call, it is never told a credential, and a
//! client that speaks MCP ends up at the gateway rather than at prose.

use agent_iap::config::Config;
use agent_iap::state::AppState;
use axum::extract::Request;
use axum::routing::any;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;

const AGENT_TOKEN: &str = "iap_agent_token";
const OUTSIDER_TOKEN: &str = "iap_outsider";
const UPSTREAM_KEY: &str = "sk-upstream-real";

async fn spawn_upstream() -> SocketAddr {
    async fn echo(request: Request) -> Json<Value> {
        Json(json!({ "path": request.uri().path() }))
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().fallback(any(echo)))
            .await
            .unwrap();
    });
    addr
}

struct Harness {
    proxy: SocketAddr,
    audit_path: std::path::PathBuf,
    _state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

impl Harness {
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.proxy)
    }

    async fn get(&self, path: &str, token: Option<&str>) -> reqwest::Response {
        let mut request = reqwest::Client::new().get(self.url(path));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        request.send().await.unwrap()
    }

    /// `GET` as the ordinary agent, returning the body as text.
    async fn text(&self, path: &str) -> String {
        let response = self.get(path, Some(AGENT_TOKEN)).await;
        assert!(
            response.status().is_success(),
            "{path} → {}",
            response.status()
        );
        assert!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("text/markdown")),
            "{path} did not come back as markdown"
        );
        response.text().await.unwrap()
    }

    async fn json(&self, path: &str) -> Value {
        let response = self.get(path, Some(AGENT_TOKEN)).await;
        assert!(
            response.status().is_success(),
            "{path} → {}",
            response.status()
        );
        response.json().await.unwrap()
    }

    fn records(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.audit_path)
            .unwrap()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

async fn spawn(workload_mode: &str) -> Harness {
    let upstream = spawn_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");

    let config_text = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[server.workload_identity]
mode = "{workload_mode}"

[audit]
path = "{audit}"
stderr = false

[[agents]]
id = "claude"
name = "Claude Code"
token_sha256 = "{token_hash}"
targets = ["echo"]

# Granted an upstream no rule ever names: reachable in name, deniable in fact.
[[agents]]
id = "outsider"
token_sha256 = "{outsider_hash}"
targets = ["unmentioned"]

[[upstreams]]
name = "echo"
base_url = "http://{upstream}"
auth = {{ type = "header", header = "x-api-key", secret = "literal:{key}" }}

[[upstreams]]
name = "unmentioned"
base_url = "http://{upstream}"

[[acl]]
name = "read-models"
target = "echo"
methods = ["GET"]
paths = ["/v1/models", "/v1/models/*"]
action = "allow"

[[acl]]
name = "confirm-sends"
target = "echo"
methods = ["POST"]
paths = ["/v1/messages"]
action = "ask"
"#,
        audit = audit_path.display(),
        token_hash = agent_iap::identity::token_hash(AGENT_TOKEN),
        outsider_hash = agent_iap::identity::token_hash(OUTSIDER_TOKEN),
        key = UPSTREAM_KEY,
    );

    let config: Config = toml::from_str(&config_text).unwrap();
    config.validate().unwrap();
    let state = AppState::build(config, false).unwrap();
    state.log_startup().unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            axum::serve(
                listener,
                agent_iap::proxy::router(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
    }

    Harness {
        proxy,
        audit_path,
        _state: state,
        _dir: dir,
    }
}

#[tokio::test]
async fn the_root_tells_an_agent_what_it_is_holding_and_what_it_can_reach() {
    let harness = spawn("off").await;
    let text = harness.text("/").await;

    // Who it is, where it is, and that the credential question is settled.
    assert!(text.contains("Claude Code"), "{text}");
    assert!(text.contains(&harness.proxy.to_string()), "{text}");
    assert!(text.contains("should not go looking for one"), "{text}");

    // The two ways in, MCP first and named as the one to prefer.
    let mcp = text.find("_iap/mcp").expect("the gateway is named");
    let http = text
        .find("<upstream>/<the path")
        .expect("the proxy is named");
    assert!(mcp < http, "MCP should be offered first:\n{text}");

    // What it can reach, and the rules that decide — but never the key.
    assert!(text.contains("`echo`"), "{text}");
    assert!(
        text.contains(&format!("http://{}/echo/<path>", harness.proxy)),
        "{text}"
    );
    assert!(text.contains("header x-api-key"), "{text}");
    assert!(text.contains("read-models"), "{text}");
    assert!(text.contains("ask a human"), "{text}");
    assert!(
        !text.contains(UPSTREAM_KEY),
        "the document leaked the credential"
    );

    // An `ask` rule exists, so the wait is explained rather than discovered.
    assert!(text.contains("do not cancel it"), "{text}");
    // An upstream this agent is not granted is not advertised.
    assert!(!text.contains("unmentioned"), "{text}");
}

#[tokio::test]
async fn the_same_document_comes_back_structured_for_a_program() {
    let harness = spawn("off").await;

    // Both ways of asking agree.
    let by_query = harness.json("/?format=json").await;
    let by_header = reqwest::Client::new()
        .get(harness.url("/"))
        .bearer_auth(AGENT_TOKEN)
        .header("accept", "application/json")
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(by_query, by_header);

    let document = by_query;
    assert_eq!(document["service"], "agent-iap");
    assert_eq!(document["agent"]["id"], "claude");
    // The field a client reads instead of the prose.
    assert_eq!(document["preferred_transport"], "mcp");
    assert_eq!(
        document["mcp"]["url"],
        format!("http://{}/_iap/mcp", harness.proxy)
    );
    assert_eq!(document["upstreams"].as_array().unwrap().len(), 1);
    assert_eq!(document["upstreams"][0]["name"], "echo");
    assert_eq!(document["upstreams"][0]["auth"], "header x-api-key");
    assert_eq!(
        document["upstreams"][0]["url"],
        format!("http://{}/echo", harness.proxy)
    );
    assert!(document["approvals"]["possible"].as_bool().unwrap());
    // Workload identity is off here, so there is no endpoint to advertise.
    assert_eq!(document["workload_identity"]["mode"], "off");
    assert!(document["endpoints"]["token"].is_null());
    assert!(!serde_json::to_string(&document)
        .unwrap()
        .contains(UPSTREAM_KEY));
}

#[tokio::test]
async fn the_well_known_path_answers_a_program_by_default() {
    let harness = spawn("off").await;
    let response = harness
        .get("/.well-known/agent-iap", Some(AGENT_TOKEN))
        .await;
    assert!(response.status().is_success());
    let document: Value = response.json().await.unwrap();
    assert_eq!(document["service"], "agent-iap");
}

#[tokio::test]
async fn an_anonymous_caller_is_told_how_to_authenticate_and_nothing_else() {
    let harness = spawn("off").await;
    let response = harness.get("/", None).await;

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()["www-authenticate"],
        "Bearer realm=\"agent-iap\""
    );
    let text = response.text().await.unwrap();
    assert!(text.contains("Authorization: Bearer"), "{text}");
    assert!(text.contains("_iap/health"), "{text}");
    // The policy starts once the token does: no agent, no upstream, no rule.
    assert!(!text.contains("echo"), "{text}");
    assert!(!text.contains("Claude Code"), "{text}");
    assert!(!text.contains("read-models"), "{text}");

    // And an anonymous read of a page that names nobody is not an audit event,
    // any more than a health check is.
    let records = harness.records();
    assert_eq!(records.len(), 1, "only the startup record: {records:?}");
    assert_eq!(records[0]["event"], "startup");
}

#[tokio::test]
async fn a_token_that_does_not_hold_up_is_refused_and_recorded() {
    let harness = spawn("off").await;
    let response = harness.get("/", Some("iap_not_a_real_token")).await;
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

    let records = harness.records();
    let last = records.last().unwrap();
    assert_eq!(last["event"], "denied");
    assert_eq!(last["target"], "<discovery>");
    assert_eq!(last["rule"], "<authentication>");
}

#[tokio::test]
async fn reading_the_document_is_recorded_against_the_agent_that_read_it() {
    let harness = spawn("off").await;
    harness.text("/").await;

    let last = harness.records().pop().unwrap();
    assert_eq!(last["event"], "discovery");
    assert_eq!(last["agent"], "claude");
    assert_eq!(last["target"], "<discovery>");
    assert_eq!(last["path"], "/");
}

#[tokio::test]
async fn an_mcp_client_given_only_the_base_url_still_completes_a_handshake() {
    let harness = spawn("off").await;

    // The literal zero-state mistake: an MCP client configured with the address
    // and nothing else. 307 keeps the method and the body, so the frame it is
    // already holding arrives at the gateway.
    let frame: Value = reqwest::Client::new()
        .post(harness.url("/"))
        .bearer_auth(AGENT_TOKEN)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(frame["result"]["serverInfo"]["name"], "agent-iap");
    assert!(frame["result"]["instructions"]
        .as_str()
        .unwrap()
        .contains("`echo`"));
}

#[tokio::test]
async fn a_client_opening_an_event_stream_at_the_root_is_sent_to_the_gateway() {
    let harness = spawn("off").await;
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(harness.url("/"))
        .bearer_auth(AGENT_TOKEN)
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(response.headers()["location"], "/_iap/mcp");
}

#[tokio::test]
async fn the_skill_bundle_is_one_file_and_a_single_skill_is_one_section() {
    let harness = spawn("off").await;

    let response = harness.get("/_iap/skill", Some(AGENT_TOKEN)).await;
    assert_eq!(
        response.headers()["content-disposition"],
        "inline; filename=\"SKILL.md\""
    );
    let bundle = response.text().await.unwrap();
    // The root document, plus every generated skill behind it.
    assert!(bundle.contains("# agent-iap"), "{bundle}");
    assert!(
        bundle.contains("# Calling APIs through agent-iap"),
        "{bundle}"
    );
    assert!(bundle.contains("# `echo`"), "{bundle}");
    assert!(!bundle.contains(UPSTREAM_KEY));

    let one = harness.text("/_iap/skill/upstream/echo").await;
    assert!(one.contains("# `echo`"), "{one}");
    assert!(one.contains("read-models"), "{one}");
    assert!(!one.contains("# agent-iap"), "one section, not the bundle");

    let index = harness.json("/_iap/skill?format=json").await;
    let names: Vec<&str> = index["skills"]
        .as_array()
        .unwrap()
        .iter()
        .map(|skill| skill["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["using-this-gateway", "upstream/echo"]);
}

#[tokio::test]
async fn asking_for_a_skill_this_agent_has_no_business_with_lists_the_ones_it_has() {
    let harness = spawn("off").await;
    let response = harness
        .get("/_iap/skill/upstream/unmentioned", Some(AGENT_TOKEN))
        .await;

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["type"], "unknown_skill");
    assert_eq!(body["skills"][1], "upstream/echo");
}

#[tokio::test]
async fn an_agent_that_can_reach_nothing_is_told_so_rather_than_shown_an_empty_list() {
    let harness = spawn("off").await;
    let text = reqwest::Client::new()
        .get(harness.url("/"))
        .bearer_auth(OUTSIDER_TOKEN)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(text.contains("Nothing, today"), "{text}");
    assert!(text.contains("say so to whoever asked you"), "{text}");
    // Not even the name of the upstream it is nominally granted: no rule names
    // it, so every call would be refused and advertising it would be a lie.
    assert!(!text.contains("unmentioned"), "{text}");
}

#[tokio::test]
async fn a_guessed_upstream_name_is_refused_with_the_names_that_would_have_worked() {
    let harness = spawn("off").await;

    let response = harness.get("/gihtub/v1/models", Some(AGENT_TOKEN)).await;
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["type"], "unknown_upstream");
    let message = body["error"]["message"].as_str().unwrap();
    assert!(message.contains("`echo`"), "{message}");
    assert!(message.contains("GET /"), "{message}");
}

#[tokio::test]
async fn a_proxy_that_requires_workload_tokens_still_answers_the_agent_holding_one_that_is_not() {
    let harness = spawn("required").await;

    // The call itself is refused — that is the mode working. The *document* is
    // not, because the agent that has to be told to exchange its token is
    // exactly this one.
    let refused = harness.get("/echo/v1/models", Some(AGENT_TOKEN)).await;
    assert_eq!(refused.status(), reqwest::StatusCode::UNAUTHORIZED);

    let text = harness.text("/").await;
    assert!(text.contains("This proxy requires one"), "{text}");
    assert!(
        text.contains(&format!("POST http://{}/_iap/token", harness.proxy)),
        "{text}"
    );

    let document = harness.json("/?format=json").await;
    assert_eq!(document["workload_identity"]["required"], true);
    assert_eq!(document["workload_identity"]["holding_one"], false);
    assert_eq!(
        document["endpoints"]["token"],
        format!("http://{}/_iap/token", harness.proxy)
    );
}
