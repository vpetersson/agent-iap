//! End-to-end tests for the MCP gateway: a real daemon, a real mock upstream,
//! and an agent that reaches the upstream by calling a tool.
//!
//! The properties are the ones the HTTP proxy is held to, asserted again on the
//! new surface — because a second way in is a second way out if it does not
//! enforce the same things. The upstream gets the real credential, the agent
//! never sees it, the policy decides, and the log records it.

use agent_iap::config::Config;
use agent_iap::state::AppState;
use axum::extract::Request;
use axum::routing::any;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;

const AGENT_TOKEN: &str = "iap_agent_token";
const UPSTREAM_KEY: &str = "sk-upstream-real";

/// A stand-in upstream that reports exactly what it was sent.
async fn spawn_upstream() -> SocketAddr {
    async fn echo(request: Request) -> Json<Value> {
        let headers = request.headers().clone();
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        Json(json!({
            "path": request.uri().path(),
            "query": request.uri().query(),
            "method": request.method().as_str(),
            "x-api-key": header("x-api-key"),
            "authorization": header("authorization"),
            "x-iap-token": header("x-iap-token"),
            "content-type": header("content-type"),
            "anthropic-version": header("anthropic-version"),
        }))
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
    fn endpoint(&self) -> String {
        format!("http://{}/_iap/mcp", self.proxy)
    }

    /// One JSON-RPC round trip as the agent, with the agent's own token.
    async fn rpc(&self, method: &str, params: Value) -> Value {
        self.rpc_as(AGENT_TOKEN, method, params).await
    }

    async fn rpc_as(&self, token: &str, method: &str, params: Value) -> Value {
        let response = reqwest::Client::new()
            .post(self.endpoint())
            .bearer_auth(token)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "{method} answered {}",
            response.status()
        );
        response.json().await.unwrap()
    }

    /// A `tools/call`, returning the tool result (which may be a tool error).
    async fn call(&self, name: &str, arguments: Value) -> Value {
        let frame = self
            .rpc(
                "tools/call",
                json!({ "name": name, "arguments": arguments }),
            )
            .await;
        assert!(
            frame.get("error").is_none(),
            "tools/call failed at the protocol level: {frame}"
        );
        frame["result"].clone()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.audit_path).unwrap()
    }

    /// Every audit record, newest last.
    fn records(&self) -> Vec<Value> {
        self.log()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

async fn spawn(extra_acl: &str) -> Harness {
    let upstream = spawn_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");

    let config_text = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[audit]
path = "{audit}"
stderr = false

[[agents]]
id = "claude"
name = "Claude Code"
token_sha256 = "{token_hash}"
targets = ["echo"]

# Granted an upstream that exists but that no rule ever names — reachable in
# name, deniable in fact, and the case the gateway has to describe honestly.
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
name = "send-messages"
target = "echo"
methods = ["POST"]
paths = ["/v1/messages"]
action = "allow"
{extra_acl}
"#,
        audit = audit_path.display(),
        token_hash = agent_iap::identity::token_hash(AGENT_TOKEN),
        outsider_hash = agent_iap::identity::token_hash("iap_outsider"),
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
async fn an_agent_reaches_the_upstream_by_calling_a_tool_and_never_sees_the_key() {
    let harness = spawn("").await;

    let result = harness
        .call(
            "iap_request",
            json!({
                "upstream": "echo",
                "method": "GET",
                "path": "/v1/models",
                "query": { "limit": 5 },
            }),
        )
        .await;

    assert!(
        result.get("isError").is_none(),
        "the call should have been allowed: {result}"
    );
    assert_eq!(result["structuredContent"]["status"], 200);

    // The mock upstream reflects what it received.
    let seen: Value = serde_json::from_str(result["structuredContent"]["body"].as_str().unwrap())
        .expect("the upstream answered JSON");

    // The upstream got the real key…
    assert_eq!(seen["x-api-key"], UPSTREAM_KEY);
    // …at the path and query the agent asked for…
    assert_eq!(seen["path"], "/v1/models");
    assert_eq!(seen["query"], "limit=5");
    // …and the agent's own token stopped at the proxy.
    assert!(
        seen["authorization"].is_null(),
        "the agent token leaked upstream"
    );
    assert!(seen["x-iap-token"].is_null());

    // Nothing in the log is either secret.
    let log = harness.log();
    assert!(
        !log.contains(UPSTREAM_KEY),
        "credential leaked into the audit log"
    );
    assert!(
        !log.contains(AGENT_TOKEN),
        "agent token leaked into the audit log"
    );
}

#[tokio::test]
async fn a_json_body_arrives_as_json() {
    let harness = spawn("").await;

    let result = harness
        .call(
            "iap_request",
            json!({
                "upstream": "echo",
                "method": "POST",
                "path": "/v1/messages",
                "body": { "model": "claude", "messages": [] },
                "headers": { "anthropic-version": "2023-06-01" },
            }),
        )
        .await;

    let seen: Value =
        serde_json::from_str(result["structuredContent"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(seen["method"], "POST");
    assert_eq!(seen["content-type"], "application/json");
    // A header the agent is entitled to set travels; the credential ones do not.
    assert_eq!(seen["anthropic-version"], "2023-06-01");
    assert_eq!(seen["x-api-key"], UPSTREAM_KEY);
}

#[tokio::test]
async fn an_agent_cannot_smuggle_its_own_credential_header_past_the_proxy() {
    let harness = spawn("").await;

    let result = harness
        .call(
            "iap_request",
            json!({
                "upstream": "echo",
                "path": "/v1/models",
                "headers": {
                    "authorization": "Bearer stolen-from-somewhere",
                    "x-api-key": "sk-the-agents-own",
                },
            }),
        )
        .await;

    let seen: Value =
        serde_json::from_str(result["structuredContent"]["body"].as_str().unwrap()).unwrap();
    // The proxy's key, not the agent's, and no stray Authorization alongside it.
    assert_eq!(seen["x-api-key"], UPSTREAM_KEY);
    assert!(seen["authorization"].is_null());
}

#[tokio::test]
async fn a_policy_denial_comes_back_as_a_tool_error_naming_the_rule() {
    let harness = spawn("").await;

    // Right upstream, wrong method and path: nothing matches, default denies.
    let result = harness
        .call(
            "iap_request",
            json!({ "upstream": "echo", "method": "DELETE", "path": "/v1/models/opus" }),
        )
        .await;

    assert_eq!(result["isError"], true);
    let message = result["content"][0]["text"].as_str().unwrap();
    assert!(message.starts_with("policy_denied"), "{message}");
    assert!(message.contains("DELETE /v1/models/opus"), "{message}");

    // Refused before the network: the record is a denial, with no status from
    // any upstream, because there was no upstream call to get one from.
    let denial = harness
        .records()
        .into_iter()
        .find(|record| record["event"] == "denied")
        .expect("the refusal is in the log");
    assert_eq!(denial["agent"], "claude");
    assert_eq!(denial["rule"], "<default>");
    assert_eq!(denial["detail"]["via"], "mcp-gateway");
}

#[tokio::test]
async fn an_upstream_this_agent_was_never_granted_is_refused_by_name() {
    let harness = spawn("").await;

    let result = harness
        .call(
            "iap_request",
            json!({ "upstream": "unmentioned", "path": "/v1/models" }),
        )
        .await;

    assert_eq!(result["isError"], true);
    let message = result["content"][0]["text"].as_str().unwrap();
    assert!(message.starts_with("target_not_permitted"), "{message}");
}

#[tokio::test]
async fn a_path_that_climbs_out_of_the_upstream_is_refused_before_the_acl() {
    let harness = spawn("").await;

    for path in ["/v1/models/../../admin", "/v1/models/%2e%2e/admin"] {
        let result = harness
            .call("iap_request", json!({ "upstream": "echo", "path": path }))
            .await;
        assert_eq!(result["isError"], true, "{path} was not refused");
        let message = result["content"][0]["text"].as_str().unwrap();
        assert!(message.contains("`..` segment"), "{path}: {message}");
    }

    // A full URL is the same class of problem arriving as an argument rather
    // than as a path — the proxy's own routing makes this unreachable.
    let result = harness
        .call(
            "iap_request",
            json!({ "upstream": "echo", "path": "https://evil.invalid/v1/models" }),
        )
        .await;
    assert_eq!(result["isError"], true);
    assert!(result["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("must start with `/`"));
}

#[tokio::test]
async fn an_upstreams_own_error_is_a_result_not_a_refusal() {
    // The mock upstream answers 200 to everything, so ask for a status it will
    // mirror instead: the point is that a non-2xx is not reported as `isError`.
    let harness = spawn("").await;

    let result = harness
        .call(
            "iap_request",
            json!({ "upstream": "echo", "path": "/v1/models", "method": "GET" }),
        )
        .await;
    assert!(result.get("isError").is_none());
    assert_eq!(result["structuredContent"]["status"], 200);
}

#[tokio::test]
async fn the_gateway_refuses_an_unknown_token_and_records_it() {
    let harness = spawn("").await;

    let response = reqwest::Client::new()
        .post(harness.endpoint())
        .bearer_auth("iap_not_a_real_token")
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["type"], "unknown_agent");

    // And with no credential at all.
    let anonymous = reqwest::Client::new()
        .post(harness.endpoint())
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), 401);

    assert!(
        harness
            .records()
            .iter()
            .any(|record| record["rule"] == "<authentication>"),
        "an unknown token reaching the gateway should leave a trace"
    );
}

#[tokio::test]
async fn initialize_serves_instructions_naming_what_this_agent_can_reach() {
    let harness = spawn("").await;

    let frame = harness
        .rpc("initialize", json!({ "protocolVersion": "2025-06-18" }))
        .await;
    let result = &frame["result"];

    assert_eq!(result["serverInfo"]["name"], "agent-iap");
    assert!(result["capabilities"]["tools"].is_object());
    let instructions = result["instructions"].as_str().unwrap();
    assert!(instructions.contains("`echo`"), "{instructions}");
    assert!(instructions.contains("never ask for one"), "{instructions}");
    // `unmentioned` is in the policy but not granted to this agent.
    assert!(!instructions.contains("unmentioned"), "{instructions}");

    // Attaching is an event an operator should be able to see.
    assert!(
        harness
            .records()
            .iter()
            .any(|record| record["event"] == "session_start" && record["agent"] == "claude"),
        "the gateway session is not in the log"
    );
}

#[tokio::test]
async fn two_agents_are_told_two_different_things() {
    let harness = spawn("").await;

    let mine = harness
        .rpc("initialize", json!({}))
        .await
        .get("result")
        .unwrap()["instructions"]
        .as_str()
        .unwrap()
        .to_string();
    let theirs = harness
        .rpc_as("iap_outsider", "initialize", json!({}))
        .await
        .get("result")
        .unwrap()["instructions"]
        .as_str()
        .unwrap()
        .to_string();

    assert!(mine.contains("`echo`"), "{mine}");
    // The outsider is granted an upstream that does not exist, so the honest
    // answer is that it can reach nothing — not a copy of somebody else's list.
    assert!(!theirs.contains("`echo`"), "{theirs}");
    assert!(theirs.contains("no upstream it may address"), "{theirs}");
}

#[tokio::test]
async fn the_catalog_and_the_skills_describe_the_running_policy() {
    let harness = spawn("").await;

    let catalog = harness.call("iap_catalog", json!({})).await;
    let upstreams = catalog["structuredContent"]["upstreams"]
        .as_array()
        .unwrap();
    assert_eq!(upstreams.len(), 1);
    assert_eq!(upstreams[0]["name"], "echo");
    assert_eq!(upstreams[0]["auth"], "header x-api-key");
    assert!(!catalog.to_string().contains(UPSTREAM_KEY));

    let skill = harness
        .call("iap_skill", json!({ "name": "upstream/echo" }))
        .await;
    let text = skill["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("read-models"), "{text}");
    assert!(text.contains("send-messages"), "{text}");
    assert!(!text.contains(UPSTREAM_KEY), "{text}");

    // The same documents are readable as MCP resources, for clients that
    // prefer them to a tool call.
    let listed = harness.rpc("resources/list", json!({})).await;
    let uris: Vec<String> = listed["result"]["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|resource| resource["uri"].as_str().unwrap().to_string())
        .collect();
    assert!(
        uris.contains(&"skill://agent-iap/upstream/echo".to_string()),
        "{uris:?}"
    );

    let read = harness
        .rpc(
            "resources/read",
            json!({ "uri": "skill://agent-iap/upstream/echo" }),
        )
        .await;
    assert_eq!(
        read["result"]["contents"][0]["text"].as_str().unwrap(),
        text
    );
}

#[tokio::test]
async fn a_held_call_that_nobody_answers_is_refused_and_says_so() {
    let harness = spawn(
        r#"
[[acl]]
name = "confirm-deletes"
target = "echo"
methods = ["DELETE"]
paths = ["**"]
action = "ask"
"#,
    )
    .await;

    let result = harness
        .call(
            "iap_request",
            json!({ "upstream": "echo", "method": "DELETE", "path": "/v1/models/opus" }),
        )
        .await;

    assert_eq!(result["isError"], true);
    let message = result["content"][0]["text"].as_str().unwrap();
    assert!(message.starts_with("approval_denied"), "{message}");
    assert!(message.contains("confirm-deletes"), "{message}");

    // And the skill warns an agent that this will happen, so a slow call is not
    // read as a hang.
    let skill = harness
        .call("iap_skill", json!({ "name": "using-this-gateway" }))
        .await;
    assert!(skill["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("## Approvals"));
}

#[tokio::test]
async fn the_tool_list_is_offered_and_a_notification_takes_no_answer() {
    let harness = spawn("").await;

    let frame = harness.rpc("tools/list", json!({})).await;
    let names: Vec<String> = frame["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, ["iap_request", "iap_catalog", "iap_skill"]);

    // A notification has no id, so it gets no frame back — answering one would
    // give the client a response it is not waiting for.
    let response = reqwest::Client::new()
        .post(harness.endpoint())
        .bearer_auth(AGENT_TOKEN)
        .json(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 202);
    assert!(response.text().await.unwrap().is_empty());
}

#[tokio::test]
async fn an_unknown_method_is_a_jsonrpc_error_not_a_tool_error() {
    let harness = spawn("").await;

    let frame = harness.rpc("sampling/createMessage", json!({})).await;
    assert_eq!(frame["error"]["code"], -32601);

    // An unknown *tool*, on the other hand, is the model's mistake to correct.
    let frame = harness
        .rpc("tools/call", json!({ "name": "iap_sudo", "arguments": {} }))
        .await;
    assert_eq!(frame["error"]["code"], -32602);
}

#[tokio::test]
async fn the_gateway_does_not_displace_the_rest_api() {
    // MCP is the default way in, not the only one: an SDK pointed at the proxy
    // must keep working exactly as it did.
    let harness = spawn("").await;

    let response = reqwest::Client::new()
        .get(format!("http://{}/echo/v1/models", harness.proxy))
        .bearer_auth(AGENT_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-iap-decision"], "allow");
    let seen: Value = response.json().await.unwrap();
    assert_eq!(seen["x-api-key"], UPSTREAM_KEY);

    // Both surfaces in one log, told apart by how the call arrived.
    let records = harness.records();
    assert!(records
        .iter()
        .any(|record| record["event"] == "request" && record["detail"]["via"].is_null()));
}

#[tokio::test]
async fn the_same_call_is_decided_the_same_way_on_both_surfaces() {
    // The reason `gate::clear` exists. A rule that stops a call through the
    // proxy must stop the same call through the gateway.
    let harness = spawn("").await;

    let over_rest = reqwest::Client::new()
        .delete(format!("http://{}/echo/v1/models/opus", harness.proxy))
        .bearer_auth(AGENT_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(over_rest.status(), 403);
    let rest_body: Value = over_rest.json().await.unwrap();

    let over_mcp = harness
        .call(
            "iap_request",
            json!({ "upstream": "echo", "method": "DELETE", "path": "/v1/models/opus" }),
        )
        .await;

    assert_eq!(rest_body["error"]["type"], "policy_denied");
    let mcp_message = over_mcp["content"][0]["text"].as_str().unwrap();
    assert!(mcp_message.starts_with("policy_denied"), "{mcp_message}");
    // Same sentence, so an operator reading one surface's refusal recognises
    // the other's.
    assert!(
        mcp_message.ends_with(rest_body["error"]["message"].as_str().unwrap()),
        "rest: {}\nmcp:  {mcp_message}",
        rest_body["error"]["message"]
    );
}

#[tokio::test]
async fn the_log_verifies_after_a_session_through_the_gateway() {
    let harness = spawn("").await;

    harness.rpc("initialize", json!({})).await;
    harness
        .call(
            "iap_request",
            json!({ "upstream": "echo", "path": "/v1/models" }),
        )
        .await;
    harness
        .call(
            "iap_request",
            json!({ "upstream": "echo", "method": "DELETE", "path": "/v1/models/opus" }),
        )
        .await;

    // The chain is walked end to end; a break is an error, not a flag.
    let report = agent_iap::audit::verify_file(&harness.audit_path).unwrap();
    assert!(
        report.entries >= 4,
        "startup, the session, one allowed call and one refusal"
    );
}
