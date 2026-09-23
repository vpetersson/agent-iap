//! Revocation, driven end to end: the claim is that removing an agent stops
//! its token working, and that claim spans three modules — the edit to the
//! policy file, the load, and the identity check in front of the proxy.
//!
//! So these tests do not assert on TOML. They build a policy the way an
//! operator would, run a real proxy in front of a mock upstream, revoke, and
//! ask the proxy. They also pin the caveat every one of those commands prints:
//! the proxy already running is not the one that read the edit.

use agent_iap::config::Config;
use agent_iap::enroll::{self, AuthSpec};
use agent_iap::state::AppState;
use axum::extract::Request;
use axum::routing::any;
use axum::{Json, Router};
use serde_json::Value;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// A stand-in upstream that answers anything with 200.
async fn spawn_upstream() -> SocketAddr {
    async fn echo(request: Request) -> Json<Value> {
        Json(serde_json::json!({ "path": request.uri().path() }))
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

/// One upstream, one rule, and an agent holding the token that was minted for
/// it — written entirely by the enrolment commands, with no fixture in between.
fn policy(dir: &Path, upstream: SocketAddr) -> (PathBuf, String) {
    let path = dir.join("iap.toml");
    agent_iap::init::init(&agent_iap::init::InitOptions {
        path: path.clone(),
        template: agent_iap::init::Template::Minimal,
        force: true,
        ..Default::default()
    })
    .unwrap();

    // A file rather than `literal:`, because `upstream add` refuses to write a
    // credential into a policy file — the same refusal an operator would hit.
    let secret = dir.join("upstream.key");
    std::fs::write(&secret, "sk-upstream-real").unwrap();
    enroll::add_upstream(
        &path,
        "echo",
        &format!("http://{upstream}"),
        &AuthSpec::Header {
            header: "x-api-key".into(),
            secret: format!("file:{}", secret.display()),
            prefix: None,
        },
        &[],
    )
    .unwrap();
    // `agent = "*"`, so what changes across a revocation is the roster and
    // nothing else — a 401 here can only be the identity check.
    enroll::add_rule(
        &path,
        &enroll::RuleSpec {
            name: Some("reads"),
            agent: "*",
            kind: "http",
            target: "echo",
            methods: &["GET".into()],
            paths: &["/v1/models".into()],
            action: "allow",
            expires: None,
            any_target: false,
        },
    )
    .unwrap();
    let agent =
        enroll::add_agent(&path, "ci", None, enroll::Reach::Only(&["echo".into()])).unwrap();
    (path, agent.token)
}

/// Start a proxy from the file as it stands. Calling this twice is the restart
/// the removal commands tell the operator they are waiting for.
async fn serve(path: &Path, audit: PathBuf) -> SocketAddr {
    let mut config: Config = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    config.audit.path = audit;
    config.audit.stderr = false;
    config.validate().unwrap();

    let state = AppState::build(config, false).unwrap();
    state.log_startup().unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            agent_iap::proxy::router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    addr
}

async fn call(proxy: SocketAddr, token: &str) -> (u16, String) {
    let response = reqwest::Client::new()
        .get(format!("http://{proxy}/echo/v1/models"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let decision = response
        .headers()
        .get("x-iap-decision")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (status, decision)
}

/// The README's claim, asserted rather than described: one command, and the
/// token buys nothing — while no upstream credential changed.
#[tokio::test]
async fn a_revoked_agent_is_a_stranger_after_the_restart() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = spawn_upstream().await;
    let (path, token) = policy(dir.path(), upstream);

    let before = serve(&path, dir.path().join("audit-before.jsonl")).await;
    assert_eq!(call(before, &token).await, (200, "allow".into()));

    enroll::remove_agent(&path, "ci", false).unwrap();

    let after = serve(&path, dir.path().join("audit-after.jsonl")).await;
    assert_eq!(
        call(after, &token).await,
        (401, "unknown_agent".into()),
        "the token that was revoked still authenticates"
    );
}

/// The other half of the same claim, and the reason every one of these commands
/// prints a restart notice: the process already running read the file once.
#[tokio::test]
async fn the_proxy_already_running_keeps_honouring_the_revoked_token() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = spawn_upstream().await;
    let (path, token) = policy(dir.path(), upstream);

    let running = serve(&path, dir.path().join("audit.jsonl")).await;
    assert_eq!(call(running, &token).await, (200, "allow".into()));

    enroll::remove_agent(&path, "ci", true).unwrap();

    assert_eq!(
        call(running, &token).await,
        (200, "allow".into()),
        "if this ever fails there is a reload, and the notice these commands \
         print is the thing to update"
    );
}

/// Rotation is the leaked-token path: same agent, same rules, different token.
#[tokio::test]
async fn rotating_swaps_which_token_the_proxy_answers_to() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = spawn_upstream().await;
    let (path, leaked) = policy(dir.path(), upstream);

    let before = serve(&path, dir.path().join("audit-before.jsonl")).await;
    assert_eq!(call(before, &leaked).await, (200, "allow".into()));

    let rotated = enroll::rotate_agent(&path, "ci").unwrap().token;
    assert_ne!(rotated, leaked);

    let after = serve(&path, dir.path().join("audit-after.jsonl")).await;
    assert_eq!(
        call(after, &leaked).await,
        (401, "unknown_agent".into()),
        "the leaked token survived its own rotation"
    );
    assert_eq!(
        call(after, &rotated).await,
        (200, "allow".into()),
        "rotation kept the agent's id but lost it its access"
    );
}
