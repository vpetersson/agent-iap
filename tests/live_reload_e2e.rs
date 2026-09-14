//! Live reload, against a proxy that is actually serving.
//!
//! The console's promise is that a policy edit is in force before the operator
//! looks away. The only way to know that is to have an agent call through the
//! thing a moment after the file changed, so this binds a real upstream, a real
//! proxy, and asks.

use std::net::SocketAddr;
use std::sync::Arc;

use agent_iap::config::Config;
use agent_iap::state::AppState;
use agent_iap::tls::Listener;
use axum::routing::get;
use axum::Router;

/// An upstream that reports the credential it was called with, so the test can
/// tell "routed" from "routed and injected".
async fn upstream() -> SocketAddr {
    let app = Router::new().route(
        "/whoami",
        get(|headers: axum::http::HeaderMap| async move {
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("none")
                .to_string()
        }),
    );
    let listener = Box::leak(Box::new(
        Listener::bind("127.0.0.1:0".parse().unwrap(), app, None).unwrap(),
    ));
    listener.addr
}

fn policy(audit: &std::path::Path, upstreams: &str) -> Config {
    toml::from_str(&format!(
        r#"
[audit]
path = "{}"
stderr = false

[[agents]]
id = "claude"
token_sha256 = "{}"
{upstreams}
"#,
        audit.display(),
        agent_iap::identity::token_hash("iap_test"),
    ))
    .unwrap()
}

#[tokio::test]
async fn an_upstream_added_while_the_proxy_is_running_serves_the_next_request() {
    std::env::set_var("AGENT_IAP_LIVE_TEST", "sk-live-reload");
    let dir = tempfile::tempdir().unwrap();
    let origin = upstream().await;

    let state = AppState::build(policy(&dir.path().join("audit.jsonl"), ""), false).unwrap();
    let proxy = Box::leak(Box::new(
        Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            agent_iap::proxy::router(Arc::clone(&state)),
            None,
        )
        .unwrap(),
    ));

    let client = reqwest::Client::new();
    let call = || {
        client
            .get(format!("http://{}/later/whoami", proxy.addr))
            .header("authorization", "Bearer iap_test")
            .send()
    };

    // Nothing called `later` yet, so there is nothing to route to.
    assert_eq!(call().await.unwrap().status(), 404);

    // The edit an operator makes mid-session.
    state
        .reload(policy(
            &dir.path().join("audit.jsonl"),
            &format!(
                r#"
[[upstreams]]
name = "later"
base_url = "http://{origin}"
auth = {{ type = "bearer", secret = "env:AGENT_IAP_LIVE_TEST" }}

[[acl]]
name = "later-reads"
target = "later"
methods = ["GET"]
paths = ["/**"]
action = "allow"
"#
            ),
        ))
        .unwrap();

    // No restart, no rebind, no reconnect: the same client, the same socket.
    let response = call().await.unwrap();
    assert_eq!(response.status(), 200, "the new upstream was not routable");
    assert_eq!(
        response.text().await.unwrap(),
        "Bearer sk-live-reload",
        "routed, but the credential the reload brought with it was not injected"
    );
}

#[tokio::test]
async fn moving_the_listen_address_moves_the_listener() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::build(policy(&dir.path().join("audit.jsonl"), ""), false).unwrap();

    let first = Listener::bind(
        "127.0.0.1:0".parse().unwrap(),
        agent_iap::proxy::router(Arc::clone(&state)),
        None,
    )
    .unwrap();
    let was = first.addr;

    // Somewhere else, chosen the way the OS chooses: bind, note, release.
    let spare = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let moving_to = spare.local_addr().unwrap();
    drop(spare);

    let mut listener = first;
    let fresh = Listener::bind(
        moving_to,
        agent_iap::proxy::router(Arc::clone(&state)),
        None,
    )
    .unwrap();
    let retired = std::mem::replace(&mut listener, fresh);
    retired.stop().await;

    assert_ne!(listener.addr, was);
    assert_eq!(listener.addr, moving_to);

    // The new address answers…
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/nowhere/x", listener.addr))
        .header("authorization", "Bearer iap_test")
        .send()
        .await
        .unwrap();
    assert!(response.status().is_client_error());

    // …and the old one has stopped.
    assert!(
        client
            .get(format!("http://{was}/nowhere/x"))
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
            .is_err(),
        "the retired listener is still accepting on {was}"
    );
}
