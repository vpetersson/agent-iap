//! Live reload, against a proxy that is actually serving.
//!
//! The console's promise is that a policy edit is in force before the operator
//! looks away. The only way to know that is to have an agent call through the
//! thing a moment after the file changed, so this binds a real upstream, a real
//! proxy, and asks.
//!
//! The second half of the file goes through the whole apparatus a deployment
//! has — a policy file on disk, the watcher that reads it, and `POST /reload`
//! on the control plane — because the claims worth pinning are about the
//! roster changing under live traffic, and none of them can be checked by
//! handing `AppState::reload` a `Config` that was never a file.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agent_iap::config::{Config, Overrides};
use agent_iap::reload::Watcher;
use agent_iap::state::AppState;
use agent_iap::tls::Listener;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::Value;

/// An upstream that reports the credential it was called with, so the test can
/// tell "routed" from "routed and injected".
///
/// `/slow` holds the response open long enough for a reload to land while a
/// request is still out at the upstream.
async fn upstream() -> SocketAddr {
    let app = Router::new()
        .route(
            "/whoami",
            get(|headers: axum::http::HeaderMap| async move {
                headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("none")
                    .to_string()
            }),
        )
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(600)).await;
                "eventually"
            }),
        );
    let listener = Box::leak(Box::new(
        Listener::bind("127.0.0.1:0".parse().unwrap(), app, None).unwrap(),
    ));
    listener.addr
}

fn policy_text(audit: &Path, body: &str) -> String {
    format!(
        r#"
[audit]
path = "{}"
stderr = false

[[agents]]
id = "claude"
token_sha256 = "{}"
{body}
"#,
        audit.display(),
        agent_iap::identity::token_hash("iap_test"),
    )
}

fn policy(audit: &Path, upstreams: &str) -> Config {
    toml::from_str(&policy_text(audit, upstreams)).unwrap()
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
        .reload(
            policy(
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
            ),
            agent_iap::reload::Trigger::Asked,
        )
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

// --- the roster changing under live traffic ---------------------------------
//
// From here down the policy is a file, the proxy reads it through a `Watcher`,
// and the control plane is the daemon's own — `router_with_reload`, so the
// reload is asked for the way a deploy script asks for it.

/// A proxy started the way the daemon starts one: from a file on disk, with the
/// watcher that owns that file and the control plane that can be told to
/// re-read it.
struct Running {
    proxy: SocketAddr,
    admin: SocketAddr,
    admin_token: String,
    path: PathBuf,
    audit: PathBuf,
    /// Held so the policy file outlives the proxy reading it.
    _dir: tempfile::TempDir,
}

/// Everything a second agent needs to exist, given the `claude` every policy
/// here already has.
fn also(id: &str, token: &str) -> String {
    format!(
        r#"
[[agents]]
id = "{id}"
token_sha256 = "{}"
"#,
        agent_iap::identity::token_hash(token),
    )
}

/// One HTTP upstream, one MCP server, and rules that allow both — the two
/// surfaces an agent can be revoked off.
fn serving(origin: SocketAddr, agents: &str) -> String {
    format!(
        r#"
{agents}

[[upstreams]]
name = "echo"
base_url = "http://{origin}"

[[mcp_servers]]
name = "notes"
transport = "http"
url = "http://{origin}/mcp"

[[acl]]
name = "read-echo"
target = "echo"
methods = ["GET"]
paths = ["/**"]
action = "allow"

[[acl]]
name = "use-notes"
kind = "mcp"
target = "notes"
action = "allow"
"#
    )
}

async fn start(body: &str) -> Running {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("iap.toml");
    let audit = dir.path().join("audit.jsonl");
    std::fs::write(&path, policy_text(&audit, body)).unwrap();

    // The daemon's arrangement exactly: one watcher, shared by the file poller
    // and the control plane, so neither reloads an edit the other already did.
    let watcher = Arc::new(Watcher::new(&path, Overrides::default()));
    let state = AppState::build(watcher.read().unwrap(), false).unwrap();
    let admin_token = state.admin_token.clone();

    let proxy = Box::leak(Box::new(
        Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            agent_iap::proxy::router(Arc::clone(&state)),
            None,
        )
        .unwrap(),
    ));
    let admin = Box::leak(Box::new(
        Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            agent_iap::admin::router_with_reload(Arc::clone(&state), Arc::clone(&watcher)),
            None,
        )
        .unwrap(),
    ));

    Running {
        proxy: proxy.addr,
        admin: admin.addr,
        admin_token,
        path,
        audit,
        _dir: dir,
    }
}

impl Running {
    /// Edit the policy file, the way `agent-iap agent add` or an editor would.
    fn rewrite(&self, body: &str) {
        std::fs::write(&self.path, policy_text(&self.audit, body)).unwrap();
    }

    /// What a deploy script does after writing the file.
    async fn reload(&self) -> (u16, Value) {
        let response = reqwest::Client::new()
            .post(format!("http://{}/reload", self.admin))
            .bearer_auth(&self.admin_token)
            .send()
            .await
            .unwrap();
        (response.status().as_u16(), response.json().await.unwrap())
    }

    /// An agent calling through the data plane.
    async fn call(&self, token: &str) -> u16 {
        reqwest::Client::new()
            .get(format!("http://{}/echo/whoami", self.proxy))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    /// One message on an MCP session that is already open: the bridge asks the
    /// daemon, with the agent's token, before it relays anything.
    async fn next_mcp_message(&self, token: &str) -> u16 {
        reqwest::Client::new()
            .post(format!("http://{}/authorize", self.admin))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "kind": "mcp",
                "target": "notes",
                "method": "tools/call",
                "path": "search",
            }))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    fn reload_records(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.audit)
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|record| record["event"] == "reload")
            .collect()
    }
}

/// The ask this was built for: enrol an agent into a proxy that is serving, and
/// have it work.
#[tokio::test]
async fn an_agent_added_to_the_file_authenticates_without_a_restart() {
    let origin = upstream().await;
    let running = start(&serving(origin, "")).await;

    assert_eq!(running.call("iap_test").await, 200);
    assert_eq!(
        running.call("iap_enrolled_later").await,
        401,
        "a token nothing in the file mentions"
    );

    running.rewrite(&serving(origin, &also("ci", "iap_enrolled_later")));
    let (status, body) = running.reload().await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["serving"]["agents"], 2);

    assert_eq!(
        running.call("iap_enrolled_later").await,
        200,
        "the agent enrolled a moment ago cannot get in"
    );
    assert_eq!(
        running.call("iap_test").await,
        200,
        "and the agent that was already there was disturbed by the enrolment"
    );
}

/// The other direction, and the one that matters more: revocation has to
/// actually revoke, on both surfaces. An MCP session is not a login — the
/// bridge asks the daemon per message — so an agent taken out of the file
/// loses a session it already has open, not just the next one it opens.
#[tokio::test]
async fn an_agent_removed_from_the_file_stops_immediately_mid_session() {
    let origin = upstream().await;
    let running = start(&serving(origin, &also("ci", "iap_doomed"))).await;

    assert_eq!(running.call("iap_doomed").await, 200);
    assert_eq!(
        running.next_mcp_message("iap_doomed").await,
        200,
        "the session this agent is mid-way through"
    );

    running.rewrite(&serving(origin, ""));
    let (status, body) = running.reload().await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["serving"]["agents"], 1);

    assert_eq!(
        running.call("iap_doomed").await,
        401,
        "a revoked agent is still being served on the data plane"
    );
    assert_eq!(
        running.next_mcp_message("iap_doomed").await,
        401,
        "a revoked agent is still being served on an MCP session it already had open"
    );
    assert_eq!(running.call("iap_test").await, 200, "and nobody else moved");
}

/// The safety property. A policy file edited into something unservable must
/// cost the edit, not the proxy.
#[tokio::test]
async fn a_policy_that_will_not_load_is_refused_and_the_old_one_keeps_serving() {
    let origin = upstream().await;
    let running = start(&serving(origin, &also("ci", "iap_second"))).await;
    assert_eq!(running.call("iap_test").await, 200);

    // Not TOML at all: the fat-fingered save.
    std::fs::write(&running.path, "this is not toml {{{").unwrap();
    let (status, body) = running.reload().await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(
        body["serving"]["agents"], 2,
        "the refusal must say what is still in force"
    );

    // TOML that parses and cannot be served: a secret reference to nothing.
    // This is the failure that would survive a parse-only check, and the one
    // that would leave a proxy holding half a policy if the swap came first.
    running.rewrite(&format!(
        r#"
[[agents]]
id = "ci"
token_ref = "env:AGENT_IAP_NO_SUCH_VARIABLE"
{}"#,
        serving(origin, "")
    ));
    let (status, body) = running.reload().await;
    assert_eq!(status, 422, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("AGENT_IAP_NO_SUCH_VARIABLE"),
        "the refusal should name the line that is wrong: {body}"
    );

    // Both refusals, and the proxy never stopped.
    assert_eq!(running.call("iap_test").await, 200);
    assert_eq!(running.call("iap_second").await, 200);

    // And the file is still readable, so a corrected edit lands.
    running.rewrite(&serving(origin, ""));
    assert_eq!(running.reload().await.0, 200);
    assert_eq!(running.call("iap_second").await, 401);
}

/// An audit log that cannot show the policy changing underneath it cannot
/// explain why the same agent was allowed at 09:00 and refused at 09:01.
#[tokio::test]
async fn a_reload_is_audited_with_what_changed_and_who_asked() {
    let origin = upstream().await;
    let running = start(&serving(origin, "")).await;

    running.rewrite(&serving(origin, &also("ci", "iap_second")));
    assert_eq!(running.reload().await.0, 200);

    let records = running.reload_records();
    let record = records.last().expect("the reload was not recorded");

    assert_eq!(record["detail"]["trigger"], "control_plane");
    assert_eq!(record["decision"], "control_plane");
    assert_eq!(record["detail"]["before"]["agents"], 1);
    assert_eq!(record["detail"]["after"]["agents"], 2);
    assert_eq!(record["detail"]["before"]["acl_rules"], 2);
    assert_eq!(record["detail"]["after"]["acl_rules"], 2);
    assert!(
        record["client"]
            .as_str()
            .is_some_and(|from| from.starts_with("127.0.0.1:")),
        "a control-plane reload should record where it came from: {record}"
    );

    // A refused reload is not a reload: nothing may claim the policy changed.
    std::fs::write(&running.path, "}{").unwrap();
    assert_eq!(running.reload().await.0, 422);
    assert_eq!(
        running.reload_records().len(),
        records.len(),
        "a refused edit was recorded as if it had been applied"
    );
}

/// Nothing may be asked for twice for no reason. A proxy fronting twenty
/// upstreams that re-mints every one of them because a rule was added has
/// turned an `[[acl]]` edit into twenty round trips and, for a provider that
/// rate-limits its token endpoint, an outage.
#[tokio::test]
async fn an_unchanged_upstream_keeps_the_token_it_already_minted() {
    let origin = upstream().await;
    let mints = Arc::new(AtomicUsize::new(0));
    let issuer = {
        let mints = Arc::clone(&mints);
        Router::new().route(
            "/token",
            post(move || {
                let mints = Arc::clone(&mints);
                async move {
                    let n = mints.fetch_add(1, Ordering::SeqCst) + 1;
                    Json(serde_json::json!({
                        "access_token": format!("minted-{n}"),
                        "token_type": "Bearer",
                        "expires_in": 3599,
                    }))
                }
            }),
        )
    };
    let issuer = Box::leak(Box::new(
        Listener::bind("127.0.0.1:0".parse().unwrap(), issuer, None).unwrap(),
    ));

    std::env::set_var("AGENT_IAP_RELOAD_CLIENT_SECRET", "shh");
    let body = |extra: &str| {
        format!(
            r#"
[[upstreams]]
name = "echo"
base_url = "http://{origin}"

[upstreams.auth]
type = "oauth2_client_credentials"
token_url = "http://{}/token"
client_id = "iap"
client_secret = "env:AGENT_IAP_RELOAD_CLIENT_SECRET"

[[acl]]
name = "read-echo"
target = "echo"
methods = ["GET"]
paths = ["/**"]
action = "allow"
{extra}
"#,
            issuer.addr,
        )
    };

    let running = start(&body("")).await;
    assert_eq!(running.call("iap_test").await, 200);
    assert_eq!(mints.load(Ordering::SeqCst), 1, "the first call mints");

    // An edit that says nothing about this upstream's credential.
    running.rewrite(&body(
        r#"
[[acl]]
name = "and-writes"
target = "echo"
methods = ["POST"]
action = "deny"
"#,
    ));
    assert_eq!(running.reload().await.0, 200);
    assert_eq!(running.call("iap_test").await, 200);
    assert_eq!(
        mints.load(Ordering::SeqCst),
        1,
        "an unrelated edit sent the proxy back to the token endpoint"
    );

    // An edit that does change it. The cached token was minted with the old
    // client secret, so continuing to serve it would be serving a credential
    // the policy file no longer describes.
    std::env::set_var("AGENT_IAP_RELOAD_CLIENT_SECRET_2", "shh");
    running.rewrite(&body("").replace(
        "AGENT_IAP_RELOAD_CLIENT_SECRET",
        "AGENT_IAP_RELOAD_CLIENT_SECRET_2",
    ));
    assert_eq!(running.reload().await.0, 200);
    assert_eq!(running.call("iap_test").await, 200);
    assert_eq!(
        mints.load(Ordering::SeqCst),
        2,
        "a changed credential was served from the token minted for the old one"
    );
}

/// A request is weighed once, on the way in. Swapping the policy under one that
/// is already out at the upstream would mean a call that was allowed coming
/// back as a 401 — or worse, a call routed to an upstream whose base URL had
/// been edited out from under it halfway through.
#[tokio::test]
async fn a_request_already_in_flight_finishes_under_the_policy_that_admitted_it() {
    let origin = upstream().await;
    let running = start(&serving(origin, &also("ci", "iap_doomed"))).await;

    let proxy = running.proxy;
    let inflight = tokio::spawn(async move {
        reqwest::Client::new()
            .get(format!("http://{proxy}/echo/slow"))
            .bearer_auth("iap_doomed")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });
    // Long enough to be admitted and be waiting on the upstream, and far short
    // of the 600ms the upstream holds it for.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // The agent that call belongs to, and the upstream it is talking to, both
    // leave the policy while it is out there.
    running.rewrite("");
    assert_eq!(running.reload().await.0, 200);
    assert_eq!(
        running.call("iap_doomed").await,
        401,
        "the next call must be refused — this test would prove nothing otherwise"
    );

    assert_eq!(
        inflight.await.unwrap(),
        200,
        "a request admitted under the old policy was cut off by the new one"
    );
}

/// A route that re-reads the policy file is a route that can put a policy in
/// force. It belongs behind the same gate as the rest of the control plane, and
/// an agent token — which every agent behind this proxy holds — is not it.
#[tokio::test]
async fn reloading_takes_the_admin_token_and_nothing_else() {
    let origin = upstream().await;
    let running = start(&serving(origin, "")).await;
    running.rewrite(&serving(origin, &also("ci", "iap_second")));

    let post = |credential: Option<&str>| {
        let request = reqwest::Client::new().post(format!("http://{}/reload", running.admin));
        let request = match credential {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        request.send()
    };

    assert_eq!(post(None).await.unwrap().status(), 401);
    assert_eq!(post(Some("iap_test")).await.unwrap().status(), 401);
    assert_eq!(
        post(Some("not-the-admin-token")).await.unwrap().status(),
        401
    );

    // Refused, and not half-refused: the file was never read.
    assert_eq!(running.call("iap_second").await, 401);
    assert!(running.reload_records().is_empty());

    assert_eq!(
        post(Some(&running.admin_token)).await.unwrap().status(),
        200
    );
    assert_eq!(running.call("iap_second").await, 200);
}
