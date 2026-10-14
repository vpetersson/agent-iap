//! An S3-compatible upstream behind a real proxy: the request arrives signed
//! with the proxy's key whatever the agent signed it with, a server-side copy
//! never leaves, and a HEAD still says how big the object is.
//!
//! The signature itself is checked against AWS's and botocore's published
//! values in `sigv4`'s unit tests; this is about what reaches the wire.

use agent_iap::config::Config;
use agent_iap::state::AppState;
use axum::body::Body;
use axum::extract::Request;
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;

const AGENT_TOKEN: &str = "iap_agent_token";
const KEY_ID: &str = "AKIDEXAMPLE";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

type Seen = Arc<Mutex<Vec<http::HeaderMap>>>;

/// Records every request's headers. A HEAD answers with the size of an
/// object, the way S3's HeadObject does: in `content-length`, with no body.
async fn spawn_store(seen: Seen) -> SocketAddr {
    let handler = move |request: Request| {
        let seen = Arc::clone(&seen);
        async move {
            seen.lock().push(request.headers().clone());
            let builder = Response::builder().status(200);
            match *request.method() == http::Method::HEAD {
                true => builder
                    .header("content-length", "5243904")
                    .body(Body::empty())
                    .unwrap(),
                false => builder.body(Body::from("object")).unwrap(),
            }
        }
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().fallback(any(handler)))
            .await
            .unwrap();
    });
    addr
}

async fn spawn_proxy(store: SocketAddr) -> (SocketAddr, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let config_text = format!(
        r#"
[server]
listen = "127.0.0.1:0"
admin_listen = "127.0.0.1:0"

[audit]
path = "{audit}"
stderr = false

[[agents]]
id = "claude"
token_sha256 = "{token_hash}"
targets = ["store"]

[[upstreams]]
name = "store"
base_url = "http://{store}"
auth = {{ type = "aws_sigv4", access_key_id = "{KEY_ID}", secret = "literal:the-real-secret", region = "auto" }}

[[acl]]
target = "store"
methods = ["*"]
paths = ["/work/**"]
action = "allow"
"#,
        audit = dir.path().join("audit.jsonl").display(),
        token_hash = agent_iap::identity::token_hash(AGENT_TOKEN),
    );
    let config: Config = toml::from_str(&config_text).unwrap();
    config.validate().unwrap();
    let state = AppState::build(config, false).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            agent_iap::proxy::router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (proxy, dir)
}

#[tokio::test]
async fn the_store_sees_the_proxys_signature_and_nothing_the_agent_signed() {
    let seen = Seen::default();
    let (proxy, _dir) = spawn_proxy(spawn_store(Arc::clone(&seen)).await).await;

    // What an S3 SDK sends: its own signature, made with a dummy key, and the
    // agent token beside it where the SDK's `Authorization` cannot clash.
    let response = reqwest::Client::new()
        .get(format!("http://{proxy}/store/work/report.csv"))
        .header("x-iap-token", AGENT_TOKEN)
        .header(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=dummy/20200101/us-east-1/s3/aws4_request, \
             SignedHeaders=host, Signature=00",
        )
        .header("x-amz-security-token", "a-session-the-agent-made-up")
        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let headers = seen.lock().pop().expect("the store was called");
    let authorization = headers["authorization"].to_str().unwrap();
    let today = chrono::Utc::now().format("%Y%m%d");
    assert!(
        authorization.starts_with(&format!(
            "AWS4-HMAC-SHA256 Credential={KEY_ID}/{today}/auto/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="
        )),
        "{authorization}"
    );
    assert!(!authorization.contains("dummy"));
    assert!(headers.get("x-amz-security-token").is_none());
    assert!(headers.get("x-iap-token").is_none());
    assert_eq!(headers["x-amz-content-sha256"], EMPTY_SHA256);
}

/// Without the refusal this is a read of any key the access key reaches,
/// approved by a rule that only ever looked at the destination.
#[tokio::test]
async fn a_server_side_copy_is_refused_and_never_sent() {
    let seen = Seen::default();
    let (proxy, _dir) = spawn_proxy(spawn_store(Arc::clone(&seen)).await).await;

    let response = reqwest::Client::new()
        .put(format!("http://{proxy}/store/work/copied.csv"))
        .header("x-iap-token", AGENT_TOKEN)
        .header("x-amz-copy-source", "/private/payroll.csv")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert_eq!(response.headers()["x-iap-decision"], "unsignable_request");
    assert!(seen.lock().is_empty(), "the copy reached the store");
}

/// HeadObject reports an object's size in `content-length` and nowhere else.
/// The proxy re-frames every body it streams, and used to drop the header on
/// a HEAD too — so `head_object()["ContentLength"]` was a `KeyError`.
#[tokio::test]
async fn a_head_keeps_its_content_length() {
    let seen = Seen::default();
    let (proxy, _dir) = spawn_proxy(spawn_store(Arc::clone(&seen)).await).await;

    let response = reqwest::Client::new()
        .head(format!("http://{proxy}/store/work/big.bin"))
        .header("x-iap-token", AGENT_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("content-length")
            .map(|value| value.to_str().unwrap()),
        Some("5243904")
    );
}
