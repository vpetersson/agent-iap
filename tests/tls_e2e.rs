//! End-to-end over TLS: a real HTTPS request, through a real proxy, to a real
//! (mock) upstream.
//!
//! The property under test is the same one the whole project exists for — the
//! upstream receives the real credential and the agent never does — asserted
//! this time across a connection an eavesdropper cannot read.

use agent_iap::config::Config;
use agent_iap::state::AppState;
use agent_iap::tls::{self, ServerTls};
use axum::extract::Request;
use axum::routing::any;
use axum::{Json, Router};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;

const AGENT_TOKEN: &str = "iap_agent_token";
const UPSTREAM_KEY: &str = "sk-upstream-real";

/// A certificate for `localhost` and `127.0.0.1`, as PEM. Self-signed, because
/// the point is that the listener serves what the policy file gave it.
fn self_signed() -> (String, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::from([
            127, 0, 0, 1,
        ])));
    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem())
}

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
        Json(serde_json::json!({
            "path": request.uri().path(),
            "x-api-key": header("x-api-key"),
            "authorization": header("authorization"),
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
    admin: SocketAddr,
    admin_token: String,
    audit_path: std::path::PathBuf,
    certificate: String,
    _dir: tempfile::TempDir,
}

/// Start the proxy exactly as `agent-iap run` does: certificates resolved from
/// the policy file through the secret resolver, parsed before anything binds,
/// then handed to the same `tls::serve` the binary uses.
async fn spawn_tls_proxy(admin_tls: bool) -> Harness {
    let upstream = spawn_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");

    let (certificate, key) = self_signed();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, &certificate).unwrap();
    std::fs::write(&key_path, &key).unwrap();

    // A second certificate for the control plane, to prove it can have its own.
    let admin_section = if admin_tls {
        let (admin_cert, admin_key) = self_signed();
        std::fs::write(dir.path().join("admin-cert.pem"), &admin_cert).unwrap();
        std::fs::write(dir.path().join("admin-key.pem"), &admin_key).unwrap();
        format!(
            r#"
[server.admin_tls]
cert = "file:{dir}/admin-cert.pem"
key = "file:{dir}/admin-key.pem"
"#,
            dir = dir.path().display()
        )
    } else {
        String::new()
    };

    let config_text = format!(
        r#"
[server]
listen = "127.0.0.1:0"
admin_listen = "127.0.0.1:0"

[server.tls]
cert = "file:{cert}"
key = "file:{key}"
{admin_section}

[audit]
path = "{audit}"
stderr = false

[[agents]]
id = "claude"
token_sha256 = "{token_hash}"
targets = ["echo"]

[[upstreams]]
name = "echo"
base_url = "http://{upstream}"
auth = {{ type = "header", header = "x-api-key", secret = "literal:{UPSTREAM_KEY}" }}

[[acl]]
name = "read-models"
target = "echo"
methods = ["GET"]
paths = ["/v1/models"]
action = "allow"
"#,
        cert = cert_path.display(),
        key = key_path.display(),
        audit = audit_path.display(),
        token_hash = agent_iap::identity::token_hash(AGENT_TOKEN),
    );

    let config: Config = toml::from_str(&config_text).unwrap();
    config.validate().unwrap();
    let state = AppState::build(config, false).unwrap();
    let loaded = ServerTls::load(&state.config().server, &state.resolver).unwrap();
    state.log_startup().unwrap();
    assert_eq!(loaded.proxy_scheme(), "https");
    assert_eq!(loaded.admin_scheme(), "https");

    let any = "127.0.0.1:0".parse().unwrap();
    // Leaked on purpose: the harness hands back the addresses and the listeners
    // have to outlive it, for as long as the test is talking to them.
    let proxy = Box::leak(Box::new(
        tls::Listener::bind(
            any,
            agent_iap::proxy::router(Arc::clone(&state)),
            loaded.proxy,
        )
        .unwrap(),
    ))
    .addr;
    let admin = Box::leak(Box::new(
        tls::Listener::bind(
            any,
            agent_iap::admin::router(Arc::clone(&state)),
            loaded.admin,
        )
        .unwrap(),
    ))
    .addr;

    Harness {
        proxy,
        admin,
        admin_token: state.admin_token.clone(),
        audit_path,
        certificate,
        _dir: dir,
    }
}

/// A client that trusts this proxy's certificate and nothing else new.
fn client(certificate: &str) -> reqwest::Client {
    reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(certificate.as_bytes()).unwrap())
        .build()
        .unwrap()
}

#[tokio::test]
async fn an_allowed_call_over_tls_reaches_the_upstream_with_the_real_credential() {
    let harness = spawn_tls_proxy(false).await;

    let response = client(&harness.certificate)
        .get(format!(
            "https://localhost:{}/echo/v1/models",
            harness.proxy.port()
        ))
        .bearer_auth(AGENT_TOKEN)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-iap-decision"], "allow");

    // ALPN offered h2 and the client took it, so TLS did not cost the agent
    // the protocol the upstream client already speaks.
    assert_eq!(response.version(), reqwest::Version::HTTP_2);

    let seen: Value = response.json().await.unwrap();
    // The upstream got the real key…
    assert_eq!(seen["x-api-key"], UPSTREAM_KEY);
    assert_eq!(seen["path"], "/v1/models");
    // …and the agent's own token stopped at the proxy.
    assert!(
        seen["authorization"].is_null(),
        "the agent token leaked upstream"
    );
}

#[tokio::test]
async fn the_agent_still_never_learns_the_upstream_credential() {
    let harness = spawn_tls_proxy(false).await;

    let response = client(&harness.certificate)
        .get(format!(
            "https://localhost:{}/echo/v1/models",
            harness.proxy.port()
        ))
        .bearer_auth(AGENT_TOKEN)
        .send()
        .await
        .unwrap();

    let headers = format!("{:?}", response.headers());
    let body = response.text().await.unwrap();

    assert!(
        !headers.contains(UPSTREAM_KEY),
        "credential echoed in headers"
    );
    assert!(
        body.contains(UPSTREAM_KEY),
        "sanity: the mock upstream reflects the key"
    );

    // Nor does the log, which now also holds a certificate's worth of startup.
    let log = std::fs::read_to_string(&harness.audit_path).unwrap();
    assert!(!log.contains(UPSTREAM_KEY), "the audit log holds the key");
    assert!(!log.contains(AGENT_TOKEN), "the audit log holds the token");
    assert!(
        !log.contains("PRIVATE KEY"),
        "the audit log holds the TLS key"
    );

    // It does say the proxy came up on TLS, which is the part an auditor wants.
    let startup: Value = serde_json::from_str(log.lines().next().unwrap()).unwrap();
    assert_eq!(startup["detail"]["tls"], true);
    assert_eq!(startup["detail"]["admin_tls"], true);
}

#[tokio::test]
async fn an_unknown_agent_is_still_rejected_over_tls() {
    let harness = spawn_tls_proxy(false).await;

    let response = client(&harness.certificate)
        .get(format!(
            "https://localhost:{}/echo/v1/models",
            harness.proxy.port()
        ))
        .bearer_auth("not-a-token")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn plain_http_against_the_tls_listener_does_not_get_a_reply() {
    let harness = spawn_tls_proxy(false).await;

    // An agent that forgets the `s` must fail, not be quietly downgraded.
    let error = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/echo/v1/models",
            harness.proxy.port()
        ))
        .bearer_auth(AGENT_TOKEN)
        .send()
        .await
        .unwrap_err();
    assert!(
        !error.is_status(),
        "the listener answered plain HTTP: {error}"
    );
}

#[tokio::test]
async fn an_untrusting_client_cannot_talk_to_the_proxy_at_all() {
    let harness = spawn_tls_proxy(false).await;

    // Self-signed, so the default roots must refuse it. This is the assertion
    // that the connection is really verified rather than merely encrypted.
    let error = reqwest::Client::new()
        .get(format!(
            "https://localhost:{}/echo/v1/models",
            harness.proxy.port()
        ))
        .bearer_auth(AGENT_TOKEN)
        .send()
        .await
        .unwrap_err();
    assert!(error.is_connect() || error.is_request(), "{error}");
}

#[tokio::test]
async fn the_control_plane_serves_its_own_certificate_and_still_wants_the_admin_token() {
    let harness = spawn_tls_proxy(true).await;
    let url = format!("https://localhost:{}/status", harness.admin.port());

    // The control plane's certificate is not the proxy's, so the proxy's client
    // must be refused — the two really are separate certificates.
    assert!(client(&harness.certificate)
        .get(&url)
        .bearer_auth(&harness.admin_token)
        .send()
        .await
        .is_err());

    // With the right one, it behaves exactly as it does over plain HTTP.
    let admin_cert = std::fs::read_to_string(harness._dir.path().join("admin-cert.pem")).unwrap();
    let admin = client(&admin_cert);

    let response = admin
        .get(&url)
        .bearer_auth(&harness.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let response = admin.get(&url).send().await.unwrap();
    assert_eq!(response.status(), 401, "TLS is not authentication");
}

#[tokio::test]
async fn the_control_plane_follows_the_proxy_onto_tls_without_being_named_twice() {
    let harness = spawn_tls_proxy(false).await;

    let response = client(&harness.certificate)
        .get(format!("https://localhost:{}/health", harness.admin.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn a_key_that_does_not_match_the_certificate_stops_startup_before_anything_binds() {
    let dir = tempfile::tempdir().unwrap();
    let (certificate, _) = self_signed();
    let (_, other_key) = self_signed();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, certificate).unwrap();
    std::fs::write(&key_path, other_key).unwrap();

    let config: Config = toml::from_str(&format!(
        r#"
[server]
listen = "127.0.0.1:0"

[server.tls]
cert = "file:{cert}"
key = "file:{key}"

[audit]
path = "{audit}"
stderr = false

[[agents]]
id = "claude"
token_sha256 = "{token_hash}"

[acl_default]
action = "deny"
"#,
        cert = cert_path.display(),
        key = key_path.display(),
        audit = dir.path().join("audit.jsonl").display(),
        token_hash = agent_iap::identity::token_hash(AGENT_TOKEN),
    ))
    .unwrap();
    config.validate().unwrap();

    let state = AppState::build(config, false).unwrap();
    let error = format!(
        "{:#}",
        ServerTls::load(&state.config().server, &state.resolver).unwrap_err()
    );
    assert!(error.contains("do not go together"), "{error}");
    assert!(error.contains("server.tls"), "{error}");
}

/// A CA, and a leaf it signed for `localhost` and `127.0.0.1`.
///
/// The private-CA arrangement, and the one the self-signed helper above cannot
/// stand in for: the certificate to verify *against* is not the certificate
/// being served, so the leaf alone is not enough to build a path from.
fn ca_signed() -> (String, String, String) {
    fn named(common_name: &str) -> rcgen::DistinguishedName {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, common_name);
        dn
    }

    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    ca.distinguished_name = named("agent-iap test CA");
    let root = ca.self_signed(&ca_key).unwrap().pem();
    let issuer = rcgen::Issuer::new(ca, ca_key);

    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let mut leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    leaf.subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::from([
            127, 0, 0, 1,
        ])));
    leaf.distinguished_name = named("control plane");
    let leaf_pem = leaf.signed_by(&leaf_key, &issuer).unwrap().pem();

    (root, leaf_pem, leaf_key.serialize_pem())
}

/// Serve `/health` over TLS on a fresh loopback port, the way `run` does.
fn spawn_https(certificate: &str, key: &str) -> SocketAddr {
    Box::leak(Box::new(
        tls::Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            Router::new().route("/health", axum::routing::get(|| async { "ok" })),
            Some(tls::build(certificate, key).unwrap()),
        )
        .unwrap(),
    ))
    .addr
}

#[tokio::test]
async fn the_bridge_verifies_the_control_plane_against_the_ca_the_policy_file_names() {
    let (root, leaf, key) = ca_signed();
    let resolver = agent_iap::secrets::SecretResolver::new("op");
    let addr = spawn_https(&leaf, &key);
    let url = format!("https://localhost:{}/health", addr.port());

    let material = |ca: Option<String>| agent_iap::config::TlsConfig {
        cert: format!("literal:{leaf}"),
        key: format!("literal:{key}"),
        ca,
    };

    // Without `ca` the only anchor available is the served certificate itself,
    // and a leaf its CA signed is not its own issuer. This is the case that
    // used to require bundling the intermediate into `cert` to work at all.
    let error = tls::control_plane_client(Some(&material(None)), &resolver)
        .unwrap()
        .get(&url)
        .send()
        .await
        .unwrap_err();
    assert!(error.is_connect() || error.is_request(), "{error}");

    // Naming the CA makes the CA the anchor, and the leaf verifies against it.
    let response =
        tls::control_plane_client(Some(&material(Some(format!("literal:{root}")))), &resolver)
            .unwrap()
            .get(&url)
            .send()
            .await
            .unwrap();
    assert_eq!(response.status(), 200);

    // And it is still verification, not a way to switch it off: the same client
    // refuses a certificate that CA did not sign.
    let (_, other_leaf, other_key) = ca_signed();
    let other = spawn_https(&other_leaf, &other_key);
    let error =
        tls::control_plane_client(Some(&material(Some(format!("literal:{root}")))), &resolver)
            .unwrap()
            .get(format!("https://localhost:{}/health", other.port()))
            .send()
            .await
            .unwrap_err();
    assert!(error.is_connect() || error.is_request(), "{error}");
}

#[tokio::test]
async fn a_self_signed_control_plane_still_needs_no_ca_named() {
    // The documented loopback case: `cert` is its own CA, and the fallback that
    // was the only behaviour before `ca` existed keeps working untouched.
    let (certificate, key) = self_signed();
    let addr = spawn_https(&certificate, &key);

    let response = tls::control_plane_client(
        Some(&agent_iap::config::TlsConfig {
            cert: format!("literal:{certificate}"),
            key: format!("literal:{key}"),
            ca: None,
        }),
        &agent_iap::secrets::SecretResolver::new("op"),
    )
    .unwrap()
    .get(format!("https://localhost:{}/health", addr.port()))
    .send()
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
}
