//! The workflows people actually set this up for, driven end to end.
//!
//! Every test here builds its policy the way an operator would — `profile add`,
//! not a hand-written TOML fixture — and then runs a real proxy in front of a
//! mock upstream. That coupling is the point: a profile whose base URL, scheme
//! or rules are wrong fails here rather than against the vendor, and a change
//! to `enroll` that stops producing what the proxy loads cannot pass.

use agent_iap::config::Config;
use agent_iap::profiles::{self, AddOptions};
use agent_iap::state::AppState;
use axum::extract::Request;
use axum::routing::any;
use axum::{Json, Router};
use serde_json::Value;
use std::net::SocketAddr;
use std::path::Path;

const AGENT_TOKEN: &str = "iap_workflow_agent";

/// An upstream that reports what it was sent, plus a token endpoint for the
/// service-account flow so the Google profiles can be exercised whole.
async fn spawn_upstream() -> SocketAddr {
    async fn handler(request: Request) -> Json<Value> {
        let path = request.uri().path().to_string();
        if path.ends_with("/token") {
            return Json(serde_json::json!({
                "access_token": "ya29.minted-by-the-proxy",
                "expires_in": 3600,
                "token_type": "Bearer",
            }));
        }
        let headers = request.headers().clone();
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        };
        Json(serde_json::json!({
            "path": path,
            // A credential can arrive in the query string as well as in a
            // header, so a mock that only reports headers cannot tell whether
            // `query` auth worked.
            "query": request.uri().query(),
            "method": request.method().as_str(),
            "authorization": header("authorization"),
            "x-api-key": header("x-api-key"),
            "x-iap-token": header("x-iap-token"),
        }))
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().fallback(any(handler)))
            .await
            .unwrap();
    });
    addr
}

struct Harness {
    proxy: SocketAddr,
    _dir: tempfile::TempDir,
}

/// Build a policy file with `profile add`, repoint it at the mock, and serve it.
///
/// The rewrite is deliberately narrow: only the host of each `base_url` moves.
/// Paths, credential scheme and every ACL rule are exactly what the profile
/// wrote, so what the test exercises is the profile and not a fixture.
async fn harness_from_profiles(specs: &[(&str, AddOptions)], upstream: SocketAddr) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("iap.toml");
    let audit_path = dir.path().join("audit.jsonl");

    agent_iap::init::init(&agent_iap::init::InitOptions {
        path: path.clone(),
        agent: "workflow-agent".into(),
        secret: None,
        template: agent_iap::init::Template::Minimal,
        force: true,
    })
    .unwrap();

    for (id, options) in specs {
        let profile = profiles::get(id).unwrap();
        profiles::add(&path, &profile, options)
            .unwrap_or_else(|error| panic!("profile `{id}`: {error:#}"));
    }

    let text = std::fs::read_to_string(&path).unwrap();
    let mut config: Config = toml::from_str(&text).unwrap();
    for up in &mut config.upstreams {
        let mut url = url::Url::parse(&up.base_url).unwrap();
        url.set_scheme("http").unwrap();
        url.set_host(Some(&upstream.ip().to_string())).unwrap();
        url.set_port(Some(upstream.port())).unwrap();
        up.base_url = url.to_string();
    }
    config.audit.path = audit_path;
    config.audit.stderr = false;
    config.agents = vec![toml::from_str(&format!(
        r#"
id = "workflow-agent"
token_sha256 = "{}"
"#,
        agent_iap::identity::token_hash(AGENT_TOKEN)
    ))
    .unwrap()];
    config.validate().unwrap();

    let state = AppState::build(config, false).unwrap();
    state.log_startup().unwrap();

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

    Harness { proxy, _dir: dir }
}

/// Every harness in this file is about what a profile's *rules* do once they
/// are in force, so it asks for them: `grant` is what writes them, and without
/// it an enrolment writes the service and nothing else. `a_profile_grants_
/// nothing_on_its_own` below covers the default.
fn options(secret: &str) -> AddOptions {
    AddOptions {
        name: None,
        secret: Some(secret.into()),
        access: None,
        vars: vec![],
        agent: None,
        grant: true,
        dry_run: false,
    }
}

async fn call(harness: &Harness, method: &str, path: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .request(
            reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
            format!("http://{}{path}", harness.proxy),
        )
        .bearer_auth(AGENT_TOKEN)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = response.json().await.unwrap_or(Value::Null);
    (status, body)
}

/// A service-account key the proxy can actually sign with, pointed at the mock.
fn service_account_key(dir: &Path, token_url: &str) -> String {
    // Generated per test rather than checked in: a private key in the tree,
    // even a throwaway one, is a thing someone eventually reuses.
    let key = rsa_pkcs8_pem();
    let json = serde_json::json!({
        "type": "service_account",
        "project_id": "test",
        "private_key_id": "test-key-id",
        "private_key": key,
        "client_email": "sa@test.iam.gserviceaccount.com",
        "client_id": "1",
        "token_uri": token_url,
    });
    let path = dir.join("sa.json");
    std::fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();
    format!("file:{}", path.display())
}

/// Same approach as `service_account_e2e`: shell out to `openssl` for a
/// throwaway key rather than take a Rust RSA crate as a dependency. Generated
/// once per test binary, because 2048-bit keygen is not free.
fn rsa_pkcs8_pem() -> String {
    static PEM: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PEM.get_or_init(|| {
        let output = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ])
            .output()
            .expect("these tests need the `openssl` binary to mint a throwaway key");
        assert!(output.status.success(), "openssl genpkey failed");
        String::from_utf8(output.stdout).unwrap()
    })
    .clone()
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn cloudflare_reads_are_allowed_and_deletes_never_reach_the_network() {
    std::env::set_var("TEST_CF_TOKEN", "cf-real-token");
    let upstream = spawn_upstream().await;
    let mut opts = options("env:TEST_CF_TOKEN");
    opts.access = Some("ask-writes".into());
    opts.vars = vec!["account_id=9a7b1c0d2e3f4a5b6c7d8e9f0a1b2c3d".into()];
    let harness = harness_from_profiles(&[("cloudflare", opts)], upstream).await;

    let (status, seen) = call(&harness, "GET", "/cloudflare/zones").await;
    assert_eq!(status, 200);
    // The upstream got the real token, and the agent's own token did not travel.
    assert_eq!(seen["authorization"], "Bearer cf-real-token");
    assert!(seen["x-iap-token"].is_null());

    // `ask-writes` denies DELETE outright, so this must not be a round trip
    // that merely returned an error — the upstream must never have been called.
    let (status, body) = call(&harness, "DELETE", "/cloudflare/zones/abc").await;
    assert_eq!(status, 403);
    assert!(
        body["path"].is_null(),
        "a denied DELETE reached the upstream: {body}"
    );
}

#[tokio::test]
async fn dataforseo_signs_with_the_login_and_holds_back_the_billed_endpoints() {
    std::env::set_var("TEST_DFS_PASSWORD", "dfs-real-password");
    let upstream = spawn_upstream().await;
    let mut opts = options("env:TEST_DFS_PASSWORD");
    opts.vars = vec!["login=seo@example.com".into()];
    let harness = harness_from_profiles(&[("dataforseo", opts)], upstream).await;

    let (status, seen) = call(
        &harness,
        "POST",
        "/dataforseo/v3/serp/google/organic/task_post",
    )
    .await;
    assert_eq!(status, 200);
    let expected = base64_encode("seo@example.com:dfs-real-password");
    assert_eq!(seen["authorization"], format!("Basic {expected}"));

    // The `live` endpoints bill more, so the default level parks them for a
    // human. Nobody is watching this queue, so `ask` resolves to a denial —
    // which is the safe end of that decision, and the assertion that matters.
    let (status, _) = call(
        &harness,
        "POST",
        "/dataforseo/v3/serp/google/organic/live/advanced",
    )
    .await;
    assert_eq!(status, 403, "a billed `live` call was let through unasked");
}

#[tokio::test]
async fn semrush_appends_the_key_to_a_url_the_agent_wrote_without_it() {
    std::env::set_var("TEST_SEMRUSH_V3_KEY", "semrush-real-v3-key");
    let upstream = spawn_upstream().await;
    let harness =
        harness_from_profiles(&[("semrush", options("env:TEST_SEMRUSH_V3_KEY"))], upstream).await;

    // v3 takes the key nowhere but the query string, and every analytics report
    // is the same path with a different `type=`. Both are the reasons this
    // profile exists, and both are only observable at the upstream.
    let (status, seen) = call(
        &harness,
        "GET",
        "/semrush/?type=domain_ranks&domain=example.com",
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(seen["path"], "/");
    let query = seen["query"].as_str().unwrap();
    assert!(
        query.contains("key=semrush-real-v3-key"),
        "the proxy did not attach the key: {query}"
    );
    // The agent asked for a report without holding a key, and its own token did
    // not travel to Semrush.
    assert!(query.contains("type=domain_ranks"));
    assert!(seen["authorization"].is_null());
    assert!(seen["x-iap-token"].is_null());

    // Backlinks v3 is a second path on the same upstream, documented with the
    // trailing slash — the spelling a rule written as `/analytics/v1` alone
    // would miss.
    let (status, seen) = call(&harness, "GET", "/semrush/analytics/v1/?type=backlinks").await;
    assert_eq!(status, 200, "the v3 backlinks path is not reachable");
    assert_eq!(seen["path"], "/analytics/v1/");

    // Trends is a third, and it is a real path rather than a `type=`.
    let (status, _) = call(&harness, "GET", "/semrush/analytics/ta/api/v3/summary").await;
    assert_eq!(status, 200);

    // `read` is GET-only: creating a Site Audit campaign is a write, and the
    // default level must not reach the network with one.
    let (status, body) = call(&harness, "POST", "/semrush/management/v1/projects").await;
    assert_eq!(status, 403);
    assert!(
        body["path"].is_null(),
        "a Projects write reached the upstream: {body}"
    );
}

#[tokio::test]
async fn semrush_trends_is_its_own_upstream_on_the_same_v3_key() {
    std::env::set_var("TEST_SEMRUSH_TRENDS_KEY", "semrush-real-v3-key");
    let upstream = spawn_upstream().await;
    let harness = harness_from_profiles(
        &[("semrush-trends", options("env:TEST_SEMRUSH_TRENDS_KEY"))],
        upstream,
    )
    .await;

    // Trends hangs off `/analytics/ta/api/v3`, which lives in the base URL: the
    // agent writes the report name and nothing else. The key goes in the query
    // string here too, appended to the parameters the agent wrote.
    let (status, seen) = call(
        &harness,
        "GET",
        "/semrush-trends/summary?targets=example.com&display_date=2026-01-01",
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(seen["path"], "/analytics/ta/api/v3/summary");
    let query = seen["query"].as_str().unwrap_or_default();
    assert!(
        query.contains("key=semrush-real-v3-key"),
        "the proxy did not attach the key: {query}"
    );
    assert!(query.contains("targets=example.com"), "{query}");
    assert!(seen["x-iap-token"].is_null(), "{seen}");

    // The Trends API has no mutations, so the default level is GET and a write
    // does not reach the network.
    let (status, body) = call(&harness, "POST", "/semrush-trends/summary").await;
    assert_eq!(status, 403);
    assert!(
        body["path"].is_null(),
        "a write reached the upstream: {body}"
    );
}

#[tokio::test]
async fn semrush_v4_signs_with_apikey_and_keeps_the_version_prefix() {
    std::env::set_var("TEST_SEMRUSH_V4_KEY", "semrush-real-v4-key");
    let upstream = spawn_upstream().await;
    let mut opts = options("env:TEST_SEMRUSH_V4_KEY");
    opts.access = Some("ask-writes".into());
    let harness = harness_from_profiles(&[("semrush-v4", opts)], upstream).await;

    let (status, seen) = call(
        &harness,
        "GET",
        "/semrush-v4/backlinks/v1/links?url=example.com",
    )
    .await;
    assert_eq!(status, 200);
    // `Apikey`, not `Bearer` — the scheme a hand-written upstream gets wrong and
    // finds out about as an unexplained 401.
    assert_eq!(seen["authorization"], "Apikey semrush-real-v4-key");
    // The v4 surface hangs off `/apis/v4`, which lives in the base URL rather
    // than in every path an agent writes.
    assert_eq!(seen["path"], "/apis/v4/backlinks/v1/links");
    assert!(seen["x-iap-token"].is_null());

    // The Local APIs write. Nobody is watching the prompt, so `ask` resolves to
    // a denial, and DELETE never gets as far as asking.
    let (status, body) = call(&harness, "DELETE", "/semrush-v4/local/v1/locations/1").await;
    assert_eq!(status, 403);
    assert!(
        body["path"].is_null(),
        "a denied DELETE reached the upstream: {body}"
    );
}

#[test]
fn the_semrush_key_is_a_reference_in_the_policy_file_and_never_a_value() {
    // `query` auth is the one scheme that puts the credential in a URL, so it
    // is the one where a profile that resolved the reference too early would
    // leave a live key in a file people commit.
    let (dir, path) = minimal_policy();
    let profile = profiles::get("semrush").unwrap();
    profiles::add(&path, &profile, &options("op://Private/Semrush/key")).unwrap();

    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.contains("type = \"query\""));
    assert!(written.contains("param = \"key\""));
    assert!(written.contains("secret = \"op://Private/Semrush/key\""));
    drop(dir);
}

#[tokio::test]
async fn graylog_authenticates_the_token_as_the_user_and_never_writes_it_down() {
    std::env::set_var("TEST_GRAYLOG_TOKEN", "graylog-real-token");
    let upstream = spawn_upstream().await;
    let mut opts = options("env:TEST_GRAYLOG_TOKEN");
    opts.vars = vec!["host=graylog.example.com:9000".into()];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("iap.toml");
    agent_iap::init::init(&agent_iap::init::InitOptions {
        path: path.clone(),
        agent: "a".into(),
        secret: None,
        template: agent_iap::init::Template::Minimal,
        force: true,
    })
    .unwrap();
    let profile = profiles::get("graylog").unwrap();
    profiles::add(&path, &profile, &opts).unwrap();

    // The whole reason `username_secret` exists: the token is a reference in
    // the file, not a value, so the policy file stays committable.
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.contains("username_secret = \"env:TEST_GRAYLOG_TOKEN\""));
    assert!(
        !written.contains("graylog-real-token"),
        "the access token was written into the policy file"
    );

    let harness = harness_from_profiles(&[("graylog", opts)], upstream).await;
    let (status, seen) = call(&harness, "GET", "/graylog/streams").await;
    assert_eq!(status, 200);
    // Graylog's documented scheme is `<token>:token`, token in the user field.
    let expected = base64_encode("graylog-real-token:token");
    assert_eq!(seen["authorization"], format!("Basic {expected}"));
}

#[tokio::test]
async fn a_google_service_account_is_exchanged_for_a_token_the_agent_never_sees() {
    let upstream = spawn_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let key = service_account_key(dir.path(), &format!("http://{upstream}/token"));

    let harness =
        harness_from_profiles(&[("google-search-console", options(&key))], upstream).await;

    // A read that is a GET.
    let (status, seen) = call(
        &harness,
        "GET",
        "/google-search-console/webmasters/v3/sites",
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(seen["authorization"], "Bearer ya29.minted-by-the-proxy");

    // …and the read that is a POST. A GET-only "read" level would deny this,
    // and Search Console's actual search-analytics data would be unreachable
    // at the level named for reading it.
    let (status, seen) = call(
        &harness,
        "POST",
        "/google-search-console/webmasters/v3/sites/example.com/searchAnalytics/query",
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(seen["authorization"], "Bearer ya29.minted-by-the-proxy");

    // The `read` level does not grant sitemap submission.
    let (status, body) = call(
        &harness,
        "PUT",
        "/google-search-console/webmasters/v3/sites/example.com/sitemaps/x",
    )
    .await;
    assert_eq!(status, 403);
    assert!(body["path"].is_null());
}

#[tokio::test]
async fn one_service_account_fronts_search_console_and_analytics_separately() {
    let upstream = spawn_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let key = service_account_key(dir.path(), &format!("http://{upstream}/token"));

    let harness = harness_from_profiles(
        &[
            ("google-search-console", options(&key)),
            ("google-analytics-data", options(&key)),
        ],
        upstream,
    )
    .await;

    let (status, _) = call(
        &harness,
        "GET",
        "/google-search-console/webmasters/v3/sites",
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = call(
        &harness,
        "POST",
        "/google-analytics-data/v1beta/properties/1:runReport",
    )
    .await;
    assert_eq!(status, 200);

    // Two upstreams, two scope sets, one key — and the ACL keeps them apart, so
    // a GA4 path is not reachable through the Search Console grant.
    let (status, _) = call(
        &harness,
        "POST",
        "/google-search-console/v1beta/properties/1:runReport",
    )
    .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn two_accounts_of_one_service_are_kept_apart() {
    std::env::set_var("TEST_PH_MAIN", "ph-main-key");
    std::env::set_var("TEST_PH_CLIENT", "ph-client-key");
    let upstream = spawn_upstream().await;

    let mut main = options("env:TEST_PH_MAIN");
    main.name = Some("posthog-main".into());
    let mut client = options("env:TEST_PH_CLIENT");
    client.name = Some("posthog-client".into());

    let harness = harness_from_profiles(&[("posthog", main), ("posthog", client)], upstream).await;

    let (status, seen) = call(&harness, "GET", "/posthog-main/api/projects/").await;
    assert_eq!(status, 200);
    assert_eq!(seen["authorization"], "Bearer ph-main-key");

    let (status, seen) = call(&harness, "GET", "/posthog-client/api/projects/").await;
    assert_eq!(status, 200);
    assert_eq!(
        seen["authorization"], "Bearer ph-client-key",
        "the two accounts share one credential"
    );
}

/// A value for every variable a profile declares, for the tests that walk the
/// whole catalog.
///
/// A declared default is used in preference to a made-up string, because some
/// variables are a closed set rather than free text — a scheme is `https` or
/// `http` and nothing else, and `placeholder://host` is not a base URL any
/// proxy would load. Only a variable with no default gets the stand-in.
fn stand_in_vars(profile: &profiles::Profile) -> Vec<String> {
    profile
        .vars
        .iter()
        .map(|var| {
            let value = var.default.clone().unwrap_or_else(|| "placeholder".into());
            format!("{}={value}", var.name)
        })
        .collect()
}

#[tokio::test]
async fn every_mcp_profile_admits_the_handshake_it_would_otherwise_deny() {
    // `initialize` names no tool, so a tool-scoped rule never matches it. Every
    // MCP profile must therefore write a session rule, or the server it just
    // configured cannot be opened at all.
    for profile in profiles::catalog() {
        if profile.service.kind() != "mcp" {
            continue;
        }
        for level in &profile.access {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("iap.toml");
            agent_iap::init::init(&agent_iap::init::InitOptions {
                path: path.clone(),
                agent: "a".into(),
                secret: None,
                template: agent_iap::init::Template::Minimal,
                force: true,
            })
            .unwrap();

            let mut opts = options("env:UNUSED");
            opts.access = Some(level.name.clone());
            opts.vars = stand_in_vars(&profile);
            profiles::add(&path, &profile, &opts)
                .unwrap_or_else(|error| panic!("{}/{}: {error:#}", profile.id, level.name));

            let config: Config = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let acl = agent_iap::acl::Acl::compile(&config).unwrap();
            let request = agent_iap::acl::AccessRequest {
                agent: "any-agent".into(),
                kind: agent_iap::acl::Kind::Mcp,
                target: config.mcp_servers[0].name.clone(),
                method: "initialize".into(),
                // `initialize` names no tool, which is exactly why it is the
                // one that falls through a tool-scoped rule.
                path: String::new(),
            };
            assert_eq!(
                acl.evaluate(&request).action,
                agent_iap::config::Action::Allow,
                "{}/{}: `initialize` is not allowed, so the session never opens",
                profile.id,
                level.name
            );
        }
    }
}

/// What a Spotify app-only grant may and may not do, decided by the ACL the
/// profile writes rather than discovered as a status code.
///
/// The client-credentials token belongs to the app and to no listener, and
/// Spotify refuses several catalogue endpoints outright for apps registered
/// after November 2024. Neither is visible in a base URL, so the default level
/// names the endpoints that work — and a rule that granted `/v1/**` would be a
/// policy promising what the vendor will not serve.
#[test]
fn spotifys_default_grant_covers_the_catalogue_and_nothing_personal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("iap.toml");
    agent_iap::init::init(&agent_iap::init::InitOptions {
        path: path.clone(),
        agent: "a".into(),
        secret: None,
        template: agent_iap::init::Template::Minimal,
        force: true,
    })
    .unwrap();

    let profile = profiles::get("spotify").unwrap();
    let mut opts = options("op://Private/Spotify/secret");
    opts.vars = vec!["client_id=1a2b3c".into()];
    profiles::add(&path, &profile, &opts).unwrap();

    let config: Config = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    config.validate().unwrap();
    let acl = agent_iap::acl::Acl::compile(&config).unwrap();
    let allowed = |method: &str, request_path: &str| {
        acl.evaluate(&agent_iap::acl::AccessRequest {
            agent: "a".into(),
            kind: agent_iap::acl::Kind::Http,
            target: "spotify".into(),
            method: method.into(),
            path: request_path.into(),
        })
        .action
            == agent_iap::config::Action::Allow
    };

    assert!(allowed("GET", "/v1/search"));
    assert!(allowed("GET", "/v1/artists/0OdUWJ0sBjDrqHygGUXeCF"));
    assert!(
        allowed("GET", "/v1/markets"),
        "the probe has to be callable"
    );

    // A listener's own account, which this grant simply does not reach.
    assert!(!allowed("GET", "/v1/me"));
    assert!(!allowed("GET", "/v1/me/player"));
    // Restricted by Spotify for apps registered after November 2024, so the
    // level leaves them out rather than granting a 403.
    assert!(!allowed("GET", "/v1/audio-features/0OdUWJ0sBjDrqHygGUXeCF"));
    assert!(!allowed("GET", "/v1/recommendations"));
    assert!(!allowed("GET", "/v1/browse/featured-playlists"));
    // And nothing writes: there is no method on this token that could.
    assert!(!allowed("POST", "/v1/search"));
    assert!(!allowed("PUT", "/v1/me/player/play"));
}

/// The xAI grant an agent actually gets, decided by the ACL the profile writes
/// rather than discovered on a bill.
///
/// One key and one `/v1` prefix cover text generation, image generation and
/// video generation, and only the first is what "inference" means to the agent
/// being enrolled. Nothing in the base URL shows that split, so the rules have
/// to: a default level spelled `/v1/**` would be a per-asset spend granted by a
/// profile nobody read that far into.
#[test]
fn xais_default_grant_generates_text_and_no_assets() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("iap.toml");
    agent_iap::init::init(&agent_iap::init::InitOptions {
        path: path.clone(),
        agent: "a".into(),
        secret: None,
        template: agent_iap::init::Template::Minimal,
        force: true,
    })
    .unwrap();

    let profile = profiles::get("xai").unwrap();
    profiles::add(&path, &profile, &options("env:XAI_API_KEY")).unwrap();

    let config: Config = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    config.validate().unwrap();
    let acl = agent_iap::acl::Acl::compile(&config).unwrap();
    let allowed = |method: &str, request_path: &str| {
        acl.evaluate(&agent_iap::acl::AccessRequest {
            agent: "a".into(),
            kind: agent_iap::acl::Kind::Http,
            target: "xai".into(),
            method: method.into(),
            path: request_path.into(),
        })
        .action
            == agent_iap::config::Action::Allow
    };

    assert!(allowed("POST", "/v1/responses"));
    assert!(allowed("POST", "/v1/chat/completions"));
    assert!(allowed("POST", "/v1/tokenize-text"));
    // A `deferred` completion and a stored response are both collected by id
    // on a second request, so a grant that could only start one would spend
    // the tokens and never read the answer.
    assert!(allowed("GET", "/v1/chat/deferred-completion/1a2b3c"));
    assert!(allowed("GET", "/v1/responses/resp_1a2b3c"));
    assert!(allowed("GET", "/v1/models"));
    assert!(allowed("GET", "/v1/language-models/grok-4"));
    assert!(
        allowed("GET", "/v1/api-key"),
        "the probe has to be callable"
    );

    // Same key, same prefix, billed per asset: `all` reaches these and the
    // level an operator gets by default does not.
    assert!(!allowed("POST", "/v1/images/generations"));
    assert!(!allowed("POST", "/v1/images/edits"));
    assert!(!allowed("POST", "/v1/videos/generations"));
    // Reading a stored response back is a read; throwing it away is not.
    assert!(!allowed("DELETE", "/v1/responses/resp_1a2b3c"));
    // And nothing here manages the account or the keys.
    assert!(!allowed("POST", "/v1/api-key"));
}

#[test]
fn every_profile_produces_a_policy_file_the_proxy_would_load() {
    // A profile is only useful if what it writes survives the same `validate()`
    // the daemon runs at startup. Broken base URL, unknown auth key, empty rule
    // list — all of it fails here rather than on someone's first run.
    for profile in profiles::catalog() {
        for level in &profile.access {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("iap.toml");
            agent_iap::init::init(&agent_iap::init::InitOptions {
                path: path.clone(),
                agent: "a".into(),
                secret: None,
                template: agent_iap::init::Template::Minimal,
                force: true,
            })
            .unwrap();

            let mut opts = options("op://Vault/Item/field");
            opts.access = Some(level.name.clone());
            opts.vars = stand_in_vars(&profile);
            profiles::add(&path, &profile, &opts)
                .unwrap_or_else(|error| panic!("{}/{}: {error:#}", profile.id, level.name));

            let text = std::fs::read_to_string(&path).unwrap();
            let config: Config = toml::from_str(&text)
                .unwrap_or_else(|error| panic!("{}/{}: {error:#}", profile.id, level.name));
            config
                .validate()
                .unwrap_or_else(|error| panic!("{}/{}: {error:#}", profile.id, level.name));

            // The credential must survive as a *reference*. The only literal
            // any profile may write is a documented scheme constant, and the
            // only one in the catalog is Graylog's password.
            assert!(
                !text.contains("literal:op://"),
                "{}: a reference was wrapped in `literal:`",
                profile.id
            );
            for literal in text.match_indices("literal:") {
                let tail = &text[literal.0..];
                let value = tail
                    .trim_start_matches("literal:")
                    .split('"')
                    .next()
                    .unwrap();
                assert_eq!(
                    value, "token",
                    "{}: wrote an unexpected `literal:` into the policy file",
                    profile.id
                );
            }
        }
    }
}

#[test]
fn a_dry_run_writes_nothing_and_prints_what_it_would_have() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("iap.toml");
    agent_iap::init::init(&agent_iap::init::InitOptions {
        path: path.clone(),
        agent: "a".into(),
        secret: None,
        template: agent_iap::init::Template::Minimal,
        force: true,
    })
    .unwrap();
    let before = std::fs::read_to_string(&path).unwrap();

    let profile = profiles::get("cloudflare").unwrap();
    let mut opts = options("op://Vault/Cloudflare/token");
    opts.vars = vec!["account_id=9a7b1c0d2e3f4a5b6c7d8e9f0a1b2c3d".into()];
    opts.dry_run = true;
    let added = profiles::add(&path, &profile, &opts).unwrap();

    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    assert_eq!(added.name, "cloudflare");
    assert!(!added.rules.is_empty());
}

#[tokio::test]
async fn sentry_triage_resolves_an_issue_and_can_do_nothing_else() {
    std::env::set_var("TEST_SENTRY_TOKEN", "sntryu_real-token");
    let upstream = spawn_upstream().await;
    let mut opts = options("env:TEST_SENTRY_TOKEN");
    opts.access = Some("triage".into());
    opts.vars = vec!["region=de".into()];
    let harness = harness_from_profiles(&[("sentry", opts)], upstream).await;

    let (status, seen) = call(&harness, "GET", "/sentry/organizations/acme/issues/").await;
    assert_eq!(status, 200);
    assert_eq!(seen["authorization"], "Bearer sntryu_real-token");
    assert!(seen["x-iap-token"].is_null());

    // Resolving, ignoring and assigning are one PUT with different bodies, and
    // they are the whole point of the level.
    let (status, seen) = call(&harness, "PUT", "/sentry/organizations/acme/issues/4242/").await;
    assert_eq!(status, 200, "a triage agent cannot resolve an issue");
    assert_eq!(seen["method"], "PUT");

    // The same method one path over is a project setting, not a triage action.
    // `ask` with nobody watching resolves to a denial, which is the safe end.
    let (status, body) = call(&harness, "PUT", "/sentry/projects/acme/web/").await;
    assert_eq!(status, 403);
    assert!(
        body["path"].is_null(),
        "a project edit reached Sentry from the triage level: {body}"
    );

    // Deleting an issue is denied outright rather than parked for a human:
    // there is nothing to weigh, and the events are gone when it succeeds.
    let (status, body) = call(
        &harness,
        "DELETE",
        "/sentry/organizations/acme/issues/4242/",
    )
    .await;
    assert_eq!(status, 403);
    assert!(body["path"].is_null(), "a DELETE reached Sentry: {body}");
}

/// The same three levels front sentry.io and an install of your own, and the
/// issue rules cover the endpoint spelling an older self-hosted version has.
#[tokio::test]
async fn the_self_hosted_profile_is_the_hosted_one_with_a_different_host() {
    std::env::set_var("TEST_SENTRY_ONPREM", "onprem-token");
    let (dir, path) = minimal_policy();

    let mut hosted = options("env:TEST_SENTRY_ONPREM");
    hosted.vars = vec!["region=de".into()];
    profiles::add(&path, &profiles::get("sentry").unwrap(), &hosted).unwrap();

    let mut onprem = options("env:TEST_SENTRY_ONPREM");
    onprem.name = Some("sentry-onprem".into());
    onprem.vars = vec!["host=sentry.example.com".into()];
    profiles::add(
        &path,
        &profiles::get("sentry-self-hosted").unwrap(),
        &onprem,
    )
    .unwrap();

    let written = std::fs::read_to_string(&path).unwrap();
    // A region is a host, not a path: getting it wrong has to be visible in the
    // base URL rather than in a 401 an agent reports later.
    assert!(
        written.contains("base_url = \"https://de.sentry.io/api/0\""),
        "{written}"
    );
    // And an install of your own is the same API at your own address, `https`
    // unless the operator says otherwise.
    assert!(
        written.contains("base_url = \"https://sentry.example.com/api/0\""),
        "{written}"
    );
    // Both get the same probe, because it is the same API.
    assert_eq!(
        written.matches("verify_path = \"/organizations/\"").count(),
        2
    );
    drop(dir);

    // `triage` on a self-hosted upstream has to reach the project-scoped issue
    // endpoint too: a 9.x install predates the organization-wide one, so rules
    // that knew only the modern spelling would grant nothing there.
    let upstream = spawn_upstream().await;
    let mut opts = options("env:TEST_SENTRY_ONPREM");
    opts.access = Some("triage".into());
    opts.vars = vec!["host=sentry.example.com".into()];
    let harness = harness_from_profiles(&[("sentry-self-hosted", opts)], upstream).await;

    let (status, seen) = call(&harness, "PUT", "/sentry/projects/acme/web/issues/4242/").await;
    assert_eq!(
        status, 200,
        "the older project-scoped issue path is not reachable"
    );
    assert_eq!(seen["path"], "/api/0/projects/acme/web/issues/4242/");
}

/// A plain-HTTP install is reachable, and saying so is a decision the operator
/// makes rather than one the profile makes for them.
#[test]
fn a_self_hosted_sentry_without_tls_is_an_explicit_choice() {
    let (dir, path) = minimal_policy();
    let profile = profiles::get("sentry-self-hosted").unwrap();

    let mut opts = options("env:TEST_SENTRY_ONPREM");
    opts.vars = vec!["host=sentry.internal".into(), "scheme=http".into()];
    opts.dry_run = true;
    let plan = profiles::add(&path, &profile, &opts).unwrap().plan.unwrap();
    assert!(
        plan.contains("base_url = \"http://sentry.internal/api/0\""),
        "{plan}"
    );

    // …and the default is not that.
    let mut secure = options("env:TEST_SENTRY_ONPREM");
    secure.vars = vec!["host=sentry.internal".into()];
    secure.dry_run = true;
    let plan = profiles::add(&path, &profile, &secure)
        .unwrap()
        .plan
        .unwrap();
    assert!(
        plan.contains("base_url = \"https://sentry.internal/api/0\""),
        "{plan}"
    );
    drop(dir);
}

fn base64_encode(value: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(value)
}

// ---- `upstream add --profile` ---------------------------------------------
//
// The two used to be separate commands for one decision: `upstream add` asked
// for a base URL, a scheme and a set of ACL paths, and never mentioned that a
// profile with all three already existed. These drive the joined-up path
// through the real binary, because the refusals below are argument parsing and
// a library test would not see them.

fn minimal_policy() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("iap.toml");
    agent_iap::init::init(&agent_iap::init::InitOptions {
        path: path.clone(),
        agent: "workflow-agent".into(),
        secret: None,
        template: agent_iap::init::Template::Minimal,
        force: true,
    })
    .unwrap();
    (dir, path)
}

fn agent_iap(path: &Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_agent-iap"))
        .args(args)
        .args(["--config", path.to_str().unwrap()])
        .output()
        .unwrap()
}

#[test]
fn adding_an_upstream_can_start_from_a_profile() {
    let (_dir, path) = minimal_policy();

    let output = agent_iap(
        &path,
        &[
            "upstream",
            "add",
            "gh",
            "--profile",
            "github",
            "--secret",
            "env:GITHUB_TOKEN",
            "--grant",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config: Config = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let upstream = config
        .upstreams
        .iter()
        .find(|upstream| upstream.name == "gh")
        .expect("the profile writes the upstream under the name the command was given");
    assert_eq!(upstream.base_url, "https://api.github.com");
    assert!(
        config.acl.iter().any(|rule| rule.target == "gh"),
        "and, asked for with `--grant`, the rules that go with it — the part \
         `upstream add` never wrote"
    );
}

#[test]
fn a_dry_run_from_upstream_add_writes_nothing() {
    let (_dir, path) = minimal_policy();
    let before = std::fs::read_to_string(&path).unwrap();

    let output = agent_iap(
        &path,
        &[
            "upstream",
            "add",
            "gh",
            "--profile",
            "github",
            "--secret",
            "env:GITHUB_TOKEN",
            "--dry-run",
        ],
    );

    assert!(output.status.success());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("api.github.com"), "{stdout}");
}

/// Upstream and MCP names share one namespace, so writing an `[[mcp_servers]]`
/// entry from a command called `upstream add` would put a service somewhere
/// nobody goes looking for it.
#[test]
fn an_mcp_profile_is_refused_by_upstream_add_with_the_command_that_does_take_it() {
    let (_dir, path) = minimal_policy();

    let output = agent_iap(
        &path,
        &["upstream", "add", "ph", "--profile", "posthog-mcp"],
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("not an upstream"), "{stderr}");
    assert!(
        stderr.contains("profile add posthog-mcp --as ph"),
        "{stderr}"
    );
}

/// A credential flag next to `--profile` is an operator configuring something
/// that is not going to be read — which shows up as a 401 an hour later.
#[test]
fn a_credential_flag_the_profile_would_ignore_is_refused_rather_than_dropped() {
    let (_dir, path) = minimal_policy();

    let output = agent_iap(
        &path,
        &[
            "upstream",
            "add",
            "gh",
            "--profile",
            "github",
            "--secret",
            "env:GITHUB_TOKEN",
            "--header",
            "x-api-key",
        ],
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("supplies the credential scheme"),
        "{stderr}"
    );
}

#[test]
fn spelling_a_service_out_still_needs_a_base_url() {
    let (_dir, path) = minimal_policy();

    let output = agent_iap(&path, &["upstream", "add", "gh"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--base-url"), "{stderr}");
}

/// Cloudflare needs two things, and a token is only one of them.
///
/// Most of `client/v4` lives under `/accounts/<id>/…`, and an account-owned
/// token can only be verified at that account's own endpoint — so the profile
/// asks for the account, writes it into the probe `verify` will call, and
/// refuses the enrolment rather than writing an upstream nobody can check.
#[test]
fn cloudflare_asks_for_the_account_and_writes_the_probe_that_proves_the_token() {
    let (dir, path) = minimal_policy();
    let profile = profiles::get("cloudflare").unwrap();

    let complaint = match profiles::add(&path, &profile, &options("env:TEST_CF_TOKEN")) {
        Err(error) => format!("{error:#}"),
        Ok(added) => panic!("`{}` was enrolled without an account", added.name),
    };
    assert!(
        complaint.contains("account_id"),
        "the account is required and the error has to name it: {complaint}"
    );

    let mut opts = options("env:TEST_CF_TOKEN");
    opts.vars = vec!["account_id=9a7b1c0d2e3f4a5b6c7d8e9f0a1b2c3d".into()];
    profiles::add(&path, &profile, &opts).unwrap();

    let written = std::fs::read_to_string(&path).unwrap();
    assert!(
        written
            .contains("verify_path = \"/accounts/9a7b1c0d2e3f4a5b6c7d8e9f0a1b2c3d/tokens/verify\""),
        "the account never reached the probe:\n{written}"
    );
    // The account is a path parameter, not a credential: it belongs in the
    // file in the clear, while the token stays a reference.
    assert!(written.contains("secret = \"env:TEST_CF_TOKEN\""));
    drop(dir);
}

/// A probe is a promise about what will be written, so the dry run has to make
/// the same one.
#[test]
fn the_probe_shows_up_in_a_dry_run_before_anything_is_written() {
    let (dir, path) = minimal_policy();
    let profile = profiles::get("dataforseo").unwrap();
    let mut opts = options("env:TEST_DFS_PASSWORD");
    opts.vars = vec!["login=v@example.com".into()];
    opts.dry_run = true;

    let added = profiles::add(&path, &profile, &opts).unwrap();
    let plan = added.plan.expect("a dry run renders a plan");
    assert!(
        plan.contains("verify_path = \"/v3/appendix/user_data\""),
        "the plan does not show the probe the write would add:\n{plan}"
    );
    drop(dir);
}
