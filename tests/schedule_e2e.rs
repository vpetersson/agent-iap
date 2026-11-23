//! A rule that applies only at certain hours, driven end to end.
//!
//! The claim spans the enrolment command that writes the window, the load that
//! parses it, the engine that weighs it against the clock, and the refusal an
//! agent reads when it calls at the wrong hour. So these write the policy with
//! the real binary, run a real proxy in front of a mock upstream, and ask it.
//!
//! The windows are placed relative to the current UTC hour, with hours of
//! margin either side, so a run at 59 minutes past is not a flaky one.

use agent_iap::config::Config;
use agent_iap::enroll::{self, AuthSpec};
use agent_iap::state::AppState;
use axum::extract::Request;
use axum::routing::any;
use axum::{Json, Router};
use chrono::Timelike;
use serde_json::Value;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// `HH:00-HH:00`, starting `from` hours after the current UTC hour.
fn window_from_now(from: i64, len: i64) -> String {
    let hour = |offset: i64| (chrono::Utc::now().hour() as i64 + offset).rem_euclid(24);
    format!("{:02}:00-{:02}:00", hour(from), hour(from + len))
}

fn agent_iap(path: &Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_agent-iap"))
        .args(args)
        .args(["--config", path.to_str().unwrap()])
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

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

/// Two upstreams, an agent that may reach both, and no rules yet.
fn policy(dir: &Path, upstream: SocketAddr) -> (PathBuf, String) {
    let path = dir.join("iap.toml");
    agent_iap::init::init(&agent_iap::init::InitOptions {
        path: path.clone(),
        template: agent_iap::init::Template::Minimal,
        force: true,
        ..Default::default()
    })
    .unwrap();
    let secret = dir.join("upstream.key");
    std::fs::write(&secret, "sk-upstream-real").unwrap();
    for name in ["backups", "warehouse"] {
        enroll::add_upstream(
            &path,
            name,
            &format!("http://{upstream}"),
            &AuthSpec::Header {
                header: "x-api-key".into(),
                secret: format!("file:{}", secret.display()),
                prefix: None,
            },
            &[],
        )
        .unwrap();
    }
    let agent = enroll::add_agent(
        &path,
        "nightly",
        None,
        enroll::Reach::Only(&["backups".into(), "warehouse".into()]),
    )
    .unwrap();
    (path, agent.token)
}

async fn serve(path: &Path, audit: PathBuf) -> SocketAddr {
    let mut config: Config = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    config.audit.path = audit;
    config.audit.stderr = false;
    config.validate().unwrap();
    let state = AppState::build(config, false).unwrap();
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

async fn get(proxy: SocketAddr, token: &str, target: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .get(format!("http://{proxy}/{target}/v1/dump"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_rule_lets_the_agent_in_during_its_window_and_says_when_it_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = spawn_upstream().await;
    let (path, token) = policy(dir.path(), upstream);

    let shut = window_from_now(4, 2);
    let open = window_from_now(-1, 3);
    for (name, target, hours) in [
        ("nightly-backup", "backups", shut.as_str()),
        ("business-hours", "warehouse", open.as_str()),
    ] {
        let output = agent_iap(
            &path,
            &[
                "acl",
                "add",
                "--name",
                name,
                "--agent",
                "nightly",
                "--kind",
                "http",
                "--target",
                target,
                "--methods",
                "GET",
                "--paths",
                "/v1/**",
                "--action",
                "allow",
                "--days",
                "mon-sun",
                "--hours",
                hours,
                "--tz",
                "UTC",
            ],
        );
        assert!(output.status.success(), "{}", text(&output.stderr));
        let said = text(&output.stdout);
        assert!(
            said.contains(&format!("It applies only {hours} UTC")),
            "the command says when the rule it wrote applies:\n{said}"
        );
    }
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(
        written.contains(&format!(
            "schedule = {{ days = [\"mon-sun\"], hours = [\"{shut}\"], tz = \"UTC\" }}"
        )),
        "one inline table under the rule, in the operator's own words:\n{written}"
    );

    let audit = dir.path().join("audit.jsonl");
    let proxy = serve(&path, audit.clone()).await;

    let (status, body) = get(proxy, &token, "warehouse").await;
    assert_eq!(status, 200, "inside its window the rule allows: {body}");

    let (status, body) = get(proxy, &token, "backups").await;
    assert_eq!(
        status, 403,
        "outside its window the rule decides nothing: {body}"
    );
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("`nightly-backup` applies only") && message.contains(&shut),
        "the refusal names the rule that would have allowed it, and when:\n{message}"
    );
    assert!(message.contains("closed, opens in"), "{message}");

    // And the audit log carries the same sentence, so the question "why was
    // this refused at 06:00" is answerable after the fact too.
    let log = std::fs::read_to_string(&audit).unwrap();
    let refused: Vec<Value> = log
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|record| record["target"] == "backups")
        .collect();
    assert_eq!(refused.len(), 1, "{log}");
    assert!(
        refused[0]["error"]
            .as_str()
            .is_some_and(|error| error.contains("`nightly-backup` applies only")),
        "{log}"
    );

    // The rule list shows both, with where each window stands right now.
    let listed = text(&agent_iap(&path, &["list", "acl"]).stdout);
    assert!(listed.contains("WHEN"), "{listed}");
    assert!(listed.contains("(closed, opens in"), "{listed}");
    assert!(listed.contains("(open, closes in"), "{listed}");
}

#[test]
fn a_window_without_a_zone_is_refused_and_the_file_is_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("iap.toml");
    agent_iap::init::init(&agent_iap::init::InitOptions {
        path: path.clone(),
        template: agent_iap::init::Template::Minimal,
        force: true,
        ..Default::default()
    })
    .unwrap();
    let before = std::fs::read(&path).unwrap();

    let output = agent_iap(
        &path,
        &[
            "acl",
            "add",
            "--target",
            "x",
            "--action",
            "deny",
            "--hours",
            "03:00-05:00",
        ],
    );
    assert!(!output.status.success());
    let said = text(&output.stderr);
    assert!(said.contains("needs `tz`"), "{said}");
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn a_bad_window_in_the_file_stops_the_load_on_its_own_line() {
    let error = toml::from_str::<Config>(
        r#"
[[acl]]
target = "backups"
action = "allow"
schedule = { hours = ["03:00-25:00"], tz = "UTC" }
"#,
    )
    .expect_err("25:00 is not an hour")
    .to_string();
    assert!(error.contains("25:00"), "{error}");
    assert!(error.contains("line 5"), "it points at the line: {error}");
}
