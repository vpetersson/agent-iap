//! Getting back to a policy you can reason about, in the ways that can be meant.
//!
//! A policy file grows. Rules get added to unblock something at four in the
//! afternoon, `acl_default` gets flipped to `allow` "just to test", an agent
//! ends up with a `*` it was never meant to keep. Getting back from that by
//! hand means being sure about *every* rule rather than about one.
//!
//! Three things, and the difference between them is what happens next:
//!
//! - `agent-iap acl reset` empties the list and leaves the default asking, so
//!   the traffic those rules were deciding arrives at a human instead and the
//!   list is rebuilt from what actually shows up. It edits the file, so the
//!   next `agent-iap run` starts from it.
//! - `agent-iap acl reset --deny` is the same wipe with nothing asked: every
//!   request refused, for keeps.
//! - `agent-iap run --lockdown` edits nothing and refuses everything for as
//!   long as that process runs, including anything an `ask` rule would
//!   otherwise have parked on a human.
//!
//! These drive the real binary where the behaviour under test is the command
//! line's, and the real ACL engine where it is the decision's.

use agent_iap::acl::{AccessRequest, Acl, LOCKDOWN};
use agent_iap::config::{Action, Config};
use std::path::{Path, PathBuf};

fn minimal_policy() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("iap.toml");
    agent_iap::init::init(&agent_iap::init::InitOptions {
        path: path.clone(),
        agent: "claude-code".into(),
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

fn policy(path: &Path) -> Config {
    toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// A file talked into saying yes, by the two routes it can be talked into it:
/// a default of `allow`, and rules on top of it.
fn opened_up() -> (tempfile::TempDir, PathBuf) {
    let (dir, path) = minimal_policy();
    for name in ["anthropic", "github"] {
        assert!(agent_iap(
            &path,
            &[
                "upstream",
                "add",
                name,
                "--base-url",
                "https://example.invalid",
                "--auth",
                "none",
            ],
        )
        .status
        .success());
        assert!(agent_iap(
            &path,
            &["acl", "add", "--target", name, "--action", "allow"],
        )
        .status
        .success());
    }
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replace("[acl_default]\naction = \"deny\"", "");
    std::fs::write(&path, text + "\n[acl_default]\naction = \"allow\"\n").unwrap();
    assert_eq!(policy(&path).acl.len(), 2);
    assert_eq!(policy(&path).acl_default.action, Action::Allow);
    (dir, path)
}

#[test]
fn a_reset_empties_the_list_and_leaves_the_default_asking() {
    let (_dir, path) = opened_up();

    let output = agent_iap(&path, &["acl", "reset", "--yes"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config = policy(&path);
    assert!(config.acl.is_empty(), "every rule is gone");
    assert_eq!(
        config.acl_default.action,
        Action::Ask,
        "and the default that decides in their absence asks"
    );

    // Weighed by the engine that will weigh it in production, rather than by
    // reading the file back and believing it. A `deny` here would be the bug
    // this is guarding: every one of these refused, and nobody asked.
    let acl = Acl::compile(&config).unwrap();
    for request in [
        AccessRequest::http("claude-code", "anthropic", "POST", "/v1/messages"),
        AccessRequest::http("claude-code", "github", "GET", "/repos/x"),
        AccessRequest::mcp("claude-code", "github", "tools/call", "create_issue"),
    ] {
        assert_eq!(acl.evaluate(&request).action, Action::Ask, "{request:?}");
    }
    assert!(acl.can_ask(), "so a console has something to draw");
}

/// The quiet half, for when the answer really is "nothing, and stop asking me".
#[test]
fn a_strict_reset_denies_the_same_requests_without_asking() {
    let (_dir, path) = opened_up();

    let output = agent_iap(&path, &["acl", "reset", "--deny", "--yes"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config = policy(&path);
    assert!(config.acl.is_empty());
    assert_eq!(config.acl_default.action, Action::Deny);

    let acl = Acl::compile(&config).unwrap();
    let request = AccessRequest::http("claude-code", "anthropic", "POST", "/v1/messages");
    assert_eq!(acl.evaluate(&request).action, Action::Deny);
    assert!(!acl.can_ask(), "and nothing will stop on a human");
}

/// What it took out, by name. This is the last place those rules exist, and
/// the operator's next move is putting some of them back.
#[test]
fn a_reset_says_what_it_removed() {
    let (_dir, path) = opened_up();

    let stdout =
        String::from_utf8_lossy(&agent_iap(&path, &["acl", "reset", "--yes"]).stdout).into_owned();

    assert!(stdout.contains("acl[0]"), "{stdout}");
    assert!(stdout.contains("acl[1]"), "{stdout}");
    assert!(
        stdout.contains("`allow`"),
        "the default it replaced:\n{stdout}"
    );
    assert!(
        stdout.contains("`ask`"),
        "and the one that replaced it:\n{stdout}"
    );
    assert!(
        stdout.contains("agent-iap acl add"),
        "and the way back:\n{stdout}"
    );
}

/// The services stay. A reset that also revoked every agent and forgot every
/// upstream would be one nobody reaches for — and the state it left behind
/// would take an afternoon to rebuild rather than a command.
#[test]
fn a_reset_touches_nothing_but_the_rules() {
    let (_dir, path) = opened_up();
    let before = policy(&path);

    assert!(agent_iap(&path, &["acl", "reset", "--yes"])
        .status
        .success());

    let after = policy(&path);
    assert_eq!(after.upstreams.len(), before.upstreams.len());
    assert_eq!(after.agents.len(), before.agents.len());
    assert_eq!(after.server.listen, before.server.listen);
}

/// Deleting every rule in the file is not something to do because a script
/// piped a stray newline in.
#[test]
fn a_reset_with_no_terminal_to_ask_at_refuses_rather_than_assuming() {
    let (_dir, path) = opened_up();

    let output = agent_iap(&path, &["acl", "reset"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--yes"),
        "and it names the way to: {stderr}"
    );
    assert_eq!(policy(&path).acl.len(), 2, "the file is untouched");
}

/// `agent-iap check` is what a deployment runs before restarting, so a reset
/// has to leave a file that passes it.
#[test]
fn the_file_a_reset_leaves_is_one_the_proxy_would_start_on() {
    let (_dir, path) = opened_up();
    assert!(agent_iap(&path, &["acl", "reset", "--yes"])
        .status
        .success());

    let output = agent_iap(&path, &["check"]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The other half. Lockdown decides nothing in the file and everything at
/// runtime, which is what makes it the one to reach for while something is
/// actively going wrong: no edit, no reload, no window in between.
#[test]
fn lockdown_refuses_what_the_file_grants_without_changing_the_file() {
    let (_dir, path) = opened_up();
    let before = std::fs::read_to_string(&path).unwrap();

    let acl = Acl::compile(&policy(&path)).unwrap();
    let request = AccessRequest::http("claude-code", "anthropic", "POST", "/v1/messages");
    assert_eq!(acl.evaluate(&request).action, Action::Allow);

    acl.set_lockdown(true);

    let stopped = acl.evaluate(&request);
    assert_eq!(stopped.action, Action::Deny);
    assert_eq!(
        stopped.rule_label(),
        LOCKDOWN,
        "and the audit log can tell this apart from a rule that denied"
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        before,
        "the policy file is the record of the policy, and this is not one"
    );

    // Which is what makes it liftable: the file still says what it said.
    acl.set_lockdown(false);
    assert_eq!(acl.evaluate(&request).action, Action::Allow);
}

/// `--lockdown` is a flag on `run`, so the one thing a test without a proxy
/// can hold is that it exists and is spelled that way.
#[test]
fn run_takes_the_lockdown_flag() {
    let (_dir, path) = minimal_policy();

    let stdout = String::from_utf8_lossy(&agent_iap(&path, &["run", "--help"]).stdout).into_owned();

    assert!(stdout.contains("--lockdown"), "{stdout}");
    assert!(stdout.contains("--no-bell"), "{stdout}");
}
