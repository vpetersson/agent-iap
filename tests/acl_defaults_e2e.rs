//! What the enrolment commands write when you do not argue with them.
//!
//! The pitch for this proxy is "default deny, and prompt for the rest", and
//! `[acl_default]` holds up that half of it. The half that quietly did not was
//! `agent-iap acl add`: every one of its flags defaults to the widest thing it
//! can mean — every agent, every kind, every target, every method, every path —
//! and `--action` defaulted to `allow` on top of that. So the command you reach
//! for right after `upstream add`, run bare, appended one rule granting
//! everything to everyone, in front of the deny it was supposed to sit behind.
//!
//! These tests drive the real binary, because the defaults under test are
//! clap's rather than anything the library would see.

use agent_iap::acl::{AccessRequest, Acl};
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

/// The reported bug, as one command.
#[test]
fn a_rule_added_with_nothing_but_defaults_prompts_rather_than_grants() {
    let (_dir, path) = minimal_policy();

    let output = agent_iap(&path, &["acl", "add"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config = policy(&path);
    let rule = &config.acl[0];

    // The rule really is the unrestricted one — if some later change narrows
    // these, the assertion below stops being the interesting one and this says
    // so rather than passing for the wrong reason.
    assert_eq!(rule.agent, "*");
    assert_eq!(rule.kind, "*");
    assert_eq!(rule.target, "*");
    assert_eq!(rule.methods, vec!["*".to_string()]);
    assert_eq!(rule.paths, vec!["**".to_string()]);

    assert_eq!(
        rule.action,
        Action::Ask,
        "a bare `acl add` must not hand every agent every upstream"
    );
    assert_eq!(config.acl_default.action, Action::Deny);
}

/// And the decision that rule produces, weighed by the engine that will weigh
/// it in production: an agent calling an upstream stops on a human.
#[test]
fn that_default_rule_stops_a_real_request_on_a_human() {
    let (_dir, path) = minimal_policy();

    assert!(agent_iap(
        &path,
        &[
            "upstream",
            "add",
            "anthropic",
            "--base-url",
            "https://api.anthropic.com",
            "--auth",
            "header",
            "--header",
            "x-api-key",
            "--secret",
            "env:ANTHROPIC_API_KEY",
        ],
    )
    .status
    .success());
    assert!(agent_iap(&path, &["acl", "add"]).status.success());

    let acl = Acl::compile(&policy(&path)).unwrap();
    let decision = acl.evaluate(&AccessRequest::http(
        "claude-code",
        "anthropic",
        "POST",
        "/v1/messages",
    ));
    assert_eq!(decision.action, Action::Ask);
}

/// Spelling `allow` out still means allow. The fix is a changed default, not a
/// command that can no longer grant anything.
#[test]
fn an_explicit_allow_is_still_an_allow() {
    let (_dir, path) = minimal_policy();

    let output = agent_iap(
        &path,
        &[
            "acl",
            "add",
            "--target",
            "anthropic",
            "--methods",
            "POST",
            "--paths",
            "/v1/messages",
            "--action",
            "allow",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(policy(&path).acl[0].action, Action::Allow);
}

/// The commands that tell an operator how to open something up say `--action
/// allow` out loud, now that leaving it off no longer means allow. A hint that
/// does not do what its own sentence claims is worse than no hint.
#[test]
fn the_printed_next_step_spells_out_the_action_it_promises() {
    let (_dir, path) = minimal_policy();

    let output = agent_iap(
        &path,
        &[
            "upstream",
            "add",
            "anthropic",
            "--base-url",
            "https://api.anthropic.com",
            "--auth",
            "none",
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Allow something with"),
        "the hint is still printed:\n{stdout}"
    );
    assert!(
        stdout.contains("--action allow"),
        "and running it verbatim allows:\n{stdout}"
    );
}
