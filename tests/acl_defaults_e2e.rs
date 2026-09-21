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
//! The same shape turned up once more on `agent-iap agent add`. An agent's
//! `targets` is the coarse gate *in front of* the ACL, an omitted one means
//! every upstream and every MCP server the proxy fronts — and it was what a
//! bare `agent add` wrote. Same bug, one command over: the widest thing the
//! flag can mean, handed out for saying nothing.
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
    // The floor behind it. `init` writes `ask`, so an uncovered request is a
    // question rather than a silence — the rule above is what must not be an
    // `allow` in front of it.
    assert_eq!(config.acl_default.action, Action::Ask);
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

/// The reported bug, one command over.
#[test]
fn enrolling_an_agent_with_nothing_but_defaults_does_not_hand_it_every_target() {
    let (_dir, path) = minimal_policy();

    let output = agent_iap(&path, &["agent", "add", "ci-runner"]);

    assert!(
        !output.status.success(),
        "a bare `agent add` must not write the widest grant in the file"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--target"), "{stderr}");
    assert!(stderr.contains("--any-target"), "{stderr}");
    assert!(
        policy(&path).agents.iter().all(|a| a.id != "ci-runner"),
        "and nothing was enrolled"
    );
}

/// Spelling it out still works, exactly as `--action allow` still does.
#[test]
fn an_explicit_any_target_is_still_the_blanket_grant() {
    let (_dir, path) = minimal_policy();

    let output = agent_iap(&path, &["agent", "add", "ci-runner", "--any-target"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let agent = policy(&path)
        .agents
        .into_iter()
        .find(|a| a.id == "ci-runner")
        .expect("enrolled");
    assert!(
        agent.targets.is_empty(),
        "an absent `targets` is how the file has always spelled `any`"
    );
    // And the operator is told, rather than finding out from `list agents`.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("every upstream and MCP server"), "{stdout}");
}

/// The narrow spelling is the one that needs no extra flag.
#[test]
fn naming_a_target_needs_nothing_else() {
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
            "none",
        ],
    )
    .status
    .success());

    let output = agent_iap(
        &path,
        &["agent", "add", "ci-runner", "--target", "anthropic"],
    );

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let agent = policy(&path)
        .agents
        .into_iter()
        .find(|a| a.id == "ci-runner")
        .expect("enrolled");
    assert_eq!(agent.targets, vec!["anthropic".to_string()]);
}

/// Reading is unchanged, so every policy file already written goes on meaning
/// what it meant. `check` is where an existing blanket grant becomes visible
/// rather than a thing you have to know to go and look for.
#[test]
fn check_names_the_agents_that_already_hold_a_blanket_grant() {
    let (_dir, path) = minimal_policy();
    assert!(agent_iap(&path, &["agent", "add", "wide", "--any-target"])
        .status
        .success());

    let stdout = String::from_utf8_lossy(&agent_iap(&path, &["check"]).stdout).into_owned();

    assert!(stdout.contains("may address every target"), "{stdout}");
    assert!(stdout.contains("wide"), "{stdout}");
}

/// The state the console's screenshot was taken in, reached the way it was
/// actually reached: `init`, then services, and no rule written yet.
///
/// The fallthrough is the entire policy at that point, so what it says decides
/// whether an operator sitting in front of the console sees the request or a
/// silence. `deny` there was the reported bug — agents enrolled, upstreams
/// enrolled, every call refused by `<default>`, nothing ever reaching the
/// queue. `acl reset` had already been changed to write `ask`; the file this
/// starts from never went through a reset.
#[test]
fn a_policy_with_services_but_no_rules_asks_rather_than_refusing_in_silence() {
    let (_dir, path) = minimal_policy();

    assert!(agent_iap(
        &path,
        &[
            "upstream",
            "add",
            "github",
            "--base-url",
            "https://api.github.com",
            "--auth",
            "bearer",
            "--secret",
            "env:GITHUB_TOKEN",
        ],
    )
    .status
    .success());
    assert!(
        agent_iap(&path, &["agent", "add", "claude", "--target", "github"])
            .status
            .success()
    );

    let config = policy(&path);
    assert!(config.acl.is_empty(), "nobody has written a rule yet");

    // Weighed by the engine that weighs it in production rather than read off
    // the file: this is the decision the proxy makes for the agent's first call.
    let acl = Acl::compile(&config).unwrap();
    let decision = acl.evaluate(&AccessRequest::http(
        "claude",
        "github",
        "GET",
        "/repos/acme/api",
    ));
    assert_eq!(
        decision.action,
        Action::Ask,
        "a request nothing covers must reach a human, not a `<default>` refusal"
    );
}

/// And where the file does say `deny` with nothing that can ask — an existing
/// policy, or one written that way on purpose — the tools say so instead of
/// leaving it to be worked out from the audit log.
#[test]
fn check_says_when_a_policy_can_never_ask() {
    let (_dir, path) = minimal_policy();
    assert!(agent_iap(&path, &["acl", "reset", "--deny", "--yes"])
        .status
        .success());

    let stdout = String::from_utf8_lossy(&agent_iap(&path, &["check"]).stdout).into_owned();

    assert!(
        stdout.contains("nothing in this policy can ask"),
        "{stdout}"
    );
    assert!(
        stdout.contains("acl reset"),
        "and how to change it: {stdout}"
    );

    // The inverse, so the warning cannot become something `check` always says.
    assert!(agent_iap(&path, &["acl", "reset", "--yes"])
        .status
        .success());
    let stdout = String::from_utf8_lossy(&agent_iap(&path, &["check"]).stdout).into_owned();
    assert!(!stdout.contains("can ask"), "{stdout}");
}
