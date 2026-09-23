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

/// What an enrolment says happens next is read out of the file, not asserted.
///
/// This said "No `[[acl]]` rules yet, so it is not reachable" and then offered
/// `--action allow` — wrong twice over on a file whose `acl_default` is `ask`.
/// An uncovered call is not refused there, it stops on a human; and the way out
/// it recommended was the standing grant that made SIRI-197 a bug report.
#[test]
fn an_enrolment_says_what_an_ungranted_call_will_actually_meet() {
    let (_dir, path) = minimal_policy();
    assert_eq!(policy(&path).acl_default.action, Action::Ask);

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
        stdout.contains("Nothing is granted"),
        "it says nothing was granted:\n{stdout}"
    );
    assert!(
        stdout.contains("stops at the `agent-iap run` console"),
        "and what `acl_default = ask` does about that:\n{stdout}"
    );
    assert!(
        !stdout.contains("not reachable"),
        "`ask` is not unreachable — a human is asked:\n{stdout}"
    );
    assert!(
        !stdout.contains("--action allow"),
        "and nothing here recommends a standing grant:\n{stdout}"
    );
    assert!(policy(&path).acl.is_empty(), "nor wrote one");
}

/// The same command against a policy that cannot ask. The sentence above would
/// be a promise this file cannot keep, so it is not the sentence printed.
#[test]
fn an_enrolment_onto_a_policy_that_cannot_ask_says_so() {
    let (_dir, path) = minimal_policy();
    assert!(agent_iap(&path, &["acl", "reset", "--deny", "--yes"])
        .status
        .success());

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
        stdout.contains("nothing in this policy can ask"),
        "the one diagnosis, at the moment it starts mattering:\n{stdout}"
    );
    assert!(
        stdout.contains("agent-iap acl reset"),
        "and the way out of it:\n{stdout}"
    );
    assert!(
        !stdout.contains("stops at the `agent-iap run` console"),
        "which is exactly what this policy will not do:\n{stdout}"
    );
}

/// The reported bug: enrolling a service granted standing access to it.
///
/// `upstream add --profile github` wrote `allow GET /** on github for *` beside
/// the upstream, so the first call an agent made went straight through with the
/// real credential attached and nobody asked — on a proxy whose `acl_default`
/// was `ask` and whose whole pitch is that it stops there.
#[test]
fn a_profile_enrols_a_service_without_granting_anything() {
    let (_dir, path) = minimal_policy();

    let output = agent_iap(
        &path,
        &[
            "upstream",
            "add",
            "github",
            "--profile",
            "github",
            "--secret",
            "env:GH_TOKEN",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config = policy(&path);
    assert!(
        config.upstream("github").is_some(),
        "the service is enrolled"
    );
    assert!(
        config.acl.is_empty(),
        "and nothing permits it: {:?}",
        config.acl
    );

    // Which is the decision the engine reaches, not just the file's shape.
    let decision = Acl::compile(&config)
        .unwrap()
        .evaluate(&AccessRequest::http(
            "claude-code",
            "github",
            "GET",
            "/user",
        ));
    assert_eq!(decision.action, Action::Ask);
}

/// `--grant` is the advanced option: the reviewed rules, because a human typed
/// the flag that writes them.
#[test]
fn a_profile_writes_its_rules_when_the_operator_asks_for_them() {
    let (_dir, path) = minimal_policy();

    let output = agent_iap(
        &path,
        &[
            "upstream",
            "add",
            "github",
            "--profile",
            "github",
            "--secret",
            "env:GH_TOKEN",
            "--grant",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config = policy(&path);
    let decision = Acl::compile(&config)
        .unwrap()
        .evaluate(&AccessRequest::http(
            "claude-code",
            "github",
            "GET",
            "/user",
        ));
    assert_eq!(decision.action, Action::Allow);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("github-reads"),
        "and says which rules it wrote"
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

/// The other half of "a default never widens access": the target.
///
/// `--action allow` is one word, and worth typing — but typed against the rest
/// of the defaults it wrote `allow * ** on *`, a standing grant covering every
/// service in the file and every one enrolled after it. The console wrote the
/// same rule from its widest row. Nothing writes it now: a grant has to name
/// what it grants.
#[test]
fn an_allow_that_names_no_target_is_refused() {
    let (_dir, path) = minimal_policy();

    for flags in [
        vec!["acl", "add", "--action", "allow"],
        vec!["acl", "add", "--target", "*", "--action", "allow"],
    ] {
        let output = agent_iap(&path, &flags);
        assert!(
            !output.status.success(),
            "`{}` wrote a grant naming no service",
            flags.join(" ")
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("--target"),
            "and the refusal says how to write it properly:\n{stderr}"
        );
        assert!(policy(&path).acl.is_empty(), "nothing was written");
    }

    // The same rule as a question is the policy this proxy is for.
    assert!(agent_iap(&path, &["acl", "add", "--action", "ask"])
        .status
        .success());
    assert_eq!(policy(&path).acl[0].action, Action::Ask);
}

/// The state, not the command that produced it.
///
/// A file that already carries a blanket grant — written by a console that
/// could still write one — permits the next service enrolled into it before
/// anybody is asked about it. "Nothing is granted to `linear` yet" was true of
/// the rules naming `linear` and false of the file, on the one line an operator
/// reads after enrolling.
#[test]
fn an_enrolment_onto_a_standing_grant_says_it_is_granted_already() {
    let (_dir, path) = minimal_policy();
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str(
        "\n[[acl]]\nname = \"console-allow-claude-code-*\"\nagent = \"claude-code\"\n\
         target = \"*\"\naction = \"allow\"\n",
    );
    std::fs::write(&path, text).unwrap();

    let output = agent_iap(
        &path,
        &[
            "upstream",
            "add",
            "linear",
            "--base-url",
            "https://api.linear.app",
            "--auth",
            "none",
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("granted already"),
        "the enrolment says what the first call will actually meet:\n{stdout}"
    );
    assert!(
        stdout.contains("console-allow-claude-code-*"),
        "and which rule is doing it:\n{stdout}"
    );
    assert!(
        !stdout.contains("Nothing is granted"),
        "never both:\n{stdout}"
    );

    // And the same diagnosis from the command whose whole job is the file.
    let check = agent_iap(&path, &["check"]);
    let reported = String::from_utf8_lossy(&check.stdout).into_owned()
        + &String::from_utf8_lossy(&check.stderr);
    assert!(
        reported.contains("allows every target"),
        "`check` names it too:\n{reported}"
    );
    assert!(
        reported.contains("agent-iap acl rm"),
        "and the way out:\n{reported}"
    );
}
