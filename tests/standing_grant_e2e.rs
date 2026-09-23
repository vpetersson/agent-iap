//! A service enrolled today is not inside a grant written yesterday.
//!
//! The reported failure (SIRI-186): `agent-iap upstream add stripe` on a policy
//! holding one `allow` rule with `target = "*"` — the shape the console's
//! widest approval row used to write from a single keystroke — and the new
//! service is in accept mode before anybody has seen it. The enrolment prints
//! "Nothing is granted to `stripe` yet", `check` says nothing, and the first
//! call goes upstream with the real credential attached while the approval
//! queue stays empty.
//!
//! Two halves, and both are needed. Nothing writes such a rule unasked any
//! more, and a file that already holds one says so — at the moment a service
//! walks into it, and in `check`.
//!
//! These drive the real binary, because what is under test is what an operator
//! reads.

use agent_iap::acl::{AccessRequest, Acl};
use agent_iap::config::{Action, Config};
use std::path::{Path, PathBuf};

fn policy_file() -> (tempfile::TempDir, PathBuf) {
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

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn policy(path: &Path) -> Config {
    toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The file an operator is left with by a console answer given before this
/// fix, or by any hand edit: one standing grant, about nothing in particular.
fn with_a_blanket_grant() -> (tempfile::TempDir, PathBuf) {
    let (dir, path) = policy_file();
    assert!(agent_iap(
        &path,
        &[
            "upstream",
            "add",
            "github",
            "--base-url",
            "https://example.invalid",
            "--auth",
            "none",
        ],
    )
    .status
    .success());
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        text + "\n[[acl]]\nname = \"console-allow-claude-code-*\"\nagent = \"claude-code\"\n\
                kind = \"*\"\ntarget = \"*\"\nmethods = [\"*\"]\npaths = [\"**\"]\n\
                action = \"allow\"\n",
    )
    .unwrap();
    (dir, path)
}

#[test]
fn enrolling_a_service_into_a_blanket_grant_says_so_instead_of_saying_nothing_is_granted() {
    let (_dir, path) = with_a_blanket_grant();

    let output = agent_iap(
        &path,
        &[
            "upstream",
            "add",
            "stripe",
            "--base-url",
            "https://example.invalid",
            "--auth",
            "none",
        ],
    );
    assert!(output.status.success(), "the service is still enrolled");
    let said = stdout(&output);

    assert!(
        said.contains("already allowed"),
        "the first call is not going to stop on a human:\n{said}"
    );
    assert!(
        said.contains("console-allow-claude-code-*"),
        "and it names the rule that did it:\n{said}"
    );
    assert!(
        said.contains("agent-iap acl rm 0"),
        "and the way out:\n{said}"
    );
    assert!(
        !said.contains("Nothing is granted to `stripe` yet"),
        "the sentence that was false:\n{said}"
    );

    // Weighed by the engine that will weigh it in production: this is what the
    // message is about.
    let acl = Acl::compile(&policy(&path)).unwrap();
    let call = AccessRequest::http("claude-code", "stripe", "POST", "/v1/charges");
    assert_eq!(acl.evaluate(&call).action, Action::Allow);

    // And the fix it printed is a fix.
    assert!(agent_iap(&path, &["acl", "rm", "0"]).status.success());
    let acl = Acl::compile(&policy(&path)).unwrap();
    assert_eq!(acl.evaluate(&call).action, Action::Ask);
}

/// `check` is what a deployment runs, and the one place a whole policy is
/// read out. A grant over services nobody has enrolled yet belongs in it.
#[test]
fn check_names_the_grants_that_are_not_about_any_service_in_the_file() {
    let (_dir, path) = with_a_blanket_grant();

    let said = stdout(&agent_iap(&path, &["check"]));

    assert!(
        said.contains("console-allow-claude-code-*"),
        "check is silent about it:\n{said}"
    );
    assert!(said.contains("acl rm 0"), "{said}");
}

/// The write side. `acl add` defaults every flag to the widest thing it can
/// mean, so `--action allow` and nothing else is one rule that grants every
/// service, now and later.
#[test]
fn acl_add_will_not_write_a_grant_over_services_that_are_not_in_the_file() {
    let (_dir, path) = policy_file();

    let output = agent_iap(&path, &["acl", "add", "--action", "allow"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--any-target"), "{stderr}");
    assert!(policy(&path).acl.is_empty(), "and wrote nothing");
}

/// Available, said out loud. The point is that it is a decision, not that it
/// is unavailable.
#[test]
fn the_blanket_grant_is_still_writable_when_it_is_named() {
    let (_dir, path) = policy_file();

    assert!(
        agent_iap(&path, &["acl", "add", "--action", "allow", "--any-target"],)
            .status
            .success()
    );

    assert_eq!(policy(&path).acl[0].target, "*");
    assert_eq!(policy(&path).acl[0].action, Action::Allow);
}

/// The refusal is about widening. A pattern that asks is this proxy doing the
/// thing it is for, and one that denies keeps a class of service out.
#[test]
fn a_pattern_that_asks_or_denies_is_written_without_argument() {
    let (_dir, path) = policy_file();

    for action in ["ask", "deny"] {
        assert!(
            agent_iap(&path, &["acl", "add", "--target", "*", "--action", action])
                .status
                .success(),
            "`{action}` over a pattern does not widen anything"
        );
    }

    assert_eq!(policy(&path).acl.len(), 2);
}
