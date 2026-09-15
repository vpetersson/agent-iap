//! `agent-iap check` against a stand-in for the 1Password CLI.
//!
//! The interesting part of an `op://` reference is that a human named the vault,
//! the item and the field, so it has spaces in it. Nothing between the policy
//! file and `op` is a shell — the reference is one argument — and this is the
//! test that holds that true from the file all the way to the process.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// A fake `op` that echoes back the reference it was given, and exits non-zero
/// if it was handed anything other than exactly `read --no-newline <reference>`.
/// A reference that arrived split in two fails here rather than resolving to
/// half of itself.
fn stub_op(dir: &Path) -> PathBuf {
    let op = dir.join("op");
    std::fs::write(
        &op,
        "#!/bin/sh\n\
         [ \"$1\" = read ] || exit 2\n\
         [ \"$2\" = --no-newline ] || exit 2\n\
         [ $# -eq 3 ] || exit 3\n\
         printf 'resolved<%s>' \"$3\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
    op
}

fn check(path: &Path) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_agent-iap"))
        .args(["check", "--config", path.to_str().unwrap()])
        .env("IAP_NO_CLIPBOARD", "1")
        .output()
        .unwrap()
}

fn policy(dir: &Path, op: &Path, secret: &str) -> PathBuf {
    let path = dir.join("iap.toml");
    std::fs::write(
        &path,
        format!(
            r#"
[server]
listen = "127.0.0.1:0"
admin_listen = "127.0.0.1:0"
op_binary = "{op}"

[acl_default]
action = "deny"

[[upstreams]]
name = "anthropic"
base_url = "https://api.anthropic.com"
auth = {{ type = "header", header = "x-api-key", secret = "{secret}" }}
"#,
            op = op.display(),
        ),
    )
    .unwrap();
    path
}

#[test]
fn a_1password_reference_with_spaces_in_it_resolves_and_is_reported_whole() {
    let dir = tempfile::tempdir().unwrap();
    let op = stub_op(dir.path());
    let reference = "op://Private/Anthropic API/credential";
    let path = policy(dir.path(), &op, reference);

    let output = check(&path);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains(&format!("secrets     ok      {reference}")),
        "the reference should be reported exactly as it will be used:\n{stdout}"
    );
}

#[test]
fn space_around_a_reference_is_trimmed_rather_than_sent_to_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let op = stub_op(dir.path());
    let reference = "op://Private/Anthropic API/credential";
    // The way it gets written: a copy-paste that picked up a leading space.
    let path = policy(dir.path(), &op, &format!(" {reference} "));

    let output = check(&path);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "a stray space is a typo, not an unrecognised scheme:\n{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains(&format!("secrets     ok      {reference}")),
        "and the trimmed reference is what is reported:\n{stdout}"
    );
}

/// `check` resolves every reference, so it is the command most likely to be run
/// in a terminal somebody else can scroll back through — or in CI. `literal:`
/// is the one scheme that *is* the credential, and it is masked here exactly as
/// `agent-iap list` masks it.
#[test]
fn check_never_puts_an_inline_credential_on_the_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let op = stub_op(dir.path());
    let path = policy(dir.path(), &op, "literal:sk-live-the-real-thing");

    let output = check(&path);
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{printed}");
    assert!(printed.contains("literal:***"), "{printed}");
    assert!(
        !printed.contains("sk-live-the-real-thing"),
        "check leaked the credential: {printed}"
    );
}
