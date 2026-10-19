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

/// One policy, two 1Password accounts: the company one by default and a
/// personal one for a single upstream — the setup the report could not write.
///
/// The stand-in `op` writes down its whole command line and answers with the
/// account it was told to read from, so a credential read from the wrong
/// account would come back visibly wrong.
#[test]
fn references_in_two_1password_accounts_are_read_from_each_with_its_own_op() {
    let dir = tempfile::tempdir().unwrap();
    let op = dir.path().join("op");
    let calls = dir.path().join("op-calls");
    std::fs::write(
        &op,
        format!(
            "#!/bin/sh\n\
             echo \"$*\" >> '{calls}'\n\
             account=default\n\
             command=$1; shift\n\
             reference=\n\
             while [ $# -gt 0 ]; do\n\
               case \"$1\" in\n\
               --account) account=$2; shift 2 ;;\n\
               --no-newline) shift ;;\n\
               *) reference=$1; shift ;;\n\
               esac\n\
             done\n\
             case \"$command\" in\n\
             read) printf '%s@%s' \"$reference\" \"$account\" ;;\n\
             *) exit 2 ;;\n\
             esac\n",
            calls = calls.display(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();

    let path = dir.path().join("iap.toml");
    std::fs::write(
        &path,
        format!(
            r#"
[server]
listen = "127.0.0.1:0"
admin_listen = "127.0.0.1:0"
op_binary = "{op}"

[secrets]
op_account = "company.example.com"

[acl_default]
action = "deny"

[[upstreams]]
name = "company"
base_url = "https://api.example.com"
auth = {{ type = "bearer", secret = "op://Work/API/token" }}

[[upstreams]]
name = "github-public"
base_url = "https://api.github.com"
auth = {{ type = "bearer", secret = "op://Private/GitHub classic/token?account=my.1password.com" }}
"#,
            op = op.display(),
        ),
    )
    .unwrap();

    let output = check(&path);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // One reference per account is one `op read` per account, each told which.
    let mut invocations: Vec<String> = std::fs::read_to_string(&calls)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    invocations.sort();
    assert_eq!(
        invocations,
        vec![
            "read --no-newline op://Private/GitHub classic/token --account my.1password.com",
            "read --no-newline op://Work/API/token --account company.example.com",
        ],
        "`?account=` is agent-iap's, so it reaches `op` as `--account` and not in the reference"
    );

    // Both resolved, and `check` says which account each one needed.
    assert!(
        stdout.contains(
            "secrets     ok      op://Work/API/token  (1Password account `company.example.com`)"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "secrets     ok      op://Private/GitHub classic/token?account=my.1password.com"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains("1password   ok      `company.example.com` — 1 of 1 reference(s) read"),
        "{stdout}"
    );
    assert!(
        stdout.contains("1password   ok      `my.1password.com` — 1 of 1 reference(s) read"),
        "{stdout}"
    );
}
