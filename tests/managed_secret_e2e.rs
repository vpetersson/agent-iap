//! A credential with nowhere else to live, from the command that stores it to
//! the request that carries it.
//!
//! The failure this covers had no error at the point it bit — it had two, and
//! they pointed at each other. Typing a token where a reference goes was
//! refused for not being a reference, by a message that named `literal:VALUE`
//! as a spelling that would work; `literal:VALUE` was then refused for putting
//! the credential in a file meant to be committable, by a message that named
//! `op://`, `env:` and `file:`. An operator holding a read-only token and no
//! vault had been told, twice, to do something else, and there was no third
//! thing to do.
//!
//! So these run the whole way through the real binary: store a value, enrol an
//! upstream against it, resolve it the way startup does, and take it out again.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The binary, with its own config and state directories — so a test never
/// reads, and never writes, the store belonging to whoever is running it.
fn iap(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agent-iap"))
        .args(args)
        .env("IAP_CONFIG_DIR", home.join("config"))
        .env("IAP_STATE_DIR", home.join("state"))
        .env("IAP_NO_CLIPBOARD", "1")
        .output()
        .unwrap()
}

/// `secret set` reads the credential from stdin, because an argument would be
/// visible in `ps` and would stay in the shell history.
fn store(home: &Path, name: &str, value: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-iap"))
        .args(["secret", "set", name])
        .env("IAP_CONFIG_DIR", home.join("config"))
        .env("IAP_STATE_DIR", home.join("state"))
        .env("IAP_NO_CLIPBOARD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(value.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn out(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn store_path(home: &Path) -> PathBuf {
    home.join("state").join("secrets.toml")
}

const TOKEN: &str = "ghp_readonly_not_a_real_token";

/// The whole path, in the order an operator walks it.
#[test]
fn a_stored_credential_is_enrolled_resolved_and_kept_out_of_the_policy_file() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();

    assert!(iap(home, &["init", "--template", "minimal"])
        .status
        .success());

    let stored = store(home, "github-readonly", TOKEN);
    assert!(stored.status.success(), "{}", out(&stored));
    // The command tells the operator the reference to use, because a name they
    // just invented is no use to them as a name.
    assert!(
        out(&stored).contains("iap://github-readonly"),
        "{}",
        out(&stored)
    );

    // Enrolling against it is an ordinary enrolment: `iap://` is a reference
    // like any other, so nothing about the credential rules bends for it.
    let added = iap(
        home,
        &[
            "upstream",
            "add",
            "gh",
            "--base-url",
            "https://api.github.com",
            "--auth",
            "bearer",
            "--secret",
            "iap://github-readonly",
        ],
    );
    assert!(added.status.success(), "{}", out(&added));

    // The policy file holds the pointer and not the credential — the property
    // that makes `iap://` a reference rather than a `literal:` with a nicer
    // name, and the whole reason it is allowed where `literal:` is not.
    let policy = std::fs::read_to_string(home.join("config").join("iap.toml")).unwrap();
    assert!(policy.contains("iap://github-readonly"), "{policy}");
    assert!(
        !policy.contains(TOKEN),
        "the credential reached the policy file"
    );

    // And startup's own resolution finds it. `check` is the code path the proxy
    // runs before it binds, so a credential that resolves here is one that does
    // not surface as a 502 on the first live call.
    let checked = iap(home, &["check"]);
    assert!(checked.status.success(), "{}", out(&checked));
    assert!(
        out(&checked).contains("ok      iap://github-readonly"),
        "{}",
        out(&checked)
    );
    // `check` prints references, never credentials.
    assert!(!out(&checked).contains(TOKEN), "{}", out(&checked));
}

/// The refusal that had no way out. Whatever the parser offers as an accepted
/// spelling has to be a spelling the enrolment commands actually accept — this
/// is the assertion that the two messages cannot drift back into a loop.
#[test]
fn every_spelling_the_refusal_offers_is_one_that_enrols() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    assert!(iap(home, &["init", "--template", "minimal"])
        .status
        .success());

    let refused = iap(
        home,
        &[
            "upstream",
            "add",
            "gh",
            "--base-url",
            "https://api.github.com",
            "--auth",
            "bearer",
            "--secret",
            TOKEN,
        ],
    );
    assert!(!refused.status.success());
    let message = out(&refused);
    // Never the credential itself, however it is refused.
    assert!(!message.contains(TOKEN), "{message}");

    // `literal:` is the one spelling that cannot be offered here: it is refused
    // by every enrolment surface, so naming it sends the operator to a second
    // refusal rather than to a working command.
    assert!(
        !message.contains("literal:"),
        "the refusal still offers a spelling the next command refuses: {message}"
    );
    assert!(message.contains("iap://"), "{message}");

    // And the spelling it does offer gets all the way through.
    assert!(store(home, "gh-token", TOKEN).status.success());
    let added = iap(
        home,
        &[
            "upstream",
            "add",
            "gh",
            "--base-url",
            "https://api.github.com",
            "--auth",
            "bearer",
            "--secret",
            "iap://gh-token",
        ],
    );
    assert!(added.status.success(), "{}", out(&added));
}

/// A reference the store cannot answer fails where the file is read, not on the
/// first request — the same bar every other reference kind is held to.
#[test]
fn a_reference_to_nothing_stops_the_proxy_before_it_binds() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    assert!(iap(home, &["init", "--template", "minimal"])
        .status
        .success());
    assert!(store(home, "kept", TOKEN).status.success());

    // Enrol against the stored one, then take it away.
    assert!(iap(
        home,
        &[
            "upstream",
            "add",
            "gh",
            "--base-url",
            "https://api.github.com",
            "--auth",
            "bearer",
            "--secret",
            "iap://kept",
        ],
    )
    .status
    .success());

    // Removing it while the policy points at it is refused: a store that let go
    // of a credential the file names would be a proxy that stops starting, with
    // the command that caused it long gone from the scrollback.
    let refused = iap(home, &["secret", "rm", "kept"]);
    assert!(!refused.status.success(), "{}", out(&refused));
    assert!(out(&refused).contains("upstream `gh`"), "{}", out(&refused));

    // Forced, it goes — and `check` names what is now missing rather than
    // leaving it to be found as a 502.
    let forced = iap(home, &["secret", "rm", "kept", "--force"]);
    assert!(forced.status.success(), "{}", out(&forced));

    let checked = iap(home, &["check"]);
    assert!(!checked.status.success(), "{}", out(&checked));
    assert!(out(&checked).contains("iap://kept"), "{}", out(&checked));
    assert!(
        out(&checked).contains("agent-iap secret set kept"),
        "the failure has to say how to fix it: {}",
        out(&checked)
    );
}

/// The store holds credentials, so nothing that prints may print one and the
/// file it lives in is the operator's alone.
#[test]
fn the_store_is_owner_only_and_nothing_prints_what_is_in_it() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    assert!(iap(home, &["init", "--template", "minimal"])
        .status
        .success());
    assert!(store(home, "alpha", TOKEN).status.success());
    assert!(store(home, "beta", "another-secret-value").status.success());

    let listed = iap(home, &["secret", "list"]);
    assert!(listed.status.success(), "{}", out(&listed));
    let shown = out(&listed);
    assert!(shown.contains("alpha") && shown.contains("beta"), "{shown}");
    assert!(!shown.contains(TOKEN), "`secret list` printed a credential");
    assert!(!shown.contains("another-secret-value"), "{shown}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(store_path(home))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }
}

/// `echo token | agent-iap secret set …` is how a value gets piped, and a
/// credential with the shell's newline on the end is a 401 nobody can see.
#[test]
fn a_piped_value_does_not_keep_the_newline_the_shell_added() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    assert!(store(home, "piped", &format!("{TOKEN}\n")).status.success());

    let on_disk = std::fs::read_to_string(store_path(home)).unwrap();
    assert!(
        on_disk.contains(&format!("value = \"{TOKEN}\"")),
        "{on_disk}"
    );
}

/// Nothing is stored under a name that is plainly the credential, and the
/// refusal is not what puts it in the scrollback.
#[test]
fn a_credential_passed_as_the_name_is_refused_without_being_echoed() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let pasted = format!("sk-ant-{}", "x".repeat(96));
    let refused = store(home, &pasted, "value");
    assert!(!refused.status.success());
    assert!(!out(&refused).contains(&pasted), "{}", out(&refused));
    // Refused for being a credential rather than a name, and saying which of
    // the two the argument is for — not merely refused.
    assert!(
        out(&refused).contains("secret set <name>"),
        "{}",
        out(&refused)
    );
    assert!(!store_path(home).exists(), "something was written anyway");
}

/// `[server].secret_store` moves the store, and every command that touches it
/// has to follow — a `secret set` that wrote to the default while the daemon
/// read somewhere else would be a credential that is silently not there.
#[test]
fn the_commands_write_where_the_policy_file_says_the_store_is() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    assert!(iap(home, &["init", "--template", "minimal"])
        .status
        .success());

    let elsewhere = home.join("elsewhere").join("creds.toml");
    let policy_path = home.join("config").join("iap.toml");
    let policy = std::fs::read_to_string(&policy_path).unwrap().replace(
        "[server]",
        &format!("[server]\nsecret_store = \"{}\"", elsewhere.display()),
    );
    std::fs::write(&policy_path, policy).unwrap();

    assert!(store(home, "moved", TOKEN).status.success());
    assert!(
        elsewhere.exists(),
        "the store did not follow the policy file"
    );
    assert!(
        !store_path(home).exists(),
        "it was written to the default too"
    );

    // And it is read back from there, by the commands and by startup alike.
    assert!(out(&iap(home, &["secret", "list"])).contains("moved"));
    assert!(iap(
        home,
        &[
            "upstream",
            "add",
            "gh",
            "--base-url",
            "https://api.github.com",
            "--auth",
            "bearer",
            "--secret",
            "iap://moved",
        ],
    )
    .status
    .success());
    let checked = iap(home, &["check"]);
    assert!(checked.status.success(), "{}", out(&checked));
}
