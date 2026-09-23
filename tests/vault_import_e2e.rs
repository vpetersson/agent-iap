//! Getting a policy off the vault, and what it costs while it is still on one.
//!
//! agent-iap reads an `op://` reference by running `op`, and 1Password's
//! desktop app authorizes a *process*. Every process that needs a credential is
//! therefore a dialogue: the daemon at startup and on each reload that means
//! it, `check`, `verify`, and the MCP bridge the agent spawns fresh for every
//! session. Batching made each of those one dialogue instead of several. It
//! could not make them none, because the credential lived somewhere that asks.
//!
//! `secret import` is the way out: read the lot once, keep them in agent-iap's
//! own store, repoint the file. These count the `op` processes on both sides of
//! that, through the real binary, with `op` replaced by a stand-in that writes
//! down every time it is run (SIRI-205).

use std::path::{Path, PathBuf};
use std::process::Command;

fn iap(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agent-iap"))
        .args(args)
        .env("IAP_CONFIG_DIR", home.join("config"))
        .env("IAP_STATE_DIR", home.join("state"))
        .env("IAP_NO_CLIPBOARD", "1")
        .output()
        .unwrap()
}

fn out(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// A stand-in `op` that answers both ways the real one is asked, and records
/// every invocation — one line per process, which is one dialogue per line.
#[cfg(unix)]
fn recording_op(dir: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let op = dir.join("op");
    let calls = dir.join("op-calls");
    std::fs::write(
        &op,
        format!(
            "#!/bin/sh\n\
             echo \"$1\" >> {}\n\
             case \"$1\" in\n\
             read) printf 'value-for-%s' \"$3\" ;;\n\
             inject) sed -E 's/\\{{\\{{ ([^}}]*) \\}}\\}}/value-for-\\1/g' ;;\n\
             *) exit 2 ;;\n\
             esac\n",
            calls.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
    (op, calls)
}

#[cfg(unix)]
fn dialogues(calls: &Path) -> usize {
    std::fs::read_to_string(calls)
        .map(|text| text.lines().count())
        .unwrap_or(0)
}

/// Five services behind four vault items, one of them shared — the shape of
/// the policy this was reported against.
#[cfg(unix)]
fn policy(dir: &Path, op: &Path) -> PathBuf {
    let path = dir.join("iap.toml");
    std::fs::write(
        &path,
        format!(
            r#"# A comment that has to survive the rewrite.
[server]
op_binary = "{op}"

[audit]
path = "{audit}"
stderr = false

[[agents]]
id = "claude-code"
token_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

# The one two services share.
[[upstreams]]
name = "dataforseo"
base_url = "https://api.dataforseo.com"
auth = {{ type = "bearer", secret = "op://Private/DataForSEO/api-token" }}

[[upstreams]]
name = "cloudflare"
base_url = "https://api.cloudflare.com"
auth = {{ type = "bearer", secret = "op://Private/Cloudflare Analytics Token/password" }}

[[upstreams]]
name = "sentry"
base_url = "https://sentry.io"
auth = {{ type = "bearer", secret = "op://Private/Sentry agent-iam/password" }}

[[mcp_servers]]
name = "semrush"
transport = "stdio"
command = "npx"
args = ["-y", "semrush-mcp"]
env = {{ SEMRUSH_TOKEN = "op://Private/semrush-token/password", SHARED = "op://Private/DataForSEO/api-token" }}

[[acl]]
name = "ask-everything"
action = "ask"
"#,
            op = op.display(),
            audit = dir.join("audit.jsonl").display(),
        ),
    )
    .unwrap();
    path
}

/// The whole point, in one number: after importing, nothing runs `op` at all.
#[cfg(unix)]
#[test]
fn importing_takes_the_policy_off_the_vault_for_good() {
    let home = tempfile::tempdir().unwrap();
    let (op, calls) = recording_op(home.path());
    let path = policy(home.path(), &op);
    let config = path.display().to_string();

    // Before: `check` reads every reference — in one process, but a process.
    let checked = iap(home.path(), &["check", "--config", &config]);
    assert!(checked.status.success(), "{}", out(&checked));
    assert_eq!(
        dialogues(&calls),
        1,
        "`check` asked 1Password once per reference"
    );

    let imported = iap(home.path(), &["secret", "import", "--config", &config]);
    assert!(imported.status.success(), "{}", out(&imported));
    let said = out(&imported);
    assert!(said.contains("Stored 4 credential(s)"), "{said}");
    assert!(said.contains("repointed 5 reference(s)"), "{said}");

    // One process for the migration, however many credentials it moved.
    assert_eq!(
        dialogues(&calls),
        2,
        "the import should be one `op`, on top of the `check` above"
    );

    // After: nothing asks. Not `check`, not `list`, not anything.
    std::fs::remove_file(&calls).unwrap();
    for args in [
        vec!["check", "--config", &config],
        vec!["list", "--config", &config],
    ] {
        let output = iap(home.path(), &args);
        assert!(output.status.success(), "{:?}: {}", args, out(&output));
    }
    assert_eq!(
        dialogues(&calls),
        0,
        "something still went to the vault after the import"
    );

    let rewritten = std::fs::read_to_string(&path).unwrap();
    assert!(
        !rewritten.contains("op://"),
        "a reference was left behind:\n{rewritten}"
    );
    // Both sites of the shared item, and the one inside an inline table.
    assert_eq!(
        rewritten.matches("iap://dataforseo").count(),
        2,
        "{rewritten}"
    );
    assert!(
        rewritten.contains(r#"SEMRUSH_TOKEN = "iap://semrush_token""#),
        "{rewritten}"
    );
    // Somebody's committed file comes back as their file.
    assert!(
        rewritten.contains("# A comment that has to survive the rewrite."),
        "{rewritten}"
    );
    assert!(
        rewritten.contains("# The one two services share."),
        "{rewritten}"
    );

    // And the values really are the ones the vault held.
    let listed = iap(home.path(), &["secret", "list", "--config", &config]);
    let listed = out(&listed);
    for name in ["dataforseo", "cloudflare", "sentry", "semrush_token"] {
        assert!(
            listed.contains(name),
            "`{name}` is not in the store:\n{listed}"
        );
    }
}

/// An item shared by two services is one credential, not two.
///
/// Importing it twice under two names would turn one rotation into two, and
/// the second one would be the one nobody remembers.
#[cfg(unix)]
#[test]
fn a_vault_item_two_services_share_is_imported_once() {
    let home = tempfile::tempdir().unwrap();
    let (op, _) = recording_op(home.path());
    let path = policy(home.path(), &op);
    let config = path.display().to_string();

    let planned = iap(
        home.path(),
        &["secret", "import", "--config", &config, "--dry-run"],
    );
    let said = out(&planned);
    assert!(said.contains("4 `op://` reference(s)"), "{said}");
    assert!(
        said.contains("upstream dataforseo auth.secret") && said.contains("mcp semrush env.SHARED"),
        "both sites should be listed under the one item:\n{said}"
    );
    // A dry run is a plan, so the file is untouched and nothing is stored.
    assert!(std::fs::read_to_string(&path).unwrap().contains("op://"));
}

/// Nothing is stored and nothing is rewritten when a reference will not read.
///
/// The half-done state is the bad one: a policy pointing at a store that has
/// half the credentials will not start, and the vault it used to point at is
/// no longer named anywhere.
#[cfg(unix)]
#[test]
fn a_vault_that_refuses_leaves_the_policy_exactly_as_it_was() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().unwrap();
    let (op, _) = recording_op(home.path());
    let path = policy(home.path(), &op);
    let config = path.display().to_string();
    let before = std::fs::read_to_string(&path).unwrap();

    // The vault stops answering between planning and reading.
    std::fs::write(
        &op,
        "#!/bin/sh\necho 'authorization prompt dismissed' >&2\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();

    let refused = iap(home.path(), &["secret", "import", "--config", &config]);
    assert!(!refused.status.success(), "{}", out(&refused));
    let said = out(&refused);
    assert!(said.contains("nothing was stored"), "{said}");

    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        before,
        "the policy file was edited on a failed import"
    );
    let listed = iap(home.path(), &["secret", "list", "--config", &config]);
    assert!(
        !out(&listed).contains("dataforseo"),
        "a credential was stored on a failed import:\n{}",
        out(&listed)
    );
}

/// A policy with nothing in the vault says so, and does not run `op`.
#[cfg(unix)]
#[test]
fn a_policy_with_no_vault_references_is_left_alone() {
    let home = tempfile::tempdir().unwrap();
    let (op, calls) = recording_op(home.path());
    let path = home.path().join("iap.toml");
    std::fs::write(
        &path,
        format!(
            r#"
[server]
op_binary = "{}"

[audit]
path = "{}"
stderr = false

[[upstreams]]
name = "gh"
base_url = "https://api.github.com"
auth = {{ type = "bearer", secret = "env:AGENT_IAP_NOT_A_VAULT" }}
"#,
            op.display(),
            home.path().join("audit.jsonl").display(),
        ),
    )
    .unwrap();
    let config = path.display().to_string();
    let before = std::fs::read_to_string(&path).unwrap();

    let imported = iap(home.path(), &["secret", "import", "--config", &config]);
    assert!(imported.status.success(), "{}", out(&imported));
    assert!(
        out(&imported).contains("nothing to import"),
        "{}",
        out(&imported)
    );
    assert_eq!(dialogues(&calls), 0);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
}

/// Which build is this?
///
/// The question three rounds of SIRI-205 were spent unable to settle. With no
/// tagged release, every install is a build somebody made, and `2026.9.0` is
/// the same string for all of them — so "the fix is merged" and "the binary you
/// are running has it" could not be told apart by anyone, from either side.
#[test]
fn the_binary_says_what_it_was_built_from() {
    let home = tempfile::tempdir().unwrap();
    let version = out(&iap(home.path(), &["--version"]));

    assert!(version.contains(env!("CARGO_PKG_VERSION")), "{version}");
    // Built from this repository, so the build script had a git to ask.
    assert!(
        version.contains('(') && version.contains("built "),
        "a version with no commit and no date cannot answer the question it is \
         there for: {version}"
    );

    // And `check` says it before anything that can fail, because the run worth
    // identifying is the one that goes wrong.
    let path = home.path().join("iap.toml");
    std::fs::write(&path, "this is not toml {{{").unwrap();
    let checked = iap(
        home.path(),
        &["check", "--config", &path.display().to_string()],
    );
    assert!(!checked.status.success());
    assert!(
        out(&checked).contains("build       "),
        "the failing run did not say which build it was: {}",
        out(&checked)
    );
}
