//! Where the proxy keeps its own files when nobody names a path.
//!
//! The binary is installed once and run from wherever the operator happens to
//! be standing, so the current directory is not a place to keep a policy file
//! or an append-only log. It used to be: `agent-iap init` wrote `./iap.toml`
//! and the proxy wrote `./audit/` beside it, which meant `cd` somewhere else
//! and the same command was suddenly a different proxy — or, for anyone who
//! installed the binary into `~/.local/bin` and ran it from their home
//! directory, a scattering of state wherever they had last been working.
//!
//! So the defaults live under the user's own directories, and only an explicit
//! path or an `IAP_*` override moves them.
//!
//! Two directories rather than one, because the files age differently. The
//! policy file is configuration: small, hand-edited, reviewed, the sort of
//! thing that ends up in a dotfile repository. The audit log is state:
//! append-only, unbounded, and the last thing anyone wants synced to a second
//! machine. The XDG base directory spec separates those and so do we.
//!
//! |         | Linux, macOS, BSD                                        | Windows                  |
//! | ------- | -------------------------------------------------------- | ------------------------ |
//! | config  | `$XDG_CONFIG_HOME/agent-iap`, else `~/.config/agent-iap`  | `%APPDATA%\agent-iap`     |
//! | state   | `$XDG_STATE_HOME/agent-iap`, else `~/.local/state/agent-iap` | `%LOCALAPPDATA%\agent-iap` |
//!
//! macOS gets the XDG layout rather than `~/Library/Application Support`: this
//! is a terminal tool whose config file is meant to be read, edited and
//! version-controlled by hand, and `~/.config` is where the rest of a
//! developer's terminal tools already keep theirs.
//!
//! `IAP_CONFIG_DIR` and `IAP_STATE_DIR` override each directory outright, which
//! is how the unit file and the container image point the daemon at
//! `/var/lib/agent-iap` without depending on a home directory that
//! `ProtectHome=yes` has made unreachable anyway.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The directory name under whichever base directory applies.
pub const APP: &str = "agent-iap";

/// The policy file's name, in whichever directory holds it.
pub const CONFIG_FILE: &str = "iap.toml";

/// The audit log's name, when the policy file does not choose one.
pub const AUDIT_FILE: &str = "iap-audit.jsonl";

/// An environment lookup, so the resolution below can be tested against a fixed
/// environment instead of the process's — which the test harness shares with
/// every other test running at the same time.
type Lookup<'a> = &'a dyn Fn(&str) -> Option<OsString>;

fn process_env(key: &str) -> Option<OsString> {
    std::env::var_os(key)
}

/// Empty is unset. A variable exported as `IAP_STATE_DIR=` is a common way to
/// mean "I did not set this", and joining a path onto `XDG_STATE_HOME=` would
/// silently put the audit log at the filesystem root.
fn get(env: Lookup, key: &str) -> Option<OsString> {
    env(key).filter(|value| !value.is_empty())
}

/// The user's home, by whichever name this platform gives it.
fn home(env: Lookup) -> Option<PathBuf> {
    let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    get(env, key).map(PathBuf::from)
}

fn config_dir_in(env: Lookup) -> PathBuf {
    if let Some(dir) = get(env, "IAP_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(base) = get(env, "XDG_CONFIG_HOME") {
        return PathBuf::from(base).join(APP);
    }
    if cfg!(windows) {
        if let Some(base) = get(env, "APPDATA") {
            return PathBuf::from(base).join(APP);
        }
        return match home(env) {
            Some(home) => home.join("AppData").join("Roaming").join(APP),
            None => PathBuf::new(),
        };
    }
    match home(env) {
        Some(home) => home.join(".config").join(APP),
        // No home to put it under — a container built `FROM scratch`, a daemon
        // whose user has none. Relative paths fall back to the old behaviour
        // rather than to somebody else's absolute directory.
        None => PathBuf::new(),
    }
}

fn state_dir_in(env: Lookup) -> PathBuf {
    if let Some(dir) = get(env, "IAP_STATE_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(base) = get(env, "XDG_STATE_HOME") {
        return PathBuf::from(base).join(APP);
    }
    if cfg!(windows) {
        if let Some(base) = get(env, "LOCALAPPDATA") {
            return PathBuf::from(base).join(APP);
        }
        return match home(env) {
            Some(home) => home.join("AppData").join("Local").join(APP),
            None => PathBuf::new(),
        };
    }
    match home(env) {
        Some(home) => home.join(".local").join("state").join(APP),
        None => PathBuf::new(),
    }
}

/// Where the policy file lives.
pub fn config_dir() -> PathBuf {
    config_dir_in(&process_env)
}

/// Where the audit log, the diagnostics log and the control-plane token live.
pub fn state_dir() -> PathBuf {
    state_dir_in(&process_env)
}

/// The user-level policy file, whether or not it exists yet.
pub fn config_file() -> PathBuf {
    config_dir().join(CONFIG_FILE)
}

/// The audit log the proxy writes when `[audit].path` says nothing.
pub fn audit_file() -> PathBuf {
    state_dir().join(AUDIT_FILE)
}

/// What `--config` falls back to.
///
/// A policy file in the current directory still wins, for two reasons: it is
/// what every existing checkout has, and a directory that keeps its own policy
/// — a repository, a demo, one of the walkthroughs in the docs — is a thing
/// people deliberately do. What changed is that nothing *writes* there unless
/// the file is already sitting there.
pub fn default_config_file() -> PathBuf {
    let local = PathBuf::from(CONFIG_FILE);
    if local.is_file() {
        return local;
    }
    config_file()
}

/// Anchor a path from the policy file to the state directory.
///
/// `[audit].path` is usually absolute — that is what `init` writes now — but a
/// relative one has to mean something, and "wherever the operator was standing"
/// is the answer this module exists to get rid of. With no state directory to
/// resolve against (no home, no override) the path stays relative and lands in
/// the current directory as it always did.
pub fn in_state_dir(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    state_dir().join(path)
}

/// Create a directory the proxy is about to write into, owner-only.
///
/// Only the leaf is narrowed. `~/.local` and `~/.config` are shared with every
/// other tool on the machine and are not ours to tighten — but the directory
/// holding an audit log, a control-plane token and a policy file full of
/// credential *references* has no business being world-readable, and a user
/// install has no `UMask=0077` in a unit file to arrange that for it.
pub fn ensure_dir(path: &Path) -> std::io::Result<()> {
    let fresh = !path.exists();
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    if fresh {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A fixed environment, so these do not read — or race on — the process's.
    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key| map.get(key).map(OsString::from)
    }

    #[test]
    #[cfg(unix)]
    fn the_defaults_are_the_xdg_ones() {
        let env = env_of(&[("HOME", "/home/ada")]);
        assert_eq!(
            config_dir_in(&env),
            Path::new("/home/ada/.config/agent-iap")
        );
        assert_eq!(
            state_dir_in(&env),
            Path::new("/home/ada/.local/state/agent-iap")
        );
    }

    #[test]
    #[cfg(unix)]
    fn xdg_variables_move_both_directories() {
        let env = env_of(&[
            ("HOME", "/home/ada"),
            ("XDG_CONFIG_HOME", "/elsewhere/config"),
            ("XDG_STATE_HOME", "/elsewhere/state"),
        ]);
        assert_eq!(
            config_dir_in(&env),
            Path::new("/elsewhere/config/agent-iap")
        );
        assert_eq!(state_dir_in(&env), Path::new("/elsewhere/state/agent-iap"));
    }

    /// What the unit file and the container image use, and the reason they can
    /// stop depending on a working directory.
    #[test]
    fn the_iap_overrides_win_outright_and_are_not_suffixed() {
        let env = env_of(&[
            ("HOME", "/home/ada"),
            ("XDG_CONFIG_HOME", "/elsewhere/config"),
            ("IAP_CONFIG_DIR", "/etc/agent-iap"),
            ("IAP_STATE_DIR", "/var/lib/agent-iap"),
        ]);
        assert_eq!(config_dir_in(&env), Path::new("/etc/agent-iap"));
        assert_eq!(state_dir_in(&env), Path::new("/var/lib/agent-iap"));
    }

    /// `IAP_STATE_DIR=` reaching `PathBuf::from("").join("iap-audit.jsonl")`
    /// would be a relative path; `XDG_STATE_HOME=` would be worse, because
    /// joining onto it produces the same thing while looking absolute.
    #[test]
    #[cfg(unix)]
    fn an_empty_variable_is_an_unset_one() {
        let env = env_of(&[
            ("HOME", "/home/ada"),
            ("XDG_STATE_HOME", ""),
            ("IAP_STATE_DIR", ""),
        ]);
        assert_eq!(
            state_dir_in(&env),
            Path::new("/home/ada/.local/state/agent-iap")
        );
    }

    /// No home and no override: the old behaviour, which is a path that lands
    /// in the current directory rather than an unwritable absolute one.
    #[test]
    fn without_a_home_the_paths_stay_relative() {
        let env = env_of(&[]);
        assert_eq!(config_dir_in(&env), Path::new(""));
        assert_eq!(state_dir_in(&env), Path::new(""));
        assert_eq!(config_dir_in(&env).join(CONFIG_FILE), Path::new("iap.toml"));
    }

    #[test]
    #[cfg(unix)]
    fn a_directory_we_create_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let leaf = dir.path().join("state").join(APP);
        ensure_dir(&leaf).unwrap();

        let mode = std::fs::metadata(&leaf).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "{mode:o}");

        // Already there, and someone else's to set: left as we found it.
        let existing = dir.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_dir(&existing).unwrap();
        let mode = std::fs::metadata(&existing).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "{mode:o}");
    }

    #[test]
    fn an_absolute_audit_path_is_left_alone() {
        let absolute = if cfg!(windows) {
            PathBuf::from(r"C:\logs\iap-audit.jsonl")
        } else {
            PathBuf::from("/var/log/iap-audit.jsonl")
        };
        assert_eq!(in_state_dir(&absolute), absolute);
    }
}
