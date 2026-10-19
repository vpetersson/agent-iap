//! Where the commands an agent runs find the agent's own token.
//!
//! `IAP_TOKEN` used to be the only place, and an environment variable is a
//! poor home for it: it exists only in the processes that inherited it. An
//! agent's tool shell is usually not a login shell, so a token exported from a
//! shell profile is simply not there, and the agent — told everywhere that it
//! holds no credential — concludes it has none. A file does not depend on who
//! inherited what, can be read by the MCP client's header helper and by git
//! alike, and can be rotated without restarting either.
//!
//! In order, the first that is set wins:
//!
//! 1. `--token`, or `IAP_TOKEN`;
//! 2. `--token-file`, or `IAP_TOKEN_FILE`;
//! 3. `token` in the config directory — `~/.config/agent-iap/token`.
//!
//! The variable keeps precedence so that every setup that works today keeps
//! working unchanged. A file is refused if anybody but its owner may read or
//! write it, the way `ssh` refuses a private key: this is the agent's whole
//! access, and unlike the proxy's own credential store there is no daemon to
//! take down by refusing — only one command, with the fix in its message.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// The variable holding the token itself.
pub const TOKEN_VAR: &str = "IAP_TOKEN";

/// The variable naming a file that holds it.
pub const TOKEN_FILE_VAR: &str = "IAP_TOKEN_FILE";

/// The default file's name, in the config directory.
pub const TOKEN_FILE: &str = "token";

/// The default file as an agent should read it in a document, which is written
/// for a machine this process may not be running on.
pub const DEFAULT_FILE_DISPLAY: &str = "~/.config/agent-iap/token";

/// Where the token file is when nothing names one.
pub fn default_path() -> PathBuf {
    crate::paths::config_dir().join(TOKEN_FILE)
}

/// What a command was told about the token, before any of it is read.
#[derive(Debug, Clone, Default)]
pub struct TokenSource {
    /// `--token` / `IAP_TOKEN`.
    pub token: Option<String>,
    /// `--token-file` / `IAP_TOKEN_FILE`.
    pub file: Option<PathBuf>,
}

impl TokenSource {
    /// The token, from the first source that is set.
    pub fn resolve(&self) -> Result<String> {
        self.resolve_with(&default_path())
    }

    fn resolve_with(&self, default: &Path) -> Result<String> {
        // An exported-but-empty variable is a common way to mean "not set".
        if let Some(token) = self.token.as_deref().map(str::trim) {
            if !token.is_empty() {
                return Ok(token.to_string());
            }
        }
        if let Some(file) = self.file.as_deref().filter(|f| !f.as_os_str().is_empty()) {
            return read(file);
        }
        if default.exists() {
            return read(default);
        }
        bail!(
            "no agent token — set {TOKEN_VAR}, or {TOKEN_FILE_VAR} to a file holding it, or \
             put it in `{}` (mode 0600)",
            default.display()
        )
    }
}

/// Read a token file: owner-only, one token, nothing else.
pub fn read(path: &Path) -> Result<String> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("reading the agent token from `{}`", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "`{path}` holds the agent token and other users may read it (mode {mode:04o}) — \
                 `chmod 600 {path}`",
                path = path.display()
            );
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading the agent token from `{}`", path.display()))?;
    let token = text.trim();
    if token.is_empty() {
        bail!(
            "`{}` is empty — it should hold the agent token",
            path.display()
        );
    }
    // The value goes into a header. A second line would be a second header, or
    // a request git refuses to send, and either fails far from here.
    if token.chars().any(|c| c.is_whitespace() || c.is_control()) {
        bail!(
            "`{}` should hold one token and nothing else — it has more than one line or a space",
            path.display()
        );
    }
    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, text: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        path
    }

    #[test]
    fn the_variable_wins_then_the_named_file_then_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let named = write(dir.path(), "named", "iap_named\n", 0o600);
        let default = write(dir.path(), "token", "iap_default\n", 0o600);

        let all = TokenSource {
            token: Some("iap_env".into()),
            file: Some(named.clone()),
        };
        assert_eq!(all.resolve_with(&default).unwrap(), "iap_env");

        // Empty is unset, for the variable and for the file alike.
        let file = TokenSource {
            token: Some("  ".into()),
            file: Some(named),
        };
        assert_eq!(file.resolve_with(&default).unwrap(), "iap_named");

        let neither = TokenSource {
            token: None,
            file: Some(PathBuf::new()),
        };
        assert_eq!(neither.resolve_with(&default).unwrap(), "iap_default");
    }

    #[test]
    fn nothing_anywhere_names_every_place_it_looked() {
        let dir = tempfile::tempdir().unwrap();
        let error = TokenSource::default()
            .resolve_with(&dir.path().join("token"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("IAP_TOKEN"), "{error}");
        assert!(error.contains("IAP_TOKEN_FILE"), "{error}");
        assert!(error.contains("token`"), "{error}");
    }

    /// A file that was named and is missing is an error about that file, not a
    /// quiet fall back to the default.
    #[test]
    fn a_named_file_that_is_missing_is_not_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let default = write(dir.path(), "token", "iap_default", 0o600);
        let source = TokenSource {
            token: None,
            file: Some(dir.path().join("missing")),
        };
        let error = format!("{:#}", source.resolve_with(&default).unwrap_err());
        assert!(error.contains("missing"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn a_file_others_can_read_is_refused_with_the_fix() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o644, 0o640, 0o604, 0o620] {
            let path = write(dir.path(), "token", "iap_secret", mode);
            let error = read(&path).unwrap_err().to_string();
            assert!(error.contains("chmod 600"), "{mode:o}: {error}");
            assert!(!error.contains("iap_secret"), "{error}");
        }
        let path = write(dir.path(), "token", "iap_secret", 0o400);
        assert_eq!(read(&path).unwrap(), "iap_secret");
    }

    #[test]
    fn the_file_holds_one_token_and_surrounding_whitespace_is_not_part_of_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "token", "\n iap_secret \r\n", 0o600);
        assert_eq!(read(&path).unwrap(), "iap_secret");

        for bad in ["", "   \n", "iap_one\niap_two\n", "Bearer iap_secret"] {
            let path = write(dir.path(), "token", bad, 0o600);
            let error = read(&path).unwrap_err().to_string();
            assert!(!error.contains("iap_"), "{bad:?}: {error}");
        }
    }
}
