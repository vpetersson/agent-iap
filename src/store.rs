//! Credentials agent-iap keeps itself.
//!
//! Every other scheme in `secrets` points at something that already holds the
//! credential: an environment variable the operator exported, a file some
//! secret manager dropped, a 1Password item. That is the right shape when such
//! a place exists — and for a read-only token on a hobby account there often is
//! no such place, and setting one up is more ceremony than the credential is
//! worth. The answer used to be that the credential could not be enrolled at
//! all: a bare value was refused for not being a reference, the `literal:`
//! spelling the refusal suggested was refused again for putting the credential
//! in a file meant to be committable, and the two refusals pointed at each
//! other.
//!
//! So this is the place that holds it. `iap://<name>` is a reference like any
//! other — the policy file still contains a pointer and is still safe to
//! commit — and what it points at is a store this process owns.
//!
//! Where it lives decides most of its properties. The store is **state**, not
//! configuration: the config directory is documented as the sort of thing that
//! ends up in a dotfile repository, and a file of plaintext credentials has no
//! business being synced anywhere. It sits beside `admin-token`, under
//! `$XDG_STATE_HOME/agent-iap/`, owner-only, in a directory `paths::ensure_dir`
//! has already narrowed to `0700`.
//!
//! What this is *not* is a secret manager. There is no encryption at rest:
//! anything that can read the file as its owner can read the credentials, which
//! is exactly as true of `~/.aws/credentials` and of a `.env`, and is the trade
//! the operator is making when they choose this over `op://`. It is written
//! down here, in `secret set`'s own output, and in the README, because a
//! capability whose limits are not written down will be relied on past them.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::secrets::Secret;

/// The store's file name, in whichever directory holds it.
pub const STORE_FILE: &str = "secrets.toml";

/// Longest name worth accepting. Nothing breaks above it; it is the point past
/// which a name stopped being one and started being a pasted credential.
const MAX_NAME: usize = 64;

/// One stored credential. `value` is the credential itself, so this type never
/// derives `Debug` and zeroes what it held on the way out.
#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    value: String,
    /// When it was last written, RFC 3339. Informational only — `secret list`
    /// showing a token nobody has touched in two years is how it gets rotated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    updated: Option<String>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Serialize, Deserialize, Default)]
struct StoreFile {
    /// Sorted, because the file is rewritten whole on every edit and a stable
    /// order keeps that diff to the line that actually changed.
    #[serde(default)]
    secrets: BTreeMap<String, Entry>,
}

/// What `secret list` prints: the names and when they were written, never the
/// values.
pub struct Stored {
    pub name: String,
    pub updated: Option<String>,
}

/// The credential store at a path. Cheap to make; every method reads the file.
///
/// Deliberately not cached. The values behind these names are read through
/// `SecretResolver`, which has a cache of its own and a documented rule about
/// when it is refreshed — a second cache here would be a second answer to
/// "has this rotated", and the two would disagree the first time somebody ran
/// `secret set` against a running proxy.
pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Store { path: path.into() }
    }

    /// The store this machine uses when nobody names a path.
    pub fn default_path() -> PathBuf {
        crate::paths::state_dir().join(STORE_FILE)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A name that can be written as `iap://<name>`, read back out of a TOML
    /// key, and told apart from a credential somebody pasted into the wrong
    /// argument.
    pub fn check_name(name: &str) -> Result<()> {
        if name.is_empty() {
            bail!("a stored credential needs a name");
        }
        if name.len() > MAX_NAME {
            // Redacted: the overwhelmingly likely way to get here is
            // `agent-iap secret set sk-live-…`, and echoing it back would put
            // the credential in the terminal scrollback and the shell history
            // twice over.
            bail!(
                "that name is {} characters — a name, not the credential itself, goes here \
                 (`agent-iap secret set <name>` then types the value)",
                name.len()
            );
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            bail!("credential name `{name}` must be ASCII letters, digits, `-`, `_` or `.`");
        }
        Ok(())
    }

    /// The credential behind a name, or an error naming what to do about it.
    ///
    /// Read from the file every time. A `secret set` while the proxy is up is
    /// meant to be picked up by the next reload, and a reload calls `refresh`,
    /// which calls this.
    pub fn get(&self, name: &str) -> Result<Secret> {
        Self::check_name(name)?;
        let file = self.read()?;
        match file.secrets.get(name) {
            Some(entry) if entry.value.is_empty() => bail!(
                "`iap://{name}` is stored with an empty value — \
                 `agent-iap secret set {name}` writes it again"
            ),
            Some(entry) => Ok(Secret::new(entry.value.clone())),
            None if file.secrets.is_empty() => bail!(
                "no credential named `{name}` — this proxy has none stored. \
                 `agent-iap secret set {name}` stores one"
            ),
            None => bail!(
                "no credential named `{name}` — `agent-iap secret list` shows the {} \
                 this proxy has stored",
                file.secrets.len()
            ),
        }
    }

    /// Store a value under a name, replacing whatever was there.
    ///
    /// Answers whether it replaced something, because "set" is the same command
    /// for a new credential and for a rotated one, and an operator who has just
    /// overwritten the wrong name is entitled to find out from the command
    /// rather than from a 401.
    pub fn set(&self, name: &str, value: &str) -> Result<bool> {
        Self::check_name(name)?;
        if value.is_empty() {
            bail!("refusing to store an empty value as `{name}` — that resolves to no credential");
        }
        let mut file = self.read()?;
        let replaced = file.secrets.contains_key(name);
        file.secrets.insert(
            name.to_string(),
            Entry {
                value: value.to_string(),
                updated: Some(
                    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                ),
            },
        );
        self.write(&file)?;
        Ok(replaced)
    }

    /// Forget a name. Answers whether there was anything under it.
    pub fn remove(&self, name: &str) -> Result<bool> {
        Self::check_name(name)?;
        let mut file = self.read()?;
        let had = file.secrets.remove(name).is_some();
        if had {
            self.write(&file)?;
        }
        Ok(had)
    }

    /// Every name in the store, never a value.
    pub fn list(&self) -> Result<Vec<Stored>> {
        Ok(self
            .read()?
            .secrets
            .iter()
            .map(|(name, entry)| Stored {
                name: name.clone(),
                updated: entry.updated.clone(),
            })
            .collect())
    }

    /// True when the file is readable by somebody other than its owner.
    ///
    /// Not a refusal: the file may predate this check, or live on a filesystem
    /// that does not carry a mode, and refusing to start over it would take a
    /// proxy down for a condition the operator can fix in one command. It is
    /// reported wherever the store is touched, which is `secret set`,
    /// `secret list` and startup.
    pub fn exposed(&self) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&self.path) {
                return meta.permissions().mode() & 0o077 != 0;
            }
        }
        false
    }

    fn read(&self) -> Result<StoreFile> {
        let mut text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            // A store nobody has written yet is an empty one, not an error: the
            // reference that named it still fails, and it fails saying the name
            // is not stored rather than blaming a missing file the operator
            // never made.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(StoreFile::default())
            }
            Err(error) => {
                return Err(error).with_context(|| format!("reading `{}`", self.path.display()))
            }
        };
        let parsed = toml::from_str(&text)
            .with_context(|| format!("`{}` is not a valid credential store", self.path.display()));
        // The text held every credential in the file. Whatever the parse did,
        // it does not stay in this process's memory afterwards.
        text.zeroize();
        parsed
    }

    /// Write the store whole, owner-only, atomically.
    ///
    /// Whole because it is small and rewriting it is simpler than editing it in
    /// place; atomically because the alternative is a truncated file, and a
    /// truncated credential store is every upstream on this proxy failing to
    /// resolve at once. The temporary file is created `0600` rather than
    /// narrowed afterwards — a file that is world-readable for the microsecond
    /// between `create` and `set_permissions` is world-readable.
    fn write(&self, file: &StoreFile) -> Result<()> {
        let dir = match self.path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
            _ => PathBuf::from("."),
        };
        crate::paths::ensure_dir(&dir).with_context(|| format!("creating `{}`", dir.display()))?;

        let mut text = format!(
            "# agent-iap's own credential store. The values in this file are the \
             credentials\n# themselves, not references to them — keep it out of \
             version control and off\n# any directory that syncs. `agent-iap secret \
             list` shows what is in here.\n\n{}",
            toml::to_string_pretty(file).context("serialising the credential store")?
        );

        let temporary = self.path.with_extension("toml.tmp");
        let outcome = Self::write_owner_only(&temporary, &text).and_then(|()| {
            std::fs::rename(&temporary, &self.path)
                .with_context(|| format!("writing `{}`", self.path.display()))
        });
        text.zeroize();
        if outcome.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        outcome
    }

    fn write_owner_only(path: &Path, text: &str) -> Result<()> {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut handle = options
            .open(path)
            .with_context(|| format!("creating `{}`", path.display()))?;
        handle
            .write_all(text.as_bytes())
            .and_then(|()| handle.sync_all())
            .with_context(|| format!("writing `{}`", path.display()))?;
        // An existing temporary file is opened rather than created, and
        // `OpenOptions::mode` only applies to a creation — so narrow it either
        // way before anything is in it. Done after the write for the same
        // reason the mode is set at creation: the window that matters is the
        // one where the file has contents.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("narrowing `{}`", path.display()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path().join(STORE_FILE));
        (dir, store)
    }

    #[test]
    fn a_stored_value_comes_back_under_its_name() {
        let (_dir, store) = store();
        assert!(!store.set("readonly", "ghp_notreal").unwrap());
        assert_eq!(store.get("readonly").unwrap().expose(), "ghp_notreal");
        // Setting it again says so, which is how a rotation is told from a typo.
        assert!(store.set("readonly", "ghp_rotated").unwrap());
        assert_eq!(store.get("readonly").unwrap().expose(), "ghp_rotated");
    }

    /// The whole point of reading the file on every `get`: `secret set` against
    /// a running proxy has to be visible to the reload that follows it.
    #[test]
    fn a_value_replaced_behind_the_store_is_read_fresh() {
        let (_dir, store) = store();
        store.set("token", "v1").unwrap();
        let again = Store::at(store.path());
        again.set("token", "v2").unwrap();
        assert_eq!(store.get("token").unwrap().expose(), "v2");
    }

    #[test]
    fn a_missing_name_says_how_to_store_one() {
        let (_dir, store) = store();
        // Nothing stored at all.
        let error = store.get("readonly").unwrap_err().to_string();
        assert!(error.contains("agent-iap secret set readonly"), "{error}");

        // Something stored, but not this.
        store.set("other", "value").unwrap();
        let error = store.get("readonly").unwrap_err().to_string();
        assert!(error.contains("agent-iap secret list"), "{error}");
        assert!(!error.contains("value"), "error leaked a secret: {error}");
    }

    #[test]
    fn removing_says_whether_there_was_anything_there() {
        let (_dir, store) = store();
        store.set("gone", "value").unwrap();
        assert!(store.remove("gone").unwrap());
        assert!(!store.remove("gone").unwrap());
        assert!(store.get("gone").is_err());
    }

    #[test]
    fn listing_gives_names_and_never_values() {
        let (_dir, store) = store();
        store.set("b", "second").unwrap();
        store.set("a", "first").unwrap();
        let names: Vec<String> = store.list().unwrap().into_iter().map(|s| s.name).collect();
        assert_eq!(names, vec!["a", "b"], "sorted, so the file diffs cleanly");

        let on_disk = std::fs::read_to_string(store.path()).unwrap();
        assert!(on_disk.contains("first"), "the store does hold the value");
        // …and nothing that prints goes near it.
        assert!(store
            .list()
            .unwrap()
            .iter()
            .all(|s| s.updated.is_some() && !s.name.contains("first")));
    }

    #[test]
    fn an_empty_value_is_refused_rather_than_stored_as_no_credential() {
        let (_dir, store) = store();
        let error = store.set("blank", "").unwrap_err().to_string();
        assert!(error.contains("empty"), "{error}");
        assert!(store.get("blank").is_err());
    }

    /// `agent-iap secret set sk-live-…` is the mistake this catches, and the
    /// refusal must not be what puts the credential in the scrollback.
    #[test]
    fn a_pasted_credential_in_the_name_is_refused_without_echoing_it() {
        let pasted = "sk-ant-".to_string() + &"x".repeat(96);
        let error = Store::check_name(&pasted).unwrap_err().to_string();
        assert!(!error.contains(&pasted), "{error}");
        assert!(error.contains("secret set <name>"), "{error}");

        let error = Store::check_name("has spaces").unwrap_err().to_string();
        assert!(error.contains("ASCII letters"), "{error}");
        assert!(Store::check_name("").is_err());
    }

    #[test]
    #[cfg(unix)]
    fn the_file_is_owner_only_and_says_when_it_is_not() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, store) = store();
        store.set("token", "value").unwrap();

        let mode = std::fs::metadata(store.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
        assert!(!store.exposed());

        std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.exposed());

        // And a rewrite puts it back rather than preserving what it found.
        store.set("token", "value2").unwrap();
        let mode = std::fs::metadata(store.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }

    /// The store is rewritten whole on every edit, so a write that dies
    /// half-way would take every credential on the proxy with it.
    #[test]
    fn a_write_leaves_no_temporary_file_behind() {
        let (dir, store) = store();
        store.set("a", "1").unwrap();
        store.set("b", "2").unwrap();
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok().map(|e| e.file_name()))
            .collect();
        assert_eq!(left.len(), 1, "{left:?}");
    }

    #[test]
    fn a_store_nobody_has_written_is_empty_rather_than_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path().join("never-written.toml"));
        assert!(store.list().unwrap().is_empty());
        assert!(!store.exposed());
    }
}
