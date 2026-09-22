//! Secret references and resolution.
//!
//! The whole point of the IAP is that the agent never sees the real credential.
//! Credentials therefore live behind a *reference* in the config file — the file
//! itself stays safe to commit — and are resolved inside this process only.

use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use zeroize::Zeroize;

/// A resolved credential. Never `Debug`-printed, zeroed when the last handle drops.
#[derive(Clone)]
pub struct Secret(Arc<SecretInner>);

struct SecretInner(String);

impl Drop for SecretInner {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Secret {
    pub fn new(value: String) -> Self {
        Secret(Arc::new(SecretInner(value)))
    }

    pub fn expose(&self) -> &str {
        &self.0 .0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// Where a secret comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRef {
    /// `env:ANTHROPIC_API_KEY`
    Env(String),
    /// `file:/run/secrets/anthropic`
    File(PathBuf),
    /// `op://Private/Anthropic/credential` — resolved with the 1Password CLI.
    OnePassword(String),
    /// `literal:sk-...` — supported for tests and demos, warned about on load.
    Literal(String),
}

impl SecretRef {
    pub fn parse(raw: &str) -> Result<Self> {
        // Whitespace *inside* a reference is part of it: a 1Password vault,
        // item, section or field may be called `agent-iap tls` or `private
        // key`, and `op read` takes the whole reference as one argument. The
        // whitespace *around* one never is — a reference is a pointer, and a
        // stray space in front of it is a typo rather than a different vault.
        // Trimmed here so the policy file and the flags agree with the console,
        // whose fields have always been trimmed on the way in.
        let reference = raw.trim();

        if let Some(rest) = reference.strip_prefix("env:") {
            if rest.is_empty() {
                bail!("`env:` secret reference is missing a variable name");
            }
            Ok(SecretRef::Env(rest.to_string()))
        } else if let Some(rest) = reference.strip_prefix("file:") {
            if rest.is_empty() {
                bail!("`file:` secret reference is missing a path");
            }
            Ok(SecretRef::File(PathBuf::from(rest)))
        } else if reference.starts_with("op://") {
            Ok(SecretRef::OnePassword(reference.to_string()))
        } else if let Some(rest) = raw.trim_start().strip_prefix("literal:") {
            // The one scheme whose payload *is* the credential, so only the
            // space in front of it comes off: a trailing one may be part of the
            // value, and silently shortening a credential is not this parser's
            // to do.
            Ok(SecretRef::Literal(rest.to_string()))
        } else {
            bail!(
                "unrecognised secret reference `{}` — expected `env:NAME`, `file:/path`, \
                 `op://vault/item/field` or `literal:VALUE`",
                redact_for_error(reference)
            )
        }
    }

    /// True for reference kinds that put the plaintext in the config file itself.
    pub fn is_inline(&self) -> bool {
        matches!(self, SecretRef::Literal(_))
    }
}

/// A reference rendered for display. Everything but `literal:` is a *pointer*
/// to a credential and safe to print; `literal:` is the credential itself, so it
/// is masked — `agent-iap list` must never put a secret on a terminal.
pub fn display_ref(raw: &str) -> String {
    match SecretRef::parse(raw) {
        Ok(SecretRef::Literal(_)) => "literal:***".to_string(),
        // The reference as the resolver will use it, which is the trimmed one —
        // an inventory that prints a stray space is an inventory nobody can
        // match against the vault.
        Ok(_) => raw.trim().to_string(),
        // Unparseable references never resolve, but a pasted credential is
        // exactly how one gets written, so mask it the way errors do.
        Err(_) => redact_for_error(raw),
    }
}

fn redact_for_error(raw: &str) -> String {
    // Never echo a possible credential back into logs or error strings.
    match raw.split_once(':') {
        Some((scheme, _)) => format!("{scheme}:***"),
        None => "***".to_string(),
    }
}

/// Resolves secret references, caching results so a 1Password lookup happens once.
pub struct SecretResolver {
    cache: Mutex<HashMap<String, Secret>>,
    op_bin: String,
}

/// How many secret references are re-read at the same time.
///
/// High enough that a policy with a realistic number of `op://` references
/// reloads in about the time one vault lookup takes, low enough that a large
/// one does not arrive at 1Password as a burst of processes.
const REFRESH_AT_ONCE: usize = 8;

fn render(error: anyhow::Error) -> String {
    format!("{error:#}")
}

impl SecretResolver {
    pub fn new(op_bin: impl Into<String>) -> Self {
        SecretResolver {
            cache: Mutex::new(HashMap::new()),
            op_bin: op_bin.into(),
        }
    }

    /// Seed the cache directly. Used by tests and by `--standalone` bootstrapping.
    pub fn preset(&self, raw: &str, value: Secret) {
        self.cache.lock().insert(raw.to_string(), value);
    }

    /// Re-read a reference from its source and replace the cached value with
    /// what comes back.
    ///
    /// The cache exists so twenty upstreams sharing a vault item cost one `op`
    /// call — the right default for a value that stays put under a running
    /// proxy. `refresh` is how a value that *did* move takes effect without a
    /// restart: a renewed certificate, replaced on disk every ninety days, and
    /// a rotated credential, whose reference string is unchanged but whose
    /// secret behind it is new. Nothing in the file says either of those
    /// happened, so this is reached from the triggers that mean *re-read*:
    /// `SIGHUP`, the console's `r`, and its `c` on the credentials pane.
    ///
    /// The old value is replaced only if the re-read succeeds. A refresh that
    /// cannot reach the source — a locked vault, a half-written file — returns
    /// the error and leaves the last good value in the cache, so a reload that
    /// refuses does not also evict a credential the proxy is still serving.
    pub fn refresh(&self, raw: &str) -> Result<Secret> {
        let secret = self.read(raw)?;
        self.cache.lock().insert(raw.to_string(), secret.clone());
        Ok(secret)
    }

    /// Re-read many references at once, one answer per reference, in the order
    /// they were given. Every one of them goes to its source.
    ///
    /// `refresh` on an `op://` reference is a subprocess and a network round
    /// trip, and these used to be done one after another: a policy naming eight
    /// of them cost eight vault lookups back to back. That is paid on startup,
    /// on every `SIGHUP`, and on the console's `r`, where it was seconds of a
    /// console that had stopped drawing the request somebody was waiting to
    /// answer.
    ///
    /// Nothing here depends on anything else here, so they go at once. The
    /// bound is only so that a fifty-upstream policy does not fork fifty `op`
    /// processes in the same instant; a locked vault answers a burst that size
    /// with rate limits rather than with secrets.
    ///
    /// Only *whether* each one resolved comes back. Every caller is asking
    /// about the references rather than about the credentials behind them, and
    /// the values themselves are already where they are wanted — in the cache.
    pub fn refresh_all(&self, references: &[String]) -> Vec<Result<(), String>> {
        self.read_all(references, true)
    }

    /// The same, cache-first: a reference this process has already read is
    /// answered from what it read, and only one it has never seen costs a
    /// lookup.
    ///
    /// What a reload nobody asked for uses. An `[[acl]]` rule appended by the
    /// approval dialogue says nothing about any credential, and re-reading
    /// twenty references because of it is twenty vault lookups for an edit that
    /// touched none of them — which on a desktop 1Password is an authorization
    /// prompt in front of the operator every time they answer an `ask`
    /// (SIRI-205). A reference the edit *added* or repointed is not in the
    /// cache under its new spelling, so it is still read here and a policy that
    /// names a credential this process cannot get is still refused at reload
    /// rather than on the first live call.
    pub fn resolve_all(&self, references: &[String]) -> Vec<Result<(), String>> {
        self.read_all(references, false)
    }

    fn read_one(&self, reference: &str, fresh: bool) -> Result<(), String> {
        match fresh {
            true => self.refresh(reference),
            false => self.resolve(reference),
        }
        .map(|_| ())
        .map_err(render)
    }

    fn read_all(&self, references: &[String], fresh: bool) -> Vec<Result<(), String>> {
        if references.len() < 2 {
            return references
                .iter()
                .map(|reference| self.read_one(reference, fresh))
                .collect();
        }

        let width = references.len().div_ceil(REFRESH_AT_ONCE);
        std::thread::scope(|scope| {
            let running: Vec<_> = references
                .chunks(width)
                .map(|chunk| {
                    (
                        chunk,
                        scope.spawn(move || {
                            chunk
                                .iter()
                                .map(|reference| self.read_one(reference, fresh))
                                .collect::<Vec<_>>()
                        }),
                    )
                })
                .collect();
            running
                .into_iter()
                .flat_map(|(chunk, handle)| match handle.join() {
                    Ok(answers) => answers,
                    // A panicked read is not a reference that resolved. Fail
                    // closed: every reference in that chunk is reported
                    // unresolved, which is what refuses the policy.
                    Err(_) => chunk
                        .iter()
                        .map(|_| Err("panicked while reading this reference".to_string()))
                        .collect(),
                })
                .collect()
        })
    }

    /// Resolve a raw reference string, returning a cached value when there is
    /// one. Blocking: 1Password shells out to `op`.
    pub fn resolve(&self, raw: &str) -> Result<Secret> {
        if let Some(hit) = self.cache.lock().get(raw) {
            return Ok(hit.clone());
        }
        let secret = self.read(raw)?;
        self.cache.lock().insert(raw.to_string(), secret.clone());
        Ok(secret)
    }

    /// Read a reference straight from its source, touching no cache on either
    /// side. The shared body of `resolve` and `refresh`.
    fn read(&self, raw: &str) -> Result<Secret> {
        Ok(match SecretRef::parse(raw)? {
            SecretRef::Env(name) => {
                let value = std::env::var(&name).with_context(|| {
                    format!("environment variable `{name}` is not set (from `env:{name}`)")
                })?;
                Secret::new(value)
            }
            SecretRef::File(path) => {
                let value = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading secret file `{}`", path.display()))?;
                Secret::new(value.trim_end_matches(['\n', '\r']).to_string())
            }
            SecretRef::OnePassword(reference) => self.resolve_onepassword(&reference)?,
            SecretRef::Literal(value) => Secret::new(value),
        })
    }

    fn resolve_onepassword(&self, reference: &str) -> Result<Secret> {
        let output = Command::new(&self.op_bin)
            .args(["read", "--no-newline", reference])
            .output()
            .with_context(|| {
                format!(
                    "running `{}` — install the 1Password CLI to use `op://` references",
                    self.op_bin
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "`op read {reference}` failed ({}): {}",
                output.status,
                stderr.trim()
            );
        }

        let value = String::from_utf8(output.stdout)
            .context("1Password returned a non-UTF-8 secret")?
            .trim_end_matches(['\n', '\r'])
            .to_string();

        if value.is_empty() {
            bail!("`op read {reference}` returned an empty value");
        }
        Ok(Secret::new(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_supported_scheme() {
        assert_eq!(
            SecretRef::parse("env:TOKEN").unwrap(),
            SecretRef::Env("TOKEN".into())
        );
        assert_eq!(
            SecretRef::parse("file:/run/secrets/x").unwrap(),
            SecretRef::File(PathBuf::from("/run/secrets/x"))
        );
        assert_eq!(
            SecretRef::parse("op://Private/Anthropic/credential").unwrap(),
            SecretRef::OnePassword("op://Private/Anthropic/credential".into())
        );
        assert_eq!(
            SecretRef::parse("literal:hunter2").unwrap(),
            SecretRef::Literal("hunter2".into())
        );
    }

    /// A 1Password vault, item, section or field is named by a human, so it has
    /// spaces in it: `op://Infra/agent-iap tls/private key` is one reference,
    /// not three words. The whole thing is the argument `op read` is handed.
    #[test]
    fn whitespace_inside_a_1password_reference_is_part_of_it() {
        for raw in [
            "op://Infra/agent-iap tls/private key",
            "op://Private/Anthropic API/credential",
            // vault / item / section / field, the four-segment form
            "op://development/aws/Access Keys/access_key_id",
        ] {
            assert_eq!(
                SecretRef::parse(raw).unwrap(),
                SecretRef::OnePassword(raw.into()),
                "`{raw}`"
            );
            assert_eq!(display_ref(raw), raw);
        }
    }

    /// And the whitespace *around* one is not. A leading space used to make a
    /// perfectly good reference "unrecognised" — reported as `op:***`, which
    /// redacts away the only part that would have explained it — and a trailing
    /// one used to be handed to `op` as part of the field name.
    #[test]
    fn whitespace_around_a_reference_is_a_typo_and_not_part_of_it() {
        let wanted = "op://Infra/agent-iap tls/private key";
        for raw in [
            " op://Infra/agent-iap tls/private key",
            "op://Infra/agent-iap tls/private key ",
            "\top://Infra/agent-iap tls/private key\n",
        ] {
            assert_eq!(
                SecretRef::parse(raw).unwrap(),
                SecretRef::OnePassword(wanted.into()),
                "`{raw}`"
            );
            assert_eq!(display_ref(raw), wanted, "`{raw}`");
        }

        assert_eq!(
            SecretRef::parse(" env:TOKEN\n").unwrap(),
            SecretRef::Env("TOKEN".into())
        );
        assert_eq!(
            SecretRef::parse(" file:/run/secrets/x ").unwrap(),
            SecretRef::File(PathBuf::from("/run/secrets/x"))
        );
    }

    /// `literal:` is the credential rather than a pointer to one, so trimming
    /// its payload would quietly change a secret. Only the space in front of
    /// the scheme comes off.
    #[test]
    fn a_literal_keeps_the_value_it_was_given() {
        assert_eq!(
            SecretRef::parse("  literal:hunter2 ").unwrap(),
            SecretRef::Literal("hunter2 ".into())
        );
    }

    /// End to end, through a stand-in for the 1Password CLI: the reference
    /// arrives as one argument with its spaces intact. `op read` is never run
    /// through a shell, so nothing here needs quoting — this is the test that
    /// says so.
    #[cfg(unix)]
    #[test]
    fn a_1password_reference_reaches_op_as_a_single_argument() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let op = dir.path().join("op");
        // Echoes back the reference it was given, and refuses to be given two.
        std::fs::write(
            &op,
            "#!/bin/sh\n\
             [ \"$1\" = read ] || exit 2\n\
             [ \"$2\" = --no-newline ] || exit 2\n\
             [ $# -eq 3 ] || exit 3\n\
             printf '%s' \"$3\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();

        let reference = "op://Infra/agent-iap tls/private key";
        let resolver = SecretResolver::new(op.to_str().unwrap());
        assert_eq!(resolver.resolve(reference).unwrap().expose(), reference);

        // And the trimmed form is what a reference written with a stray space
        // resolves to, rather than a field name with a space on the end.
        assert_eq!(
            resolver
                .resolve(&format!(" {reference}\n"))
                .unwrap()
                .expose(),
            reference
        );
    }

    /// A `1Password` stand-in that takes as long as the real one does, so the
    /// shape of the cost is the thing under test rather than the cost itself.
    #[cfg(unix)]
    fn slow_op(dir: &std::path::Path, millis: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let op = dir.join("op");
        std::fs::write(
            &op,
            format!(
                "#!/bin/sh\n\
                 sleep {}\n\
                 printf 'value-for-%s' \"$3\"\n",
                millis as f64 / 1000.0
            ),
        )
        .unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
        op
    }

    /// The reload cost that made the console unusable: every `op://` reference
    /// in the file was read one after another, so a policy with eight of them
    /// paid eight vault round trips in a row — on startup, on every `SIGHUP`,
    /// and on `r`, where it was seconds of a console that had stopped drawing.
    ///
    /// The bound is deliberately loose. What is being asserted is that the cost
    /// no longer scales with the number of references, not a particular number
    /// of milliseconds on a particular machine.
    #[cfg(unix)]
    #[test]
    fn many_references_cost_about_one_lookup_rather_than_one_each() {
        let dir = tempfile::tempdir().unwrap();
        let op = slow_op(dir.path(), 200);
        let resolver = SecretResolver::new(op.to_str().unwrap());

        let references: Vec<String> = (0..8)
            .map(|n| format!("op://Private/item-{n}/credential"))
            .collect();

        let started = std::time::Instant::now();
        let answers = resolver.refresh_all(&references);
        let took = started.elapsed();

        assert!(answers.iter().all(|answer| answer.is_ok()), "{answers:?}");
        // The stand-in really did sleep, so the bound below means something.
        assert!(
            took >= std::time::Duration::from_millis(150),
            "the stand-in did not run: {took:?}"
        );
        assert!(
            took < std::time::Duration::from_millis(800),
            "eight 200ms lookups took {took:?} — they are still happening one at a time"
        );
        // And every value actually landed in the cache, under its own reference.
        for (n, reference) in references.iter().enumerate() {
            assert_eq!(
                resolver.resolve(reference).unwrap().expose(),
                format!("value-for-op://Private/item-{n}/credential")
            );
        }
    }

    /// Reading them at once must not reorder the answers. The list of failures
    /// is what an operator reads to find the line of the file that is wrong, so
    /// it is paired with the references by position.
    #[test]
    fn an_answer_comes_back_beside_the_reference_it_belongs_to() {
        std::env::set_var("AGENT_IAP_ORDER_TEST", "sk-not-real");
        let resolver = SecretResolver::new("op-not-installed");
        let references: Vec<String> = (0..12)
            .map(|n| match n % 3 {
                0 => "env:AGENT_IAP_ORDER_TEST".to_string(),
                1 => format!("env:AGENT_IAP_UNSET_{n}"),
                _ => format!("literal:value-{n}"),
            })
            .collect();

        let answers = resolver.refresh_all(&references);
        assert_eq!(answers.len(), references.len());
        for (index, answer) in answers.iter().enumerate() {
            match index % 3 {
                1 => {
                    let error = answer.as_ref().expect_err("an unset variable");
                    assert!(
                        error.contains(&format!("AGENT_IAP_UNSET_{index}")),
                        "answer {index} names the wrong reference: {error}"
                    );
                }
                _ => assert!(answer.is_ok(), "answer {index}: {answer:?}"),
            }
        }
    }

    #[test]
    fn rejects_bare_values_so_a_pasted_key_is_never_silently_accepted() {
        let err = SecretRef::parse("sk-ant-secret").unwrap_err().to_string();
        assert!(err.contains("unrecognised secret reference"));
        assert!(
            !err.contains("sk-ant-secret"),
            "error leaked the value: {err}"
        );
    }

    #[test]
    fn errors_never_echo_the_value_after_the_scheme() {
        let err = SecretRef::parse("bogus:sk-ant-secret")
            .unwrap_err()
            .to_string();
        assert!(err.contains("bogus:***"));
        assert!(!err.contains("sk-ant-secret"));
    }

    #[test]
    fn debug_never_reveals_the_secret() {
        let s = Secret::new("sk-ant-supersecret".into());
        assert_eq!(format!("{s:?}"), "Secret(***)");
        assert_eq!(s.expose(), "sk-ant-supersecret");
    }

    #[test]
    fn env_and_file_resolve_and_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "from-file\n").unwrap();

        let resolver = SecretResolver::new("op");
        std::env::set_var("LLM_IAP_TEST_SECRET", "from-env");

        assert_eq!(
            resolver
                .resolve("env:LLM_IAP_TEST_SECRET")
                .unwrap()
                .expose(),
            "from-env"
        );
        assert_eq!(
            resolver
                .resolve(&format!("file:{}", path.display()))
                .unwrap()
                .expose(),
            "from-file",
            "trailing newline should be trimmed"
        );

        // Cached: removing the source still resolves.
        std::env::remove_var("LLM_IAP_TEST_SECRET");
        assert_eq!(
            resolver
                .resolve("env:LLM_IAP_TEST_SECRET")
                .unwrap()
                .expose(),
            "from-env"
        );
    }

    #[test]
    fn refresh_picks_up_a_rotated_source_that_resolve_still_caches() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "v1\n").unwrap();
        let reference = format!("file:{}", path.display());

        let resolver = SecretResolver::new("op");
        assert_eq!(resolver.resolve(&reference).unwrap().expose(), "v1");

        // The value behind the reference changes; the reference string does not.
        std::fs::write(&path, "v2\n").unwrap();
        assert_eq!(
            resolver.resolve(&reference).unwrap().expose(),
            "v1",
            "resolve keeps serving the cached value"
        );
        assert_eq!(
            resolver.refresh(&reference).unwrap().expose(),
            "v2",
            "refresh re-reads the source"
        );
        assert_eq!(
            resolver.resolve(&reference).unwrap().expose(),
            "v2",
            "and the fresh value is what the cache now holds"
        );
    }

    #[test]
    fn a_failed_refresh_keeps_the_last_good_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "v1\n").unwrap();
        let reference = format!("file:{}", path.display());

        let resolver = SecretResolver::new("op");
        assert_eq!(resolver.resolve(&reference).unwrap().expose(), "v1");

        // The source is gone: a refresh cannot read it…
        std::fs::remove_file(&path).unwrap();
        assert!(resolver.refresh(&reference).is_err());

        // …and must not have evicted the value the proxy is still serving.
        assert_eq!(
            resolver.resolve(&reference).unwrap().expose(),
            "v1",
            "a failed refresh leaves the last good value in place"
        );
    }
}
