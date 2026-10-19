//! `agent-iap git-config`: the settings that send git through the proxy.
//!
//! Git is a program, not an SDK with a base URL, so the HTTP gateway reaches it
//! through git's own configuration: `url.<proxy>/<upstream>/.insteadOf` turns
//! `https://github.com/o/r.git` into the proxied address, and
//! `http.<proxy>/<upstream>/.extraHeader` carries the agent's token as
//! `X-IAP-Token` — git sends an `Authorization` of its own when it has one, and
//! the header is scoped to the proxied prefix so it goes nowhere else.
//!
//! The settings are printed as `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_<n>`
//! environment variables for `eval`, rather than as `git config --global`
//! commands, because the header's value is the token: written into
//! `~/.gitconfig` it would be a credential on disk that outlives the shell.
//! Here it is `$IAP_TOKEN`, expanded by the shell that evaluates the output.

use anyhow::{bail, Context, Result};

/// What `git-config` is asked to describe.
pub struct GitConfigOptions {
    /// The proxy's data-plane address, e.g. `http://127.0.0.1:8080`.
    pub proxy_url: String,
    /// The upstream enrolled from the `github-git` profile.
    pub upstream: String,
}

/// The remote whose URLs are rewritten. Only HTTPS: an `ssh://` or
/// `git@github.com:` remote is a different transport the proxy does not speak.
const GITHUB: &str = "https://github.com/";

/// The variable the header reads the token from, never its value.
const TOKEN_VAR: &str = "IAP_TOKEN";

/// One git setting, as `git config` would name it.
#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub value: Value,
}

/// A setting's value: written as it is, or read from the environment when the
/// output is evaluated so that a credential is never part of it.
#[derive(Debug, PartialEq, Eq)]
pub enum Value {
    Literal(String),
    /// `prefix` followed by the named environment variable.
    FromEnv {
        prefix: String,
        var: &'static str,
    },
}

/// The settings, in the order they are emitted.
pub fn entries(options: &GitConfigOptions) -> Result<Vec<Entry>> {
    let base = proxied_prefix(&options.proxy_url, &options.upstream)?;
    Ok(vec![
        Entry {
            key: format!("url.{base}.insteadOf"),
            value: Value::Literal(GITHUB.into()),
        },
        Entry {
            key: format!("http.{base}.extraHeader"),
            value: Value::FromEnv {
                prefix: "X-IAP-Token: ".into(),
                var: TOKEN_VAR,
            },
        },
    ])
}

/// `<proxy>/<upstream>/`, the prefix both settings are keyed on. The trailing
/// slash matters: git matches `http.<url>.*` by path segment, and without it
/// `github-git` would also cover a sibling upstream called `github-gitlab`.
fn proxied_prefix(proxy_url: &str, upstream: &str) -> Result<String> {
    let url = url::Url::parse(proxy_url.trim())
        .with_context(|| format!("`{proxy_url}` is not a proxy address"))?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("`{proxy_url}` is not an http:// or https:// address");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("`{proxy_url}` should be the proxy's address alone, without a query");
    }
    let upstream = upstream.trim_matches('/');
    if upstream.is_empty() || upstream.contains(['/', '?', '#', ' ']) {
        bail!("`{upstream}` is not an upstream name");
    }
    Ok(format!(
        "{}/{upstream}/",
        url.as_str().trim_end_matches('/')
    ))
}

/// The entries as `export` lines for a POSIX shell's `eval`.
///
/// `existing` is the `GIT_CONFIG_COUNT` already in the environment, with the
/// keys it holds: the new settings are appended after them rather than
/// replacing them, and a key this command already set — evaluating it twice in
/// one shell — is overwritten in place rather than sent twice, which for the
/// header would mean two tokens on every request.
pub fn render_env(entries: &[Entry], existing: &[String]) -> String {
    let mut keys: Vec<String> = existing.to_vec();
    let mut out = String::from(
        "# Routes https://github.com/ through agent-iap for this shell. The token stays\n\
         # in $IAP_TOKEN: nothing here is written to a file.\n",
    );
    let mut lines = Vec::new();
    for entry in entries {
        let index = match keys.iter().position(|key| key == &entry.key) {
            Some(index) => index,
            None => {
                keys.push(entry.key.clone());
                keys.len() - 1
            }
        };
        lines.push(format!(
            "export GIT_CONFIG_KEY_{index}={}",
            single_quoted(&entry.key)
        ));
        let value = match &entry.value {
            Value::Literal(value) => single_quoted(value),
            // Double-quoted so the shell expands it; `:?` makes an unset
            // variable an error at `eval` rather than an empty header that
            // fails later as a 401 nobody can explain.
            Value::FromEnv { prefix, var } => {
                format!("\"{}${{{var}:?{var} is not set}}\"", double_escaped(prefix))
            }
        };
        lines.push(format!("export GIT_CONFIG_VALUE_{index}={value}"));
    }
    out.push_str(&format!("export GIT_CONFIG_COUNT={}\n", keys.len()));
    for line in lines {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// The `GIT_CONFIG_KEY_<n>` entries already in this environment, in order.
pub fn existing_keys() -> Vec<String> {
    let count = std::env::var("GIT_CONFIG_COUNT")
        .ok()
        .and_then(|count| count.trim().parse::<usize>().ok())
        .unwrap_or(0);
    (0..count)
        .map(|index| std::env::var(format!("GIT_CONFIG_KEY_{index}")).unwrap_or_default())
        .collect()
}

fn single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn double_escaped(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| match c {
            '"' | '\\' | '$' | '`' => vec!['\\', c],
            c => vec![c],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(proxy_url: &str) -> GitConfigOptions {
        GitConfigOptions {
            proxy_url: proxy_url.into(),
            upstream: "github-git".into(),
        }
    }

    #[test]
    fn rewrites_github_to_the_upstream_and_scopes_the_header_to_it() {
        let entries = entries(&options("http://127.0.0.1:8080")).unwrap();
        assert_eq!(
            entries,
            [
                Entry {
                    key: "url.http://127.0.0.1:8080/github-git/.insteadOf".into(),
                    value: Value::Literal("https://github.com/".into()),
                },
                Entry {
                    key: "http.http://127.0.0.1:8080/github-git/.extraHeader".into(),
                    value: Value::FromEnv {
                        prefix: "X-IAP-Token: ".into(),
                        var: "IAP_TOKEN",
                    },
                },
            ]
        );
        // A trailing slash on the address, or a TLS one, changes nothing else.
        let tls = entries_for("https://iap.example.com:8443/");
        assert_eq!(
            tls[0].key,
            "url.https://iap.example.com:8443/github-git/.insteadOf"
        );
    }

    fn entries_for(proxy_url: &str) -> Vec<Entry> {
        entries(&options(proxy_url)).unwrap()
    }

    #[test]
    fn an_address_that_is_not_one_is_refused() {
        for bad in [
            "127.0.0.1:8080",
            "ftp://iap.example.com",
            "http://iap.example.com/?x=1",
        ] {
            assert!(entries(&options(bad)).is_err(), "{bad}");
        }
        let mut options = options("http://127.0.0.1:8080");
        options.upstream = "a/b".into();
        assert!(entries(&options).is_err());
    }

    /// The token is referenced, never printed, and an unset variable fails
    /// where it is evaluated.
    #[test]
    fn the_output_names_the_token_variable_and_never_a_value() {
        let script = render_env(&entries_for("http://127.0.0.1:8080"), &[]);
        assert!(script.contains("export GIT_CONFIG_COUNT=2\n"), "{script}");
        assert!(script.contains(
            "export GIT_CONFIG_KEY_0='url.http://127.0.0.1:8080/github-git/.insteadOf'\n"
        ));
        assert!(script.contains("export GIT_CONFIG_VALUE_0='https://github.com/'\n"));
        assert!(script.contains(
            "export GIT_CONFIG_VALUE_1=\"X-IAP-Token: ${IAP_TOKEN:?IAP_TOKEN is not set}\"\n"
        ));
        assert!(!script.contains("iap_"), "{script}");
    }

    /// Settings already in the environment are kept, and running it twice in
    /// one shell does not send the header twice.
    #[test]
    fn existing_settings_are_appended_to_and_its_own_are_replaced() {
        let entries = entries_for("http://127.0.0.1:8080");
        let script = render_env(&entries, &["core.autocrlf".into()]);
        assert!(script.contains("export GIT_CONFIG_COUNT=3\n"), "{script}");
        assert!(script.contains("GIT_CONFIG_KEY_1='url."));
        assert!(script.contains("GIT_CONFIG_KEY_2='http."));
        assert!(!script.contains("GIT_CONFIG_KEY_0"));

        let again = render_env(&entries, &[entries[0].key.clone(), entries[1].key.clone()]);
        assert!(again.contains("export GIT_CONFIG_COUNT=2\n"), "{again}");
        assert!(again.contains("GIT_CONFIG_KEY_1='http."));
    }

    #[test]
    fn quoting_survives_a_quote() {
        assert_eq!(single_quoted("it's"), r"'it'\''s'");
        assert_eq!(double_escaped("a\"$`\\"), r#"a\"\$\`\\"#);
    }
}
