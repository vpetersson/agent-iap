//! `agent-iap git-config` and `agent-iap git-credential`: sending git through
//! the proxy.
//!
//! Git is a program, not an SDK with a base URL, so the HTTP gateway reaches it
//! through git's own configuration: `url.<proxy>/<upstream>/.insteadOf` turns
//! `https://github.com/o/r.git` into the proxied address, and
//! `credential.<proxy>/<upstream>/.helper` has git ask `agent-iap
//! git-credential` for the agent's token when the proxy asks for one.
//!
//! A credential helper rather than an `http.extraHeader` holding the token,
//! because a helper is asked at the moment git needs it: no setting holds the
//! token, so the same settings work in a shell that never saw `$IAP_TOKEN`, can
//! go into `~/.gitconfig` without putting a credential there, and pick up a
//! rotated token file on the next fetch. The proxy accepts the token as the
//! password of HTTP Basic for this, and challenges for Basic when a request on
//! an upstream arrives with no token at all — which is what makes git ask.
//! The `Authorization` git sends is the agent's, and is consumed by the proxy;
//! github.com is sent the profile's own `x-access-token:<PAT>` in its place.
//!
//! The helper list for the proxied prefix is reset before ours is added. A
//! `credential.helper = store` from the user's own configuration would
//! otherwise be handed the agent token after the first successful fetch, and
//! write it to `~/.git-credentials` in the clear.

use anyhow::{bail, Context, Result};
use std::path::Path;

/// What `git-config` is asked to describe.
pub struct GitConfigOptions {
    /// The proxy's data-plane address, e.g. `http://127.0.0.1:8080`.
    pub proxy_url: String,
    /// The upstream enrolled from the `github-git` profile.
    pub upstream: String,
    /// The `credential.helper` value: see [`helper_command`].
    pub helper: String,
}

/// The remote whose URLs are rewritten. Only HTTPS: an `ssh://` or
/// `git@github.com:` remote is a different transport the proxy does not speak.
const GITHUB: &str = "https://github.com/";

/// The user name the helper answers with. The proxy reads only the password,
/// but git will not send a credential without one.
pub const USERNAME: &str = "agent-iap";

/// One git setting, as `git config` would name it.
#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub value: String,
}

/// The settings, in the order they are emitted. A key may appear more than
/// once — `credential.*.helper` is a list — and order within it matters.
pub fn entries(options: &GitConfigOptions) -> Result<Vec<Entry>> {
    let base = proxied_prefix(&options.proxy_url, &options.upstream)?;
    let helper = format!("credential.{base}.helper");
    Ok(vec![
        Entry {
            key: format!("url.{base}.insteadOf"),
            value: GITHUB.into(),
        },
        // Empty first: it clears every helper configured before this one, for
        // this prefix only.
        Entry {
            key: helper.clone(),
            value: String::new(),
        },
        Entry {
            key: helper,
            value: options.helper.clone(),
        },
    ])
}

/// The helper as git runs it: `!` makes git hand it to the shell, which is how
/// a helper takes arguments. The path is absolute so the setting works from a
/// shell whose `PATH` has no `agent-iap` on it, and the proxy's address is
/// named so the helper can refuse to answer anybody else.
pub fn helper_command(exe: &Path, proxy_url: &str, token_file: Option<&Path>) -> String {
    let mut command = format!(
        "!{} git-credential --proxy-url {}",
        single_quoted(&exe.to_string_lossy()),
        single_quoted(proxy_url.trim())
    );
    if let Some(file) = token_file {
        command.push_str(&format!(
            " --token-file {}",
            single_quoted(&file.to_string_lossy())
        ));
    }
    command
}

/// `<proxy>/<upstream>/`, the prefix the settings are keyed on. The trailing
/// slash matters: git matches `http.<url>.*` by path segment, and without it
/// `github-git` would also cover a sibling upstream called `github-gitlab`.
fn proxied_prefix(proxy_url: &str, upstream: &str) -> Result<String> {
    let url = proxy_address(proxy_url)?;
    let upstream = upstream.trim_matches('/');
    if upstream.is_empty() || upstream.contains(['/', '?', '#', ' ']) {
        bail!("`{upstream}` is not an upstream name");
    }
    Ok(format!(
        "{}/{upstream}/",
        url.as_str().trim_end_matches('/')
    ))
}

/// The proxy's address, parsed, or why it is not one.
pub fn proxy_address(proxy_url: &str) -> Result<url::Url> {
    let url = url::Url::parse(proxy_url.trim())
        .with_context(|| format!("`{proxy_url}` is not a proxy address"))?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("`{proxy_url}` is not an http:// or https:// address");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("`{proxy_url}` should be the proxy's address alone, without a query");
    }
    Ok(url)
}

/// The entries as `export` lines for a POSIX shell's `eval`.
///
/// `existing` is the `GIT_CONFIG_COUNT` already in the environment, with the
/// keys it holds: the new settings are appended after them rather than
/// replacing them, and a setting this command already made — evaluating it
/// twice in one shell — is overwritten in place rather than added again. A key
/// that appears twice in `entries` takes the first and second slot holding
/// that key, so the helper list stays one reset and one helper.
pub fn render_env(entries: &[Entry], existing: &[String]) -> String {
    let mut keys: Vec<String> = existing.to_vec();
    let mut out = String::from(
        "# Routes https://github.com/ through agent-iap for this shell. No token is in\n\
         # these settings: git asks `agent-iap git-credential` for it when it is needed.\n",
    );
    let mut lines = Vec::new();
    for (position, entry) in entries.iter().enumerate() {
        let occurrence = entries[..position]
            .iter()
            .filter(|earlier| earlier.key == entry.key)
            .count();
        let found = keys
            .iter()
            .enumerate()
            .filter(|(_, key)| *key == &entry.key)
            .nth(occurrence)
            .map(|(index, _)| index);
        let index = match found {
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
        lines.push(format!(
            "export GIT_CONFIG_VALUE_{index}={}",
            single_quoted(&entry.value)
        ));
    }
    out.push_str(&format!("export GIT_CONFIG_COUNT={}\n", keys.len()));
    for line in lines {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// The entries as `git config --global` commands, for `| sh`.
///
/// What makes this safe to offer is that nothing in the settings is a
/// credential. It is what an agent whose every tool call is a fresh shell
/// needs: an `eval` in one call is gone by the next. The first value of a key
/// replaces whatever that key held, so running it twice leaves one copy.
pub fn render_global(entries: &[Entry]) -> String {
    let mut out = String::from(
        "# Routes https://github.com/ through agent-iap for every git this user runs.\n\
         # No token is written: git asks `agent-iap git-credential` for it when it is needed.\n",
    );
    for (position, entry) in entries.iter().enumerate() {
        let first = !entries[..position]
            .iter()
            .any(|earlier| earlier.key == entry.key);
        out.push_str(&format!(
            "git config --global {} {} {}\n",
            if first { "--replace-all" } else { "--add" },
            single_quoted(&entry.key),
            single_quoted(&entry.value)
        ));
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

/// One run of the credential helper: what to print for `operation`, given what
/// git wrote on stdin.
///
/// Only `get` is answered. `store` and `erase` are git reporting that a
/// credential worked or did not; there is nothing to keep, and the token file
/// is not this helper's to delete. An operation git adds later is ignored, as
/// the protocol asks.
///
/// `get` is answered only for the proxy's own scheme, host and port. The
/// helper is configured for the proxied prefix and nothing else, but a copy of
/// the setting pasted somewhere wider would otherwise hand the agent token to
/// whatever host git happened to be talking to.
pub fn credential(
    operation: &str,
    input: &str,
    proxy: &url::Url,
    token: impl FnOnce() -> Result<String>,
) -> Result<CredentialAnswer> {
    if operation != "get" {
        return Ok(CredentialAnswer::Nothing);
    }
    let field = |name: &str| {
        input
            .lines()
            .take_while(|line| !line.is_empty())
            .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
            .unwrap_or_default()
    };
    let (protocol, host) = (field("protocol"), field("host"));
    if !same_origin(proxy, protocol, host) {
        return Ok(CredentialAnswer::NotTheProxy(format!(
            "{protocol}://{host}"
        )));
    }
    let token = token()?;
    Ok(CredentialAnswer::Credential(format!(
        "username={USERNAME}\npassword={token}\n"
    )))
}

/// What the helper says back.
#[derive(Debug, PartialEq, Eq)]
pub enum CredentialAnswer {
    /// The lines to print.
    Credential(String),
    /// Asked about somewhere else, named here for the message. Nothing is
    /// printed, so git moves on to whatever it would have done.
    NotTheProxy(String),
    /// Nothing to say.
    Nothing,
}

fn same_origin(proxy: &url::Url, protocol: &str, host: &str) -> bool {
    if !protocol.eq_ignore_ascii_case(proxy.scheme()) {
        return false;
    }
    let Some(proxy_host) = proxy.host_str() else {
        return false;
    };
    // Git writes the port only when the URL had one; `[::1]:8080` keeps its
    // brackets, so a colon after the closing one is the port.
    let (name, port) = match host.rsplit_once(':') {
        Some((name, port)) if !host.ends_with(']') && port.bytes().all(|b| b.is_ascii_digit()) => {
            (name, port.parse::<u16>().ok())
        }
        _ => (host, None),
    };
    let default = match protocol {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    };
    name.eq_ignore_ascii_case(proxy_host) && port.or(default) == proxy.port_or_known_default()
}

fn single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELPER: &str = "!'/usr/bin/agent-iap' git-credential --proxy-url 'http://127.0.0.1:8080'";

    fn options(proxy_url: &str) -> GitConfigOptions {
        GitConfigOptions {
            proxy_url: proxy_url.into(),
            upstream: "github-git".into(),
            helper: HELPER.into(),
        }
    }

    fn entries_for(proxy_url: &str) -> Vec<Entry> {
        entries(&options(proxy_url)).unwrap()
    }

    fn entry(key: &str, value: &str) -> Entry {
        Entry {
            key: key.into(),
            value: value.into(),
        }
    }

    #[test]
    fn rewrites_github_to_the_upstream_and_scopes_the_helper_to_it() {
        assert_eq!(
            entries_for("http://127.0.0.1:8080"),
            [
                entry(
                    "url.http://127.0.0.1:8080/github-git/.insteadOf",
                    "https://github.com/"
                ),
                entry("credential.http://127.0.0.1:8080/github-git/.helper", ""),
                entry(
                    "credential.http://127.0.0.1:8080/github-git/.helper",
                    HELPER
                ),
            ]
        );
        // A trailing slash on the address, or a TLS one, changes nothing else.
        let tls = entries_for("https://iap.example.com:8443/");
        assert_eq!(
            tls[0].key,
            "url.https://iap.example.com:8443/github-git/.insteadOf"
        );
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

    #[test]
    fn the_helper_is_quoted_for_the_shell_git_hands_it_to() {
        assert_eq!(
            helper_command(
                Path::new("/opt/it's here/agent-iap"),
                "http://127.0.0.1:8080 ",
                Some(Path::new("/home/a/token"))
            ),
            r"!'/opt/it'\''s here/agent-iap' git-credential --proxy-url 'http://127.0.0.1:8080' --token-file '/home/a/token'"
        );
    }

    /// No token is printed, in either form.
    #[test]
    fn the_output_holds_settings_and_never_a_token() {
        let script = render_env(&entries_for("http://127.0.0.1:8080"), &[]);
        assert!(script.contains("export GIT_CONFIG_COUNT=3\n"), "{script}");
        assert!(script.contains(
            "export GIT_CONFIG_KEY_0='url.http://127.0.0.1:8080/github-git/.insteadOf'\n"
        ));
        assert!(script.contains("export GIT_CONFIG_VALUE_0='https://github.com/'\n"));
        assert!(
            script.contains("export GIT_CONFIG_VALUE_1=''\n"),
            "{script}"
        );
        assert!(script.contains("export GIT_CONFIG_VALUE_2='!'\\''/usr/bin/agent-iap"));
        assert!(!script.contains("iap_"), "{script}");

        let global = render_global(&entries_for("http://127.0.0.1:8080"));
        assert_eq!(
            global.lines().skip(2).collect::<Vec<_>>(),
            [
                "git config --global --replace-all 'url.http://127.0.0.1:8080/github-git/.insteadOf' 'https://github.com/'",
                "git config --global --replace-all 'credential.http://127.0.0.1:8080/github-git/.helper' ''",
                "git config --global --add 'credential.http://127.0.0.1:8080/github-git/.helper' '!'\\''/usr/bin/agent-iap'\\'' git-credential --proxy-url '\\''http://127.0.0.1:8080'\\'''",
            ]
        );
    }

    /// Settings already in the environment are kept, and running it twice in
    /// one shell leaves one reset and one helper, not two of each.
    #[test]
    fn existing_settings_are_appended_to_and_its_own_are_replaced() {
        let entries = entries_for("http://127.0.0.1:8080");
        let script = render_env(&entries, &["core.autocrlf".into()]);
        assert!(script.contains("export GIT_CONFIG_COUNT=4\n"), "{script}");
        assert!(script.contains("GIT_CONFIG_KEY_1='url."));
        assert!(script.contains("GIT_CONFIG_KEY_2='credential."));
        assert!(script.contains("GIT_CONFIG_KEY_3='credential."));
        assert!(!script.contains("GIT_CONFIG_KEY_0"));

        let mut keys: Vec<String> = vec!["core.autocrlf".into()];
        keys.extend(entries.iter().map(|entry| entry.key.clone()));
        let again = render_env(&entries, &keys);
        assert!(again.contains("export GIT_CONFIG_COUNT=4\n"), "{again}");
        assert!(again.contains("GIT_CONFIG_VALUE_2=''"), "{again}");
        assert!(again.contains("GIT_CONFIG_VALUE_3='!"), "{again}");
    }

    fn proxy() -> url::Url {
        url::Url::parse("http://127.0.0.1:8080").unwrap()
    }

    fn ask(operation: &str, input: &str) -> CredentialAnswer {
        credential(operation, input, &proxy(), || Ok("iap_agent".into())).unwrap()
    }

    #[test]
    fn get_for_the_proxy_answers_with_the_token_as_the_password() {
        assert_eq!(
            ask(
                "get",
                "capability[]=authtype\nprotocol=http\nhost=127.0.0.1:8080\nwwwauth[]=Basic realm=\"agent-iap\"\n\n"
            ),
            CredentialAnswer::Credential("username=agent-iap\npassword=iap_agent\n".into())
        );
    }

    #[test]
    fn store_and_erase_say_nothing_and_read_no_token() {
        for operation in ["store", "erase", "something-new"] {
            let answer = credential(
                operation,
                "protocol=http\nhost=127.0.0.1:8080\n",
                &proxy(),
                || panic!("{operation} read the token"),
            )
            .unwrap();
            assert_eq!(answer, CredentialAnswer::Nothing, "{operation}");
        }
    }

    /// The token goes to the proxy and nowhere else, whatever git was
    /// configured to ask.
    #[test]
    fn get_for_anywhere_else_reads_no_token() {
        for input in [
            "protocol=https\nhost=github.com\n",
            "protocol=https\nhost=127.0.0.1:8080\n",
            "protocol=http\nhost=127.0.0.1:8081\n",
            "protocol=http\nhost=127.0.0.1\n",
            "protocol=http\nhost=127.0.0.1.example.com:8080\n",
            "host=127.0.0.1:8080\n",
            "",
            // A field after the blank line is not part of the request.
            "protocol=http\n\nhost=127.0.0.1:8080\n",
        ] {
            let answer = credential("get", input, &proxy(), || {
                panic!("{input:?} read the token")
            })
            .unwrap();
            assert!(
                matches!(answer, CredentialAnswer::NotTheProxy(_)),
                "{input:?}: {answer:?}"
            );
        }
    }

    #[test]
    fn a_default_port_matches_whether_or_not_git_writes_it() {
        let proxy = url::Url::parse("https://IAP.example.com").unwrap();
        for host in ["iap.example.com", "iap.example.com:443"] {
            let input = format!("protocol=https\nhost={host}\n");
            let answer = credential("get", &input, &proxy, || Ok("iap_agent".into())).unwrap();
            assert!(matches!(answer, CredentialAnswer::Credential(_)), "{host}");
        }
        let v6 = url::Url::parse("http://[::1]:8080").unwrap();
        let answer = credential("get", "protocol=http\nhost=[::1]:8080\n", &v6, || {
            Ok("iap_agent".into())
        })
        .unwrap();
        assert!(matches!(answer, CredentialAnswer::Credential(_)));
    }

    #[test]
    fn quoting_survives_a_quote() {
        assert_eq!(single_quoted("it's"), r"'it'\''s'");
    }
}
