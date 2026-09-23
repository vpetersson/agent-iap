//! An identity-aware proxy for LLM agents.
//!
//! The goal in one sentence: give an agent access to an API or an MCP server
//! without ever giving it the credential. Everything else here — the ACL, the
//! interactive prompt, the hash-chained audit log — exists to make that grant
//! narrow, observable and revocable.

/// How agent-iap introduces itself to anything it calls.
///
/// What this binary was built from: the version, and — when the build knew
/// them — the commit and the day.
///
/// `2026.9.0` is the same string for every build of every commit between two
/// releases, and with no tagged release yet, *every* install is a build
/// somebody made themselves. So the one question an operator has when a fix is
/// reported to have landed — "is it in the thing I am running?" — had no answer
/// anywhere in this program. Three rounds of a bug report were spent on it
/// (SIRI-205). This is that answer, and it is printed where the question comes
/// up: `--version`, the startup banner, `check`, and the console's header.
///
/// Both extras are optional. A build from a source tarball has no git to ask,
/// and falls back to exactly what it printed before.
pub fn version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        let mut version = env!("CARGO_PKG_VERSION").to_string();
        match (
            option_env!("AGENT_IAP_COMMIT"),
            option_env!("AGENT_IAP_BUILD_DATE"),
        ) {
            (Some(commit), Some(date)) => version.push_str(&format!(" ({commit}, built {date})")),
            (Some(commit), None) => version.push_str(&format!(" ({commit})")),
            (None, Some(date)) => version.push_str(&format!(" (built {date})")),
            (None, None) => {}
        }
        version
    })
}

/// The commit alone, for the places that have room for one field rather than a
/// sentence. `None` when the build had no git to ask.
pub fn commit() -> Option<&'static str> {
    option_env!("AGENT_IAP_COMMIT")
}

/// The same, shortened for a status bar — `aabbe24`, or `aabbe24+` when the
/// tree it was built from had edits in it. The `+` is the part worth keeping:
/// "the fix is in that commit" says nothing about a tree edited afterwards.
pub fn short_commit() -> Option<String> {
    let commit = commit()?;
    let (hash, modified) = match commit.strip_suffix("-modified") {
        Some(hash) => (hash, "+"),
        None => (commit, ""),
    };
    let short: String = hash.chars().take(7).collect();
    Some(format!("{short}{modified}"))
}

/// A product token, its version, and where to find the project — the shape RFC
/// 9110 describes, and the shape a server operator reading a log expects. Both
/// halves come from `Cargo.toml`, so a release cannot ship a stale one.
///
/// It is never the whole story on a forwarded request: there, this is *appended*
/// to whatever the agent sent, so an upstream sees the agent that asked as well
/// as the proxy that carried it.
pub const USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    " (+",
    env!("CARGO_PKG_REPOSITORY"),
    ")"
);

/// A client that says who it is. Every outbound request agent-iap makes on its
/// own behalf — minting a token, reaching an MCP server, calling its own
/// control plane — goes through one of these.
///
/// The data plane builds its own (`state::build_http_client`): its timeouts come
/// from the policy file, and change under a reload.
pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .build()
        // Only a TLS backend that will not initialise fails here, and nothing
        // this process does afterwards would work anyway.
        .expect("building an HTTP client with no options set")
}

pub mod acl;
pub mod admin;
pub mod approval;
pub mod audit;
pub mod bell;
pub mod clipboard;
pub mod config;
pub mod credentials;
pub mod discovery;
pub mod enroll;
pub mod gate;
pub mod gateway;
pub mod identity;
pub mod init;
pub mod list;
pub mod mcp;
pub mod paths;
pub mod profiles;
pub mod proxy;
pub mod reload;
pub mod secrets;
pub mod service_account;
pub mod skills;
pub mod state;
pub mod stdio;
pub mod store;
pub mod term;
pub mod tls;
pub mod tokens;
pub mod tui;
pub mod verify;
pub mod workload;
