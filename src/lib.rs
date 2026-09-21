//! An identity-aware proxy for LLM agents.
//!
//! The goal in one sentence: give an agent access to an API or an MCP server
//! without ever giving it the credential. Everything else here — the ACL, the
//! interactive prompt, the hash-chained audit log — exists to make that grant
//! narrow, observable and revocable.

/// How agent-iap introduces itself to anything it calls.
///
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
pub mod term;
pub mod tls;
pub mod tokens;
pub mod tui;
pub mod verify;
pub mod workload;
