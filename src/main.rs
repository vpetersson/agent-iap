use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agent_iap::audit;
use agent_iap::clipboard;
use agent_iap::config::Config;
use agent_iap::enroll;
use agent_iap::identity;
use agent_iap::init::{self, InitOptions, Template};
use agent_iap::list::{Inventory, ListOptions, What};
use agent_iap::mcp;
use agent_iap::paths;
use agent_iap::profiles;
use agent_iap::reload::Watcher;
use agent_iap::secrets::SecretResolver;
use agent_iap::state::AppState;
use agent_iap::stdio;
use agent_iap::tls::{self, Listener, ServerTls};
use agent_iap::tui::{self, Console};
use agent_iap::verify;

#[derive(Parser)]
#[command(
    name = "agent-iap",
    version,
    about = "Identity-aware proxy for LLM agents — authenticated, ACL-gated, audited access to APIs and MCP servers without handing over the credential."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Clone)]
struct ConfigArg {
    /// Path to the TOML policy file. Defaults to `./iap.toml` when one is
    /// already there, and otherwise to the user config directory —
    /// `~/.config/agent-iap/iap.toml` on Linux and macOS.
    #[arg(
        short,
        long,
        default_value_os_t = paths::default_config_file(),
        env = "IAP_CONFIG",
        global = true
    )]
    config: PathBuf,
}

/// The opt-out for the one convenience that touches a secret.
///
/// A token is printed once and has to be pasted somewhere; putting it on the
/// clipboard is the point. But a desktop clipboard is shared with everything
/// else on that desktop and is often kept in a history, so the operator gets a
/// say — per command here, or once and for all with `IAP_NO_CLIPBOARD`.
#[derive(Args, Clone, Copy)]
struct ClipboardArg {
    /// Do not put the minted token on the terminal's clipboard. The
    /// `IAP_NO_CLIPBOARD` environment variable does the same for every command.
    #[arg(long)]
    no_clipboard: bool,
}

impl ClipboardArg {
    fn allowed(self) -> bool {
        !self.no_clipboard
    }
}

#[derive(Subcommand)]
enum Command {
    /// Write a policy file the proxy will start with.
    Init {
        #[command(flatten)]
        config: ConfigArg,
        /// Id of the agent to mint a token for.
        #[arg(long, default_value = init::DEFAULT_AGENT_ID)]
        agent: String,
        /// Credential reference for the starter upstream: `env:NAME`,
        /// `file:/path` or `op://vault/item/field`. Starter template only.
        #[arg(long, value_name = "REF")]
        secret: Option<String>,
        /// `minimal` is the proxy and nothing else; `starter` adds one agent
        /// and one Anthropic upstream; `full` is the annotated example, with
        /// GitHub, MCP and a service account worked out.
        #[arg(long, value_enum, default_value_t = TemplateArg::Minimal)]
        template: TemplateArg,
        /// Replace an existing file. Mints a new token, retiring the old one.
        #[arg(short, long)]
        force: bool,
        #[command(flatten)]
        clipboard: ClipboardArg,
    },
    /// Run the proxy, with the approval console on a terminal.
    Run {
        #[command(flatten)]
        config: ConfigArg,
        /// Where agents connect: `HOST:PORT`, or a bare port to keep the
        /// interface the config file chose. Overrides `server.listen`.
        #[arg(long, value_name = "ADDR", env = "IAP_LISTEN")]
        listen: Option<String>,
        /// Where the control plane listens, or `off` to disable it. Overrides
        /// `server.admin_listen`.
        #[arg(long, value_name = "ADDR", env = "IAP_ADMIN_LISTEN")]
        admin_listen: Option<String>,
        /// Open the approval console. The default wherever there is a
        /// terminal to draw it on; pass it to insist on one we did not
        /// recognise.
        #[arg(long)]
        tui: bool,
        /// Run without the console: the log on stderr, and an `ask` answered
        /// over the control plane or not at all. The default with no terminal,
        /// so a unit file or a container needs neither this flag nor a TTY.
        #[arg(long, conflicts_with = "tui")]
        no_tui: bool,
    },
    /// Bridge one MCP server for an agent. Requires a running `agent-iap run`.
    Mcp {
        #[command(flatten)]
        config: ConfigArg,
        /// Name of the `[[mcp_servers]]` entry to front.
        #[arg(short, long)]
        server: String,
        /// The agent's IAP token.
        #[arg(long, env = "IAP_TOKEN", hide_env_values = true)]
        token: String,
        /// Control-plane address of the running proxy.
        #[arg(long, env = "IAP_ADMIN_URL")]
        admin_url: Option<String>,
    },
    /// Serve agent-iap's own MCP gateway on stdio for a client that cannot speak
    /// HTTP MCP. Requires a running `agent-iap run`.
    Gateway {
        #[command(flatten)]
        config: ConfigArg,
        /// The agent's IAP token.
        #[arg(long, env = "IAP_TOKEN", hide_env_values = true)]
        token: String,
        /// Data-plane address of the running proxy.
        #[arg(long, env = "IAP_PROXY_URL")]
        proxy_url: Option<String>,
    },
    /// Show every service this proxy exposes: agents, upstreams, MCP servers, ACL.
    List {
        #[command(flatten)]
        config: ConfigArg,
        /// Limit the view to one section. Omit for all of them.
        #[arg(value_enum)]
        what: Option<WhatArg>,
        /// Show only what this agent can reach: the targets it may address and
        /// the rules that match it.
        #[arg(long, value_name = "ID")]
        agent: Option<String>,
        /// `table` for a terminal, `json` for an inventory script.
        #[arg(long, value_enum, default_value_t = OutputArg::Table)]
        output: OutputArg,
    },
    /// Validate the policy file and resolve every secret reference in it.
    Check {
        #[command(flatten)]
        config: ConfigArg,
    },
    /// Enrol, revoke or re-key the agents allowed to call the proxy.
    #[command(subcommand)]
    Agent(AgentCommand),
    /// Add or remove the services the proxy fronts.
    #[command(subcommand)]
    Upstream(UpstreamCommand),
    /// Add or remove an MCP server in the policy file.
    #[command(subcommand, name = "mcp-server")]
    McpServer(McpServerCommand),
    /// Ready-made service definitions: base URL, credential scheme and rules.
    #[command(subcommand)]
    Profile(ProfileCommand),
    /// Add or remove ACL rules.
    #[command(subcommand)]
    Acl(AclCommand),
    /// Mint an agent token and print the config block to paste.
    GenToken {
        /// Agent id to use in the printed block.
        #[arg(default_value = "my-agent")]
        id: String,
        #[command(flatten)]
        clipboard: ClipboardArg,
    },
    /// Print the sha256 of a token you already have (reads stdin when omitted).
    HashToken { token: Option<String> },
    /// Inspect the audit log.
    #[command(subcommand)]
    Audit(AuditCommand),
}

#[derive(Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
enum WhatArg {
    Agents,
    Upstreams,
    Mcp,
    Acl,
    Credentials,
}

impl From<WhatArg> for What {
    fn from(arg: WhatArg) -> Self {
        match arg {
            WhatArg::Agents => What::Agents,
            WhatArg::Upstreams => What::Upstreams,
            WhatArg::Mcp => What::Mcp,
            WhatArg::Acl => What::Acl,
            WhatArg::Credentials => What::Credentials,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
enum OutputArg {
    Table,
    Json,
}

#[derive(Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
enum TemplateArg {
    Minimal,
    Starter,
    Full,
}

impl From<TemplateArg> for Template {
    fn from(arg: TemplateArg) -> Self {
        match arg {
            TemplateArg::Minimal => Template::Minimal,
            TemplateArg::Starter => Template::Starter,
            TemplateArg::Full => Template::Full,
        }
    }
}

#[derive(Subcommand)]
enum AgentCommand {
    /// Mint a token, enrol the agent, and write only the hash to the file.
    Add {
        /// Id the agent authenticates as, and the name every audit record uses.
        id: String,
        #[command(flatten)]
        config: ConfigArg,
        /// Display name for the console, when the id is not what a human calls it.
        #[arg(long)]
        name: Option<String>,
        /// Upstream or MCP server this agent may address at all. Repeatable.
        /// Omit for "any", which still leaves the ACL in charge.
        #[arg(long = "target", value_name = "NAME")]
        targets: Vec<String>,
        #[command(flatten)]
        clipboard: ClipboardArg,
    },
    /// Revoke an agent: remove it, and its token stops being one.
    #[command(alias = "remove")]
    Rm {
        /// Id of the agent to remove.
        id: String,
        #[command(flatten)]
        config: ConfigArg,
        /// Also delete the ACL rules that name this agent outright. Without
        /// it they stay, matching nothing, and are listed by number.
        #[arg(long)]
        prune: bool,
    },
    /// Replace an agent's token with a new one. The leaked-token path: one
    /// command, and nothing upstream rotates.
    Rotate {
        /// Id of the agent to re-key.
        id: String,
        #[command(flatten)]
        config: ConfigArg,
        #[command(flatten)]
        clipboard: ClipboardArg,
    },
}

/// The opt-in that turns an enrolment into an enrolment plus a phone call.
///
/// Off by default, and after the write rather than before it: adding a service
/// should not depend on that service being up, and a base URL typed wrong is
/// fixed with `upstream edit`, not by doing the whole enrolment again. What it
/// buys is finding out now instead of on the agent's first call.
#[derive(Args, Clone, Copy)]
struct VerifyArg {
    /// After writing it, call the service: resolve the credential (minting the
    /// token, for a scheme that mints one), make one request, and check the ACL
    /// for a rule that reaches it. The entry is written either way; a failed
    /// verification only changes the exit status. Nothing is written by a dry
    /// run, so nothing is verified by one either.
    #[arg(long)]
    verify: bool,
}

#[derive(Subcommand)]
enum UpstreamCommand {
    /// Add a service the proxy fronts, and the credential it attaches.
    ///
    /// Either start from a profile — `--profile github` brings the base URL,
    /// the credential scheme and a reviewed set of ACL rules with it — or spell
    /// the service out with `--base-url` and the credential flags.
    /// `agent-iap profile list` shows every profile there is.
    Add {
        /// Routing prefix and policy name: agents call `/<name>/<path>`.
        name: String,
        #[command(flatten)]
        config: ConfigArg,
        /// Start from a profile, from `agent-iap profile list`. Supplies the
        /// base URL, the credential scheme and the ACL rules; the credential
        /// itself is still yours to name with `--secret`.
        #[arg(long, value_name = "ID")]
        profile: Option<String>,
        /// Where the proxy forwards to, e.g. `https://api.anthropic.com`.
        /// Not needed with `--profile`, which already knows.
        #[arg(
            long,
            value_name = "URL",
            required_unless_present = "profile",
            conflicts_with = "profile"
        )]
        base_url: Option<String>,
        // Boxed only for its size: the credential flags dwarf every other
        // variant of this enum, `rm` most of all.
        #[command(flatten)]
        auth: Box<AuthFlags>,
        /// With `--profile`: which bundle of scopes and rules to write.
        /// Defaults to the narrowest the profile offers.
        #[arg(long, value_name = "LEVEL", requires = "profile")]
        access: Option<String>,
        /// With `--profile`: a profile variable, `name=value`. Repeatable.
        #[arg(long = "var", value_name = "NAME=VALUE", requires = "profile")]
        vars: Vec<String>,
        /// With `--profile`: scope the rules to one agent or glob. Defaults to
        /// every agent.
        #[arg(long, value_name = "ID", requires = "profile")]
        agent: Option<String>,
        /// With `--profile`: print the TOML that would be appended, and write
        /// nothing.
        #[arg(long, requires = "profile")]
        dry_run: bool,
        /// Static header to send upstream, `Name=Value`. Repeatable. Never a
        /// credential — that is what `--secret` is for.
        #[arg(
            long = "set-header",
            value_name = "NAME=VALUE",
            conflicts_with = "profile"
        )]
        set_headers: Vec<String>,
        #[command(flatten)]
        verify: VerifyArg,
    },
    /// Call a service the proxy fronts and report what came back.
    ///
    /// The half of a policy file `check` cannot read: `check` proves the
    /// credential resolves, this proves the service accepts it. One GET, with
    /// the credential attached exactly the way the proxy attaches it — which
    /// for an OAuth or service-account upstream means the token is really
    /// minted. Name nothing to verify every upstream.
    Verify {
        /// Name of the `[[upstreams]]` entry. Every one of them when omitted.
        name: Option<String>,
        #[command(flatten)]
        config: ConfigArg,
        /// Endpoint to call, relative to the base URL — `/user`, or
        /// `/v1/models?limit=1`. Defaults to the root, which most APIs answer
        /// with a 404 that says nothing about the credential.
        #[arg(long, value_name = "PATH")]
        path: Option<String>,
        /// How long one call gets.
        #[arg(long, value_name = "SECS", default_value_t = 10)]
        timeout: u64,
    },
    /// Remove a service, and stop injecting its credential.
    #[command(alias = "remove")]
    Rm {
        /// Name of the `[[upstreams]]` entry to remove.
        name: String,
        #[command(flatten)]
        config: ConfigArg,
        /// Also delete the ACL rules aimed at it, and drop it from the
        /// `targets` of agents scoped to it. Without it, an agent still
        /// naming it makes the removal a refusal rather than a broken file.
        #[arg(long)]
        prune: bool,
    },
}

/// Add an MCP server to the policy file. `mcp` itself is the bridge an agent
/// runs, so enrolment lives under its own noun rather than shadowing it.
#[derive(Subcommand)]
enum McpServerCommand {
    /// Add a `[[mcp_servers]]` entry: a stdio server to spawn, or a remote one.
    Add {
        /// Policy name agents address, and the name every audit record uses.
        name: String,
        #[command(flatten)]
        config: ConfigArg,
        /// Remote endpoint for an HTTP MCP server. Omit for a stdio child.
        #[arg(long, value_name = "URL", conflicts_with = "command")]
        url: Option<String>,
        /// Executable to spawn for a stdio MCP server.
        #[arg(long, value_name = "BIN")]
        command: Option<String>,
        /// Argument for `--command`. Repeatable, in order.
        #[arg(long = "arg", value_name = "ARG", requires = "command")]
        args: Vec<String>,
        /// Child environment entry, `NAME=<secret-ref>`. Repeatable. This is
        /// how a stdio server gets its credential — the value is a reference,
        /// resolved in the proxy, never the credential itself.
        #[arg(long = "env", value_name = "NAME=REF", requires = "command")]
        env: Vec<String>,
        /// Working directory for the child.
        #[arg(long, value_name = "DIR", requires = "command")]
        cwd: Option<String>,
        // Boxed for size, as in `UpstreamCommand::Add`.
        #[command(flatten)]
        auth: Box<AuthFlags>,
        #[command(flatten)]
        verify: VerifyArg,
    },
    /// Open an MCP session with a configured server and report what came back.
    ///
    /// Spawns the child, or calls the remote endpoint, with the credential the
    /// policy file names, does the `initialize` handshake and asks for the tool
    /// list — which is the list the ACL's `tools/call` rules are written
    /// against. Name nothing to verify every server.
    Verify {
        /// Name of the `[[mcp_servers]]` entry. Every one of them when omitted.
        name: Option<String>,
        #[command(flatten)]
        config: ConfigArg,
        /// How long the handshake gets.
        #[arg(long, value_name = "SECS", default_value_t = 10)]
        timeout: u64,
    },
    /// Remove a `[[mcp_servers]]` entry.
    #[command(alias = "remove")]
    Rm {
        /// Name of the `[[mcp_servers]]` entry to remove.
        name: String,
        #[command(flatten)]
        config: ConfigArg,
        /// Also delete the ACL rules aimed at it, and drop it from the
        /// `targets` of agents scoped to it.
        #[arg(long)]
        prune: bool,
    },
}

#[derive(Subcommand)]
enum ProfileCommand {
    /// List every profile there is.
    List {
        /// Only profiles from this vendor, matched case-insensitively.
        #[arg(long)]
        vendor: Option<String>,
        #[arg(long, value_enum, default_value_t = OutputArg::Table)]
        output: OutputArg,
    },
    /// Show what a profile would add: endpoint, credential, scopes, rules.
    Show {
        /// Profile id, from `agent-iap profile list`.
        id: String,
    },
    /// Add a profile's service and rules to the policy file.
    Add {
        /// Profile id, from `agent-iap profile list`.
        id: String,
        #[command(flatten)]
        config: ConfigArg,
        /// Name to use in the policy file. Defaults to the profile's own, and
        /// is how one proxy fronts two accounts of the same service.
        #[arg(long = "as", value_name = "NAME")]
        name: Option<String>,
        /// Credential *reference*: `env:NAME`, `file:/path`, `op://vault/item/field`.
        #[arg(long, value_name = "REF")]
        secret: Option<String>,
        /// Which bundle of scopes and rules to write. Defaults to the
        /// narrowest the profile offers.
        #[arg(long, value_name = "LEVEL")]
        access: Option<String>,
        /// Profile variable, `name=value`. Repeatable.
        #[arg(long = "var", value_name = "NAME=VALUE")]
        vars: Vec<String>,
        /// Scope the rules to one agent or glob. Defaults to every agent.
        #[arg(long, value_name = "ID")]
        agent: Option<String>,
        /// Print the TOML that would be appended, and write nothing.
        #[arg(long)]
        dry_run: bool,
        #[command(flatten)]
        verify: VerifyArg,
    },
}

/// Everything the credential schemes need. Shared by `upstream add` and
/// `mcp-server add`, which inject credentials the same way.
#[derive(Args, Clone)]
struct AuthFlags {
    /// Credential scheme to inject on the way out.
    #[arg(long, value_enum, default_value_t = AuthArg::None)]
    auth: AuthArg,
    /// Credential *reference*: `env:NAME`, `file:/path`, `op://vault/item/field`.
    #[arg(long, value_name = "REF")]
    secret: Option<String>,
    /// Header name for `--auth header`, e.g. `x-api-key`.
    #[arg(long, value_name = "NAME")]
    header: Option<String>,
    /// Value prefix for `--auth header`, when the API wants one.
    #[arg(long, value_name = "PREFIX")]
    prefix: Option<String>,
    /// Username for `--auth basic`.
    #[arg(long)]
    username: Option<String>,
    /// Reference for a `--auth basic` user field that *is* the credential —
    /// Graylog authenticates an access token as `<token>:token`.
    #[arg(long, value_name = "REF", conflicts_with = "username")]
    username_secret: Option<String>,
    /// Query parameter for `--auth query`, e.g. `key`.
    #[arg(long, value_name = "NAME")]
    param: Option<String>,
    /// `--auth service-account-jwt`: reference to the service-account JSON
    /// key exactly as Google issues it. Supplies issuer, key id and token URL.
    #[arg(long, value_name = "REF")]
    key_file: Option<String>,
    /// Or spell the pieces out: reference to a PKCS#8 PEM private key.
    #[arg(long, value_name = "REF", conflicts_with = "key_file")]
    private_key: Option<String>,
    /// Assertion issuer, for `--private-key`.
    #[arg(long, value_name = "ISS")]
    issuer: Option<String>,
    /// Key id to put in the JWT header, for `--private-key`.
    #[arg(long, value_name = "KID")]
    key_id: Option<String>,
    /// Token endpoint to exchange the assertion at.
    #[arg(long, value_name = "URL")]
    token_url: Option<String>,
    /// The `aud` claim. Defaults to the token URL, which is what Google wants.
    #[arg(long, value_name = "AUD")]
    audience: Option<String>,
    /// Requested scope. Repeatable.
    #[arg(long = "scope", value_name = "SCOPE")]
    scopes: Vec<String>,
    /// Impersonate this user (Google domain-wide delegation).
    #[arg(long, value_name = "EMAIL")]
    subject: Option<String>,
    /// Assertion lifetime in seconds. Clamped to an hour, Google's ceiling.
    #[arg(long, value_name = "SECS")]
    lifetime_secs: Option<u64>,
    /// Client id for `--auth oauth2-client-credentials`.
    #[arg(long, value_name = "ID")]
    client_id: Option<String>,
    /// Client secret *reference* for `--auth oauth2-client-credentials`.
    #[arg(long, value_name = "REF")]
    client_secret: Option<String>,
}

impl AuthFlags {
    /// Is `--secret` the only credential flag given?
    ///
    /// What `--profile` can live with: the profile already knows the scheme and
    /// everything it reads, and the credential reference is the one thing it
    /// cannot know. Spelled out field by field rather than derived from
    /// `to_spec`, because the point is to catch a flag that would be *ignored*
    /// — and an ignored `--header` is a credential attached the wrong way with
    /// nothing on screen to say so.
    fn only_secret(&self) -> bool {
        matches!(self.auth, AuthArg::None)
            && self.header.is_none()
            && self.prefix.is_none()
            && self.username.is_none()
            && self.username_secret.is_none()
            && self.param.is_none()
            && self.key_file.is_none()
            && self.private_key.is_none()
            && self.issuer.is_none()
            && self.key_id.is_none()
            && self.token_url.is_none()
            && self.audience.is_none()
            && self.scopes.is_empty()
            && self.subject.is_none()
            && self.lifetime_secs.is_none()
            && self.client_id.is_none()
            && self.client_secret.is_none()
    }

    /// Hand the flags to `enroll`, which owns the rule about which scheme needs
    /// which of them. The console's form builds the same struct, so the two
    /// front ends cannot disagree about what a credential needs.
    fn to_spec(&self) -> Result<enroll::AuthSpec> {
        enroll::AuthInput {
            scheme: self.auth.as_str().to_string(),
            secret: self.secret.clone(),
            header: self.header.clone(),
            prefix: self.prefix.clone(),
            username: self.username.clone(),
            username_secret: self.username_secret.clone(),
            param: self.param.clone(),
            key_file: self.key_file.clone(),
            private_key: self.private_key.clone(),
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            token_url: self.token_url.clone(),
            audience: self.audience.clone(),
            scopes: self.scopes.clone(),
            subject: self.subject.clone(),
            lifetime_secs: self.lifetime_secs,
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
        }
        .to_spec()
    }
}

#[derive(Subcommand)]
enum AclCommand {
    /// Append a rule. Appended, not inserted: first match wins, so a new rule
    /// cannot silently shadow one already in the file.
    Add {
        #[command(flatten)]
        config: ConfigArg,
        /// Shown in the audit log and the TUI, so a decision traces to a rule.
        #[arg(long)]
        name: Option<String>,
        /// Agent id or glob. Defaults to every agent.
        #[arg(long, default_value = "*")]
        agent: String,
        /// `http`, `mcp`, or `*`.
        #[arg(long, default_value = "*")]
        kind: String,
        /// Upstream or MCP server name, or `*`.
        #[arg(long, default_value = "*")]
        target: String,
        /// HTTP verbs, or JSON-RPC methods such as `tools/call`. Repeatable.
        #[arg(long = "methods", value_name = "METHOD", default_values_t = [String::from("*")])]
        methods: Vec<String>,
        /// URL paths, or for MCP the tool name. Repeatable.
        #[arg(long = "paths", value_name = "PATH", default_values_t = [String::from("**")])]
        paths: Vec<String>,
        /// `allow`, `deny`, or `ask` to prompt a human at the `run` console.
        #[arg(long, value_enum, default_value_t = ActionArg::Allow)]
        action: ActionArg,
        /// How long this rule lasts: `30s`, `5m`, `1h`, `7d`. Past it the rule
        /// matches nothing and whatever is behind it decides instead. The
        /// grant you can hand out without having to remember to take it back.
        #[arg(long, value_name = "DURATION")]
        expires_in: Option<String>,
    },
    /// Remove a rule by its number. Everything after it moves up one, so
    /// removing several means re-reading the list between them.
    #[command(alias = "remove")]
    Rm {
        /// Rule number — the `#` column of `agent-iap list acl`, counting from 0.
        index: usize,
        #[command(flatten)]
        config: ConfigArg,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
enum AuthArg {
    None,
    Bearer,
    Header,
    Basic,
    Query,
    Oauth2ClientCredentials,
    ServiceAccountJwt,
}

impl AuthArg {
    fn as_str(self) -> &'static str {
        match self {
            AuthArg::None => "none",
            AuthArg::Bearer => "bearer",
            AuthArg::Header => "header",
            AuthArg::Basic => "basic",
            AuthArg::Query => "query",
            AuthArg::Oauth2ClientCredentials => "oauth2-client-credentials",
            AuthArg::ServiceAccountJwt => "service-account-jwt",
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
enum ActionArg {
    Allow,
    Deny,
    Ask,
}

impl ActionArg {
    fn as_str(self) -> &'static str {
        match self {
            ActionArg::Allow => "allow",
            ActionArg::Deny => "deny",
            ActionArg::Ask => "ask",
        }
    }
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Prove the log has not been edited, reordered or truncated.
    Verify {
        /// Log to read. Defaults to `audit.path` from the policy file, which is
        /// the one the proxy is writing.
        path: Option<PathBuf>,
        #[command(flatten)]
        config: ConfigArg,
    },
    /// Print the last N entries, one line each — with `-f`, keep printing as
    /// the proxy writes them.
    Tail {
        /// Log to read. Defaults to `audit.path` from the policy file, which is
        /// the one the proxy is writing.
        path: Option<PathBuf>,
        #[command(flatten)]
        config: ConfigArg,
        /// How many entries to show. With `-f`, how much history comes before
        /// the stream.
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
        /// Stay open and print entries as they are written, like `tail -f`.
        /// Survives the log being rotated, waits for one that does not exist
        /// yet, and ends on Ctrl-C.
        #[arg(short = 'f', long)]
        follow: bool,
        /// Only this agent. One proxy fronts many agents, so the log is
        /// interleaved and "what has bravo been doing" is the usual question.
        #[arg(long, value_name = "ID")]
        agent: Option<String>,
        /// Only this upstream or MCP server.
        #[arg(long, value_name = "NAME")]
        target: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init {
            config,
            agent,
            secret,
            template,
            force,
            clipboard,
        } => init_config(
            &InitOptions {
                path: config.config,
                agent,
                secret,
                template: template.into(),
                force,
            },
            clipboard,
        ),
        Command::Run {
            config,
            listen,
            admin_listen,
            tui,
            no_tui,
        } => {
            let config_path = config.config.clone();
            // Held rather than applied once: the file is re-read under a
            // running proxy, and the watcher puts these back on top of every
            // read. Otherwise somebody else's unrelated edit would move the
            // proxy off the address `--listen` put it on.
            let overrides = agent_iap::config::Overrides {
                listen: listen.clone(),
                admin_listen: admin_listen.clone(),
            };
            let overridden = overrides.any();
            let watcher = Arc::new(Watcher::new(&config_path, overrides));
            let config = watcher.read()?;

            let console = tui::choose(tui, no_tui, tui::at_a_terminal());
            init_tracing(console, &config)?;
            if overridden {
                // Otherwise the file and the socket disagree and nothing says why.
                tracing::info!(
                    listen = %config.server.listen,
                    admin_listen = ?config.server.admin_listen,
                    "listen addresses overridden outside the config file"
                );
            }
            tokio_runtime()?.block_on(run(config, console, watcher))
        }
        Command::Mcp {
            config,
            server,
            token,
            admin_url,
        } => {
            let config = Config::load(&config.config)?;
            // stdout belongs to the JSON-RPC stream; diagnostics go to stderr.
            init_tracing(Console::Headless, &config)?;
            let admin_url = admin_url
                .or_else(|| {
                    let scheme = tls::scheme(config.server.admin_tls_material().is_some());
                    config
                        .server
                        .admin_listen
                        .map(|addr| format!("{scheme}://{addr}"))
                })
                .context(
                    "no control-plane address — pass --admin-url or set server.admin_listen",
                )?;
            tokio_runtime()?.block_on(mcp::run(
                config,
                mcp::BridgeOptions {
                    server,
                    agent_token: token,
                    admin_url,
                },
            ))
        }
        Command::Gateway {
            config,
            token,
            proxy_url,
        } => {
            let config = Config::load(&config.config)?;
            // stdout belongs to the JSON-RPC stream; diagnostics go to stderr.
            init_tracing(Console::Headless, &config)?;
            let proxy_url = proxy_url.unwrap_or_else(|| {
                let scheme = tls::scheme(config.server.tls.is_some());
                format!("{scheme}://{}", config.server.listen)
            });
            tokio_runtime()?.block_on(stdio::run(
                config,
                stdio::StdioOptions {
                    agent_token: token,
                    proxy_url,
                },
            ))
        }
        Command::List {
            config,
            what,
            agent,
            output,
        } => list_config(
            &config.config,
            &ListOptions {
                what: what.map(What::from).unwrap_or_default(),
                agent,
            },
            output,
        ),
        Command::Check { config } => check(&config.config),
        Command::Agent(AgentCommand::Add {
            id,
            config,
            name,
            targets,
            clipboard,
        }) => add_agent(&config.config, &id, name.as_deref(), &targets, clipboard),
        Command::Agent(AgentCommand::Rm { id, config, prune }) => {
            remove_agent(&config.config, &id, prune)
        }
        Command::Agent(AgentCommand::Rotate {
            id,
            config,
            clipboard,
        }) => rotate_agent(&config.config, &id, clipboard),
        Command::Upstream(UpstreamCommand::Add {
            name,
            config,
            profile,
            base_url,
            auth,
            access,
            vars,
            agent,
            dry_run,
            set_headers,
            verify,
        }) => add_upstream(AddUpstream {
            path: config.config,
            name,
            profile,
            base_url,
            auth,
            access,
            vars,
            agent,
            dry_run,
            set_headers,
            verify,
        }),
        Command::Upstream(UpstreamCommand::Verify {
            name,
            config,
            path,
            timeout,
        }) => verify_upstreams(&config.config, name.as_deref(), path, timeout),
        Command::Upstream(UpstreamCommand::Rm {
            name,
            config,
            prune,
        }) => remove_upstream(&config.config, &name, prune),
        Command::Profile(ProfileCommand::List { vendor, output }) => {
            list_profiles(vendor.as_deref(), output)
        }
        Command::Profile(ProfileCommand::Show { id }) => show_profile(&id),
        Command::Profile(ProfileCommand::Add {
            id,
            config,
            name,
            secret,
            access,
            vars,
            agent,
            dry_run,
            verify,
        }) => add_profile(
            &config.config,
            &id,
            profiles::AddOptions {
                name,
                secret,
                access,
                vars,
                agent,
                dry_run,
            },
            verify,
        ),
        Command::McpServer(McpServerCommand::Add {
            name,
            config,
            url,
            command,
            args,
            env,
            cwd,
            auth,
            verify,
        }) => add_mcp_server(AddMcpServer {
            path: config.config,
            name,
            url,
            command,
            args,
            env,
            cwd,
            auth,
            verify,
        }),
        Command::McpServer(McpServerCommand::Verify {
            name,
            config,
            timeout,
        }) => verify_mcp_servers(&config.config, name.as_deref(), timeout),
        Command::McpServer(McpServerCommand::Rm {
            name,
            config,
            prune,
        }) => remove_mcp_server(&config.config, &name, prune),
        Command::Acl(AclCommand::Add {
            config,
            name,
            agent,
            kind,
            target,
            methods,
            paths,
            action,
            expires_in,
        }) => add_rule(AddRule {
            path: config.config,
            name,
            agent,
            kind,
            target,
            methods,
            paths,
            action,
            expires_in,
        }),
        Command::Acl(AclCommand::Rm { index, config }) => remove_rule(&config.config, index),
        Command::GenToken { id, clipboard } => gen_token(&id, clipboard),
        Command::HashToken { token } => {
            let token = match token {
                Some(token) => token,
                None => {
                    let mut buffer = String::new();
                    std::io::stdin().read_to_string(&mut buffer)?;
                    buffer
                }
            };
            println!("{}", identity::token_hash(&token));
            Ok(())
        }
        Command::Audit(AuditCommand::Verify { path, config }) => {
            verify_audit(&audit_log_path(path, &config.config, true)?)
        }
        Command::Audit(AuditCommand::Tail {
            path,
            config,
            lines,
            follow,
            agent,
            target,
        }) => tail_audit(
            // A follower may legitimately start before the log exists; a
            // one-shot dump of a log that does not is a mistake worth naming.
            &audit_log_path(path, &config.config, !follow)?,
            &TailOptions {
                lines,
                follow,
                agent: agent.as_deref(),
                target: target.as_deref(),
            },
        ),
    }
}

fn tokio_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")
}

fn init_tracing(console: Console, config: &Config) -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_env("IAP_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if console.draws() {
        // The terminal is the console's; send diagnostics to a file beside the log.
        let path = config
            .audit
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .join("agent-iap.log");
        if let Some(parent) = path.parent() {
            paths::ensure_dir(parent).ok();
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening `{}`", path.display()))?;
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file))
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
    }
    Ok(())
}

async fn run(config: Config, console: Console, watcher: Arc<Watcher>) -> Result<()> {
    let listen = config.server.listen;
    let admin_listen = config.server.admin_listen;
    let audit_path = config.audit.path.clone();
    let audit_to_stderr = config.audit.stderr && !console.draws();

    let state = AppState::build(config, audit_to_stderr)?;

    // Before anything binds. The secrets are already warm from `AppState`; this
    // is where a malformed certificate, or a key that belongs to a different
    // one, stops the process instead of becoming a failed handshake later.
    let tls = ServerTls::load(&state.config().server, &state.resolver)?;
    let (proxy_scheme, admin_scheme) = (tls.proxy_scheme(), tls.admin_scheme());

    state.log_startup()?;

    // The console and the control API are the only things that can answer an
    // `ask`. Without either, `ask` denies rather than hanging.
    state.broker.set_has_approver(console.draws());

    let mut proxy = Listener::bind(
        listen,
        agent_iap::proxy::router(Arc::clone(&state)),
        tls.proxy,
    )
    .context("binding the proxy")?;

    let mut admin = match admin_listen {
        Some(addr) => {
            let listener = Listener::bind(
                addr,
                agent_iap::admin::router(Arc::clone(&state)),
                tls.admin,
            )
            .context("binding the control plane")?;
            let token_path = write_admin_token(&audit_path, &state.admin_token)?;
            if !console.draws() {
                eprintln!(
                    "control plane on {}://{addr} (token in {})",
                    admin_scheme,
                    token_path.display()
                );
            }
            Some(listener)
        }
        None => None,
    };

    if !console.draws() {
        eprintln!(
            "agent-iap listening on {}://{listen} — {} agents, {} rules, default {}",
            proxy_scheme,
            state.agents.len(),
            state.acl.rule_count(),
            state.acl.default_action()
        );
        eprintln!("audit log: {}", audit_path.display());
        // Running headless is what silences the `ask` rules: with no console,
        // nothing parks a request unless something is polling the queue. Say
        // so here rather than leaving it to be discovered in the audit log.
        if state.acl.can_ask() {
            match admin_listen {
                Some(addr) => eprintln!(
                    "no console: `ask` denies unless something polls {admin_scheme}://{addr}/pending"
                ),
                None => eprintln!("no console and no control plane: `ask` denies immediately"),
            }
        }
    }

    // Running whether or not anything is drawn. This is what makes a `--no-tui`
    // unit file reload rather than restart — the deployment least able to take
    // a restart is exactly the one with nobody at a keyboard.
    tokio::spawn(Arc::clone(&watcher).run(Arc::clone(&state)));

    if !console.draws() {
        eprintln!(
            "watching {} — edit it, or send SIGHUP, and this picks it up without a restart",
            watcher.path().display()
        );
    }

    let mut drawing = console.draws().then(|| {
        let state = Arc::clone(&state);
        // The console shares the watcher rather than keeping its own, so `r`
        // and a form it just submitted do not look like somebody else's edit.
        let watcher = Arc::clone(&watcher);
        tokio::task::spawn_blocking(move || agent_iap::tui::run(state, watcher))
    });

    // The listeners are the one part of the proxy a lock cannot replace: a
    // socket is bound to an address, and a certificate is negotiated per
    // connection. So they are supervised instead. Everything else a reload
    // touches is already live by the time this hears about it.
    let mut reloads = state.subscribe_reloads();

    loop {
        tokio::select! {
            result = proxy.serving() => return Ok(result?),
            result = serving(&mut admin) => return Ok(result?),
            result = drawn(&mut drawing) => return result,
            _ = tokio::signal::ctrl_c() => return Ok(()),
            Ok(config) = reloads.recv() => {
                if let Err(error) = adopt(&state, &config, &mut proxy, &mut admin).await {
                    // The policy itself is already in force; only the sockets
                    // did not follow. Loud, and not fatal — killing a proxy
                    // that is serving correctly because it could not move to a
                    // new port is worse than not moving to the new port.
                    tracing::error!(?error, "the listeners could not follow the edited config");
                }
            }
        }
    }
}

/// Await an optional listener, or never — so `select!` has an arm either way.
async fn serving(listener: &mut Option<Listener>) -> std::io::Result<()> {
    match listener {
        Some(listener) => listener.serving().await,
        None => std::future::pending().await,
    }
}

async fn drawn(drawing: &mut Option<tokio::task::JoinHandle<Result<()>>>) -> Result<()> {
    match drawing {
        Some(handle) => handle.await?,
        None => std::future::pending().await,
    }
}

/// Move the listeners onto an edited config.
///
/// A changed certificate is served from the next handshake and costs nothing. A
/// changed address means a new socket: the new one is bound *first*, so a port
/// already taken leaves the old listener exactly where it was rather than
/// leaving the proxy listening on nothing at all.
async fn adopt(
    state: &Arc<AppState>,
    config: &Config,
    proxy: &mut Listener,
    admin: &mut Option<Listener>,
) -> Result<()> {
    // Re-read rather than reuse: a certificate is the one credential in the
    // file expected to be replaced under a running process.
    let tls = ServerTls::reload(&config.server, &state.resolver)?;

    rebind(
        proxy,
        config.server.listen,
        tls.proxy,
        || agent_iap::proxy::router(Arc::clone(state)),
        "proxy",
    )
    .await?;

    match (config.server.admin_listen, admin.take()) {
        (Some(addr), Some(mut listening)) => {
            rebind(
                &mut listening,
                addr,
                tls.admin,
                || agent_iap::admin::router(Arc::clone(state)),
                "control plane",
            )
            .await?;
            *admin = Some(listening);
        }
        // Turned on while running.
        (Some(addr), None) => {
            *admin = Some(
                Listener::bind(addr, agent_iap::admin::router(Arc::clone(state)), tls.admin)
                    .context("binding the control plane")?,
            );
            tracing::info!(%addr, "control plane opened");
        }
        // Turned off while running.
        (None, Some(listening)) => {
            tracing::info!(addr = %listening.addr, "control plane closed");
            listening.stop().await;
        }
        (None, None) => {}
    }
    Ok(())
}

async fn rebind(
    listener: &mut Listener,
    addr: std::net::SocketAddr,
    tls: Option<Arc<rustls::ServerConfig>>,
    router: impl Fn() -> axum::Router,
    what: &str,
) -> Result<()> {
    let same_address = listener.addr == addr;
    let same_mode = listener.tls == tls.is_some();

    if same_address && same_mode {
        if let Some(tls) = tls {
            listener.serve_certificate(tls);
        }
        return Ok(());
    }

    // Bound before the old one is told to stop, so a port that is taken is a
    // failed reload rather than a proxy serving nothing.
    let fresh = Listener::bind(addr, router(), tls)
        .with_context(|| format!("moving the {what} to {addr}"))?;
    let retired = std::mem::replace(listener, fresh);
    tracing::info!(from = %retired.addr, to = %addr, "{what} moved");
    retired.stop().await;
    Ok(())
}

/// Persist the control-plane token so the TUI and `curl` can find it, owner-only.
fn write_admin_token(audit_path: &Path, token: &str) -> Result<PathBuf> {
    let dir = audit_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    paths::ensure_dir(dir).ok();
    let path = dir.join("admin-token");

    // Created 0600 rather than created-then-chmodded: the old order left the
    // token world-readable for however long the chmod took, and discarded the
    // chmod's own failure on top of that.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("creating `{}`", path.display()))?;

    // An existing file keeps its old mode, so tighten it either way.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting `{}` to the current user", path.display()))?;
    }

    use std::io::Write;
    file.write_all(token.as_bytes())
        .with_context(|| format!("writing `{}`", path.display()))?;
    Ok(path)
}

/// `list` reads the policy file and nothing else — no daemon, no network, and
/// no credential resolution, so it answers the same whether the proxy is up or
/// down and cannot turn a reference into a secret on the way.
fn list_config(path: &Path, options: &ListOptions, output: OutputArg) -> Result<()> {
    let config = Config::load(path)?;
    let inventory = Inventory::build(&config, options)?;
    match output {
        OutputArg::Table => print!("{}", inventory.render()),
        OutputArg::Json => println!("{}", serde_json::to_string_pretty(&inventory)?),
    }
    Ok(())
}

fn check(path: &Path) -> Result<()> {
    let config = Config::load(path)?;
    println!("config      {}", path.display());
    println!(
        "proxy       {}://{}",
        tls::scheme(config.server.tls.is_some()),
        config.server.listen
    );
    println!(
        "control     {}",
        config
            .server
            .admin_listen
            .map(|a| format!(
                "{}://{a}",
                tls::scheme(config.server.admin_tls_material().is_some())
            ))
            .unwrap_or_else(|| "disabled".into())
    );
    println!("audit log   {}", config.audit.path.display());
    println!(
        "agents      {}",
        config
            .agents
            .iter()
            .map(|a| a.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "upstreams   {}",
        config
            .upstreams
            .iter()
            .map(|u| format!("{} → {}", u.name, u.base_url))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "mcp servers {}",
        config
            .mcp_servers
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "acl         {} rules, default {}",
        config.acl.len(),
        config.acl_default.action
    );
    // Worth a line of its own: whether the data plane takes a standing grant or
    // an hour of one is the single biggest thing this file decides.
    let workload = &config.server.workload_identity;
    println!(
        "identity    agent tokens{}",
        match workload.mode {
            agent_iap::config::WorkloadMode::Off => String::new(),
            agent_iap::config::WorkloadMode::Optional => format!(
                ", workload tokens accepted ({}s) — set mode = \"required\" to insist",
                workload.lifetime_secs
            ),
            agent_iap::config::WorkloadMode::Required => format!(
                " to mint only, workload tokens required ({}s)",
                workload.lifetime_secs
            ),
        }
    );

    // Before the secrets, because a shape problem in the policy is worth
    // reporting even on a run that bails on an unresolvable credential.
    for warning in verify::mcp_handshake_warnings(&config) {
        println!();
        for (index, line) in warning.lines().enumerate() {
            // First line under the `warning` label, the rest aligned to it, so
            // the copy-pasteable command comes out as one intact block.
            if index == 0 {
                println!("warning     {line}");
            } else {
                println!("            {line}");
            }
        }
    }

    let resolver = agent_iap::secrets::SecretResolver::new(config.server.op_binary.clone());
    let references = config.secret_refs();
    if references.is_empty() {
        println!("secrets     none referenced");
    }
    let mut failed = 0;
    for reference in &references {
        match resolver.resolve(reference) {
            Ok(_) => println!("secrets     ok      {reference}"),
            Err(error) => {
                failed += 1;
                println!("secrets     FAILED  {reference}: {error:#}");
            }
        }
    }
    if failed > 0 {
        anyhow::bail!(
            "{failed} of {} secret references failed to resolve",
            references.len()
        );
    }

    // Resolving the certificate is not the same as it being usable: `check`
    // runs the same load the listener will, so a mismatched pair is found here
    // rather than by the first agent to connect.
    if config.server.tls.is_some() || config.server.admin_tls.is_some() {
        ServerTls::load(&config.server, &resolver)?;
        let named_a_ca = [&config.server.tls, &config.server.admin_tls]
            .iter()
            .any(|tls| tls.as_ref().is_some_and(|tls| tls.ca.is_some()));
        println!(
            "tls         ok      certificate and key parse and match{}",
            if named_a_ca {
                ", and the CA parses"
            } else {
                ""
            }
        );
    }

    println!("\nconfig is valid.");
    Ok(())
}

// ---- verify ---------------------------------------------------------------

/// `--verify` on an enrolment: the service was written, now call it.
///
/// Whatever comes back, the entry stays — only the exit status carries the
/// verdict, so a script that adds a service and a script that proves it works
/// can be the same script without the first half having to be undone.
fn verify_after_write(path: &Path, name: &str, verify: VerifyArg) -> Result<()> {
    if !verify.verify {
        return Ok(());
    }
    let config = Config::load(path)?;
    let resolver = resolver_for(&config);
    let options = verify::Options {
        timeout: verify::DEFAULT_TIMEOUT,
        path: None,
        audit: None,
    };

    println!();
    let report = tokio_runtime()?.block_on(verify::target(&config, &resolver, name, &options))?;
    print_report(&report);
    match report.ok() {
        true => Ok(()),
        // The write stands; this is the verdict on the service, not on the
        // enrolment, and the message has to keep the two apart.
        false => bail!(
            "`{name}` was written to {} — but it did not verify",
            path.display()
        ),
    }
}

fn verify_upstreams(
    path: &Path,
    name: Option<&str>,
    probe: Option<String>,
    timeout: u64,
) -> Result<()> {
    let config = Config::load(path)?;
    let names = chosen(
        name,
        config.upstreams.iter().map(|u| u.name.as_str()),
        "upstream",
    )?;
    let resolver = resolver_for(&config);
    let options = verify::Options {
        timeout: Duration::from_secs(timeout),
        path: probe,
        audit: None,
    };

    let runtime = tokio_runtime()?;
    report_all(
        names
            .iter()
            .map(|name| runtime.block_on(verify::upstream(&config, &resolver, name, &options))),
    )
}

fn verify_mcp_servers(path: &Path, name: Option<&str>, timeout: u64) -> Result<()> {
    let config = Config::load(path)?;
    let names = chosen(
        name,
        config.mcp_servers.iter().map(|s| s.name.as_str()),
        "MCP server",
    )?;
    let resolver = resolver_for(&config);
    let options = verify::Options {
        timeout: Duration::from_secs(timeout),
        path: None,
        audit: None,
    };

    let runtime = tokio_runtime()?;
    report_all(
        names
            .iter()
            .map(|name| runtime.block_on(verify::mcp_server(&config, &resolver, name, &options))),
    )
}

/// The one that was named, or all of them — and a refusal rather than a silent
/// success when the file has none to verify.
fn chosen<'a>(
    name: Option<&str>,
    all: impl Iterator<Item = &'a str>,
    noun: &str,
) -> Result<Vec<String>> {
    if let Some(name) = name {
        return Ok(vec![name.to_string()]);
    }
    let all: Vec<String> = all.map(str::to_string).collect();
    if all.is_empty() {
        bail!("this policy file has no {noun} to verify");
    }
    Ok(all)
}

/// Print every report, and let the exit status carry the worst of them.
fn report_all(reports: impl Iterator<Item = Result<verify::Report>>) -> Result<()> {
    let mut failed = 0;
    let mut total = 0;
    for report in reports {
        let report = report?;
        total += 1;
        if !report.ok() {
            failed += 1;
        }
        print_report(&report);
        println!();
    }
    match (failed, total) {
        (0, total) => println!("{} verified.", plural(total, "service")),
        (_, 1) => bail!("verification failed"),
        (failed, total) => bail!("{failed} of {total} did not verify"),
    }
    Ok(())
}

/// One report, laid out on `check`'s column stops so the two read as one tool.
fn print_report(report: &verify::Report) {
    println!("{} `{}` → {}", report.kind, report.target, report.endpoint);
    for step in &report.steps {
        // The detail is the long half and wraps badly on its own, so it is
        // indented under itself rather than left to run back to column zero.
        let mut lines = verify::wrap(&step.detail, 58).into_iter();
        let first = lines.next().unwrap_or_default();
        println!("  {:<8} {:<11} {first}", step.outcome.label(), step.name);
        for line in lines {
            println!("  {:<8} {:<11} {line}", "", "");
        }
    }
}

fn resolver_for(config: &Config) -> Arc<SecretResolver> {
    Arc::new(SecretResolver::new(config.server.op_binary.clone()))
}

/// Print a freshly minted token, and put it on the clipboard on the way past.
///
/// Every command that mints one goes through here, so the token is indented the
/// same way, the "shown once" warning is worded the same way, and the clipboard
/// is offered — or declined — on the same terms wherever it came from.
fn show_token(headline: &str, token: &str, clipboard: ClipboardArg) {
    println!("{headline}\n");
    println!("  {token}\n");
    // The note goes to stderr, unlike everything around it: it is about what
    // just happened to this machine's clipboard, not part of what the command
    // produced. `agent-iap gen-token > token.txt` should leave the operator
    // reading it on the terminal, not find it in the file a week later.
    if let Some(note) = clipboard::copy(token, clipboard.allowed()).note() {
        eprintln!("{note}\n");
    }
}

/// Write a policy file and tell the operator what is left to do.
///
/// The token is printed rather than stored: only its hash went into the file,
/// so this is the one moment it exists in plaintext.
fn init_config(options: &InitOptions, clipboard: ClipboardArg) -> Result<()> {
    let written = init::init(options)?;
    let path = written.path.display();
    // Only worth repeating back when the file is somewhere the next command
    // would not have looked anyway — which, now that `init` writes to the user
    // config directory, is the unusual case rather than the normal one.
    let flag = if written.path == paths::default_config_file() {
        String::new()
    } else {
        format!(" --config {path}")
    };

    let (Some(agent), Some(token)) = (written.agent.as_deref(), written.token.as_deref()) else {
        // The minimal template. Nothing was granted, so the useful thing to
        // print is the shortest path to a proxy that does something.
        println!(
            "Wrote {path}. No agents, no upstreams — the proxy starts and denies everything.\n"
        );
        // A profile first, because it writes the ACL rules too — and the rules
        // are the half of this that is easy to get wrong quietly.
        println!("Add what it should front. From a profile, service and rules together:");
        println!("  agent-iap profile list");
        println!(
            "  agent-iap upstream add anthropic --profile anthropic --secret env:ANTHROPIC_API_KEY"
        );
        println!("  agent-iap agent add claude-code --target anthropic\n");
        println!("Or spell the service out, and say what it may do:");
        println!(
            "  agent-iap upstream add anthropic --base-url https://api.anthropic.com \\\n             \x20     --auth header --header x-api-key --secret env:ANTHROPIC_API_KEY"
        );
        println!("  agent-iap acl add --target anthropic --methods POST --paths /v1/messages");
        println!("  agent-iap agent add claude-code --target anthropic\n");
        println!("Then:");
        println!("  agent-iap check{flag}   # resolves every credential reference");
        println!("  agent-iap run{flag}       # the approval console");
        return Ok(());
    };

    println!("Wrote {path} for agent `{agent}`.\n");
    show_token(
        "The agent's token — shown once, and not any upstream's credential:",
        token,
        clipboard,
    );

    println!("Next:");
    // Only `env:` has a step the operator can act on from here; anything else
    // is somewhere `check` can look for itself.
    if let Some(name) = written
        .secret
        .as_deref()
        .and_then(|reference| reference.strip_prefix("env:"))
    {
        println!("  export {name}=...   # the credential the proxy injects on the way out");
    }
    println!("  agent-iap check{flag}   # resolves every credential reference");
    println!("  agent-iap run{flag}       # the approval console\n");

    println!("Then point the agent at the proxy:");
    println!(
        "  export ANTHROPIC_BASE_URL=http://{}/anthropic",
        written.listen
    );
    println!("  export ANTHROPIC_AUTH_TOKEN={token}");
    println!("\nAdd another agent with `agent-iap agent add <id>`.");
    Ok(())
}

fn add_agent(
    path: &Path,
    id: &str,
    name: Option<&str>,
    targets: &[String],
    clipboard: ClipboardArg,
) -> Result<()> {
    let enrolled = enroll::add_agent(path, id, name, targets)?;
    println!("Added agent `{}` to {}.\n", enrolled.id, path.display());
    show_token(
        "Its token — shown once, and not any upstream's credential:",
        &enrolled.token,
        clipboard,
    );
    if targets.is_empty() {
        println!("It may address any target, subject to the ACL.");
    } else {
        println!("It may address: {}.", targets.join(", "));
    }
    // An agent with no rule matching it is the quiet failure: the file is
    // valid, the token works, and every call it makes is denied.
    if enroll::rule_count(path)? == 0 {
        println!(
            "\nThere are no `[[acl]]` rules yet, so every request still falls through to \
             `acl_default` and is denied. Add one with `agent-iap acl add`."
        );
    }
    Ok(())
}

fn remove_agent(path: &Path, id: &str, prune: bool) -> Result<()> {
    let removal = enroll::remove_agent(path, id, prune)?;
    println!("Removed agent `{id}` from {}.", path.display());
    println!("Its token authenticates nothing now, and no upstream credential rotated.");
    report_removal(&removal, id);
    reload_notice("the running proxy still accepts the old token");
    Ok(())
}

fn rotate_agent(path: &Path, id: &str, clipboard: ClipboardArg) -> Result<()> {
    let rotated = enroll::rotate_agent(path, id)?;
    println!(
        "Rotated the token for agent `{id}` in {}.\n",
        path.display()
    );
    show_token(
        "Its new token — shown once, and not any upstream's credential:",
        &rotated.token,
        clipboard,
    );
    println!("The old hash is gone from the file. Hand this to the agent before you restart,");
    println!("so the two changes land together rather than as an outage in between.");
    reload_notice("the running proxy still accepts the old token and rejects this one");
    Ok(())
}

/// The half of a removal that is not the entry itself: the rules that pointed
/// at it and the agents that were scoped to it. Saying nothing here is the
/// failure these commands exist to prevent — a file that still names something
/// that is gone, or an operator who thinks it does not.
fn report_removal(removal: &enroll::Removal, subject: &str) {
    for agent in &removal.detached_agents {
        println!("Dropped `{subject}` from the targets of agent `{agent}`.");
    }
    if !removal.pruned_rules.is_empty() {
        println!(
            "Removed {} that named it: {}.",
            plural(removal.pruned_rules.len(), "ACL rule"),
            joined(&removal.pruned_rules)
        );
        println!("What is left has renumbered — `agent-iap list acl` for the current numbers.");
    }
    if !removal.orphaned_rules.is_empty() {
        println!(
            "\nStill naming `{subject}`, and now matching nothing: {}.",
            joined(&removal.orphaned_rules)
        );
        println!(
            "Remove with `agent-iap acl rm <#>` — one at a time, since the numbers shift — \
             or re-run this with `--prune`."
        );
    }
}

/// What an edit made from a shell costs before it is in force.
///
/// A console attached to the running proxy watches the policy file and adopts
/// the whole of it — rules, agents, services, credentials, the listeners. With
/// no console there is nothing reading the file, and an operator who has just
/// revoked a leaked token is exactly the person who must not assume otherwise.
fn reload_notice(consequence: &str) {
    println!(
        "\nA console on the running proxy picks this up within a second. Without one, it \
         takes effect at the next restart — until then {consequence}."
    );
}

fn plural(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

fn joined(rules: &[enroll::RuleRef]) -> String {
    rules
        .iter()
        .map(|rule| rule.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Grouped because clap hands back a base URL, a name and a whole auth scheme.
struct AddUpstream {
    path: PathBuf,
    name: String,
    profile: Option<String>,
    base_url: Option<String>,
    auth: Box<AuthFlags>,
    access: Option<String>,
    vars: Vec<String>,
    agent: Option<String>,
    dry_run: bool,
    set_headers: Vec<String>,
    verify: VerifyArg,
}

fn add_upstream(options: AddUpstream) -> Result<()> {
    let AddUpstream {
        path,
        name,
        profile,
        base_url,
        auth,
        access,
        vars,
        agent,
        dry_run,
        set_headers,
        verify,
    } = options;

    // A profile is the same enrolment with the vendor's half already answered,
    // so it goes to the same place `profile add` does — including the ACL
    // rules, which are the part of a service definition nobody enjoys writing
    // and the part that decides what the agent can actually do.
    if let Some(id) = profile {
        return add_upstream_from_profile(
            &path,
            &name,
            &id,
            &auth,
            profiles::AddOptions {
                name: Some(name.clone()),
                secret: auth.secret.clone(),
                access,
                vars,
                agent,
                dry_run,
            },
            verify,
        );
    }

    // clap has already refused the case where neither is given.
    let base_url = base_url.context("`--base-url` is required without `--profile`")?;
    let auth = auth.to_spec()?;
    let headers = parse_pairs(&set_headers, "--set-header")?;

    enroll::add_upstream(&path, &name, &base_url, &auth, &headers)?;
    println!("Added upstream `{name}` to {}.", path.display());
    println!("Agents reach it at `/{name}/<path>`.");
    if enroll::rule_count(&path)? == 0 {
        println!(
            "\nNo `[[acl]]` rules yet, so it is not reachable. Allow something with:\n  \
             agent-iap acl add --target {name} --methods GET --paths '/**'"
        );
    }
    verify_after_write(&path, &name, verify)
}

/// `upstream add --profile <id>`: the profile's service and rules, under the
/// name this command was given.
///
/// Refuses an MCP profile rather than quietly writing an `[[mcp_servers]]`
/// entry from a command called `upstream add` — the two share one name space,
/// so a silent swap would put a service where nothing looks for it.
fn add_upstream_from_profile(
    path: &Path,
    name: &str,
    id: &str,
    flags: &AuthFlags,
    options: profiles::AddOptions,
    verify: VerifyArg,
) -> Result<()> {
    let profile = profiles::get(id)?;
    if profile.service.kind() != "http" {
        bail!(
            "profile `{id}` is an MCP server, not an upstream — add it with \
             `agent-iap profile add {id} --as {name}`, which writes it to `[[mcp_servers]]`"
        );
    }
    // The profile is the scheme. A `--header` next to it is an operator who
    // believes they are configuring something that is not going to be read.
    if !flags.only_secret() {
        bail!(
            "`--profile` supplies the credential scheme — `--secret` is the only credential flag \
             it reads. Drop the others, or drop `--profile` and spell the service out"
        );
    }
    add_from_profile(path, &profile, &options, verify)
}

fn remove_upstream(path: &Path, name: &str, prune: bool) -> Result<()> {
    let removal = enroll::remove_upstream(path, name, prune)?;
    println!("Removed upstream `{name}` from {}.", path.display());
    println!("`/{name}/…` routes nowhere now, and its credential is no longer resolved.");
    report_removal(&removal, name);
    reload_notice("the running proxy still fronts it with the credential it already resolved");
    Ok(())
}

/// `Name=Value` pairs from a repeatable flag. Splits on the *first* `=` only,
/// because a secret reference (`op://vault/item/field`) may contain more.
fn parse_pairs(raw: &[String], flag: &str) -> Result<Vec<(String, String)>> {
    raw.iter()
        .map(|entry| {
            entry
                .split_once('=')
                .map(|(key, value)| (key.trim().to_string(), value.to_string()))
                .with_context(|| format!("`{flag} {entry}` should be `Name=Value`"))
        })
        .collect()
}

struct AddMcpServer {
    path: PathBuf,
    name: String,
    url: Option<String>,
    command: Option<String>,
    args: Vec<String>,
    env: Vec<String>,
    cwd: Option<String>,
    auth: Box<AuthFlags>,
    verify: VerifyArg,
}

fn add_mcp_server(options: AddMcpServer) -> Result<()> {
    let AddMcpServer {
        path,
        name,
        url,
        command,
        args,
        env,
        cwd,
        auth,
        verify,
    } = options;

    let transport = match (url, command) {
        (Some(url), None) => enroll::McpTransportSpec::Http { url },
        (None, Some(command)) => enroll::McpTransportSpec::Stdio {
            command,
            args,
            env: parse_pairs(&env, "--env")?,
            cwd,
        },
        // Neither is the interesting case: there is no default transport that
        // would be right, and guessing one writes a server that cannot start.
        (None, None) => bail!(
            "`mcp-server add` needs `--url <URL>` for a remote server, or `--command <BIN>` \
             for a stdio one"
        ),
        (Some(_), Some(_)) => unreachable!("clap rejects --url with --command"),
    };

    let auth = auth.to_spec()?;
    enroll::add_mcp_server(&path, &name, &transport, &auth)?;
    println!("Added MCP server `{name}` to {}.", path.display());
    if enroll::rule_count(&path)? == 0 {
        println!(
            "\nNo `[[acl]]` rules yet, so it is not reachable — and an MCP server needs two \
             kinds of rule:\n  \
             agent-iap acl add --kind mcp --target {name} --methods initialize \\\n    \
                 --methods 'notifications/*' --methods ping --methods 'tools/list' --paths '**'\n  \
             agent-iap acl add --kind mcp --target {name} --methods 'tools/call' --paths 'get_*'"
        );
    }
    verify_after_write(&path, &name, verify)
}

fn remove_mcp_server(path: &Path, name: &str, prune: bool) -> Result<()> {
    let removal = enroll::remove_mcp_server(path, name, prune)?;
    println!("Removed MCP server `{name}` from {}.", path.display());
    println!("`agent-iap mcp --server {name}` has nothing to bridge now.");
    report_removal(&removal, name);
    reload_notice("the running proxy still relays to it");
    Ok(())
}

/// The flags of `agent-iap acl add`, carried together.
struct AddRule {
    path: PathBuf,
    name: Option<String>,
    agent: String,
    kind: String,
    target: String,
    methods: Vec<String>,
    paths: Vec<String>,
    action: ActionArg,
    expires_in: Option<String>,
}

fn add_rule(options: AddRule) -> Result<()> {
    let expires = options
        .expires_in
        .as_deref()
        .map(|ttl| enroll::parse_ttl(ttl).map(|delta| chrono::Utc::now() + delta))
        .transpose()
        .context("--expires-in")?;

    enroll::add_rule(
        &options.path,
        &enroll::RuleSpec {
            name: options.name.as_deref(),
            agent: &options.agent,
            kind: &options.kind,
            target: &options.target,
            methods: &options.methods,
            paths: &options.paths,
            action: options.action.as_str(),
            expires,
        },
    )?;

    let count = enroll::rule_count(&options.path)?;
    println!(
        "Added rule {count} of {count} to {}: {} {} {} on `{}` for `{}`.",
        options.path.display(),
        options.action.as_str(),
        options.methods.join(","),
        options.paths.join(","),
        options.target,
        options.agent,
    );
    // Position is the whole semantics of an ACL, so say it rather than making
    // the operator infer it from the file.
    println!("Rules match in file order and the first match wins, so this one is checked last.");
    if let Some(expires) = expires {
        // A deadline nobody can see coming is a call that stops working for no
        // visible reason, so print the wall-clock time rather than the length.
        println!(
            "It stops applying at {} — after that, whatever is behind it decides.",
            expires.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        );
    }
    Ok(())
}

fn remove_rule(path: &Path, index: usize) -> Result<()> {
    let removed = enroll::remove_rule(path, index)?;
    let rule = &removed.rule;
    println!(
        "Removed rule {index} from {}: {} {} {} on `{}` for `{}`.",
        path.display(),
        rule.action,
        rule.methods.join(","),
        rule.paths.join(","),
        rule.target,
        rule.agent,
    );
    if removed.remaining == 0 {
        println!(
            "No rules left, so every request falls through to `acl_default` — which is `deny` \
             unless the file says otherwise."
        );
    } else if index == removed.remaining {
        // It was the last one, so nothing behind it moved.
        println!(
            "{} left, still numbered as they were.",
            plural(removed.remaining, "rule")
        );
    } else {
        println!(
            "{} left, and every rule after this one has moved up by one. Removing another means \
             re-reading `agent-iap list acl` first.",
            plural(removed.remaining, "rule")
        );
    }
    reload_notice("the running proxy still decides by the old rule");
    Ok(())
}

fn gen_token(id: &str, clipboard: ClipboardArg) -> Result<()> {
    let token = identity::generate_token()?;
    let hash = identity::token_hash(&token);
    show_token(
        "Give this token to the agent — it is not any upstream credential:",
        &token,
        clipboard,
    );
    println!("Add this to your policy file:\n");
    println!("[[agents]]");
    println!("id = \"{id}\"");
    println!("token_sha256 = \"{hash}\"");
    println!("# targets = [\"anthropic\"]   # optional: restrict which upstreams it may address");
    Ok(())
}

/// The log an `audit` subcommand should read: the one named on the command
/// line, or — since the policy file already says where the proxy writes — the
/// one it points at. Naming it is for the exceptions: a rotated file, or a log
/// copied off the host it was written on.
fn audit_log_path(path: Option<PathBuf>, config: &Path, must_exist: bool) -> Result<PathBuf> {
    match path {
        Some(path) => Ok(path),
        None => {
            let path = Config::audit_path_of(config)?;
            // A relative `audit.path` resolves against the working directory —
            // the proxy's when it wrote, ours when we read. Say where the name
            // came from, so a mismatch reads as that rather than a lost log.
            if must_exist && !path.exists() {
                bail!(
                    "no audit log at `{}` — that is `audit.path` from `{}`, and a relative path \
                     resolves against the current directory",
                    path.display(),
                    config.display()
                );
            }
            Ok(path)
        }
    }
}

fn verify_audit(path: &Path) -> Result<()> {
    let report = audit::verify_file(path)?;
    println!(
        "{} entries verified — the hash chain is intact.",
        report.entries
    );
    if let (Some(first), Some(last)) = (report.first_ts, report.last_ts) {
        println!("covering {first} → {last}");
    }
    Ok(())
}

/// How often a follower looks for new lines. `tail -f` polls too; the log is
/// appended a line at a time and flushed, so this is the whole of the machinery.
const FOLLOW_POLL: std::time::Duration = std::time::Duration::from_millis(200);

struct TailOptions<'a> {
    lines: usize,
    follow: bool,
    agent: Option<&'a str>,
    target: Option<&'a str>,
}

impl TailOptions<'_> {
    fn filtered(&self) -> bool {
        self.agent.is_some() || self.target.is_some()
    }

    /// What a filtered view was narrowed to, for the "nothing here" note.
    fn scope(&self) -> Option<String> {
        match (self.agent, self.target) {
            (Some(agent), Some(target)) => Some(format!("agent `{agent}` and target `{target}`")),
            (Some(agent), None) => Some(format!("agent `{agent}`")),
            (None, Some(target)) => Some(format!("target `{target}`")),
            (None, None) => None,
        }
    }

    /// One log line as it should be shown, or `None` if it is out of scope.
    fn render(&self, line: &str) -> Option<String> {
        if line.trim().is_empty() {
            return None;
        }
        match serde_json::from_str::<audit::AuditEvent>(line) {
            Ok(event) => event
                .matches(self.agent, self.target)
                .then(|| format!("{} {}", event.ts, event.oneline())),
            // A line this build cannot parse is still evidence, so it is shown
            // verbatim — but it cannot be matched against a filter, and passing
            // it through a filtered view would misreport it as a hit.
            Err(_) if !self.filtered() => Some(line.to_string()),
            Err(_) => None,
        }
    }
}

fn tail_audit(path: &Path, options: &TailOptions) -> Result<()> {
    let mut tail = audit::Tail::open(path)?;
    let mut out = std::io::stdout().lock();

    if options.follow && !tail.is_open() {
        eprintln!("waiting for `{}` to appear", path.display());
    }

    // The first file read is the dump — the last N *matching* entries, because
    // `-n 20 --agent bravo` means bravo's last twenty, not whatever bravo did
    // inside the log's last twenty. Everything after it streams in full.
    let mut dumping = true;
    let mut matched = 0usize;

    loop {
        let batch = tail.read()?;
        if batch.rotated {
            eprintln!("`{}` was replaced — following the new file", path.display());
        }

        let rendered: Vec<String> = batch
            .lines
            .iter()
            .filter_map(|line| options.render(line))
            .collect();
        matched += rendered.len();

        let skip = if dumping {
            rendered.len().saturating_sub(options.lines)
        } else {
            0
        };
        for line in rendered.iter().skip(skip) {
            if !write_line(&mut out, line)? {
                return Ok(());
            }
        }

        if !options.follow {
            // A path handed in by name is read directly, so a typo lands here
            // rather than in the policy-file check that fronts the other route.
            if !tail.is_open() {
                bail!("no audit log at `{}`", path.display());
            }
            break;
        }

        if dumping && tail.is_open() {
            dumping = false;
            if matched == 0 {
                if let Some(scope) = options.scope() {
                    eprintln!("no entries for {scope} yet — waiting");
                }
            }
        }

        std::thread::sleep(FOLLOW_POLL);
    }

    if matched == 0 {
        if let Some(scope) = options.scope() {
            eprintln!("no entries for {scope}");
        }
    }
    Ok(())
}

/// `false` once the reader has gone away. `audit tail -f | head -5` is an
/// ordinary way to end a stream, not a failure to report as one.
fn write_line(out: &mut impl std::io::Write, line: &str) -> Result<bool> {
    match writeln!(out, "{line}") {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(false),
        Err(error) => Err(error).context("writing to stdout"),
    }
}

fn list_profiles(vendor: Option<&str>, output: OutputArg) -> Result<()> {
    let wanted = vendor.map(str::to_lowercase);
    let profiles: Vec<_> = profiles::catalog()
        .into_iter()
        .filter(|profile| {
            wanted
                .as_ref()
                .is_none_or(|vendor| profile.vendor.to_lowercase() == *vendor)
        })
        .collect();

    if profiles.is_empty() {
        // Silence here reads as "there are none", which is a different answer
        // from "that vendor is not one of the ones with profiles".
        bail!(
            "no profiles for vendor `{}` — `agent-iap profile list` shows every vendor there is",
            vendor.unwrap_or("")
        );
    }

    if matches!(output, OutputArg::Json) {
        let rows: Vec<_> = profiles
            .iter()
            .map(|profile| {
                serde_json::json!({
                    "id": profile.id,
                    "title": profile.title,
                    "vendor": profile.vendor,
                    "kind": profile.service.kind(),
                    "endpoint": profile.endpoint(),
                    "summary": profile.summary,
                    "access": profile.access.iter().map(|a| &a.name).collect::<Vec<_>>(),
                    "vars": profile.vars.iter().map(|v| &v.name).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    let width = profiles.iter().map(|p| p.id.len()).max().unwrap_or(0);
    let vendor_width = profiles.iter().map(|p| p.vendor.len()).max().unwrap_or(0);
    println!(
        "{:<width$}  {:<vendor_width$}  KIND  SUMMARY",
        "PROFILE", "VENDOR"
    );
    for profile in &profiles {
        println!(
            "{:<width$}  {:<vendor_width$}  {:<4}  {}",
            profile.id,
            profile.vendor,
            profile.service.kind(),
            profile.summary
        );
    }
    println!(
        "\n`agent-iap profile show <id>` for the detail, `profile add <id> --secret <ref>` to use one."
    );
    Ok(())
}

fn show_profile(id: &str) -> Result<()> {
    let profile = profiles::get(id)?;
    println!("{}  —  {}", profile.id, profile.title);
    println!("{}\n", profile.summary);
    println!("vendor      {}", profile.vendor);
    println!("kind        {}", profile.service.kind());
    println!("endpoint    {}", profile.endpoint());
    println!("default as  {}", profile.default_name);
    println!(
        "credential  {}\n            create one at {}",
        profile.credential.about, profile.credential.url
    );

    if !profile.vars.is_empty() {
        println!("\nVARIABLES");
        for var in &profile.vars {
            let default = match &var.default {
                Some(value) => format!(" (default `{value}`)"),
                None => " (required)".to_string(),
            };
            println!("  --var {}=…{}\n      {}", var.name, default, var.about);
        }
    }

    println!("\nACCESS LEVELS  (the first is the default)");
    for level in &profile.access {
        println!("  {}  —  {}", level.name, level.about);
        for scope in &level.scopes {
            println!("      scope  {scope}");
        }
        for rule in &level.rules {
            println!(
                "      {:<5} {} on {}",
                rule.action,
                rule.methods.join(", "),
                rule.paths.join(", ")
            );
        }
    }

    if profile.service.kind() == "mcp" {
        println!(
            "\n  Every MCP profile also writes a session rule allowing {} —\n  \
             without it `initialize` falls through to the default and the handshake fails.",
            profiles::MCP_SESSION_METHODS.join(", ")
        );
    }

    if let Some(note) = &profile.note {
        println!("\nNOTE\n  {note}");
    }
    Ok(())
}

fn add_profile(
    path: &Path,
    id: &str,
    options: profiles::AddOptions,
    verify: VerifyArg,
) -> Result<()> {
    let profile = profiles::get(id)?;
    add_from_profile(path, &profile, &options, verify)
}

/// Write a profile out and say what landed. Shared with `upstream add
/// --profile`, so the two doors to one enrolment report the same thing.
fn add_from_profile(
    path: &Path,
    profile: &profiles::Profile,
    options: &profiles::AddOptions,
    verify: VerifyArg,
) -> Result<()> {
    let added = profiles::add(path, profile, options)?;

    if let Some(plan) = &added.plan {
        println!("{plan}");
        println!("# nothing was written — drop `--dry-run` to apply this.");
        return Ok(());
    }

    println!(
        "Added `{}` ({}) to {} at access level `{}`.",
        added.name,
        added.kind,
        path.display(),
        added.access
    );
    println!("  endpoint  {}", added.endpoint);
    for scope in &added.scopes {
        println!("  scope     {scope}");
    }
    println!("  rules     {}", added.rules.join(", "));

    if let Some(note) = &added.note {
        println!("\n{note}");
    }

    println!(
        "\nNext:\n  agent-iap agent add <agent-id> --target {}   # mints its token\n  \
         agent-iap check --config {}                  # proves the credential resolves",
        added.name,
        path.display()
    );
    verify_after_write(path, &added.name, verify)
}
