//! What the gateway tells an agent about itself.
//!
//! An agent that discovers a tool called `iap_request` learns nothing from the
//! name about which upstreams exist, which paths are allowed, or what happens
//! when a call is held for a human. Handing it a static README would be worse
//! than nothing, because the policy file is the truth and the README would go
//! stale the first time a rule changed.
//!
//! So every document here is generated from the running policy, for the agent
//! that asked. Two agents attached to the same daemon get two different skill
//! sets, each describing only what that agent can actually reach — which is
//! also the honest answer, since anything else would document calls the ACL is
//! going to refuse.
//!
//! Nothing here reveals a credential. A skill names the *scheme* an upstream
//! uses, because knowing that a call will arrive bearing `x-api-key` is how an
//! agent stops trying to set the header itself; the secret behind it stays in
//! the daemon, which is the whole point.
//!
//! What a skill does name is where the agent's *own* token is kept. `iap_request`
//! needs no credential, but a program the agent runs — git above all, whose
//! smart-HTTP protocol is binary and cannot go through a tool call — reaches
//! the same upstreams over the HTTP gateway, and that takes the agent token.
//! An agent told only "you hold no credential" concludes it has none, and the
//! one place it could learn otherwise is from the proxy itself: hunting through
//! its own configuration for a token is rightly treated as credential
//! exploration. So the documents say where the token is and that using it for
//! those programs is the intended route.

use crate::acl::Kind;
use crate::config::{Action, AgentConfig};
use crate::state::AppState;

/// One document, in the shape MCP wants for a resource.
pub struct Skill {
    /// Stable identifier, and the `uri` an MCP `resources/read` asks for.
    pub uri: String,
    /// The short name `iap_skill` takes, for clients that only speak tools.
    pub name: String,
    pub title: String,
    pub description: String,
    pub text: String,
}

/// The `skill://` URI namespace. MCP resource URIs are opaque to the client, so
/// the only requirement is that ours cannot collide with a fronted server's.
const SCHEME: &str = "skill://agent-iap/";

/// The text served in the `initialize` response's `instructions` field, which
/// is where an MCP client puts standing guidance in front of the model.
///
/// Deliberately short. It has to survive being pasted into a system prompt
/// alongside every other server's, so it says what this one is, the two rules
/// that change how an agent should behave, and where the detail lives.
///
/// `base` is the address the agent reached this proxy on, so the HTTP gateway
/// is named by an address it can use.
pub fn instructions(state: &AppState, agent: &AgentConfig, base: &str) -> String {
    let reachable = reachable_upstreams(state, agent);
    let names = if reachable.is_empty() {
        "nothing yet — this agent has no upstream it may address".to_string()
    } else {
        reachable
            .iter()
            .map(|upstream| format!("`{}`", upstream.name))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let mut text = format!(
        "agent-iap is an identity-aware proxy. Call third-party APIs through \
         `iap_request` instead of over the network directly: it holds the \
         credentials, so for `iap_request` you need none and should never ask \
         for one.\n\n\
         Reachable from here: {names}.\n\n\
         Two things change how you should behave:\n\n\
         1. Every call is checked against a policy and written to an audit log. \
         A refusal comes back as a tool error naming the rule that refused it. \
         That is a final answer about that call — rephrasing the path or \
         retrying will not change it. Read the rule name, pick a call that is \
         allowed, or tell the user what needs granting.\n\
         2. Some calls stop on a human for approval and take as long as the \
         person takes. That is not a hang; do not retry underneath it.\n\n\
         Start with `iap_catalog` for what you can reach, and `iap_skill` for \
         how to call any one of them."
    );

    if !reachable.is_empty() {
        text.push_str(&format!(
            "\n\nA program that cannot call a tool — git, an SDK, curl — uses the \
             same proxy over HTTP at `{base}/<upstream>/<path>`, with your agent \
             token in `Authorization: Bearer` or `X-IAP-Token`. That is the \
             intended route for those programs, not a way around this one: the \
             same policy decides and the same log records it. Your token is \
             {where_}. `using-this-gateway` has the detail.",
            where_ = token_location(),
        ));
        if let Some(git) = reachable.iter().find(|upstream| fronts_github(upstream)) {
            text.push_str(&format!(
                " For git, `{}` and then plain `git` against `https://github.com/…`.",
                git_config_command(base, &git.name)
            ));
        }
    }

    if state.acl.can_ask() {
        text.push_str(
            "\n\nThis policy does hold calls for approval, so expect the second \
             case to happen.",
        );
    }
    text
}

/// Every skill this agent may read, overview first.
pub fn catalog(state: &AppState, agent: &AgentConfig, base: &str) -> Vec<Skill> {
    let mut skills = vec![overview(state, agent, base)];
    for upstream in reachable_upstreams(state, agent) {
        skills.push(upstream_skill(state, agent, base, &upstream.name));
    }
    skills
}

/// Look a skill up by the short name or by the full `skill://` URI, so a client
/// reading resources and a model calling `iap_skill` reach the same document.
pub fn find(state: &AppState, agent: &AgentConfig, base: &str, wanted: &str) -> Option<Skill> {
    let wanted = wanted.trim();
    let short = wanted.strip_prefix(SCHEME).unwrap_or(wanted);
    catalog(state, agent, base)
        .into_iter()
        .find(|skill| skill.name == short)
}

/// The upstreams this agent could reach, in policy-file order.
///
/// "Could" is the `targets` list plus the existence of a rule that can name the
/// target. A target no rule ever mentions falls through to a default that
/// denies, so listing it would advertise a call that cannot succeed.
pub(crate) fn reachable_upstreams(
    state: &AppState,
    agent: &AgentConfig,
) -> Vec<crate::config::UpstreamConfig> {
    state
        .config()
        .upstreams
        .iter()
        .filter(|upstream| crate::identity::agent_may_address(agent, &upstream.name))
        .filter(|upstream| state.acl.rules_for(&agent.id, Kind::Http, &upstream.name) > 0)
        .cloned()
        .collect()
}

/// Where the agent's token is, in the order `agent-iap` itself reads it
/// (`crate::agent_token`). Written for the agent's machine, which may not be
/// this one, so it names the convention rather than a path resolved here.
fn token_location() -> String {
    format!(
        "`${}` when that is set, and otherwise in the file `${}` names, or `{}` \
         (under `$XDG_CONFIG_HOME` when that is set)",
        crate::agent_token::TOKEN_VAR,
        crate::agent_token::TOKEN_FILE_VAR,
        crate::agent_token::DEFAULT_FILE_DISPLAY,
    )
}

/// An upstream git can be sent to: the `github-git` profile's base.
fn fronts_github(upstream: &crate::config::UpstreamConfig) -> bool {
    upstream.base_url.trim_end_matches('/') == "https://github.com"
}

fn git_config_command(base: &str, upstream: &str) -> String {
    let upstream = match upstream {
        "github-git" => String::new(),
        other => format!(" --upstream {other}"),
    };
    format!("eval \"$(agent-iap git-config --proxy-url {base}{upstream})\"")
}

/// The HTTP gateway, for the programs `iap_request` cannot stand in for.
fn programs_section(state: &AppState, base: &str) -> String {
    let mut text = format!(
        "\n\n## Programs: git, SDKs, curl\n\n\
         `iap_request` is for you. A program you run cannot call a tool, and \
         some work can only be done by one — git's protocol is binary, and an \
         SDK expects a base URL. Those programs use this proxy's HTTP gateway, \
         which fronts the same upstreams under the same policy and writes to \
         the same audit log. Using it for them is intended; it is not routing \
         around the proxy.\n\n\
         - Address: `{base}/<upstream>/<the path the upstream sees>`. For an \
         SDK, the base URL is `{base}/<upstream>`.\n\
         - Your agent token goes in `Authorization: Bearer <token>` or \
         `X-IAP-Token: <token>` (or as the password of HTTP Basic, which is \
         what git sends). The upstream's own credential is attached here; any \
         you send is dropped.\n\
         - Your token is {where_}. That file is yours to read for this; it is \
         the whole of your access and works nowhere but this proxy.\n\n\
         ```sh\n\
         curl -H \"X-IAP-Token: $(cat {file})\" {base}/<upstream>/<path>\n\
         ```\n\n\
         For git, see the skill of an upstream fronting `https://github.com`: \
         `agent-iap git-config` sets git up so it asks for the token itself, \
         and you never handle it.",
        where_ = token_location(),
        file = crate::agent_token::DEFAULT_FILE_DISPLAY,
    );
    if state.workload.mode() == crate::config::WorkloadMode::Required {
        text.push_str(&format!(
            "\n\nThis proxy takes only workload tokens on the gateway: exchange \
             your agent token at `POST {base}/_iap/token` first, and send what \
             comes back."
        ));
    }
    text
}

fn overview(state: &AppState, agent: &AgentConfig, base: &str) -> Skill {
    let mut text = String::new();
    text.push_str(
        "# Calling APIs through agent-iap\n\n\
         You do not hold the credentials for the services below, and you do not \
         need them. `iap_request` performs the call, attaches the real \
         credential inside the proxy, and returns you the response.\n\n\
         ## Making a call\n\n\
         ```json\n\
         {\n  \"upstream\": \"<name from iap_catalog>\",\n  \"method\": \"POST\",\n  \
         \"path\": \"/v1/messages\",\n  \"query\": {\"limit\": \"10\"},\n  \
         \"body\": {\"model\": \"…\"}\n}\n\
         ```\n\n\
         `path` is the path *the upstream* sees, starting with `/`. It is not a \
         full URL — the base URL comes from the policy, and sending one will be \
         refused. `body` may be a JSON value (sent as `application/json`) or a \
         string (sent as-is). Omit `body` for a GET.\n\n\
         Do not set an `Authorization` header, an API-key header, or any other \
         credential on an `iap_request`. The proxy sets them; anything you send \
         is replaced.\n\n\
         ## Reading the answer\n\n\
         You get the upstream's status code, its headers and its body. A `4xx` \
         from the upstream is the upstream's answer, and it comes back as a \
         normal result — it is not the proxy refusing you.\n\n\
         ## When you are refused\n\n\
         A refusal is a tool error whose message names the rule. The codes:\n\n\
         - `policy_denied` — the ACL says no. Final. The rule name is in the \
         message; a different path may be allowed, the same one never will be.\n\
         - `target_not_permitted` — this agent is not granted that upstream at all.\n\
         - `approval_denied` — a human was asked and did not allow it, or nobody \
         was watching to ask.\n\
         - `scope_exceeded` — the token this run holds was minted narrower than \
         the call. Only relevant when the operator has workload identity on.\n\n\
         In every case: do not retry, and do not try to route around it. Say \
         what you were refused and which rule refused it, and let the person \
         decide whether to widen the policy.\n\n\
         ## What is recorded\n\n\
         Every call, allowed or refused, is written to an append-only audit log \
         with the agent, the rule that decided, the method and the path.",
    );

    if state.acl.can_ask() {
        text.push_str(
            "\n\n## Approvals\n\n\
             Some rules in this policy hold a call in front of a human. That \
             call blocks until the person answers or the wait times out. Treat a \
             slow `iap_request` as a person reading, not as a failure: do not \
             cancel it, do not retry it, and do not start a second copy of the \
             same call. If it comes back `approval_denied`, that is the person's \
             answer.",
        );
    }

    let upstreams = reachable_upstreams(state, agent);
    if !upstreams.is_empty() {
        text.push_str(&programs_section(state, base));
    }
    text.push_str("\n\n## What you can reach\n\n");
    if upstreams.is_empty() {
        text.push_str(
            "Nothing. No upstream in this policy is both granted to this agent \
             and named by a rule. `iap_request` will refuse every call until an \
             operator changes that.",
        );
    } else {
        for upstream in &upstreams {
            text.push_str(&format!(
                "- `{}` — {} (`{}`)\n",
                upstream.name,
                upstream.base_url,
                skill_name_for(&upstream.name)
            ));
        }
    }

    Skill {
        uri: format!("{SCHEME}using-this-gateway"),
        name: "using-this-gateway".into(),
        title: "Using this gateway".into(),
        description: "How to call APIs through agent-iap, and how to read a refusal.".into(),
        text,
    }
}

fn skill_name_for(upstream: &str) -> String {
    format!("upstream/{upstream}")
}

/// One upstream, as its policy actually reads for this agent.
fn upstream_skill(state: &AppState, agent: &AgentConfig, base: &str, name: &str) -> Skill {
    let config = state.config();
    let upstream = config.upstream(name);
    let mut text = format!("# `{name}`\n\n");

    match upstream {
        Some(upstream) => {
            text.push_str(&format!("Base URL: `{}`\n\n", upstream.base_url));
            text.push_str(&format!(
                "Authentication: the proxy attaches `{}` on your behalf. Do not \
                 set it yourself.\n\n",
                upstream.auth.describe()
            ));
            if !upstream.headers.is_empty() {
                let headers = upstream
                    .headers
                    .keys()
                    .map(|key| format!("`{key}`"))
                    .collect::<Vec<_>>()
                    .join(", ");
                text.push_str(&format!(
                    "The proxy also sets {headers} on every call to this upstream.\n\n"
                ));
            }
            text.push_str(&format!(
                "From a program: `{base}/{name}/<path>`, with your agent token \
                 (`using-this-gateway` § Programs).\n\n"
            ));
            if fronts_github(upstream) {
                text.push_str(&git_section(base, name));
            }
        }
        None => text.push_str("This upstream is no longer in the policy file.\n\n"),
    }

    text.push_str(&rules_table(state, agent, name, "##"));

    Skill {
        uri: format!("{SCHEME}{}", skill_name_for(name)),
        name: skill_name_for(name),
        title: format!("Upstream `{name}`"),
        description: format!("Base URL, credential scheme and the rules that apply to `{name}`."),
        text,
    }
}

/// The exact git invocation, for an upstream git can be sent to.
fn git_section(base: &str, name: &str) -> String {
    format!(
        "## Using git\n\n\
         Clone, fetch and push with git itself, through this upstream — not by \
         rebuilding commits through the API. In the same shell command as git, \
         since a tool shell may not keep its environment between calls:\n\n\
         ```sh\n\
         {setup} && git clone https://github.com/<owner>/<repo>.git\n\
         ```\n\n\
         `git-config` points `https://github.com/` at `{base}/{name}/` and makes \
         `agent-iap git-credential` git's credential helper for that prefix \
         alone, so git asks it for your token when the proxy asks for one. No \
         setting holds the token, and you do not handle it. Remotes stay \
         `https://github.com/…`; an `ssh://` or `git@github.com:` remote does \
         not go through the proxy.\n\n\
         Without `agent-iap` on this machine, send the token yourself, for this \
         prefix only: `git -c http.{base}/{name}/.extraHeader=\"X-IAP-Token: \
         <token>\" clone {base}/{name}/<owner>/<repo>.git`.\n\n\
         A push is allowed only if a rule below allows `git-receive-pack`.\n\n",
        setup = git_config_command(base, name),
    )
}

/// The rules that can match this agent against this target, in the order the
/// ACL walks them — because first match wins, and a table in any other order
/// would describe a policy nobody is running.
///
/// `heading` is the caller's level for the table's own heading: this reads at
/// `##` inside a document about one upstream, and deeper inside one that covers
/// several.
pub(crate) fn rules_table(
    state: &AppState,
    agent: &AgentConfig,
    target: &str,
    heading: &str,
) -> String {
    let mut text = format!("{heading} Rules that apply to you, in order\n\n");
    let mut any = false;

    for index in state.acl.rule_indices_for_agent(&agent.id) {
        let Some(rule) = state.config().acl.get(index).cloned() else {
            continue;
        };
        // `kind = "any"` covers both surfaces; an `mcp` rule has nothing to say
        // about an HTTP call to this upstream.
        if rule.kind == "mcp" {
            continue;
        }
        if !glob_covers(&rule.target, target) {
            continue;
        }
        any = true;
        let label = rule.name.clone().unwrap_or_else(|| format!("acl[{index}]"));
        text.push_str(&format!(
            "- **{}** `{}` — {} `{}`\n",
            action_word(rule.action),
            label,
            rule.methods.join("`, `"),
            rule.paths.join("`, `"),
        ));
    }

    if !any {
        text.push_str(
            "None. Every call to this upstream falls through to the default, \
             which is ",
        );
        text.push_str(&format!("`{}`.\n", state.acl.default_action()));
        return text;
    }

    text.push_str(&format!(
        "\nFirst match wins. Anything matching none of these falls through to \
         the default, which is `{}`.\n",
        state.acl.default_action()
    ));
    text
}

fn action_word(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::Deny => "deny",
        Action::Ask => "ask a human",
    }
}

/// Whether a rule's target pattern can name this upstream.
///
/// Compiled rather than compared, so `*` and `github-*` read here exactly as
/// they read in the ACL. A pattern that will not compile cannot have got this
/// far — `Acl::compile` runs at startup — so an error here means "does not
/// match" rather than a reason to fail a skill lookup.
fn glob_covers(pattern: &str, value: &str) -> bool {
    globset::Glob::new(pattern)
        .map(|glob| glob.compile_matcher().is_match(value))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::sync::Arc;

    const BASE: &str = "http://iap.example.com:8080";

    fn state() -> Arc<AppState> {
        let config: Config = toml::from_str(&format!(
            r#"
[audit]
path = "/dev/null"
stderr = false

[[agents]]
id = "claude"
name = "Claude Code"
token_sha256 = "{hash}"
targets = ["anthropic"]

[[agents]]
id = "grounded"
token_sha256 = "{other}"
targets = []

[[upstreams]]
name = "anthropic"
base_url = "https://api.anthropic.com"
auth = {{ type = "header", header = "x-api-key", secret = "literal:sk-real" }}

[[upstreams]]
name = "unmentioned"
base_url = "https://example.invalid"

[[acl]]
name = "read-models"
target = "anthropic"
methods = ["GET"]
paths = ["/v1/models"]
action = "allow"

[[acl]]
name = "confirm-sends"
target = "anthropic"
methods = ["POST"]
paths = ["/v1/messages"]
action = "ask"

[[acl]]
name = "mcp-only"
kind = "mcp"
target = "anthropic"
methods = ["*"]
paths = ["**"]
action = "allow"
"#,
            hash = crate::identity::token_hash("iap_claude"),
            other = crate::identity::token_hash("iap_grounded"),
        ))
        .unwrap();
        AppState::build(config, false).unwrap()
    }

    fn agent(state: &AppState, id: &str) -> Arc<crate::config::AgentConfig> {
        state.agents.by_id(id).unwrap()
    }

    #[test]
    fn the_catalog_covers_every_reachable_upstream_and_nothing_else() {
        let state = state();
        let names: Vec<String> = catalog(&state, &agent(&state, "claude"), BASE)
            .into_iter()
            .map(|skill| skill.name)
            .collect();
        assert_eq!(names, ["using-this-gateway", "upstream/anthropic"]);
    }

    #[test]
    fn an_upstream_no_rule_mentions_is_not_advertised() {
        // `grounded` has no `targets` list, so it may address anything — but
        // `unmentioned` falls through to a default that denies. Documenting it
        // would be documenting a call that cannot succeed.
        let state = state();
        let names: Vec<String> = catalog(&state, &agent(&state, "grounded"), BASE)
            .into_iter()
            .map(|skill| skill.name)
            .collect();
        assert_eq!(names, ["using-this-gateway", "upstream/anthropic"]);
    }

    #[test]
    fn an_upstream_skill_names_the_scheme_but_never_the_secret() {
        let state = state();
        let skill = find(&state, &agent(&state, "claude"), BASE, "upstream/anthropic").unwrap();

        assert!(
            skill.text.contains("https://api.anthropic.com"),
            "{}",
            skill.text
        );
        assert!(skill.text.contains("header x-api-key"), "{}", skill.text);
        assert!(!skill.text.contains("sk-real"), "{}", skill.text);
    }

    #[test]
    fn the_rules_listed_are_the_http_ones_in_match_order() {
        let state = state();
        let skill = find(&state, &agent(&state, "claude"), BASE, "upstream/anthropic").unwrap();

        let read = skill.text.find("read-models").expect("allow rule listed");
        let confirm = skill.text.find("confirm-sends").expect("ask rule listed");
        assert!(
            read < confirm,
            "rules must read in match order:\n{}",
            skill.text
        );
        // An `mcp` rule says nothing about an HTTP call and would only mislead.
        assert!(!skill.text.contains("mcp-only"), "{}", skill.text);
        assert!(skill.text.contains("ask a human"), "{}", skill.text);
    }

    #[test]
    fn a_skill_is_reachable_by_short_name_or_by_uri() {
        let state = state();
        let agent = agent(&state, "claude");
        let by_uri = find(&state, &agent, BASE, "skill://agent-iap/upstream/anthropic").unwrap();
        let by_name = find(&state, &agent, BASE, "upstream/anthropic").unwrap();
        assert_eq!(by_uri.uri, by_name.uri);
        assert!(find(&state, &agent, BASE, "nothing-like-this").is_none());
    }

    #[test]
    fn the_instructions_name_what_is_reachable_and_warn_about_approvals() {
        let state = state();
        let text = instructions(&state, &agent(&state, "claude"), BASE);
        assert!(text.contains("`anthropic`"), "{text}");
        assert!(text.contains("approval"), "{text}");
        // The one instruction that matters most: do not go looking for a key.
        assert!(text.contains("never ask for one"), "{text}");
    }

    /// A policy with a `github-git` upstream, and one with workload tokens
    /// required, for the documents about programs.
    fn git_state(workload: &str) -> Arc<AppState> {
        let config: Config = toml::from_str(&format!(
            r#"
[server.workload_identity]
mode = "{workload}"

[audit]
path = "/dev/null"
stderr = false

[[agents]]
id = "claude"
token_sha256 = "{hash}"
targets = ["github-git"]

[[upstreams]]
name = "github-git"
base_url = "https://github.com"
auth = {{ type = "basic", username = "x-access-token", secret = "literal:github_pat_real" }}

[[acl]]
name = "github-git-fetch"
target = "github-git"
methods = ["GET", "POST"]
paths = ["/*/*.git/info/refs", "/*/*.git/git-upload-pack"]
action = "allow"
"#,
            hash = crate::identity::token_hash("iap_claude"),
        ))
        .unwrap();
        AppState::build(config, false).unwrap()
    }

    /// The issue in one test: an MCP agent is told the HTTP gateway exists,
    /// where it is, how to authenticate to it and where its token lives — and
    /// still that `iap_request` needs nothing.
    #[test]
    fn the_instructions_point_programs_at_the_gateway_and_the_token() {
        let state = state();
        let text = instructions(&state, &agent(&state, "claude"), BASE);
        assert!(text.contains("never ask for one"), "{text}");
        assert!(
            text.contains("`http://iap.example.com:8080/<upstream>/<path>`"),
            "{text}"
        );
        assert!(text.contains("X-IAP-Token"), "{text}");
        assert!(text.contains("`$IAP_TOKEN`"), "{text}");
        assert!(text.contains("`$IAP_TOKEN_FILE`"), "{text}");
        assert!(text.contains("~/.config/agent-iap/token"), "{text}");
        assert!(text.contains("intended route"), "{text}");
        // No GitHub upstream here, so no git to speak of.
        assert!(!text.contains("git-config"), "{text}");

        let skill = find(&state, &agent(&state, "claude"), BASE, "using-this-gateway").unwrap();
        assert!(skill.text.contains("## Programs"), "{}", skill.text);
        assert!(
            skill
                .text
                .contains("http://iap.example.com:8080/<upstream>"),
            "{}",
            skill.text
        );
        assert!(skill.text.contains("not routing"), "{}", skill.text);
        // The ban on credentials is about the tool, not about every program.
        assert!(
            skill.text.contains("credential on an `iap_request`"),
            "{}",
            skill.text
        );
        let upstream = find(&state, &agent(&state, "claude"), BASE, "upstream/anthropic").unwrap();
        assert!(
            upstream
                .text
                .contains("`http://iap.example.com:8080/anthropic/<path>`"),
            "{}",
            upstream.text
        );
    }

    #[test]
    fn an_agent_that_reaches_nothing_is_not_sent_to_the_gateway_either() {
        let state = state();
        let mut config = (*state.config().agent("claude").unwrap()).clone();
        config.id = "walled".into();
        config.targets = vec!["unmentioned".into()];
        assert!(!instructions(&state, &config, BASE).contains("X-IAP-Token"));
        let overview = &catalog(&state, &config, BASE)[0];
        assert!(!overview.text.contains("## Programs"), "{}", overview.text);
    }

    #[test]
    fn a_github_upstream_carries_the_git_invocation() {
        let state = git_state("optional");
        let agent = agent(&state, "claude");
        let text = instructions(&state, &agent, BASE);
        assert!(
            text.contains(
                "`eval \"$(agent-iap git-config --proxy-url http://iap.example.com:8080)\"`"
            ),
            "{text}"
        );

        let skill = find(&state, &agent, BASE, "upstream/github-git").unwrap();
        assert!(skill.text.contains("## Using git"), "{}", skill.text);
        assert!(
            skill.text.contains(
                "eval \"$(agent-iap git-config --proxy-url http://iap.example.com:8080)\" \
                 && git clone https://github.com/<owner>/<repo>.git"
            ),
            "{}",
            skill.text
        );
        assert!(skill.text.contains("git-credential"), "{}", skill.text);
        assert!(!skill.text.contains("github_pat_real"), "{}", skill.text);
        // Workload tokens are optional here, so nothing about exchanging one.
        let overview = find(&state, &agent, BASE, "using-this-gateway").unwrap();
        assert!(!overview.text.contains("_iap/token"), "{}", overview.text);
    }

    #[test]
    fn an_upstream_under_another_name_is_named_to_git_config() {
        assert_eq!(
            git_config_command(BASE, "gh"),
            "eval \"$(agent-iap git-config --proxy-url http://iap.example.com:8080 --upstream gh)\""
        );
    }

    #[test]
    fn a_proxy_that_requires_workload_tokens_says_to_exchange_first() {
        let state = git_state("required");
        let overview = find(&state, &agent(&state, "claude"), BASE, "using-this-gateway").unwrap();
        assert!(
            overview
                .text
                .contains("`POST http://iap.example.com:8080/_iap/token`"),
            "{}",
            overview.text
        );
    }

    #[test]
    fn an_agent_that_can_reach_nothing_is_told_so_plainly() {
        let state = state();
        // A policy-file agent with a `targets` list naming an upstream that no
        // rule covers: the honest answer is "nothing", not an empty list.
        let mut config = (*state.config().agent("claude").unwrap()).clone();
        config.id = "walled".into();
        config.targets = vec!["unmentioned".into()];
        let text = instructions(&state, &config, BASE);
        assert!(text.contains("no upstream it may address"), "{text}");
    }
}
