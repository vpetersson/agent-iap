//! The one place a request is weighed against identity, scope and policy.
//!
//! Two surfaces now reach the same upstreams: the HTTP proxy an SDK points at,
//! and the MCP gateway an agent calls as a tool. If each spelled out "may this
//! happen" for itself the two spellings would drift, and the drift would be a
//! hole — a rule that stops a call on one surface and waves it through on the
//! other. So the sequence lives here once: may this agent address this target
//! at all, does the credential presented cover this request, what does the ACL
//! say, and when the ACL says `ask`, what did the human say.
//!
//! Routing, path shape and how a refusal is rendered stay with the surface that
//! parsed the request. Only the decision is shared.

use http::StatusCode;

use crate::acl::{AccessRequest, Kind};
use crate::approval::{AskingRule, Verdict};
use crate::config::Action;
use crate::identity::{agent_may_address, Caller};
use crate::state::AppState;

/// A cleared request, and what the audit record should say about how it cleared.
pub struct Cleared {
    /// `allow`, or the label of the approval outcome that released it.
    pub decision: String,
    /// The rule that decided; `<default>` when none matched.
    pub rule: String,
}

/// A refused request, carrying enough for either surface to answer in its own
/// idiom: an HTTP status for the proxy, a stable code, one sentence a human or
/// a model can act on, and the rule label the audit record wants.
pub struct Refusal {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub rule: String,
}

impl Refusal {
    fn new(status: StatusCode, code: &'static str, rule: &str, message: String) -> Self {
        Refusal {
            status,
            code,
            message,
            rule: rule.to_string(),
        }
    }
}

/// Run one request past identity, scope and policy, parking it on a human if
/// the matching rule says `ask`.
pub async fn clear(
    state: &AppState,
    caller: &Caller,
    access: &AccessRequest,
) -> Result<Cleared, Refusal> {
    let agent = caller.agent();

    // 1. May this agent address this target at all? A `targets` list is the
    //    coarse gate in front of the ACL, and it is checked first so an agent
    //    that was never granted an upstream is refused for that reason rather
    //    than for whatever the rule list happens to say about the path.
    if !agent_may_address(agent, &access.target) {
        return Err(Refusal::new(
            StatusCode::FORBIDDEN,
            "target_not_permitted",
            "<agent-targets>",
            format!("agent `{}` may not address `{}`", agent.id, access.target),
        ));
    }

    // 2. Did this run ask for this? A workload token carries the scope its
    //    holder said it needed; anything outside that is refused before policy
    //    is consulted at all. A scope can only ever narrow — the ACL still runs
    //    next and can still say no — so this is least privilege the agent opted
    //    into, not a grant it gave itself.
    if !caller.permits(access) {
        return Err(Refusal::new(
            StatusCode::FORBIDDEN,
            "scope_exceeded",
            "<workload-scope>",
            format!(
                "the workload token does not cover {} — renew it with a scope that does",
                phrase(access)
            ),
        ));
    }

    // 3. What does the policy say?
    let decision = state.acl.evaluate(access);
    let rule = decision.rule_label().to_string();

    match decision.action {
        Action::Allow => Ok(Cleared {
            decision: "allow".into(),
            rule,
        }),
        Action::Deny => Err(Refusal::new(
            StatusCode::FORBIDDEN,
            "policy_denied",
            &rule,
            format!("denied by policy `{rule}` — {}", phrase(access)),
        )),
        Action::Ask => {
            // Park the request in front of a human. Anything but an explicit
            // "allow" — timeout, no approver, an explicit no — denies.
            let outcome = state
                .broker
                .ask(access, agent.display_name(), AskingRule::of(&decision))
                .await;
            if outcome.verdict() == Verdict::Deny {
                return Err(Refusal::new(
                    StatusCode::FORBIDDEN,
                    "approval_denied",
                    &rule,
                    format!(
                        "held for approval by policy `{rule}` and not allowed ({})",
                        outcome.label()
                    ),
                ));
            }
            Ok(Cleared {
                decision: outcome.label().to_string(),
                rule,
            })
        }
    }
}

/// The request as it reads in a refusal, in the idiom of its own surface:
/// `POST /v1/messages on `anthropic``, `tools/call `create_issue` on `github``.
fn phrase(access: &AccessRequest) -> String {
    match access.kind {
        Kind::Http => format!("{} {} on `{}`", access.method, access.path, access.target),
        Kind::Mcp if access.path.is_empty() => {
            format!("{} on `{}`", access.method, access.target)
        }
        Kind::Mcp => format!("{} `{}` on `{}`", access.method, access.path, access.target),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::sync::Arc;

    fn state_with(acl: &str) -> Arc<AppState> {
        let config: Config = toml::from_str(&format!(
            r#"
[audit]
path = "/dev/null"
stderr = false

[[agents]]
id = "claude"
token_sha256 = "{hash}"
targets = ["echo"]

[[agents]]
id = "stranger"
token_sha256 = "{other}"
targets = ["somewhere-else"]

[[upstreams]]
name = "echo"
base_url = "https://example.invalid"
{acl}
"#,
            hash = crate::identity::token_hash("iap_claude"),
            other = crate::identity::token_hash("iap_stranger"),
        ))
        .unwrap();
        AppState::build(config, false).unwrap()
    }

    fn caller(state: &AppState, id: &str) -> Caller {
        Caller::Agent(state.agents.by_id(id).unwrap())
    }

    #[tokio::test]
    async fn an_allow_rule_clears_and_names_itself() {
        let state = state_with(
            r#"
[[acl]]
name = "read-models"
target = "echo"
methods = ["GET"]
paths = ["/v1/models"]
action = "allow"
"#,
        );
        let access = AccessRequest::http("claude", "echo", "GET", "/v1/models");
        let cleared = clear(&state, &caller(&state, "claude"), &access)
            .await
            .unwrap_or_else(|refusal| panic!("{}", refusal.message));

        assert_eq!(cleared.decision, "allow");
        assert_eq!(cleared.rule, "read-models");
    }

    #[tokio::test]
    async fn no_matching_rule_falls_through_to_the_default_and_denies() {
        let state = state_with("");
        let access = AccessRequest::http("claude", "echo", "POST", "/v1/messages");
        let refusal = clear(&state, &caller(&state, "claude"), &access)
            .await
            .err()
            .expect("default is deny");

        assert_eq!(refusal.code, "policy_denied");
        assert_eq!(refusal.rule, "<default>");
        // The sentence has to name what was refused, or an agent cannot tell
        // which of the calls it just made is the one that stopped.
        assert!(
            refusal.message.contains("POST /v1/messages"),
            "{}",
            refusal.message
        );
    }

    #[tokio::test]
    async fn a_target_outside_the_agents_list_is_refused_before_the_acl_runs() {
        // The rule would allow it. The `targets` list is what says no, and the
        // refusal must say so rather than blaming a rule that voted yes.
        let state = state_with(
            r#"
[[acl]]
name = "wide-open"
target = "*"
methods = ["*"]
paths = ["**"]
action = "allow"
"#,
        );
        let access = AccessRequest::http("stranger", "echo", "GET", "/v1/models");
        let refusal = clear(&state, &caller(&state, "stranger"), &access)
            .await
            .err()
            .expect("stranger may not address echo");

        assert_eq!(refusal.code, "target_not_permitted");
        assert_eq!(refusal.rule, "<agent-targets>");
    }

    #[tokio::test]
    async fn an_mcp_call_reads_as_an_mcp_call_in_the_refusal() {
        let state = state_with("");
        let access = AccessRequest::mcp("claude", "echo", "tools/call", "delete_repo");
        let refusal = clear(&state, &caller(&state, "claude"), &access)
            .await
            .err()
            .expect("default is deny");

        assert!(
            refusal.message.contains("tools/call `delete_repo`"),
            "{}",
            refusal.message
        );
    }

    #[tokio::test]
    async fn an_ask_rule_with_nobody_watching_denies_rather_than_parking_forever() {
        let state = state_with(
            r#"
[[acl]]
name = "confirm-writes"
target = "echo"
methods = ["POST"]
paths = ["**"]
action = "ask"
"#,
        );
        let access = AccessRequest::http("claude", "echo", "POST", "/v1/messages");
        let refusal = clear(&state, &caller(&state, "claude"), &access)
            .await
            .err()
            .expect("no approver is attached");

        assert_eq!(refusal.code, "approval_denied");
        assert_eq!(refusal.rule, "confirm-writes");
    }
}
