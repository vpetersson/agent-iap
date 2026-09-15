//! Zero state: what an agent can work out from a token and an address.
//!
//! The proxy's other surfaces both assume someone already explained it. An SDK
//! pointed at `/<upstream>` works because a human set `ANTHROPIC_BASE_URL`; the
//! MCP gateway works because a human wrote the server into a client config. An
//! agent handed nothing but `IAP_TOKEN=iap_…` and `127.0.0.1:8080` had no way in
//! at all — `GET /` was a 404 naming no upstream, which is true and useless.
//!
//! So the root of the data plane answers the question the agent actually has.
//! `GET /` returns a skill document, generated from the running policy for the
//! agent that asked: what this is, the two ways to call through it, which APIs
//! that one agent can reach, and what a refusal means. `GET /_iap/skill` is the
//! same thing as one file worth saving, and `/_iap/skill/<name>` is one section.
//!
//! It also points at MCP rather than describing everything twice, because for an
//! agent that can add an MCP server that is the shorter road: the catalog, the
//! skills and the call itself arrive over one connection, already structured. A
//! caller that turns out to *be* an MCP client — it POSTs to the root, or opens
//! the root asking for an event stream — is redirected to the gateway outright
//! rather than handed prose telling it to reconfigure itself.
//!
//! Nothing here discloses more than the agent could learn by making one refused
//! call: its own grants, and the *scheme* each upstream's credential uses. The
//! secret behind that scheme stays where it has always been.

use axum::extract::{ConnectInfo, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use http::header::{ACCEPT, CONTENT_TYPE, HOST, WWW_AUTHENTICATE};
use http::{HeaderMap, StatusCode, Uri};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::audit::AuditRecord;
use crate::config::UpstreamConfig;
use crate::identity::{AuthFailure, Caller};
use crate::skills;
use crate::state::AppState;

/// The saveable bundle, and the prefix one document hangs off.
pub const SKILL_MOUNT: &str = "/_iap/skill";

/// The conventional place a machine looks before it looks anywhere else. Same
/// document as the root; JSON by default, because nothing reads `.well-known`
/// for prose.
pub const WELL_KNOWN: &str = "/.well-known/agent-iap";

pub fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        // `/_iap` as well as `/`, because an agent that has been told the
        // reserved prefix exists will try it, and because a proxy mounted
        // under a path prefix by something upstream still has this one.
        .route("/", get(root).post(to_gateway))
        .route("/_iap", get(root).post(to_gateway))
        .route(WELL_KNOWN, get(well_known))
        .route(SKILL_MOUNT, get(bundle))
        .route(&format!("{SKILL_MOUNT}/{{*name}}"), get(one_skill))
        .with_state(state)
}

/// Which representation the caller wants.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Format {
    /// For a model: the skill document itself.
    Markdown,
    /// For a program: the same facts, structured.
    Json,
}

async fn root(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    serve(&state, peer, &uri, &headers, Format::Markdown)
}

/// `.well-known` is where a program looks, so answer a program unless asked
/// otherwise. Same document, same rules; only the default differs.
async fn well_known(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    serve(&state, peer, &uri, &headers, Format::Json)
}

fn serve(
    state: &AppState,
    peer: SocketAddr,
    uri: &Uri,
    headers: &HeaderMap,
    fallback: Format,
) -> Response {
    // An MCP client opening the streamable-HTTP transport asks for an event
    // stream. It is not going to read a document telling it where the gateway
    // is, so send it there.
    if wants_event_stream(headers) {
        return Redirect::temporary(crate::gateway::MOUNT).into_response();
    }

    let format = negotiate(uri, headers, fallback);
    let caller = match identify(state, headers) {
        Ok(caller) => caller,
        Err(failure) => return refuse(state, peer, uri.path(), format, &failure),
    };
    note(state, &caller, peer, uri.path());

    let base = base_url(state, headers);
    match format {
        Format::Markdown => markdown(document(state, &caller, &base)),
        Format::Json => Json(describe(state, &caller, &base)).into_response(),
    }
}

/// Everything this agent is told, as one file.
///
/// The root document plus every generated skill, in one response, so an agent
/// that would rather keep a copy than fetch four can save it as `SKILL.md` and
/// be done. `?format=json` gets the index instead, for a client assembling its
/// own.
async fn bundle(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let format = negotiate(&uri, &headers, Format::Markdown);
    let caller = match identify(&state, &headers) {
        Ok(caller) => caller,
        Err(failure) => return refuse(&state, peer, uri.path(), format, &failure),
    };
    note(&state, &caller, peer, uri.path());
    let base = base_url(&state, &headers);

    if format == Format::Json {
        return Json(json!({ "skills": skill_index(&state, &caller, &base) })).into_response();
    }

    let mut text = document(&state, &caller, &base);
    for skill in skills::catalog(&state, caller.agent()) {
        text.push_str("\n\n---\n\n");
        text.push_str(&skill.text);
    }
    (
        [
            (CONTENT_TYPE, "text/markdown; charset=utf-8"),
            // Names the file for anything that saves it, without claiming a
            // download: the body is still meant to be read inline.
            (
                http::header::CONTENT_DISPOSITION,
                "inline; filename=\"SKILL.md\"",
            ),
        ],
        text,
    )
        .into_response()
}

async fn one_skill(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let format = negotiate(&uri, &headers, Format::Markdown);
    let caller = match identify(&state, &headers) {
        Ok(caller) => caller,
        Err(failure) => return refuse(&state, peer, uri.path(), format, &failure),
    };

    let wanted = uri
        .path()
        .strip_prefix(SKILL_MOUNT)
        .unwrap_or_default()
        .trim_start_matches('/');
    let Some(skill) = skills::find(&state, caller.agent(), wanted) else {
        let known: Vec<String> = skills::catalog(&state, caller.agent())
            .into_iter()
            .map(|skill| skill.name)
            .collect();
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": {
                    "type": "unknown_skill",
                    "message": format!(
                        "no skill `{wanted}` for this agent — this proxy has: {}",
                        known.join(", ")
                    ),
                },
                "skills": known,
                "proxy": "agent-iap",
            })),
        )
            .into_response();
    };
    note(&state, &caller, peer, uri.path());

    match format {
        Format::Markdown => markdown(skill.text),
        Format::Json => Json(json!({
            "uri": skill.uri,
            "name": skill.name,
            "title": skill.title,
            "description": skill.description,
            "media_type": "text/markdown",
            "text": skill.text,
        }))
        .into_response(),
    }
}

/// A POST to the root is an MCP client that was given the base URL and nothing
/// more. 307 keeps the method and the body, so the JSON-RPC frame it is already
/// holding arrives at the gateway unchanged and the handshake simply works.
async fn to_gateway() -> Response {
    Redirect::temporary(crate::gateway::MOUNT).into_response()
}

/// Who is asking, for the purpose of writing them a document.
///
/// `AppState::authenticate` refuses a bare agent token outright when workload
/// identity is `required`, which is the right answer for a *call* and the wrong
/// one here: the agent holding a bare agent token is precisely the one who needs
/// to be told to go and exchange it. So resolve it anyway, and let the document
/// say what to do next.
fn identify(state: &AppState, headers: &HeaderMap) -> Result<Caller, AuthFailure> {
    let token = crate::proxy::extract_token(headers).ok_or(AuthFailure::Missing)?;
    match state.authenticate(&token) {
        Err(AuthFailure::WorkloadRequired) => state
            .agents
            .authenticate(&token)
            .map(Caller::Agent)
            .ok_or(AuthFailure::UnknownAgent),
        other => other,
    }
}

/// The address the agent actually reached us on, so the MCP snippet in the
/// document is one it can paste rather than one it has to adapt.
///
/// `Host` is the caller's own claim, so it is used only after it looks like a
/// host and nothing else — a header carrying a path, a scheme or a space would
/// otherwise come back as a URL this proxy appeared to vouch for.
fn base_url(state: &AppState, headers: &HeaderMap) -> String {
    let config = state.config();
    let scheme = if config.server.tls.is_some() {
        "https"
    } else {
        "http"
    };
    let host = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|host| {
            !host.is_empty()
                && host.len() <= 255
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
        })
        .map(str::to_string)
        .unwrap_or_else(|| config.server.listen.to_string());
    format!("{scheme}://{host}")
}

fn negotiate(uri: &Uri, headers: &HeaderMap, fallback: Format) -> Format {
    // An explicit `?format=` is the caller saying it outright, and outranks a
    // header its HTTP library may have set on its behalf.
    if let Some(query) = uri.query() {
        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            if key == "format" {
                return match value.as_ref() {
                    "json" => Format::Json,
                    _ => Format::Markdown,
                };
            }
        }
    }

    let accept = headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if accept.contains("text/markdown") || accept.contains("text/plain") {
        Format::Markdown
    } else if accept.contains("application/json") {
        Format::Json
    } else {
        // `*/*`, or nothing at all. Both mean the caller did not care, and the
        // caller that does not care is a model reading prose.
        fallback
    }
}

fn wants_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains("text/event-stream"))
}

fn markdown(text: String) -> Response {
    ([(CONTENT_TYPE, "text/markdown; charset=utf-8")], text).into_response()
}

/// A discovery read is a read of this agent's own grants, so it goes in the log
/// like anything else that consults the policy on its behalf.
fn note(state: &AppState, caller: &Caller, peer: SocketAddr, path: &str) {
    let mut record = AuditRecord::new("http", "discovery");
    record.agent = caller.agent().id.clone();
    record.agent_name = Some(caller.display_name().to_string());
    record.workload = caller.label();
    record.target = "<discovery>".into();
    record.method = "GET".into();
    record.path = path.to_string();
    record.client = Some(peer.to_string());
    state.audit.write_best_effort(record);
}

/// Answer a caller we could not place — still saying what this is and how to
/// present a credential, because that is the whole question at zero state.
///
/// A token that was presented and did not hold up is audited; a request with no
/// token at all is not. The first is somebody trying credentials, which is
/// evidence; the second is an anonymous GET of a page that names no agent, no
/// upstream and no rule, which is `/_iap/health` with better prose.
fn refuse(
    state: &AppState,
    peer: SocketAddr,
    path: &str,
    format: Format,
    failure: &AuthFailure,
) -> Response {
    if !matches!(failure, AuthFailure::Missing) {
        let mut record = AuditRecord::new("http", "denied");
        record.agent = failure.agent().unwrap_or("<unknown>").to_string();
        record.target = "<discovery>".into();
        record.method = "GET".into();
        record.path = path.to_string();
        record.decision = Some("deny".into());
        record.rule = Some(failure.rule());
        record.client = Some(peer.to_string());
        record.detail = failure.detail();
        state.audit.write_best_effort(record);
    }

    let body = match format {
        Format::Markdown => markdown(anonymous_document(state, failure)),
        Format::Json => Json(json!({
            "service": "agent-iap",
            "version": env!("CARGO_PKG_VERSION"),
            "error": { "type": failure.code(), "message": failure.message() },
            "authenticate": {
                "header": "Authorization: Bearer <iap token>",
                "alternative": "X-IAP-Token: <iap token>",
            },
            "endpoints": {
                "discovery": "/",
                "skill": SKILL_MOUNT,
                "mcp": crate::gateway::MOUNT,
                "health": "/_iap/health",
            },
            "proxy": "agent-iap",
        }))
        .into_response(),
    };

    let mut response = (failure.status(), body).into_response();
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        "Bearer realm=\"agent-iap\"".parse().unwrap(),
    );
    response
}

/// What an unauthenticated caller is told: what this is, and how to come back
/// as somebody. No upstream, no rule, no agent name — the policy starts once
/// the token does.
fn anonymous_document(state: &AppState, failure: &AuthFailure) -> String {
    let mcp = crate::gateway::MOUNT;
    // `AuthFailure::Missing`'s own message tells the caller to come back to
    // `GET /`, which is where it already is. Everything else is a credential
    // that arrived and did not hold up, and that reason is worth repeating.
    let lead = match failure {
        AuthFailure::Missing => {
            "You have not sent a token, so there is nothing here for you yet.".to_string()
        }
        other => capitalise(&other.message()),
    };

    let mut text = format!(
        "# agent-iap\n\n\
         {lead}\n\n\
         This is agent-iap {version}, an identity-aware proxy. It fronts a set of \
         APIs and holds their credentials, so a caller here never needs one of \
         its own — but it does need to say who it is.\n\n\
         ## Authenticate\n\n\
         Send the `iap_…` token you were given, on every request:\n\n\
         ```http\n\
         GET / HTTP/1.1\n\
         Authorization: Bearer iap_…\n\
         ```\n\n\
         `X-IAP-Token: iap_…` does the same thing, for a client that needs \
         `Authorization` for something else.\n\n\
         Then ask for `/` again. It answers with what *you* can reach, which is \
         not the same document for any two agents. If you have no token, ask \
         whoever runs this proxy for one — there is nothing to guess at here and \
         no anonymous access to find.\n\n\
         ## The rest of this address\n\n\
         - `GET /_iap/health` — that this proxy is up, and its version. The only \
         thing here that takes no token.\n\
         - `POST {mcp}` — MCP, over the streamable HTTP transport. A client given \
         that URL and the header above discovers everything else on its own.\n",
        version = env!("CARGO_PKG_VERSION"),
    );

    if state.workload.mode().enabled() {
        text.push_str(
            "- `POST /_iap/token` — where an agent token is exchanged for a \
             short-lived one scoped to the run in front of it.\n",
        );
    }
    text
}

fn capitalise(message: &str) -> String {
    let mut chars = message.chars();
    match chars.next() {
        Some(first) => format!("{}{}.", first.to_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

/// The document itself: everything this one agent needs to use this proxy,
/// generated from the policy that is running.
pub fn document(state: &AppState, caller: &Caller, base: &str) -> String {
    let agent = caller.agent();
    let mcp_url = format!("{base}{}", crate::gateway::MOUNT);
    let mut text = format!(
        "# agent-iap\n\n\
         You have reached agent-iap {version} at `{base}`, as `{id}` ({name}).\n\n\
         This is an identity-aware proxy. It holds the credentials for the APIs \
         below and attaches them on the way out, after checking a policy and \
         writing an audit record. You are not holding any of those credentials, \
         you do not need one, and you should not go looking for one or ask a \
         person for one: the `iap_…` token you just used is the whole of your \
         access, and it buys nothing anywhere but here.\n\n",
        version = env!("CARGO_PKG_VERSION"),
        id = agent.id,
        name = agent.display_name(),
    );

    // Written out rather than serialised: this is a config file a person or an
    // agent pastes, and it should read the way the documentation writes it.
    let client_config = format!(
        "{{ \"mcpServers\": {{ \"iap\": {{\n    \"type\": \"http\",\n    \
         \"url\": \"{mcp_url}\",\n    \"headers\": {{ \"Authorization\": \
         \"Bearer <the token you just used>\" }} }} }} }}"
    );

    text.push_str(&format!(
        "## The short way: add this as an MCP server\n\n\
         If you can add an MCP server, add this one and you can stop reading. \
         Everything below arrives over that connection instead, generated from \
         the same policy, and a call becomes one tool call rather than a request \
         you assemble:\n\n\
         ```json\n{client_config}\n```\n\n\
         `iap_catalog` lists what you can reach, `iap_skill` explains any one of \
         them, and `iap_request` makes the call. That is the fastest route from \
         here and the one to prefer.\n\n\
         ## The other way: it is also an HTTP proxy\n\n\
         Each API is mounted under its own name. Send the request you would have \
         sent to the API, to this address instead:\n\n\
         ```http\n\
         GET {base}/<upstream>/<the path the API would see>\n\
         Authorization: Bearer <the token you just used>\n\
         ```\n\n\
         For an SDK that takes a base URL, point it at `{base}/<upstream>` and \
         give it your `iap_…` token where it asks for an API key — most work \
         unchanged from there. For one that cannot take a path in its base URL, \
         name the upstream in `X-IAP-Upstream` and leave the path alone.\n\n\
         Do not set an API-key header yourself. Whatever credential header you \
         send is dropped rather than forwarded, and the real one is attached \
         here.\n\n"
    ));

    text.push_str(&reachable_section(state, caller, base));
    text.push_str(&refusals_section(state));
    text.push_str(&workload_section(state, caller, base));
    text.push_str(&endpoints_section(state, base));
    text
}

fn reachable_section(state: &AppState, caller: &Caller, base: &str) -> String {
    let agent = caller.agent();
    let upstreams = skills::reachable_upstreams(state, agent);
    let mut text = String::from("## What you can reach\n\n");

    if upstreams.is_empty() {
        text.push_str(
            "Nothing, today. No API in this policy is both granted to this agent \
             and named by a rule that could allow a call, so every request would \
             be refused. That is a policy question, not something to work around: \
             say so to whoever asked you to do this, and name this proxy.\n\n",
        );
        return text;
    }

    for upstream in &upstreams {
        text.push_str(&format!(
            "### `{name}`\n\n\
             - proxied at `{base}/{name}/<path>`\n\
             - the API itself is `{url}`\n\
             - the proxy attaches the credential — `{auth}` — and drops any you \
             send\n\n",
            name = upstream.name,
            url = upstream.base_url,
            auth = upstream.auth.describe(),
        ));
        text.push_str(&skills::rules_table(state, agent, &upstream.name, "####"));
        text.push('\n');
    }
    text
}

fn refusals_section(state: &AppState) -> String {
    let mut text = String::from(
        "## When you are refused\n\n\
         A refusal from the proxy names the rule that refused it, in an \
         `x-iap-decision` header and in the JSON body. The codes:\n\n\
         - `policy_denied` — the ACL says no. That is final for that call: \
         rephrasing the path or trying again will not change it.\n\
         - `target_not_permitted` — this agent is not granted that API at all.\n\
         - `no_route` / `unknown_upstream` — the first path segment is not an \
         API this proxy fronts. The names above are the complete list.\n\
         - `approval_denied` — a person was asked and said no, or nobody was \
         there to ask.\n\
         - `missing_credentials` / `unknown_agent` — the token did not arrive or \
         was not recognised.\n\n\
         None of these are worth a retry, and none of them are worth routing \
         around — calling the API directly will fail too, because you do not \
         have its credential. Say what you were refused and which rule refused \
         it, and let the person decide whether to widen the policy.\n\n\
         A `4xx` from the API itself is not a refusal: it comes back as that \
         API's own answer, with its status and body intact.\n\n",
    );

    if state.acl.can_ask() {
        text.push_str(
            "### Some calls stop on a person\n\n\
             This policy holds certain calls in front of a human, who allows or \
             denies them one at a time. Such a request takes as long as the \
             person takes. That is not a hang: do not cancel it, do not retry \
             underneath it, and do not start a second copy of the same call.\n\n",
        );
    }
    text
}

fn workload_section(state: &AppState, caller: &Caller, base: &str) -> String {
    let mode = state.workload.mode();
    if !mode.enabled() {
        return String::new();
    }
    let lifetime = state.workload.lifetime_secs();
    let mut text = format!(
        "## Trading your token down\n\n\
         `POST {base}/_iap/token` exchanges the standing token you hold for one \
         that expires — at most {lifetime} seconds — and covers only the calls \
         you ask it to cover. Use it as the credential afterwards, and the copy \
         of it that ends up in a log or a context window is worth nothing an \
         hour later.\n\n",
    );

    match caller.workload() {
        Some(_) => text.push_str(
            "You are already using one. Renew it at `/_iap/token/renew` before it \
             lapses rather than going back to the agent token.\n\n",
        ),
        None if mode == crate::config::WorkloadMode::Required => text.push_str(
            "**This proxy requires one.** The token you are holding mints \
             workload tokens and does nothing else — every call you make with it \
             directly will be refused `workload_token_required`. Exchange it \
             first.\n\n",
        ),
        None => text.push_str(
            "It is optional here: your agent token still works for calls. \
             Exchanging it is better practice and costs one request.\n\n",
        ),
    }
    text
}

fn endpoints_section(state: &AppState, base: &str) -> String {
    let mut text = format!(
        "## Everything on this address\n\n\
         | | |\n\
         | --- | --- |\n\
         | `GET {base}/` | this document |\n\
         | `GET {base}{SKILL_MOUNT}` | the same, plus every skill below it, as one file |\n\
         | `GET {base}{SKILL_MOUNT}/<name>` | one of them |\n\
         | `POST {base}{mcp}` | MCP, streamable HTTP |\n\
         | `GET {base}/_iap/health` | liveness, no token needed |\n",
        mcp = crate::gateway::MOUNT,
    );
    if state.workload.mode().enabled() {
        text.push_str(&format!(
            "| `POST {base}/_iap/token` | exchange your token for a scoped, expiring one |\n"
        ));
    }
    text.push_str(&format!(
        "| `<method> {base}/<upstream>/<path>` | the call itself |\n\n\
         Add `?format=json` to any of the first three for the same facts \
         structured, if you would rather parse than read.\n"
    ));
    text
}

/// The same document for a program.
pub fn describe(state: &AppState, caller: &Caller, base: &str) -> Value {
    let agent = caller.agent();
    let mode = state.workload.mode();

    let upstreams: Vec<Value> = skills::reachable_upstreams(state, agent)
        .iter()
        .map(|upstream: &UpstreamConfig| {
            json!({
                "name": upstream.name,
                "url": format!("{base}/{}", upstream.name),
                "api_base_url": upstream.base_url,
                "auth": upstream.auth.describe(),
                "skill": format!("{base}{SKILL_MOUNT}/upstream/{}", upstream.name),
            })
        })
        .collect();

    let mut document = json!({
        "service": "agent-iap",
        "version": env!("CARGO_PKG_VERSION"),
        "summary":
            "An identity-aware proxy. It holds the credentials for the APIs it \
             fronts and attaches them after a policy check, so the caller never \
             holds one.",
        "base_url": base,
        "agent": { "id": agent.id, "name": agent.display_name() },
        // Named rather than implied: a client that can speak MCP should, and
        // this is the field that tells it so without reading the prose.
        "preferred_transport": "mcp",
        "mcp": {
            "url": format!("{base}{}", crate::gateway::MOUNT),
            "transport": "streamable-http",
            "protocol_version": crate::gateway::PROTOCOL_VERSION,
            "tools": ["iap_catalog", "iap_skill", "iap_request"],
            "client_config": {
                "mcpServers": {
                    "iap": {
                        "type": "http",
                        "url": format!("{base}{}", crate::gateway::MOUNT),
                        "headers": { "Authorization": "Bearer <your iap token>" },
                    }
                }
            },
        },
        "http": {
            "url_pattern": format!("{base}/<upstream>/<path>"),
            "authorization": "Authorization: Bearer <your iap token>",
            "upstream_header": "X-IAP-Upstream",
            "note":
                "Send no credential of your own — a credential header is dropped \
                 rather than forwarded, and the real one is attached by the proxy.",
        },
        "upstreams": upstreams,
        "skills": skill_index(state, caller, base),
        "workload_identity": {
            "mode": mode.as_str(),
            "required": mode == crate::config::WorkloadMode::Required,
            "max_lifetime_secs": state.workload.lifetime_secs(),
            "token_url": mode.enabled().then(|| format!("{base}/_iap/token")),
            "holding_one": caller.workload().is_some(),
        },
        "approvals": {
            "possible": state.acl.can_ask(),
            "note":
                "A call held for a human takes as long as the person takes. It is \
                 not a hang: do not cancel it and do not retry underneath it.",
        },
        "refusals": {
            "policy_denied": "The ACL refused this call. Final — do not retry.",
            "target_not_permitted": "This agent is not granted that upstream.",
            "no_route": "No upstream named in the request path.",
            "unknown_upstream": "That upstream is not configured here.",
            "approval_denied": "A human refused it, or nobody was there to ask.",
            "scope_exceeded": "The workload token is narrower than the call.",
            "missing_credentials": "No token arrived.",
            "unknown_agent": "The token is not recognised.",
        },
        "endpoints": {
            "discovery": format!("{base}/"),
            "skill_bundle": format!("{base}{SKILL_MOUNT}"),
            "mcp": format!("{base}{}", crate::gateway::MOUNT),
            "health": format!("{base}/_iap/health"),
        },
    });

    if mode.enabled() {
        document["endpoints"]["token"] = json!(format!("{base}/_iap/token"));
    }
    document
}

fn skill_index(state: &AppState, caller: &Caller, base: &str) -> Vec<Value> {
    skills::catalog(state, caller.agent())
        .into_iter()
        .map(|skill| {
            json!({
                "name": skill.name,
                "title": skill.title,
                "description": skill.description,
                "uri": skill.uri,
                "url": format!("{base}{SKILL_MOUNT}/{}", skill.name),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn state() -> Arc<AppState> {
        let config: Config = toml::from_str(&format!(
            r#"
[server]
listen = "127.0.0.1:8080"

[audit]
path = "/dev/null"
stderr = false

[[agents]]
id = "claude"
name = "Claude Code"
token_sha256 = "{hash}"

[[upstreams]]
name = "anthropic"
base_url = "https://api.anthropic.com"
auth = {{ type = "header", header = "x-api-key", secret = "literal:sk-real" }}

[[acl]]
name = "read-models"
target = "anthropic"
methods = ["GET"]
paths = ["/v1/models"]
action = "allow"
"#,
            hash = crate::identity::token_hash("iap_claude"),
        ))
        .unwrap();
        AppState::build(config, false).unwrap()
    }

    fn caller(state: &AppState) -> Caller {
        Caller::Agent(state.agents.by_id("claude").unwrap())
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        headers
    }

    fn uri(path: &str) -> Uri {
        path.parse().unwrap()
    }

    #[test]
    fn a_caller_that_expressed_no_preference_gets_the_prose() {
        // The common case: `curl` sends `*/*`, an agent sends nothing at all,
        // and both of them are reading rather than parsing.
        assert_eq!(
            negotiate(&uri("/"), &headers(&[("accept", "*/*")]), Format::Markdown),
            Format::Markdown
        );
        assert_eq!(
            negotiate(&uri("/"), &HeaderMap::new(), Format::Markdown),
            Format::Markdown
        );
        // …but `.well-known` is read by programs, so its own default holds.
        assert_eq!(
            negotiate(&uri(WELL_KNOWN), &HeaderMap::new(), Format::Json),
            Format::Json
        );
    }

    #[test]
    fn asking_outright_beats_whatever_the_http_library_put_in_accept() {
        let json = headers(&[("accept", "application/json")]);
        assert_eq!(
            negotiate(&uri("/?format=md"), &json, Format::Json),
            Format::Markdown
        );
        assert_eq!(
            negotiate(
                &uri("/?format=json"),
                &headers(&[("accept", "text/markdown")]),
                Format::Markdown
            ),
            Format::Json
        );
        assert_eq!(negotiate(&uri("/"), &json, Format::Markdown), Format::Json);
    }

    #[test]
    fn the_address_in_the_document_is_the_one_the_agent_reached_us_on() {
        let state = state();
        assert_eq!(
            base_url(&state, &headers(&[("host", "iap.internal:9000")])),
            "http://iap.internal:9000"
        );
        // Nothing to reflect: fall back to what the policy file says we listen on.
        assert_eq!(base_url(&state, &HeaderMap::new()), "http://127.0.0.1:8080");
    }

    #[test]
    fn a_host_header_that_is_not_a_host_is_not_echoed_back_as_one() {
        // `Host` is the caller's own claim. A document that pasted it into
        // every URL would be this proxy appearing to vouch for an address
        // somebody else chose.
        let state = state();
        for hostile in [
            "evil.example/path",
            "https://evil.example",
            "evil.example?x=1",
            "evil.example foo",
        ] {
            assert_eq!(
                base_url(&state, &headers(&[("host", hostile)])),
                "http://127.0.0.1:8080",
                "`{hostile}` was reflected"
            );
        }
    }

    #[test]
    fn the_document_names_the_scheme_and_never_the_secret() {
        let state = state();
        let text = document(&state, &caller(&state), "http://127.0.0.1:8080");
        assert!(text.contains("header x-api-key"), "{text}");
        assert!(!text.contains("sk-real"), "{text}");

        let json =
            serde_json::to_string(&describe(&state, &caller(&state), "http://127.0.0.1:8080"))
                .unwrap();
        assert!(json.contains("header x-api-key"), "{json}");
        assert!(!json.contains("sk-real"), "{json}");
    }

    #[test]
    fn a_policy_with_no_ask_rule_does_not_warn_about_a_wait_that_cannot_happen() {
        let state = state();
        let text = document(&state, &caller(&state), "http://127.0.0.1:8080");
        assert!(!text.contains("stop on a person"), "{text}");
        assert!(
            !describe(&state, &caller(&state), "http://127.0.0.1:8080")["approvals"]["possible"]
                .as_bool()
                .unwrap()
        );
        // Workload identity defaults to `optional`, and the document says which
        // of the two things that means — not that it exists.
        assert!(text.contains("It is optional here"), "{text}");
        assert!(!text.contains("This proxy requires one"), "{text}");
    }

    #[test]
    fn what_an_anonymous_caller_is_told_names_no_agent_and_no_upstream() {
        let state = state();
        let text = anonymous_document(&state, &AuthFailure::Missing);
        assert!(text.contains("Authorization: Bearer"), "{text}");
        assert!(!text.contains("anthropic"), "{text}");
        assert!(!text.contains("Claude Code"), "{text}");
        assert!(!text.contains("read-models"), "{text}");
    }
}
