//! The gateway: agent-iap as an MCP server in its own right.
//!
//! The proxy fronts REST APIs in REST's own idiom — point an SDK at
//! `http://127.0.0.1:8080/<upstream>` and it works unchanged. That is the right
//! surface for a program. It is the wrong one for an agent, which has to be
//! told out of band that the proxy exists, what it fronts, and what it will
//! refuse; none of which is discoverable from a base URL.
//!
//! MCP is the idiom agents already discover. So the same upstreams are offered
//! here as tools: `iap_catalog` says what is reachable, `iap_skill` says how to
//! call it, and `iap_request` performs the call. Everything an agent needs to
//! use the proxy well arrives over the same connection it uses to call through
//! it, generated from the policy that is actually running.
//!
//! This is not a second policy engine. `iap_request` goes through
//! `crate::gate`, the same function the HTTP proxy calls, and writes the same
//! audit records — the surface is new, the decision is not.
//!
//! The discovery tools are not themselves ACL-gated, and that is deliberate.
//! They report what the policy already decided about *this* agent, so they
//! disclose nothing the agent could not learn by making one refused call; and
//! gating them would mean every existing policy file needed a rule naming the
//! gateway before an agent could so much as list its own grants.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{json, Map, Value};
use std::sync::Arc;
use std::time::Instant;

use crate::acl::AccessRequest;
use crate::audit::AuditRecord;
use crate::gate;
use crate::identity::Caller;
use crate::skills;
use crate::state::AppState;

/// Where the gateway lives on the data plane. Under the reserved `_iap` prefix,
/// so it cannot collide with an upstream named `mcp`.
pub const MOUNT: &str = "/_iap/mcp";

/// The MCP revision this server implements.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// JSON-RPC reserved codes.
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

pub fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route(
            MOUNT,
            post(serve)
                // The streamable HTTP transport lets a client open a GET for a
                // stream of server-initiated messages. This server never sends
                // one — every response is the answer to a request — and the
                // spec's prescribed answer for that is 405 rather than an idle
                // stream the client waits on forever.
                .get(no_server_stream)
                // Sessions are not kept, so there is nothing to tear down; say
                // so rather than 405, which reads as "this went wrong".
                .delete(no_session),
        )
        .with_state(state)
}

async fn no_server_stream() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(json!({ "error": "this server sends no unsolicited messages — POST your requests" })),
    )
        .into_response()
}

async fn no_session() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn serve(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Authenticate before parsing, so an anonymous caller never learns anything
    // from how we read a body. Same rule the control plane follows.
    let Some(token) = crate::proxy::extract_token(&headers) else {
        return unauthenticated(&crate::identity::AuthFailure::Missing);
    };
    let caller = match state.authenticate(&token) {
        Ok(caller) => caller,
        Err(failure) => {
            let mut record = AuditRecord::new("mcp", "denied");
            record.agent = failure.agent().unwrap_or("<unknown>").to_string();
            record.target = "<gateway>".into();
            record.decision = Some("deny".into());
            record.rule = Some(failure.rule());
            record.detail = failure.detail();
            state.audit.write_best_effort(record);
            return unauthenticated(&failure);
        }
    };

    let Ok(message) = serde_json::from_slice::<Value>(&body) else {
        return Json(error_frame(
            &Value::Null,
            PARSE_ERROR,
            "the body is not JSON",
        ))
        .into_response();
    };

    // JSON-RPC batching was removed from MCP in this revision, and supporting it
    // here would mean deciding what a half-refused batch means — the one thing
    // the bridge had to go out of its way to get right. One frame, one answer.
    if message.is_array() {
        return Json(error_frame(
            &Value::Null,
            INVALID_REQUEST,
            "batched requests are not supported — send one message per request",
        ))
        .into_response();
    }

    match dispatch(&state, &caller, &message).await {
        // A notification. No body, and 202 is what the transport expects.
        None => StatusCode::ACCEPTED.into_response(),
        Some(response) => Json(response).into_response(),
    }
}

fn unauthenticated(failure: &crate::identity::AuthFailure) -> Response {
    (
        failure.status(),
        Json(json!({
            "error": { "type": failure.code(), "message": failure.message() },
            "proxy": "agent-iap",
        })),
    )
        .into_response()
}

/// Answer one JSON-RPC frame. `None` for a notification, which takes no reply.
pub async fn dispatch(state: &AppState, caller: &Caller, message: &Value) -> Option<Value> {
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    let params = message.get("params").cloned().unwrap_or(json!({}));

    // A frame with no id is a notification: act on it, answer nothing. The only
    // one that matters to us is `initialized`, and it needs no action either.
    let is_notification = message.get("id").is_none() || id.is_null();

    let outcome = match method {
        "initialize" => Ok(initialize(state, caller)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(tools_list(state, caller)),
        "tools/call" => call_tool(state, caller, &params).await,
        "resources/list" => Ok(resources_list(state, caller)),
        "resources/read" => read_resource(state, caller, &params),
        // Advertised as empty rather than unimplemented: a client that asks is
        // enumerating, and an error would read as a fault it should report.
        "resources/templates/list" => Ok(json!({ "resourceTemplates": [] })),
        "prompts/list" => Ok(json!({ "prompts": [] })),
        _ if method.starts_with("notifications/") => Ok(json!({})),
        _ => Err(RpcError {
            code: METHOD_NOT_FOUND,
            message: format!("`{method}` is not something this server implements"),
        }),
    };

    if is_notification {
        return None;
    }

    Some(match outcome {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(error) => error_frame(&id, error.code, &error.message),
    })
}

struct RpcError {
    code: i64,
    message: String,
}

fn error_frame(id: &Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}

fn initialize(state: &AppState, caller: &Caller) -> Value {
    let mut record = AuditRecord::new("mcp", "session_start");
    record.agent = caller.agent().id.clone();
    record.agent_name = Some(caller.display_name().to_string());
    record.workload = caller.label();
    record.target = "<gateway>".into();
    record.method = "initialize".into();
    state.audit.write_best_effort(record);

    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            // What an agent may reach does change while the process runs — a
            // reload swaps the policy under a live session — but this transport
            // has no channel to say so: there is no server-to-client stream and
            // no session to address one to. So no `listChanged` is promised.
            // Instead nothing served once and cached by a client claims to be
            // final: the instructions and `iap_request`'s description both
            // defer to `iap_catalog`, which is computed on every call.
            "tools": {},
            "resources": {},
        },
        "serverInfo": {
            "name": "agent-iap",
            "title": "agent-iap gateway",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": skills::instructions(state, caller.agent()),
    })
}

fn tools_list(state: &AppState, caller: &Caller) -> Value {
    let reachable: Vec<String> = skills::reachable_upstreams(state, caller.agent())
        .into_iter()
        .map(|reachable| match reachable.access.note() {
            Some(note) => format!("{} ({note})", reachable.upstream.name),
            None => reachable.upstream.name,
        })
        .collect();

    // Naming them in the description rather than as an `enum`: a model that
    // guesses a name it was not given gets the proxy's refusal, which explains
    // itself, instead of a client-side schema rejection, which does not.
    //
    // Never "nothing is reachable", though. A client may keep this description
    // for the whole session, and the policy can be reloaded under it — a
    // cached absolute would outlive the grant that made it false. `iap_catalog`
    // is computed per call, so that is where the description sends the agent.
    let upstreams = if reachable.is_empty() {
        "named by `iap_catalog`, which has the current list — call it first".to_string()
    } else {
        format!(
            "one of: {} — or call `iap_catalog` for the current list, which can \
             change while you run",
            reachable.join(", ")
        )
    };

    json!({ "tools": [
        {
            "name": "iap_request",
            "title": "Call an API through the proxy",
            "description": format!(
                "Perform an HTTP request against one of the APIs this proxy fronts. The \
                 proxy holds the credential and attaches it — never send one. Every call \
                 is policy-checked and audited, and some may be held for human approval. \
                 Upstream is {upstreams}. A textual response comes back as `body`; \
                 anything else (an archive, an image, bytes that are not UTF-8) comes back \
                 base64-encoded as `body_base64` instead — decode it, never read it as \
                 text. Read `using-this-gateway` via iap_skill first."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "upstream": {
                        "type": "string",
                        "description": format!("Which API to call — {upstreams}."),
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method. Defaults to GET.",
                    },
                    "path": {
                        "type": "string",
                        "description":
                            "Path as the upstream sees it, starting with `/`. Not a full \
                             URL — the base URL comes from the policy.",
                    },
                    "query": {
                        "type": "object",
                        "description": "Query parameters, as a flat object of strings.",
                    },
                    "body": {
                        "description":
                            "Request body. A JSON value is sent as application/json; a \
                             string is sent verbatim.",
                    },
                    "headers": {
                        "type": "object",
                        "description":
                            "Extra request headers. Credential headers are ignored — the \
                             proxy sets those.",
                    },
                    "response_encoding": {
                        "type": "string",
                        "enum": ["auto", "base64"],
                        "description":
                            "`auto` (the default) returns a textual response as `body` and \
                             anything else as `body_base64`. `base64` always returns \
                             `body_base64`, for when the bytes must arrive exactly.",
                    },
                },
                "required": ["upstream", "path"],
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "status": { "type": "integer" },
                    "headers": { "type": "object" },
                    "body": { "type": "string" },
                    "body_base64": { "type": "string" },
                    "truncated": { "type": "boolean" },
                },
                "required": ["status"],
            },
        },
        {
            "name": "iap_catalog",
            "title": "What this agent can reach",
            "description":
                "List the APIs this agent may call through the proxy, with the base URL, \
                 the credential scheme the proxy attaches, and the rules that apply. Call \
                 this before guessing an upstream name.",
            "inputSchema": { "type": "object", "properties": {} },
        },
        {
            "name": "iap_skill",
            "title": "Read a usage skill",
            "description":
                "Read one of this gateway's generated skill documents: \
                 `using-this-gateway` for how to call and how to read a refusal, or \
                 `upstream/<name>` for one API's base URL, credential scheme and rules.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Skill name, e.g. `using-this-gateway`.",
                    },
                },
                "required": ["name"],
            },
        },
    ]})
}

fn resources_list(state: &AppState, caller: &Caller) -> Value {
    let resources: Vec<Value> = skills::catalog(state, caller.agent())
        .into_iter()
        .map(|skill| {
            json!({
                "uri": skill.uri,
                "name": skill.name,
                "title": skill.title,
                "description": skill.description,
                "mimeType": "text/markdown",
            })
        })
        .collect();
    json!({ "resources": resources })
}

fn read_resource(state: &AppState, caller: &Caller, params: &Value) -> Result<Value, RpcError> {
    let uri = params
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError {
            code: INVALID_PARAMS,
            message: "`uri` is required".into(),
        })?;

    let skill = skills::find(state, caller.agent(), uri).ok_or_else(|| RpcError {
        code: INVALID_PARAMS,
        message: format!("no resource `{uri}` — list them with resources/list"),
    })?;

    Ok(json!({ "contents": [{
        "uri": skill.uri,
        "name": skill.name,
        "title": skill.title,
        "mimeType": "text/markdown",
        "text": skill.text,
    }]}))
}

async fn call_tool(state: &AppState, caller: &Caller, params: &Value) -> Result<Value, RpcError> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError {
            code: INVALID_PARAMS,
            message: "`name` is required".into(),
        })?;
    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

    match name {
        "iap_request" => Ok(match request(state, caller, &arguments).await {
            Ok(result) => result,
            // A policy refusal, a bad path, an upstream that did not answer:
            // these are outcomes of the call, not faults in the protocol. MCP
            // wants them as tool errors so the model reads them and adapts,
            // rather than as JSON-RPC errors, which most clients surface to the
            // user as a broken tool.
            Err(failure) => tool_error(&failure),
        }),
        "iap_catalog" => Ok(catalog_result(state, caller)),
        "iap_skill" => Ok(skill_result(state, caller, &arguments)),
        other => Err(RpcError {
            code: INVALID_PARAMS,
            message: format!("`{other}` is not a tool this server offers"),
        }),
    }
}

fn tool_error(message: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": message }],
        "isError": true,
    })
}

fn text_result(text: String, structured: Option<Value>) -> Value {
    let mut result = json!({ "content": [{ "type": "text", "text": text }] });
    if let Some(structured) = structured {
        result["structuredContent"] = structured;
    }
    result
}

fn catalog_result(state: &AppState, caller: &Caller) -> Value {
    let agent = caller.agent();
    let mut entries = Vec::new();
    let mut text = String::new();

    for reachable in skills::reachable_upstreams(state, agent) {
        let upstream = reachable.upstream;
        let name = &upstream.name;
        let skill = format!("upstream/{name}");
        let note = reachable
            .access
            .note()
            .map(|note| format!("; {note}"))
            .unwrap_or_default();
        text.push_str(&format!(
            "- `{}` — {} (credential: {}; skill: `{}`{note})\n",
            name,
            upstream.base_url,
            upstream.auth.describe(),
            skill,
        ));
        entries.push(json!({
            "name": name,
            "base_url": upstream.base_url,
            "auth": upstream.auth.describe(),
            "skill": skill,
            // `rules` when the ACL names this upstream for this agent, else the
            // default every call falls through to: `ask` or `allow`. A `deny`
            // default with no rule is not listed at all.
            "access": reachable.access.as_str(),
        }));
    }

    if entries.is_empty() {
        text = "This agent may not reach any upstream through this proxy. Either it \
                has no `targets` grant, or the upstreams it has are named by no ACL \
                rule and the default denies. An operator has to change the policy file."
            .to_string();
    } else {
        text = format!(
            "APIs reachable through this proxy:\n\n{text}\nCall them with `iap_request`. \
             The proxy attaches the credential — do not send one."
        );
    }

    text_result(text, Some(json!({ "upstreams": entries })))
}

fn skill_result(state: &AppState, caller: &Caller, arguments: &Value) -> Value {
    let Some(wanted) = arguments.get("name").and_then(Value::as_str) else {
        return tool_error("`name` is required — try `using-this-gateway`");
    };
    match skills::find(state, caller.agent(), wanted) {
        Some(skill) => text_result(skill.text, None),
        None => {
            let known: Vec<String> = skills::catalog(state, caller.agent())
                .into_iter()
                .map(|skill| skill.name)
                .collect();
            tool_error(&format!(
                "no skill `{wanted}`. This gateway has: {}",
                known.join(", ")
            ))
        }
    }
}

/// The whole point of the surface: one upstream call, decided and recorded
/// exactly as the HTTP proxy would have decided and recorded it.
async fn request(state: &AppState, caller: &Caller, arguments: &Value) -> Result<Value, String> {
    let started = Instant::now();
    let agent = caller.agent();

    let upstream_name = string_arg(arguments, "upstream")
        .ok_or("`upstream` is required — call `iap_catalog` for the names")?;
    let path = string_arg(arguments, "path").ok_or("`path` is required, starting with `/`")?;
    let method = string_arg(arguments, "method").unwrap_or_else(|| "GET".into());

    let method: http::Method = method
        .to_uppercase()
        .parse()
        .map_err(|_| format!("`{method}` is not an HTTP method"))?;
    let force_base64 = match string_arg(arguments, "response_encoding").as_deref() {
        None | Some("auto") => false,
        Some("base64") => true,
        Some(other) => {
            return Err(format!(
                "`response_encoding` must be `auto` or `base64` — `{other}` is neither"
            ))
        }
    };

    let mut record = AuditRecord::new("http", "request");
    record.agent = agent.id.clone();
    record.agent_name = Some(caller.display_name().to_string());
    record.workload = caller.label();
    record.target = upstream_name.clone();
    record.method = method.to_string();
    record.path = path.clone();
    // Which surface the call came in on. Two agents can be reaching the same
    // upstream through the proxy and through the gateway at once, and an
    // operator reading the log should not have to infer which is which.
    record.detail = Some(json!({ "via": "mcp-gateway" }));

    // A full URL here would mean the ACL matched one thing and the request went
    // somewhere else entirely. The proxy cannot receive this — its routing makes
    // it impossible — but a tool argument can say anything.
    if !path.starts_with('/') {
        record.event = "denied".into();
        record.decision = Some("deny".into());
        record.rule = Some("<invalid-path>".into());
        state.audit.write_best_effort(record);
        return Err(format!(
            "`path` must start with `/` and be the path only — `{path}` is not. The base \
             URL comes from the policy."
        ));
    }
    if let Err(reason) = crate::proxy::check_path(&path) {
        record.event = "denied".into();
        record.decision = Some("deny".into());
        record.rule = Some("<path-traversal>".into());
        state.audit.write_best_effort(record);
        return Err(reason.to_string());
    }

    let Some(upstream) = state.config().upstream(&upstream_name).cloned() else {
        record.event = "denied".into();
        record.decision = Some("deny".into());
        record.rule = Some("<unknown-upstream>".into());
        state.audit.write_best_effort(record);
        return Err(format!(
            "`{upstream_name}` is not an upstream this proxy fronts — call `iap_catalog`"
        ));
    };

    let headers = supplied_headers(arguments.get("headers"), &upstream);
    if let Some(reason) = crate::sigv4::refusal_for(&upstream.auth, &headers) {
        record.event = "denied".into();
        record.decision = Some("deny".into());
        record.rule = Some("<unsignable>".into());
        state.audit.write_best_effort(record);
        return Err(format!("unsignable_request: {reason}"));
    }

    let access = AccessRequest::http(&agent.id, &upstream.name, method.as_str(), &path);
    match gate::clear(state, caller, &access).await {
        Ok(cleared) => {
            record.decision = Some(cleared.decision);
            record.rule = Some(cleared.rule);
        }
        Err(refusal) => {
            record.event = "denied".into();
            record.decision = Some("deny".into());
            record.rule = Some(refusal.rule);
            record.status = Some(refusal.status.as_u16());
            record.error = Some(refusal.message.clone());
            state.audit.write_best_effort(record);
            // The code travels with the sentence because the skill document
            // tells the agent what each one means and whether retrying helps.
            return Err(format!("{}: {}", refusal.code, refusal.message));
        }
    }

    let body = encode_body(arguments.get("body"));
    if let Some((_, bytes)) = &body {
        record.request_bytes = Some(bytes.len() as u64);
    }

    let query = encode_query(arguments.get("query"))?;
    let url = crate::proxy::build_url(&upstream.base_url, &path, query.as_deref())
        .map_err(|error| error.to_string())?;

    let mut outbound = reqwest::Request::new(method.clone(), url);
    *outbound.headers_mut() = headers;
    if let Some((content_type, bytes)) = body {
        // Only when the agent did not name one itself: a caller that knows it
        // is sending `application/x-ndjson` should not be overridden.
        if !outbound.headers().contains_key(http::header::CONTENT_TYPE) {
            outbound
                .headers_mut()
                .insert(http::header::CONTENT_TYPE, content_type);
        }
        *outbound.body_mut() = Some(reqwest::Body::from(bytes));
    }

    state
        .injector
        .apply(&upstream.name, &upstream.auth, &mut outbound)
        .await
        .map_err(|error| {
            let mut record = record.clone();
            record.event = "error".into();
            record.error = Some(error.to_string());
            state.audit.write_best_effort(record);
            format!("could not resolve the credential for `{}`", upstream.name)
        })?;

    let response = state.http().execute(outbound).await.map_err(|error| {
        let mut record = record.clone();
        record.event = "error".into();
        record.error = Some(crate::proxy::describe_upstream_error(&error));
        record.duration_ms = Some(started.elapsed().as_millis() as u64);
        state.audit.write_best_effort(record);
        format!("upstream `{}` did not answer", upstream.name)
    })?;

    let status = response.status();
    // Same question as the proxy asks, answered by the same function: a token
    // the upstream rejected is worth nothing, and a caller the upstream refused
    // says nothing about the token.
    state
        .injector
        .note_upstream_status(&upstream.name, status, &upstream.auth);

    let headers = readable_headers(response.headers());
    let (bytes, truncated) = read_capped(response, state.config().server.max_body_bytes).await?;

    record.status = Some(status.as_u16());
    record.duration_ms = Some(started.elapsed().as_millis() as u64);
    record.response_bytes = Some(bytes.len() as u64);
    // Same rule as the proxy: a call that happened and cannot be recorded does
    // not get its response back. The log is the product.
    state.audit.write(record).map_err(|error| {
        tracing::error!(?error, "withholding a response that could not be audited");
        "the request was permitted and performed, but could not be written to the audit \
         log, so its response was withheld"
            .to_string()
    })?;

    Ok(response_result(
        &upstream.name,
        status,
        headers,
        bytes,
        truncated,
        force_base64,
    ))
}

/// The body as the agent will receive it.
enum Body {
    Text(String),
    Base64(String),
}

/// Text when the response is text, base64 otherwise.
///
/// Decoding lossily would be wrong in the worst way: a tarball's gzip magic
/// `1f 8b` arrives as `1f U+FFFD`, the archive will not unpack, and nothing
/// says why. So bytes are only ever handed over as text when they are text —
/// a textual content type (or none) *and* valid UTF-8 — and otherwise as
/// base64, which is exact. An agent that asked for base64 gets it regardless.
fn encode_response(
    content_type: Option<&str>,
    bytes: Vec<u8>,
    truncated: bool,
    force_base64: bool,
) -> Body {
    use base64::Engine;
    let base64 =
        |bytes: &[u8]| Body::Base64(base64::engine::general_purpose::STANDARD.encode(bytes));

    if force_base64 || !content_type.is_none_or(is_textual) {
        return base64(&bytes);
    }
    match String::from_utf8(bytes) {
        Ok(text) => Body::Text(text),
        Err(error) => {
            let utf8 = error.utf8_error();
            // The cap can land in the middle of a multi-byte character. That
            // is a cut, not binary: keep the text and drop the partial
            // character, which was never going to arrive whole anyway.
            if truncated && utf8.error_len().is_none() {
                let mut bytes = error.into_bytes();
                bytes.truncate(utf8.valid_up_to());
                return Body::Text(String::from_utf8(bytes).unwrap_or_default());
            }
            base64(error.as_bytes())
        }
    }
}

/// Whether a content type names text. A charset parameter settles it; past
/// that, `text/*` and the structured-text formats APIs actually answer in.
fn is_textual(content_type: &str) -> bool {
    let mut parts = content_type.split(';');
    let essence = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
    if parts.any(|parameter| {
        parameter
            .trim()
            .to_ascii_lowercase()
            .starts_with("charset=")
    }) {
        return true;
    }
    let Some((kind, subtype)) = essence.split_once('/') else {
        return false;
    };
    kind == "text"
        || ["+json", "+xml", "+yaml"]
            .iter()
            .any(|suffix| subtype.ends_with(suffix))
        || matches!(
            subtype,
            "json"
                | "xml"
                | "yaml"
                | "x-yaml"
                | "x-ndjson"
                | "ndjson"
                | "javascript"
                | "ecmascript"
                | "x-www-form-urlencoded"
                | "graphql"
                | "csv"
        )
}

fn response_result(
    upstream: &str,
    status: StatusCode,
    headers: Value,
    bytes: Vec<u8>,
    truncated: bool,
    force_base64: bool,
) -> Value {
    let content_type = headers
        .get(http::header::CONTENT_TYPE.as_str())
        .and_then(Value::as_str);
    let length = bytes.len();
    let body = encode_response(content_type, bytes, truncated, force_base64);

    let mut text = String::new();
    // A 2xx body speaks for itself. Anything else needs the status said out
    // loud, or a model reads an error document as data.
    if !status.is_success() {
        text.push_str(&format!(
            "HTTP {} from `{upstream}` — this is the upstream's own answer, not a policy \
             refusal.\n\n",
            status.as_u16()
        ));
    }
    match &body {
        _ if length == 0 => {
            text.push_str(&format!("(empty body, HTTP {})", status.as_u16()));
        }
        Body::Text(body) => text.push_str(body),
        Body::Base64(encoded) => {
            text.push_str(&format!(
                "(binary body, {length} bytes of {}, base64-encoded below and as \
                 `body_base64` — decode it before use)\n\n{encoded}",
                content_type.unwrap_or("unknown content type"),
            ));
        }
    }
    if truncated {
        text.push_str(
            "\n\n[truncated by agent-iap at the configured max_body_bytes — narrow the \
             request rather than asking again]",
        );
    }

    let mut structured = Map::new();
    structured.insert("status".into(), json!(status.as_u16()));
    structured.insert("headers".into(), headers);
    match body {
        Body::Text(body) => structured.insert("body".into(), json!(body)),
        Body::Base64(encoded) => structured.insert("body_base64".into(), json!(encoded)),
    };
    if truncated {
        structured.insert("truncated".into(), json!(true));
    }

    text_result(text, Some(Value::Object(structured)))
}

fn string_arg(arguments: &Value, key: &str) -> Option<String> {
    let value = arguments.get(key)?.as_str()?.trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// The body, as bytes plus the content type to use when the agent named none.
fn encode_body(body: Option<&Value>) -> Option<(HeaderValue, Vec<u8>)> {
    match body {
        None | Some(Value::Null) => None,
        // A string is sent verbatim. Anything else is the agent describing a
        // JSON document, which is what almost every one of these APIs wants.
        Some(Value::String(raw)) => Some((
            HeaderValue::from_static("text/plain; charset=utf-8"),
            raw.clone().into_bytes(),
        )),
        Some(value) => Some((
            HeaderValue::from_static("application/json"),
            serde_json::to_vec(value).unwrap_or_default(),
        )),
    }
}

/// The query string, from a flat object. Numbers and booleans are spelled the
/// way JSON spells them rather than refused: an agent writing `{"limit": 10}`
/// means the same thing as `{"limit": "10"}` and should not have to know.
fn encode_query(query: Option<&Value>) -> Result<Option<String>, String> {
    let Some(query) = query else {
        return Ok(None);
    };
    if query.is_null() {
        return Ok(None);
    }
    if let Some(raw) = query.as_str() {
        return Ok(Some(raw.trim_start_matches('?').to_string()));
    }
    let Some(object) = query.as_object() else {
        return Err("`query` must be an object of parameters, or a query string".into());
    };
    if object.is_empty() {
        return Ok(None);
    }

    let mut encoded = form_urlencoded::Serializer::new(String::new());
    for (key, value) in object {
        let rendered = match value {
            Value::String(raw) => raw.clone(),
            Value::Null => String::new(),
            Value::Array(_) | Value::Object(_) => {
                return Err(format!(
                    "`query.{key}` must be a string, number or boolean — nest nothing here"
                ))
            }
            other => other.to_string(),
        };
        encoded.append_pair(key, &rendered);
    }
    Ok(Some(encoded.finish()))
}

/// Headers the agent asked for, minus the ones it does not get to set, plus the
/// upstream's own. Same exclusions as the proxy: a credential header an agent
/// supplies would otherwise ride alongside the one the proxy attaches.
fn supplied_headers(
    supplied: Option<&Value>,
    upstream: &crate::config::UpstreamConfig,
) -> HeaderMap {
    let mut headers = HeaderMap::new();

    if let Some(object) = supplied.and_then(Value::as_object) {
        for (key, value) in object {
            let lower = key.to_ascii_lowercase();
            if crate::proxy::HOP_BY_HOP.contains(&lower.as_str())
                || crate::proxy::IAP_HEADERS.contains(&lower.as_str())
                || lower == "content-length"
            {
                continue;
            }
            let Some(value) = value.as_str() else {
                continue;
            };
            if let (Ok(name), Ok(value)) = (key.parse::<HeaderName>(), value.parse()) {
                headers.insert(name, value);
            }
        }
    }

    let announced = crate::proxy::forwarded_user_agent(headers.get(http::header::USER_AGENT));
    headers.insert(http::header::USER_AGENT, announced);

    for (name, value) in &upstream.headers {
        if let (Ok(name), Ok(value)) = (name.parse::<HeaderName>(), value.parse()) {
            headers.insert(name, value);
        }
    }
    headers
}

fn readable_headers(headers: &HeaderMap) -> Value {
    let mut map = Map::new();
    for (name, value) in headers {
        if let Ok(value) = value.to_str() {
            map.insert(name.as_str().to_string(), json!(value));
        }
    }
    Value::Object(map)
}

/// Buffer the response, stopping at the cap.
///
/// The proxy streams its responses straight through and never holds one in
/// memory. A JSON-RPC result cannot be streamed, so the gateway has to buffer —
/// which makes the cap load-bearing rather than advisory, and makes an
/// unbounded upstream a memory problem instead of a slow one.
async fn read_capped(
    mut response: reqwest::Response,
    cap: usize,
) -> Result<(Vec<u8>, bool), String> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "the upstream response could not be read".to_string())?
    {
        let room = cap.saturating_sub(bytes.len());
        if room == 0 {
            return Ok((bytes, true));
        }
        if chunk.len() > room {
            bytes.extend_from_slice(&chunk[..room]);
            return Ok((bytes, true));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((bytes, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_json_body_goes_out_as_json_and_a_string_goes_out_verbatim() {
        let (content_type, bytes) = encode_body(Some(&json!({ "model": "x" }))).unwrap();
        assert_eq!(content_type, "application/json");
        assert_eq!(bytes, br#"{"model":"x"}"#.to_vec());

        let (content_type, bytes) = encode_body(Some(&json!("raw text"))).unwrap();
        assert_eq!(content_type, "text/plain; charset=utf-8");
        assert_eq!(bytes, b"raw text".to_vec());

        assert!(encode_body(None).is_none());
        assert!(encode_body(Some(&Value::Null)).is_none());
    }

    #[test]
    fn query_parameters_are_encoded_whatever_scalar_they_arrive_as() {
        let query = encode_query(Some(&json!({ "q": "a b", "limit": 10, "all": true })))
            .unwrap()
            .unwrap();
        assert!(query.contains("q=a+b"), "{query}");
        assert!(query.contains("limit=10"), "{query}");
        assert!(query.contains("all=true"), "{query}");

        // A ready-made query string is taken as given, `?` or not.
        assert_eq!(
            encode_query(Some(&json!("?a=1"))).unwrap().as_deref(),
            Some("a=1")
        );
        assert_eq!(encode_query(Some(&json!({}))).unwrap(), None);
        assert_eq!(encode_query(None).unwrap(), None);
    }

    #[test]
    fn a_nested_query_value_is_refused_by_name() {
        let error = encode_query(Some(&json!({ "filter": { "nested": 1 } }))).unwrap_err();
        assert!(error.contains("`query.filter`"), "{error}");
    }

    #[test]
    fn an_agent_cannot_set_a_credential_header_through_the_tool() {
        let upstream: crate::config::UpstreamConfig = toml::from_str(
            r#"
name = "echo"
base_url = "https://example.invalid"
"#,
        )
        .unwrap();

        let headers = supplied_headers(
            Some(&json!({
                "authorization": "Bearer stolen",
                "x-iap-token": "iap_someone_elses",
                "anthropic-version": "2023-06-01",
            })),
            &upstream,
        );

        assert!(headers.get("authorization").is_none());
        assert!(headers.get("x-iap-token").is_none());
        assert_eq!(headers.get("anthropic-version").unwrap(), "2023-06-01");
    }

    #[test]
    fn an_upstreams_own_headers_win_over_the_agents() {
        let upstream: crate::config::UpstreamConfig = toml::from_str(
            r#"
name = "echo"
base_url = "https://example.invalid"
headers = { "x-tenant" = "acme" }
"#,
        )
        .unwrap();

        let headers = supplied_headers(Some(&json!({ "x-tenant": "not-acme" })), &upstream);
        assert_eq!(headers.get("x-tenant").unwrap(), "acme");
    }

    #[test]
    fn a_tool_call_announces_the_gateway_to_the_upstream() {
        let upstream: crate::config::UpstreamConfig = toml::from_str(
            r#"
name = "echo"
base_url = "https://example.invalid"
"#,
        )
        .unwrap();

        // Nothing supplied: the upstream hears the gateway.
        let headers = supplied_headers(None, &upstream);
        assert_eq!(headers.get("user-agent").unwrap(), crate::USER_AGENT);

        // Supplied: the upstream hears both, in that order.
        let headers = supplied_headers(Some(&json!({ "user-agent": "some-agent/2" })), &upstream);
        assert_eq!(
            headers.get("user-agent").unwrap(),
            format!("some-agent/2 {}", crate::USER_AGENT).as_str()
        );
    }

    #[test]
    fn a_non_success_status_is_labelled_as_the_upstreams_answer_not_a_refusal() {
        let result = response_result(
            "echo",
            StatusCode::NOT_FOUND,
            json!({}),
            b"{\"error\":\"nope\"}".to_vec(),
            false,
            false,
        );
        let text = result["content"][0]["text"].as_str().unwrap();

        assert!(text.contains("HTTP 404"), "{text}");
        assert!(text.contains("not a policy refusal"), "{text}");
        assert_eq!(result["structuredContent"]["status"], 404);
        // Not a tool error: the upstream answered, and the answer is the result.
        assert!(result.get("isError").is_none());
    }

    #[test]
    fn a_truncated_body_says_so_in_both_the_text_and_the_structure() {
        let result = response_result(
            "echo",
            StatusCode::OK,
            json!({}),
            b"abc".to_vec(),
            true,
            false,
        );
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("truncated"), "{text}");
        assert_eq!(result["structuredContent"]["truncated"], true);
    }

    fn decoded(result: &Value) -> Vec<u8> {
        use base64::Engine;
        let encoded = result["structuredContent"]["body_base64"].as_str().unwrap();
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap()
    }

    #[test]
    fn a_binary_body_arrives_as_base64_byte_for_byte() {
        // The start of a gzip stream: `8b` is not UTF-8, and lossy decoding
        // used to turn it into U+FFFD.
        let gzip = vec![0x1f, 0x8b, 0x08, 0x00, 0xff, 0x00];
        let result = response_result(
            "echo",
            StatusCode::OK,
            json!({ "content-type": "application/x-gzip" }),
            gzip.clone(),
            false,
            false,
        );

        assert_eq!(decoded(&result), gzip);
        assert!(result["structuredContent"].get("body").is_none());
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("body_base64"), "{text}");
    }

    #[test]
    fn bytes_that_are_not_utf8_are_base64_whatever_the_content_type_claims() {
        let result = response_result(
            "echo",
            StatusCode::OK,
            json!({ "content-type": "text/plain" }),
            vec![b'a', 0xff, b'b'],
            false,
            false,
        );
        assert_eq!(decoded(&result), vec![b'a', 0xff, b'b']);
    }

    #[test]
    fn a_non_textual_content_type_is_base64_even_when_the_bytes_would_decode() {
        let result = response_result(
            "echo",
            StatusCode::OK,
            json!({ "content-type": "application/octet-stream" }),
            b"plain ascii".to_vec(),
            false,
            false,
        );
        assert_eq!(decoded(&result), b"plain ascii".to_vec());
    }

    #[test]
    fn text_still_arrives_as_body() {
        for content_type in [
            None,
            Some("application/json"),
            Some("application/vnd.github+json"),
            Some("text/html; charset=utf-8"),
            Some("application/x-custom; charset=utf-8"),
        ] {
            let headers = match content_type {
                Some(value) => json!({ "content-type": value }),
                None => json!({}),
            };
            let result = response_result(
                "echo",
                StatusCode::OK,
                headers,
                "{\"name\":\"café\"}".as_bytes().to_vec(),
                false,
                false,
            );
            assert_eq!(
                result["structuredContent"]["body"], "{\"name\":\"café\"}",
                "{content_type:?}"
            );
            assert!(result["structuredContent"].get("body_base64").is_none());
        }
    }

    #[test]
    fn base64_can_be_asked_for_outright() {
        let result = response_result(
            "echo",
            StatusCode::OK,
            json!({ "content-type": "application/json" }),
            b"{}".to_vec(),
            false,
            true,
        );
        assert_eq!(decoded(&result), b"{}".to_vec());
        assert!(result["structuredContent"].get("body").is_none());
    }

    #[test]
    fn a_cap_that_splits_a_character_leaves_text_as_text() {
        // `é` is two bytes; the cap kept only the first.
        let mut bytes = "caf".as_bytes().to_vec();
        bytes.push(0xc3);
        let result = response_result(
            "echo",
            StatusCode::OK,
            json!({ "content-type": "text/plain" }),
            bytes,
            true,
            false,
        );
        assert_eq!(result["structuredContent"]["body"], "caf");
        assert_eq!(result["structuredContent"]["truncated"], true);
    }

    #[test]
    fn a_truncated_binary_body_is_the_capped_bytes_exactly() {
        let result = response_result(
            "echo",
            StatusCode::OK,
            json!({ "content-type": "image/png" }),
            vec![0x89, b'P', b'N', b'G'],
            true,
            false,
        );
        assert_eq!(decoded(&result), vec![0x89, b'P', b'N', b'G']);
        assert_eq!(result["structuredContent"]["truncated"], true);
    }
}
