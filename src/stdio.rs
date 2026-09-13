//! The gateway over stdio.
//!
//! The gateway itself lives in the daemon, where the policy, the credentials
//! and the audit log are, and speaks MCP over HTTP at `/_iap/mcp`. An agent
//! whose client does streamable HTTP should point at that directly — this
//! process is one hop it does not need.
//!
//! Plenty of clients only spawn a command and talk to its stdin, though, and
//! this is that command. It is deliberately thin: a frame in, the same frame
//! POSTed to the daemon, the answer back out. It makes no decisions, caches
//! nothing and holds no credential but the agent's own token, so a client that
//! can only do stdio loses none of the policy and gains no new trust.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub struct StdioOptions {
    pub agent_token: String,
    /// Base address of the running proxy's data plane.
    pub proxy_url: String,
}

pub async fn run(config: crate::config::Config, options: StdioOptions) -> Result<()> {
    let resolver = crate::secrets::SecretResolver::new(config.server.op_binary.clone());
    // The data plane may serve a certificate no public root signs, which is the
    // normal case for a loopback listener. This process reads the same policy
    // file as the daemon, so it can trust exactly that certificate rather than
    // the alternative, which is turning verification off.
    let http = crate::tls::control_plane_client(config.server.tls.as_ref(), &resolver)
        .context("building the client for the proxy's data plane")?;

    let endpoint = format!(
        "{}{}",
        options.proxy_url.trim_end_matches('/'),
        crate::gateway::MOUNT
    );

    // Fail here rather than at the first tool call: a client that spawns this
    // and gets a server which answers `initialize` and then nothing useful is
    // much harder to diagnose than one that never came up.
    probe(&http, &endpoint, &options.agent_token).await?;

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            tracing::warn!("dropping a non-JSON line from the agent");
            continue;
        };
        // Kept so a transport-level failure can still be answered in the client's
        // own terms. A client waiting on id 7 needs a frame carrying id 7, not an
        // HTTP status it never sees.
        let id = request.get("id").cloned().unwrap_or(Value::Null);

        let response = http
            .post(&endpoint)
            .bearer_auth(&options.agent_token)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(line)
            .send()
            .await
            .context("the mcp-iap daemon did not answer")?;

        // 202 is the daemon acknowledging a notification. Nothing to relay, and
        // inventing a frame for it would desynchronise the ids.
        if response.status() == reqwest::StatusCode::ACCEPTED {
            continue;
        }

        let status = response.status();
        let body = response
            .text()
            .await
            .context("reading the daemon's answer")?;

        // The gateway answers a JSON-RPC frame for anything it understood, at
        // whatever status. What arrives here with a non-2xx and no frame is the
        // daemon refusing the *request* — a revoked token, most likely — and
        // relaying its error document as if it were a response would leave the
        // client parsing a body with no `id` in it and waiting forever.
        let frame = match serde_json::from_str::<Value>(&body) {
            Ok(frame) if frame.get("result").is_some() || frame.get("error").is_some() => frame,
            _ if id.is_null() => continue,
            parsed => {
                let detail = parsed
                    .ok()
                    .and_then(|body| {
                        body.get("error")
                            .and_then(|error| error.get("message"))
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
                    .unwrap_or_else(|| format!("the daemon answered {status}"));
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32603, "message": format!("mcp-iap: {detail}") },
                })
            }
        };

        stdout.write_all(format!("{frame}\n").as_bytes()).await?;
        stdout.flush().await?;
    }

    Ok(())
}

/// Prove the daemon is up and this token is one it knows, before accepting a
/// single frame from the agent.
async fn probe(http: &reqwest::Client, endpoint: &str, token: &str) -> Result<()> {
    let response = http
        .post(endpoint)
        .bearer_auth(token)
        .json(&serde_json::json!({ "jsonrpc": "2.0", "id": "probe", "method": "ping" }))
        .send()
        .await
        .with_context(|| {
            format!("cannot reach the mcp-iap daemon at {endpoint} — start `mcp-iap run` first")
        })?;

    match response.status() {
        status if status.is_success() => Ok(()),
        reqwest::StatusCode::UNAUTHORIZED => bail!("the agent token was not recognised"),
        reqwest::StatusCode::NOT_FOUND => bail!(
            "the proxy at {endpoint} has no MCP gateway — it is an older mcp-iap than this one"
        ),
        status => bail!("the mcp-iap daemon answered the gateway probe with {status}"),
    }
}
