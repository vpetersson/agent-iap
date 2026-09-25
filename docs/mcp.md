# MCP

Two things share the name here and point in opposite directions.

- **The gateway** makes *agent-iap itself* an MCP server. An agent gets the REST
  APIs this proxy fronts as tools, plus skills generated from the policy that is
  actually running. This is the default way to hand an agent an API.
- **The bridge** points the other way: it fronts somebody else's MCP server, the
  way an upstream fronts somebody else's REST API.

## The gateway

The HTTP proxy is the right surface for a program: point an SDK at
`http://127.0.0.1:8080/<upstream>` and it works unchanged. It is the wrong one
for an agent, which has to be told out of band that the proxy exists, what it
fronts and what it will refuse — none of which is discoverable from a base URL.
MCP is the idiom agents already discover, so the same upstreams are offered over
it:

```json
{ "mcpServers": { "iap": {
    "type": "http",
    "url": "http://127.0.0.1:8080/_iap/mcp",
    "headers": { "Authorization": "Bearer iap_..." } } } }
```

For a client that only spawns commands, `agent-iap gateway` is the same server on
stdio — a thin relay to the daemon, holding no credential but the agent's token:

```json
{ "mcpServers": { "iap": {
    "command": "agent-iap",
    "args": ["gateway", "--config", "/etc/agent-iap/iap.toml"],
    "env": { "IAP_TOKEN": "iap_..." } } } }
```

Three tools, and no new policy to write — `iap_request` is decided by the same
`kind = "http"` rules the proxy already uses, through the same function:

| Tool | What it does |
| --- | --- |
| `iap_request` | One HTTP call against a configured upstream. The proxy attaches the credential. |
| `iap_catalog` | The upstreams this agent may reach, with base URL and credential scheme. |
| `iap_skill` | One generated skill document. |

```jsonc
// tools/call → iap_request
{ "upstream": "anthropic", "method": "POST", "path": "/v1/messages",
  "query": { "limit": 10 }, "body": { "model": "…" } }
```

`path` is the path the upstream sees, never a full URL. A credential header the
agent sets is dropped rather than forwarded, so it cannot ride alongside the one
the proxy attaches. A refusal comes back as an MCP tool error — `policy_denied`,
`target_not_permitted`, `approval_denied`, `scope_exceeded` — rather than a
JSON-RPC error, because the model is the one that has to read it and pick
something else. The upstream's own `4xx` is a normal result, labelled with its
status so it does not read as a refusal.

### Skills, and why they are generated

An agent that finds a tool called `iap_request` learns nothing from the name
about which upstreams exist or which paths are allowed, and a static README
would go stale the first time a rule changed. So the gateway serves documents
built from the running policy, for the agent that asked — two agents on one
daemon are told two different things:

- The `initialize` response's `instructions` field: what this proxy is, that
  credentials are never the agent's to hold, that refusals are final and
  approvals are slow.
- `using-this-gateway` — how to call, how to read each refusal code, and what
  is recorded.
- `upstream/<name>` — base URL, the credential *scheme* the proxy attaches, and
  the rules that apply to this agent in match order.

They are readable both as MCP resources (`skill://agent-iap/…`) and through
`iap_skill`, for clients that only do tools. A skill names the scheme —
`header x-api-key` — because that is how an agent stops trying to set the header
itself. The secret behind it stays in the daemon.

### What the gateway does not do

Responses are buffered, not streamed: a JSON-RPC result cannot be a stream, so a
response is read up to `max_body_bytes` and truncation is reported in the
result. Streaming output is what the HTTP proxy is for. JSON-RPC batching is not
accepted, having been dropped from the protocol revision this implements.

## The bridge

MCP over HTTP is just HTTP — front it as an upstream. For stdio servers, the
agent runs the bridge as its MCP server:

```json
{ "mcpServers": { "github": {
    "command": "agent-iap",
    "args": ["mcp", "--config", "/etc/agent-iap/iap.toml", "--server", "github-mcp"],
    "env": { "IAP_TOKEN": "iap_..." } } } }
```

The bridge spawns the real server with the credential in *its* environment,
relays JSON-RPC, and asks the running daemon to authorize every message.
Policy and audit stay in one process, so `tools/call` shows up in the same log
and the same approval queue as an HTTP call:

```toml
# The session. `initialize` names no tool, so it matches only a rule that
# leaves `paths` unconstrained — without this one the handshake is denied and
# the agent sees a server that never starts. It goes first.
[[acl]]
name = "github-mcp-session"
kind = "mcp"
target = "github-mcp"
methods = ["initialize", "notifications/*", "ping", "tools/list"]
paths = ["**"]
action = "allow"

# Then the tools.
[[acl]]
kind = "mcp"
target = "github-mcp"
methods = ["tools/call"]
paths = ["get_*", "list_*", "search_*"]   # `paths` is the tool name here
action = "allow"
```

That first rule is the one everybody forgets, so `agent-iap check` warns when an
MCP server has rules and none of them admits `initialize` — the failure it
prevents is a `<default>` deny that names no rule to go and fix. `agent-iap
mcp-server verify` says the same thing next to a live handshake, and an MCP
`profile add --grant` writes the rule for you, in front of the tool rules.
Without `--grant` there are no rules at all, and `initialize` stops at the
console like any other uncovered call — answer it with "anything on this server"
and the session opens.

`resources/read` matches on the URI instead. A denied call gets a JSON-RPC error
(`-32001`); a denied notification is dropped. A batch is all-or-nothing, so ids
never desynchronise. If the daemon is unreachable the bridge refuses to start,
and if an authorization call fails the call is denied.
