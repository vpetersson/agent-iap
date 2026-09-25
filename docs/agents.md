# Agents

One proxy, many agents: what each of them can address, what a single run is
allowed to do, and what an agent handed nothing but a token can find out.

## How long a grant lasts

Policy is not a clock: a rule is true until you change it, an `ask` is answered
per call, and "remember for this session" dies with the process. Two things do
expire, and between them they are what "give it Google Analytics for the next
hour" means.

The agent's own credential expires under
[§ Workload identity](#workload-identity) — it trades its standing token for
one scoped to the work in front of it, valid for an hour at most, so the copy
left in a context window buys nothing once it lapses. The default mode is
`optional`; `required` is what turns that bound into one you imposed rather
than one the agent opted into.

The credentials the proxy mints *upstream* expire too
(`oauth2_client_credentials`, `service_account_jwt`), on the provider's clock.
The agent never sees those at all.

## What is exposed

`check` validates; `list` inventories. At twenty service accounts and MCP
servers on one proxy, "what does this front, and with whose credential?" is its
own question:

```console
$ agent-iap list upstreams
NAME       BASE URL                        AUTH                 CREDENTIAL
anthropic  https://api.anthropic.com       header x-api-key     op://Private/Anthropic API/credential
gcs        https://storage.googleapis.com  service_account_jwt  op://Private/GCP Service Account/credential
github     https://api.github.com          bearer               op://Private/GitHub/token
```

`agent-iap list` alone prints every section; `agents`, `upstreams`, `mcp`, `acl`
and `credentials` narrow it to one. ACL rules keep their position in the file,
because first match wins and that order *is* the policy. `credentials` is the
inventory of references — every credential the proxy holds, and which field of
which service reads it, with never a value:

```console
$ agent-iap list credentials
HOLDER             FIELD            REFERENCE
server             admin_token      file:/var/lib/agent-iap/admin-token
upstream anthropic auth.secret      op://Private/Anthropic API/credential
upstream gcs       auth.key_file    op://Private/GCP Service Account/credential
mcp notes          env.NOTES_TOKEN  op://Private/Notes/token
```

The question that actually matters once there is more than one agent is what a
single one of them can reach — `targets` and the ACL intersected:

```console
$ agent-iap list --agent ci-bot
Everything `ci-bot` can address. Rules are in match order — first match wins.

UPSTREAMS
NAME    BASE URL                AUTH    CREDENTIAL                 RULES
github  https://api.github.com  bearer  op://Private/GitHub/token  2
stripe  https://api.stripe.com  bearer  op://Private/Stripe/key    none
```

`RULES` counts the rules that could ever reach that target as this agent, so
`none` is the interesting value: `stripe` is in the agent's `targets`, which
reads like a grant, but no rule names it — every call falls through to the
default and is denied.

`--output json` gives the same inventory to something other than a human. All of
it reads only the policy file: no running daemon, no call to 1Password, and
credential *references* rather than resolved secrets. A `literal:` reference is
the credential rather than a pointer to one, so it prints as `literal:***`.

## Multiple agents

One proxy fronts many agents: they are the tenants, the upstream credential is
the shared thing they are kept away from, and the policy file is where the
difference between them is written.

```toml
[[agents]]
id = "claude-code"
token_sha256 = "…"

[[agents]]
id = "ci-runner"
token_sha256 = "…"
targets = ["github"]                # hard scope, checked before the ACL

# No `agent` key: this rule is every agent, including ones added later.
[[acl]]
target = "anthropic"
methods = ["POST"]
paths = ["/v1/messages"]
action = "allow"

# `agent` is a glob, so one rule can cover a fleet.
[[acl]]
agent = "ci-*"
target = "github"
methods = ["GET"]
paths = ["/repos/**"]
action = "allow"

# A grant with a deadline in it. Past `expires` this rule matches nothing and
# whatever is behind it decides instead — so the access ends on the clock
# rather than on somebody remembering to take it away.
[[acl]]
agent = "claude-code"
target = "github"
methods = ["POST"]
paths = ["/repos/acme/**"]
action = "allow"
expires = "2026-09-15T09:00:00Z"
```

Each agent has its own token; the file holds only hashes, and two agents sharing
one is a startup error rather than a puzzle later. Every audit record names the
agent that caused it, so one interleaved log still answers per-agent questions:

```bash
agent-iap audit tail --agent ci-runner
agent-iap audit tail --agent ci-runner --target github

# `-f` follows, and the filter applies to the live stream too — one terminal
# per agent while a run is in flight.
agent-iap audit tail -f --agent ci-runner
```

Approvals are per agent too. A standing answer — "until quit" in the dialogue —
always names the agent that prompted it, however wide the rest of the scope is
set, so releasing a call for one agent never releases it for another.

Agents off this host need `[server.tls]`; without it their tokens are on the
wire in cleartext, and this is the process holding every upstream credential.

None of it needs a restart. Enrolling an agent, revoking one, rotating a leaked
token, adding an upstream, renewing a certificate — all of it reloads into the
running proxy, immediately from the console and within a second from a shell
([§ Reloading](policy-file.md#reloading)). Without a console attached nothing
is reading the file and a restart is what applies the change, which is what
every `rm` and `rotate` says on the way out.

What this does **not** do yet is **per-agent limits**: no rate limit, no
concurrency cap, no spend budget. The agents share one upstream credential and
therefore one quota and one bill, and one runaway agent is felt by all of them —
the audit log will tell you which one, afterwards.

## Workload identity

An agent token answers *who is calling*. It is long-lived, the same credential
for every call that agent will ever make, and says nothing about what any
particular piece of work needs — so a copy lifted out of a context window or a
crash dump is the agent's whole standing grant until somebody rotates it.

A **workload token** answers the other half: *what is this run allowed to do,
and until when*. The agent presents its agent token once, says which requests it
needs, and gets back a JWT this proxy signed that expires on its own and covers
nothing else.

```bash
# Exchange the standing credential for an hour of exactly what this run needs.
curl -s localhost:8080/_iap/token \
  -H "Authorization: Bearer $IAP_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
        "workload": "nightly-summariser",
        "scope": [{ "target": "anthropic", "methods": ["POST"], "paths": ["/v1/messages"] }]
      }'
{
  "token": "eyJhbGciOiJFZERTQSIs…",
  "token_type": "Bearer",
  "expires_in": 3600,
  "lineage": "3f7c…", "generation": 0,
  "scope": [ … ]
}

# …and use it exactly where the agent token used to go.
curl -s localhost:8080/anthropic/v1/messages -H "Authorization: Bearer $WORKLOAD_TOKEN" …
```

Turn it on in the policy file:

```toml
[server.workload_identity]
mode = "required"      # off | optional | required
lifetime_secs = 3600   # ceiling as well as default; 60s–3600s
```

`optional` is the default and accepts either credential, so a fleet migrates
without a flag day — the audit log's `workload` field is empty for the calls
still running on a standing grant, which is how you tell when the migration is
finished. `required` is the posture worth landing on: the data plane takes
workload tokens only, and the agent token becomes a bootstrap credential whose
single remaining power is asking for one.

### The three properties

- **A scope can only narrow.** The ACL still runs on every request. The token
  says what the workload asked for; policy says what it may have; a call needs
  both. A rule you delete stops working immediately rather than at expiry. Which
  is why minting is not an approval step: asking for a wide scope gets a wide
  token and exactly the same set of allowed calls.
- **Renewal rotates.** `POST /_iap/token/renew` issues the next token in the
  lineage and retires the one that asked, in the same step. There is never a
  moment when two tokens in a lineage are live. A renewal may re-scope — that is
  the point of renewing rather than holding — and the new scope goes through the
  same checks the mint did, so an agent that lost a target in the meantime does
  not keep it by renewing.
- **Using a superseded token kills the lineage.** Either the workload raced its
  own renewal or somebody else is holding a copy, and from the proxy those are
  the same event. Both end the same way: the lineage is revoked, the log says
  `token_replayed`, and the agent has to come back to the mint. Renew *before*
  the token is on the wire in parallel, and this never fires.

`POST /_iap/token/revoke` ends a lineage early — the honest end of a finished
workload — and `GET /_iap/token` says what the token in your hand covers. All
four endpoints are on the control plane too, without the `_iap` prefix, because
the MCP bridge only ever sees that listener.

The signing key is generated per process and never leaves it; nothing is
persisted. A restart invalidates every outstanding token, which for a credential
measured in minutes is the right failure mode — the agents re-mint and carry on.

### What it costs

Two extra round trips an hour per workload, and an agent that has to handle a
401 by minting again. In exchange, the credential sitting in an agent's memory
for the next hour is worth an hour of one upstream's `/v1/messages` rather than
everything that agent is allowed to do, forever.

The MCP bridge does this on its own: when the daemon reports `workload_identity`
on `/health`, `agent-iap mcp --server github` exchanges its agent token for one
scoped to `github` alone, renews it two minutes before it lapses, and keeps the
agent token for nothing but asking again.

## Zero state

An agent handed a token and an address has everything it needs and no way to
find out what to do with it. The other two surfaces assume the explaining
already happened — an SDK reaches `/<upstream>` because a human set a base URL,
the gateway ([§ MCP](mcp.md)) because a human wrote it into a client config.

So the root of the proxy answers that. `GET /` with the token returns a skill
document generated from the running policy, for the agent that asked:

```console
$ curl -sH "Authorization: Bearer $IAP_TOKEN" http://127.0.0.1:8080/
# agent-iap

You have reached agent-iap 2026.9.0 at `http://127.0.0.1:8080`, as `claude`
(Claude Code).

This is an identity-aware proxy. It holds the credentials for the APIs below and
attaches them on the way out, after checking a policy and writing an audit
record. You are not holding any of those credentials, you do not need one, and
you should not go looking for one or ask a person for one …

## The short way: add this as an MCP server
…
## What you can reach

### `anthropic`

- proxied at `http://127.0.0.1:8080/anthropic/<path>`
- the API itself is `https://api.anthropic.com`
- the proxy attaches the credential — `header x-api-key` — and drops any you send

#### Rules that apply to you, in order

- **allow** `read-models` — GET `/v1/models`, `/v1/models/*`
- **ask a human** `confirm-sends` — POST `/v1/messages`
```

It offers MCP first, because for an agent that can add an MCP server that is the
shorter road: the catalog, the skills and the call itself arrive over one
connection, already structured, and the snippet is the address the agent
actually reached, ready to paste. The HTTP form is underneath for everything
else.

A client that turns out to *be* an MCP client is not handed prose at all. The
common misconfiguration — an MCP server entry pointing at the base URL rather
than at `/_iap/mcp` — is answered with a 307, which keeps the method and the
body, so the handshake frame it is already holding arrives at the gateway and
the connection simply works. A `GET /` asking for `text/event-stream` goes the
same way.

| | |
| --- | --- |
| `GET /` | the document — markdown, or `?format=json` for the same facts structured |
| `GET /.well-known/agent-iap` | the same, JSON by default |
| `GET /_iap/skill` | the document plus every skill behind it, as one file to save |
| `GET /_iap/skill/<name>` | one of them |
| `POST /` | 307 to `/_iap/mcp` |

Nothing here discloses more than the agent could learn by making one refused
call. The document is built per agent, so an agent granted a target no rule
names is told it can reach nothing. Credential *schemes* are named; credentials
are not. Without a token the root says what this is and how to authenticate, and
nothing about the policy.

Reading it is an audit event. An anonymous read is not: it names no agent, no
upstream and no rule, which makes it `/_iap/health` with better prose.

The refusals follow the same rule. A request that names no upstream, or guesses
one wrong, comes back naming the upstreams that agent could have used:

```console
$ curl -sH "Authorization: Bearer $IAP_TOKEN" http://127.0.0.1:8080/gihtub/user
{"error":{"type":"unknown_upstream","message":"`gihtub` is not an upstream this
proxy fronts. Reachable from here: `anthropic`, `github`. `GET /` describes each
of them."},"proxy":"agent-iap"}
```
