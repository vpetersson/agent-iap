# The audit log

One JSON object per line, hash-chained: each entry commits to the one before it.

```json
{"seq":1,"id":"…","ts":"2026-09-09T06:01:18.484Z","kind":"http","event":"request",
 "agent":"demo-agent","agent_name":"Demo Agent","workload":"3f7c9a21/0",
 "target":"demo-api","method":"GET",
 "path":"/v1/models","decision":"allow","rule":"api-reads","status":200,
 "duration_ms":0,"request_bytes":0,"client":"127.0.0.1:41876",
 "prev_hash":"…","hash":"…"}
```

`workload` is the token the call was made under — `lineage/generation`, matching
the `token_mint` record that lists the scope it was granted. It is absent for a
call made with a bare agent token, which is how a log shows how much of its
traffic still runs on a standing grant. Minting, renewing and revoking are
`kind: "identity"` records of their own.

The line to alert on is `rule: "<workload-token-replayed>"` — a token presented
after it had been renewed away from. It names the agent and the lineage that was
revoked because of it, and it means either a workload racing its own renewal or
a second holder of a token that should have had exactly one.

```bash
agent-iap audit tail -n 20
agent-iap audit verify
# 9 entries verified — the hash chain is intact.

# Both read `audit.path` from the policy file. Name a file to read another one —
# a rotated log, or one copied off the host.
agent-iap audit verify ~/.local/state/agent-iap/iap-audit.jsonl.1
```

`tail -f` follows the log the way the name implies: the last `-n` entries, then
every entry as the proxy writes it, until Ctrl-C. Filters apply to the stream as
well as to the history, so `-f --agent ci-runner` is one terminal watching one
agent work.

```bash
agent-iap audit tail -f
agent-iap audit tail -f -n 0 --target github
```

A follower may be started before the proxy is — it waits for the log to appear
rather than refusing — and it survives rotation: when the file it is reading is
renamed away or truncated, it says so and picks up the new one.

Editing or removing a line is detected by `verify`. The chain resumes across
restarts, so one file covers the life of the deployment.

If a record cannot be written, the chain does not advance past it — a lost entry
leaves the log verifiable rather than making everything after it read as
tampered. And a request the proxy permitted but could not record does not reach
the agent: an unrecorded call the agent can read from is the one outcome worth
refusing outright, so it gets a 502 instead.

Bodies are **not** logged by default (`audit.log_bodies`), nor are MCP `params`
(`audit.log_mcp_params`) — both carry prompts and customer data. Credential
headers are replaced with `***` before anything is written; the tests assert that
neither the upstream credential nor the agent token ever reaches the log.
