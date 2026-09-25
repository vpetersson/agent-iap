# Deployment

Everything so far has been the proxy in a terminal, reading the policy file in
your own config directory. As a daemon it is the process on the box that holds
every upstream credential the policy file names, so where its files live and who
can read them *is* the security boundary.

| Path | What | Mode |
| --- | --- | --- |
| `/usr/local/bin/agent-iap` | The binary. | `0755 root:root` |
| `/etc/agent-iap/iap.toml` | Policy: the ACL, the agents' token hashes, the credential *references*. | `0600 agent-iap:agent-iap` |
| `/etc/agent-iap/env` | Values for the `env:` references, and `OP_SERVICE_ACCOUNT_TOKEN` if you use `op://`. | `0600 agent-iap:agent-iap` |
| `/var/lib/agent-iap/iap-audit.jsonl` | The hash-chained audit log. | `0600 agent-iap:agent-iap` |
| `/var/lib/agent-iap/admin-token` | Control-plane bearer token, written at every start. | `0600 agent-iap:agent-iap` |

The policy file holds no credential — agent tokens are stored as sha256, an
upstream's key is a reference to somewhere else. It still wants `0600`:
readable it is a map of every credential worth going after, and writable it
*is* the ACL. The audit log's claim is weaker than its mode suggests — chaining
detects tampering, it does not prevent it ([§ Security
model](../README.md#security-model)). Ship the lines somewhere append-only if
that matters.

## systemd

[`packaging/agent-iap.service`](../packaging/agent-iap.service) runs it as its own user
under a tight sandbox — `ProtectSystem=strict`, `ReadWritePaths` limited to the
state directory, `UMask=0077` so everything it writes is owner-only without
anyone remembering to say so:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin agent-iap
sudo install -d -m0755 /etc/agent-iap

# Build the policy with the same commands as § Quickstart, then hand it over.
sudo agent-iap init --config /etc/agent-iap/iap.toml
# `init` writes whatever the umask allows — usually group- and world-readable.
# The mode is the step, not a flourish.
sudo chown agent-iap:agent-iap /etc/agent-iap/iap.toml
sudo chmod 0600 /etc/agent-iap/iap.toml

sudo install -m0644 packaging/agent-iap.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now agent-iap
```

`/var/lib/agent-iap` is created `0700` by `StateDirectory=` on first start — the
audit log and the `admin-token` land there, and it is the only path the service
can write to. The unit says so with `IAP_STATE_DIR` rather than leaning on a
working directory: the service user has no home, and `ProtectHome=yes` would put
one out of reach anyway. `IAP_CONFIG` does the same for the policy file, so
`agent-iap list`, `agent-iap audit verify` and the rest read the daemon's policy
and log with no `--config`.

Two things worth knowing before the first restart:

- **`ExecStartPre=agent-iap check` resolves every credential reference.** A
  reference that no longer resolves fails startup with the name of the one that
  broke, rather than at some later call. It also means a 1Password outage stops
  a restart — which is the honest behaviour, since the proxy could not inject
  anything anyway.
- **`admin-token` is regenerated at every start.** Anything holding the old one
  — a script polling `/status`, a detached MCP bridge — re-reads the file after
  a restart. The audit log is not regenerated: the hash chain continues across
  restarts, and `agent-iap audit verify` spans them.

There is no console: `--no-tui` logs to the journal and an `ask` is answered
over the control plane ([§ Control plane](#control-plane)) or denied. The
daemon watches its own policy file, answers `SIGHUP`, and takes a `POST
/reload` either way, so `systemctl reload` — or a deploy that only has the
control plane to talk to — is a reload and not a restart ([§
Reloading](policy-file.md#reloading)). A rule set that is entirely
`allow`/`deny` needs no answerer; one that uses `ask` needs something watching,
or those calls fail closed.

## Container

The image is the same binary on `distroless/static` — no shell, no package
manager, running as uid `65532`. Two mounts and one override:

```bash
# The uid inside the image owns neither mount by default, and a 0600 policy
# file it cannot read is a `Permission denied` at startup, not a warning.
sudo chown 65532:65532 /etc/agent-iap/iap.toml /var/lib/agent-iap

docker run -d --name agent-iap \
    -e IAP_LISTEN=0.0.0.0:8080 \
    --env-file /etc/agent-iap/env \
    -v /etc/agent-iap:/etc/agent-iap:ro \
    -v /var/lib/agent-iap:/var/lib/agent-iap \
    -p 8080:8080 \
    ghcr.io/vpetersson/agent-iap:2026.9.1
```

`IAP_LISTEN` is the override that matters: the policy file's `127.0.0.1:8080` is
loopback *inside* the container, which nothing can reach. Leave `admin_listen`
on loopback — it is the control plane, and publishing it puts a bearer token's
worth of authority on the network.

If the host already runs it under systemd and you would rather keep one owner
for those files, `--user "$(id -u agent-iap):$(id -g agent-iap)"` runs the image as
that user instead; the binary needs no uid in particular.

What the image deliberately cannot do, both following from the distroless base:

- **`op://` references.** They shell out to the 1Password CLI, which is not in
  here and has no shell to run in. Use `env:` or `file:` references, or build a
  layer on a base that carries `op`.
- **stdio MCP servers.** A `command = [...]` server is a child process, and
there is no `npx` or `uvx` to be one. Front those over HTTP instead — which
[§ Security model](../README.md#security-model) recommends anyway, the stdio
bridge not being a process boundary.

## Control plane

`admin_listen` (loopback, bearer token written to `admin-token` beside the
audit log — see [§ Where things live](policy-file.md#where-things-live))
exists for the console and the MCP bridge, and is useful directly. With
`[server.tls]` set it is on `https://` too — see [§ TLS](tls.md) — and these
become `curl --cacert`:

```bash
TOKEN=$(cat ~/.local/state/agent-iap/admin-token)
curl -s -H "Authorization: Bearer $TOKEN" localhost:8081/status
curl -s -H "Authorization: Bearer $TOKEN" localhost:8081/pending
curl -s -H "Authorization: Bearer $TOKEN" localhost:8081/decide \
     -d '{"verdict":"allow","remember":true}' -H 'content-type: application/json'
curl -s -X POST -H "Authorization: Bearer $TOKEN" localhost:8081/reload
```

`POST /reload` re-reads the policy file — the scriptable half of
[§ Reloading](policy-file.md#reloading). It answers `200` with the policy now
in force:

```json
{"ok":true,"serving":{"agents":4,"upstreams":3,"mcp_servers":1,"acl_rules":11,"acl_default":"deny"}}
```

and `422` with the reason, and the policy *still* in force, when the file on
disk cannot be served. Nothing is swapped in that case, so a deploy script can
treat a non-2xx as "my edit did not land" and leave a working proxy alone.

Polling `/pending` counts as watching the queue for 30 seconds, so `curl` alone
can answer an `ask` without the TUI. With nobody watching, `ask` denies
immediately rather than parking the request for the full timeout.

`/pending` lists questions rather than requests — see
[§ The queue holds questions, not requests](console.md#the-queue-holds-questions-not-requests)
. Each entry carries `waiting`, the number of identical calls one `/decide` on
it releases, and `newest_ms` alongside `waited_ms` for how long ago the most
recent of them arrived. `/status` reports the same pair as `pending`
(questions) and `waiting` (requests held up by them).
