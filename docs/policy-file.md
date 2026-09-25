# The policy file

`agent-iap init` writes one; `iap.example.toml` is the commented walk-through it
embeds under `--template full`. The shape:

```toml
[[agents]]
id = "claude-code"
name = "Claude Code"
token_sha256 = "…"                  # from `agent-iap gen-token`
targets = ["anthropic", "github"]   # hard scope, checked before the ACL. Absent
                                    # means *any* target — `agent add` will not
                                    # write that without `--any-target`

[[upstreams]]
name = "anthropic"
base_url = "https://api.anthropic.com"
auth = { type = "header", header = "x-api-key", secret = "op://Private/Anthropic/credential" }

[[acl]]
name = "anthropic-inference"        # this name appears in every audit record
agent = "claude-code"
kind = "http"                       # http | mcp | *
target = "anthropic"
methods = ["POST"]
paths = ["/v1/messages"]
action = "allow"                    # allow | deny | ask

[acl_default]
action = "deny"
```

An `[[mcp_servers]]` block has the same shape, and `agent-iap mcp-server add`
writes one. Both it and `upstream add` take every credential scheme below.

`*` and `**` are globs. In `paths`, `*` stops at `/` and `**` crosses it, so
`/repos/*` does not silently grant everything under `/repos`. Unknown keys are a
hard error — a typo must never quietly widen access.

## Credential schemes

| `type` | Effect |
| --- | --- |
| `bearer` | `Authorization: Bearer <secret>` |
| `header` | any header, with an optional `prefix` |
| `basic` | `Authorization: Basic base64(username:secret)`, or `username_secret` when the *user* field is the credential |
| `query` | appends `?param=<secret>` |
| `oauth2_client_credentials` | fetches and caches an access token, refreshed a minute before expiry |
| `service_account_jwt` | signs a JWT with a service-account key and exchanges it for a short-lived token — see below |
| `none` | pass through |

The last two mint a token rather than forwarding a secret. Minted tokens are
cached until a minute before they expire, and a burst of requests on a cold
cache mints one token, not one each.

A cached token is thrown away early only when the upstream answers **401** —
that is the API saying the credential itself did not hold up, and the next call
mints a fresh one rather than replaying a dead token until it expires. A **403**
does not: the API accepted the credential and refused the *caller*, which is a
GA4 property the service account was never added to, an API not enabled on the
project, or a quota. Minting again from the same key with the same scopes
returns the same grant, so the cached token is kept and the 403 is passed
through as the API's own answer. This is the line `verify` draws too, and it is
why walking a list of resources you turn out not to have rights to costs no
token mints at all.

## Service accounts (Google, and anything else doing RFC 7523)

Google does not want you sending a service-account key to an API. It wants a
JWT, signed with that key, exchanged at its token endpoint for an access token
that lives an hour. The proxy does all of that — the agent never sees the key,
and never sees the access token either.

```toml
[[upstreams]]
name = "gcs"
base_url = "https://storage.googleapis.com"

[upstreams.auth]
type = "service_account_jwt"
key_file = "op://Private/GCP Service Account/credential"   # the JSON Google gave you
scopes = ["https://www.googleapis.com/auth/devstorage.read_only"]
# subject = "person@example.com"   # domain-wide delegation: act as this user
```

`key_file` points at the service-account JSON exactly as Google issues it; the
issuer, key id and token endpoint all come from inside it. For any other
provider that accepts a signed assertion, spell the pieces out instead:

```toml
[upstreams.auth]
type = "service_account_jwt"
issuer = "service@example.com"
private_key = "file:/run/secrets/service-account.pk8.pem"   # PKCS#8 PEM
token_url = "https://auth.example.com/oauth/token"
audience = "https://api.example.com"    # defaults to token_url, which is what Google wants
scopes = ["read:data"]
lifetime_secs = 3600                    # clamped to an hour, Google's ceiling
```

The key is parsed at startup, so a malformed or passphrase-encrypted key stops
the process with a message naming the problem rather than turning into a 502 on
the first call. PKCS#1 keys (`BEGIN RSA PRIVATE KEY`) are rejected with the
`openssl` command that converts them. Every mint is logged with the issuer,
scopes and expiry — never the token.

## Timeouts

`upstream_timeout_secs` (default 300) is an **idle** timeout — the longest an
upstream may go silent mid-response. A token-by-token LLM response can stream for
as long as it likes provided it keeps arriving. `upstream_connect_timeout_secs`
(default 30) bounds establishing the connection.

## Listening addresses

`server.listen` is where agents connect; `server.admin_listen` is the control
plane the TUI and the MCP bridge use. Both live in the policy file, and both can
be overridden at run time by a deployment that does not own that file:

```bash
agent-iap run --listen 0.0.0.0:8080       # full address
agent-iap run --listen 9000               # bare port: keeps the configured interface
agent-iap run --admin-listen off          # no control plane, so no MCP bridge and no curl
IAP_LISTEN=0.0.0.0:8080 agent-iap run     # same, for a container or a unit file
```

A flag beats `IAP_LISTEN` / `IAP_ADMIN_LISTEN`, which beat the file. A bare port
moves the port and never the interface — `--listen 9000` against a loopback
config stays on loopback — because a process holding live credentials reaches
every interface only when someone spells that out. The proxy and the control
plane may not share an address; that is rejected at startup.

## Where secrets come from

`op://vault/item/field` (1Password CLI), `env:NAME`, `file:/path`,
`iap://name` (a credential agent-iap keeps itself — see below), and `literal:…`
for demos, which the loader warns about and the enrolment commands refuse.
Everything is resolved at startup, so a locked vault fails the process rather
than the tenth request. A bare value that is not one of these forms is
rejected, and the error never echoes what you pasted.

### A credential with nowhere else to live

`env:`, `file:` and `op://` all point at something that already holds the
credential. A read-only token on a personal account often has no such place, and
standing one up costs more than the token is worth. `iap://` is for those:
agent-iap keeps the value, and the policy file keeps a pointer like every other
entry.

```bash
# Reads the credential from stdin, or prompts for it without echoing.
agent-iap secret set github-readonly
agent-iap upstream add gh --base-url https://api.github.com \
    --auth bearer --secret iap://github-readonly

agent-iap secret list          # names, when they were set, and what uses each
agent-iap secret rm <name>     # refuses while the policy file still points at it
agent-iap secret import        # move a whole policy off `op://`, in one prompt
```

In the console, typing a credential straight into a credential field offers
`ctrl-k keep` on it: the value goes to the store, the field becomes the
`iap://` reference, and the form you were filling in stays open.

There is deliberately no flag carrying the value. An argument is visible to
every process on the machine through `ps` and stays in the shell history, so a
credential passed as one has leaked before the command starts.

**What this is not.** The store is `secrets.toml` in the state directory, mode
`0600`, and *not encrypted at rest* — anything that can read it as you can read
the credentials, exactly as for `~/.aws/credentials` or a `.env`. That is the
trade against `op://`, and it is the right one for a read-only token and the
wrong one for a credential that can spend money. `[server].secret_store` moves
the file; a relative path is taken from the state directory.

1Password vaults, items and fields are named by humans, so they have spaces in
them — `op://Private/Anthropic API/credential` is one reference, handed to `op`
as one argument and never through a shell. The policy file needs nothing
special; a command line needs the quotes any string with a space needs:

```shell
agent-iap upstream add anthropic --base-url https://api.anthropic.com \
    --auth header --header x-api-key --secret "op://Private/Anthropic API/credential"
```

Space *around* a reference is a typo rather than part of it, and is trimmed:
`" op://Private/Anthropic API/credential"` names the same field.

However many `op://` references one read needs — five services at startup, all
of them again on `SIGHUP` — they go to 1Password in **one** `op` invocation, via
`op inject`. The desktop app authorizes a *process*, so a proxy that forked one
`op` per reference asked for CLI access once per reference, concurrently, and
the grant given to the first dialogue could not cover the ones already stacked
behind it. One process is one dialogue.

**Dismissing that dialogue ends the read.** It is an answer, and asking the same
person the same question once per remaining reference is the thing this section
is about. The references come back unresolved — the first with what 1Password
said, the rest saying they were not asked — and the proxy refuses to start on a
policy it cannot serve. Unlock 1Password, start it again, approve the one
prompt.

Where the single invocation cannot be used — an `op` too old to have `inject`, a
template it will not take — each reference is read on its own instead, so the
error still names the line of the file to fix rather than leaving you to bisect
the policy. That fallback is logged at `warn`, because the visible consequence
of it is more dialogues. It stops at the first refusal too.

### Getting off the vault entirely

Batching makes each *process* one dialogue. It cannot make them none, because a
credential behind `op://` is read by whichever process needs it — and the
processes are many and short-lived: the daemon at startup and on each reload
that means it, `check`, `verify`, and the MCP bridge your agent spawns fresh for
every session. Each is a new client asking the desktop app for CLI access.

`agent-iap secret import` ends that. It reads every `op://` reference the policy
names in one go — one prompt — keeps the values in agent-iap's own store, and
repoints the file at them:

```shell
agent-iap secret import --dry-run   # what it would read, store and repoint
agent-iap secret import
```

Afterwards nothing runs `op` at all. The file keeps pointing at names rather
than holding credentials, so it is still safe to commit, and your comments and
formatting come back as you wrote them. An item two services share is imported
once, under one name, so rotating it is still one job. A reference that will not
read stops the whole thing: nothing is stored and the file is untouched, because
a policy pointing at a store holding half the credentials is worse than one
still pointing at the vault.

The trade is the one `secret set` prints: the store is plaintext on this
machine, readable by this user, with no encryption at rest. That is the same
trade as `~/.aws/credentials` — right for a read-only token on a laptop, worth
thinking about for a credential that can spend money.

If you want to stay on 1Password and still not be asked, use a **service
account**: export `OP_SERVICE_ACCOUNT_TOKEN` before starting agent-iap and `op`
authenticates with it instead of the desktop app, which prompts for nothing.
Nothing here needs configuring for that — `op` is run with the environment it
inherits.

And if 1Password asks every single time even after you approve it, check whether
the binary changed between runs: the app authorizes the calling program, and a
rebuilt `./target/debug/agent-iap` is not the program it was asked about last
time.

### Which build am I running?

```shell
agent-iap --version
# agent-iap 2026.9.0 (aabbe24c6bf4, built 2026-09-23)
```

The commit, and a `-modified` suffix when the tree it was built from had
uncommitted edits. There is no tagged release yet, so every install is a build
somebody made, and the version number alone is the same string for all of them
— which makes "this is fixed on master" and "the binary in front of me has the
fix" two different claims that used to be indistinguishable. `check` prints it
before anything that can fail, the headless banner prints it at startup, and the
console shows the short commit in its header and the whole string under `?`.

## Where things live

Nothing is written to the directory you happen to be standing in. The binary is
installed once — `~/.local/bin`, `/usr/local/bin` — and run from everywhere, so
the policy file and the audit log live under your own directories instead:

| | Linux, macOS, BSD | Windows |
| --- | --- | --- |
| Policy file | `$XDG_CONFIG_HOME/agent-iap/iap.toml`, else `~/.config/agent-iap/iap.toml` | `%APPDATA%\agent-iap\iap.toml` |
| Audit log, `admin-token`, `secrets.toml`, `agent-iap.log` | `$XDG_STATE_HOME/agent-iap/`, else `~/.local/state/agent-iap/` | `%LOCALAPPDATA%\agent-iap\` |

Two directories rather than one, because the files age differently. The policy
file is configuration — small, hand-edited, safe to commit, the sort of thing
that ends up in a dotfile repository. The audit log is state: append-only,
unbounded, and the last thing anyone wants synced to a second machine. macOS
gets the same layout rather than `~/Library/Application Support`, because this
is a terminal tool whose config file is meant to be edited by hand next to every
other one in `~/.config`.

Four ways to move things, narrowest first:

```bash
agent-iap run --config /etc/agent-iap/iap.toml   # this command, this file
export IAP_CONFIG=/etc/agent-iap/iap.toml        # this shell, every subcommand
export IAP_STATE_DIR=/var/lib/agent-iap          # audit log, token, diagnostics
export IAP_CONFIG_DIR=/etc/agent-iap             # where `iap.toml` is looked for
```

`[audit].path` in the policy file moves the log on its own, and
`[server].secret_store` moves the credential store. An absolute path is taken as
it stands; a relative one is taken from the state directory, never from the
working directory.

The store lives with the state rather than with the config for the reason the
two directories exist at all: it holds credentials, and the config directory is
the one that ends up in a dotfile repository.

A `./iap.toml` in the current directory is still what `--config` falls back to
when one is there, so a repository, a demo or one of the walkthroughs above can
carry a policy of its own. It is a fallback for *reading*: `agent-iap init`
writes to the user config directory unless `--config` says otherwise.

> **Upgrading from a version before this?** Nothing moves on its own. An
> existing `./iap.toml` keeps being found where it is, and a `[audit].path` that
> names an absolute path keeps writing there. What changes is a *relative*
> `[audit].path` — the `audit/iap-audit.jsonl` older `init` templates wrote — which
> now resolves under the state directory instead of the working directory. Move
> the old log next to the new one, or set the path absolutely, or set
> `IAP_STATE_DIR` to the directory you were running from. The unit file and the
> container image in [§ Deployment](deployment.md) set `IAP_STATE_DIR` for exactly
> this reason.

## Reloading

The policy file is edited while the proxy is running — from the console, from
`agent-iap acl add` in the next terminal, from an editor. So nothing here is
read once and owned forever. A reload replaces the lot:

| Edited | What happens |
| --- | --- |
| `[[acl]]`, `[[agents]]` | recompiled and re-enrolled; the next request is judged by the new list |
| `[[upstreams]]`, `[[mcp_servers]]` | routable immediately, credential and all |
| a credential reference | a reference that is new, or repointed at something else, is read; one this process already resolved keeps its value unless the reload was asked for — see *What triggers one*. A minted token is dropped when its target went away, and when the credential under it was repointed |
| `[server.tls]`, `[server.admin_tls]` | the same rule, and served from the next handshake; connections already up keep the certificate they negotiated |
| `server.listen`, `server.admin_listen` | the new address is bound, then the old listener drains for ten seconds |
| timeouts, `max_body_bytes`, `approval_timeout_secs`, workload settings | in force for the next request; anything already in flight keeps what it started with |
| `[audit]` | redaction and body limits immediately; a changed `path` closes the old file and picks up the new file's hash chain |

**All of it, or none of it.** Every step that can fail happens first, against
scratch copies: the secrets resolve, the rules compile, the agents enrol, the
credential schemes parse, the client builds, the new socket binds. Only then is
anything installed, and installing cannot fail. So an edit that would not have
*started* this process does not stop it either — it is refused, the reason goes
on the console's footer, and the proxy carries on with the policy it had.

### What triggers one

The policy file is watched by the daemon, not by the console, so this is the
same wherever it runs — a terminal, a unit file, a container with nobody
attached:

```bash
agent-iap acl add --name migration-window …   # the file changed; picked up
$EDITOR /etc/agent-iap/iap.toml               # same
systemctl reload agent-iap                    # SIGHUP, for the impatient
kill -HUP "$MAINPID"                          # and what that actually sends
curl -sf -X POST -H "Authorization: Bearer $TOKEN" \
     localhost:8081/reload                    # the same thing, over the network
```

`POST /reload` on the control plane ([§ Control
plane](deployment.md#control-plane)) is the one that works where a signal does
not — a container whose PID 1 is not the proxy, a host you are deploying to
rather than sitting on, a script that already holds the admin token. It is also
the only trigger that *answers*: it returns what the policy became, or `422`
and the reason it was refused, so a deploy learns on the spot whether the file
it just wrote was accepted instead of finding out from the first agent that
gets a 401.

A changed file has to hold still for 250ms before it is read: a rewrite is a
truncate and then a write, and in between the file is half a policy. `SIGHUP`
skips the wait, which makes it the right trigger for a config-management tool
that has just finished writing. The console's `r` is the same call.

**`SIGHUP` and `r` also go back to the source for every credential the file
names; a file that merely changed does not.** A value rotated behind an
unchanged reference — the vault item replaced, the key file rewritten — is
invisible in the policy, so the only way to pick it up is to read it again, and
the only honest moment to do that is when somebody said so. An edit is not
somebody saying so: an `[[acl]]` rule appended by `agent-iap acl add`, or by
answering an `ask` with *from now on*, names no credential, and going back to
the vault because of it is a dialogue in front of whoever is answering the next
request — for an answer nothing asked for. (When a re-read *is* asked for,
every `op://` reference in the file goes in one `op` invocation, so it is one
dialogue however many references there are —
[§ Where secrets come from](#where-secrets-come-from).) References the edit
*added* or repointed are read either way, so a policy naming a credential this
proxy cannot get is still refused at the reload rather than on the first live
call.

So: rotate a credential in place, then `systemctl reload agent-iap` (or press
`r`). Repoint a reference at something else and the edit alone is enough.

Every reload is written to the audit log as a `reload` record naming which of
the five caused it — `edited`, `sighup`, `asked`, `wrote`, `control_plane`, the
last with the address it came from — and carrying `before` and `after` counts of
agents, upstreams, MCP servers and rules. A rule appearing ten seconds before a
call it allowed is something the log should be able to show you, and so is an
agent count dropping by six. A refused reload writes no record, because nothing
changed.

One thing this does not do: the signing key behind
[§ Workload identity](agents.md#workload-identity) is not rotated, because that
would invalidate every token already handed out — a fleet-wide outage rather
than a config change.
