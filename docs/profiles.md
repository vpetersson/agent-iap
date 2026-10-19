# Profiles

For a service someone has already worked out, `profile add` writes the base
URL, the credential scheme and the OAuth scopes, and carries a set of rules
narrow enough to be worth calling a policy — offered, not applied:

```bash
agent-iap profile list
agent-iap profile show graylog
agent-iap profile add graylog --secret op://Private/Graylog/token \
    --var host=graylog.example.com:9000
```

That last command knows three things you would otherwise have to look up:
Graylog's API hangs off `/api`, it authenticates an access token as basic
`<token>:token` with the *token in the user field*, and its searches are POSTs
so a GET-only "read" level cannot read anything. Getting any of those wrong
fails late — a 401 with no detail, or a rule that grants more than you meant.

`upstream add` takes the same thing from the other direction:

```bash
agent-iap upstream add gh --profile github --secret op://Private/GitHub/token
```

That is `profile add github --as gh`, because "add an upstream" is what
somebody sets out to do, rather than having to know profiles exist first.
`--access`, `--var`, `--grant`, `--agent` and `--dry-run` mean what they do
below; the credential flags do not, since the profile supplies the scheme, so
anything beyond `--secret` is refused rather than ignored. In the console, `n`
on the upstreams pane opens the same picker ([§ The approval
console](console.md#the-approval-console)).

`--dry-run` prints the exact TOML it would append and writes nothing.

| Flag | |
| --- | --- |
| `--as <name>` | name it something else — this is how one proxy fronts two accounts of the same service |
| `--access <level>` | which scopes the credential is minted with, and which rules `--grant` would write; defaults to the narrowest the profile has |
| `--var name=value` | what is yours rather than the vendor's: a self-hosted host, a region, an API login |
| `--grant` | also write that level's ACL rules — a standing `allow` for every call they cover |
| `--agent <id>` | with `--grant`: scope the granted rules to one agent instead of all of them |
| `--dry-run` | print, do not write |

**A profile grants nothing on its own.** The access level always decides the
scopes — a Search Console credential minted `webmasters.readonly` cannot submit
a sitemap however the ACL reads — but its rules are only written when `--grant`
asks for them. Without it the enrolment is a service and no permission: the
first call falls through to `acl_default`, stops at the console, and the rule
comes out of the answer. This is the Little Snitch shape the proxy is for, and
enrolment used to skip it: `upstream add --profile github` appended `allow GET
/** on github for *`, so the first call an agent made went through with the real
credential attached and nobody asked.

`--grant` is worth reaching for when the level is exactly the policy you want
and you would rather review it as TOML than answer for it call by call —
`cloudflare --access ask-writes`, say, which is already three rules and two
actions.

Access levels are per profile and `profile show` lists them. They differ in
scopes as well as paths, which is the part that is easy to get wrong by hand:
Search Console's `read` asks Google for `webmasters.readonly` and its `write`
asks for `webmasters`, and no amount of ACL gets a `readonly` token to submit a
sitemap.

Seven levels exist for reasons that are not about permissions:

- **`cloudflare --access ask-writes`** allows GET, denies DELETE outright, and
  parks everything else for a human. The ACL cannot tell a reasonable POST from
  a destructive one; this is where `ask` earns its place.
- **`dataforseo`** defaults to a level that allows the queued endpoints and makes
  the `live` ones prompt. Nothing in the method or the path says one costs more
  than the other, and an agent has no way to know.
- **`semrush-mcp --access discovery`** allows the tools that describe what
  reports exist and prompts for `execute_report`, the one that runs them and
  bills. Same reasoning as `dataforseo`, except here the expensive call has a
  name you can write a rule against.
- **`semrush-trends`** is the same v3 key as `semrush` on its own upstream.
  Trends bills against its own monthly allowance rather than Standard API units,
  so the split lets one agent have Trends and not the reports, and puts the two
  budgets on separate rows in the audit log.
- **`sentry --access triage`** allows every read and exactly one write: the PUT
  that resolves, ignores or assigns an issue — the whole of what an agent
  watching errors needs, without `write` also letting it edit projects, alert
  rules and members. DELETE is denied rather than prompted. All four Sentry
  profiles offer the same three levels.
- **`asana --access triage`** is the same shape for a task queue: every read,
  plus the POSTs and PUTs that comment on, create, complete and re-file a
  *task*, with DELETE denied and everything else — projects, teams,
  memberships, webhooks, exports — left to prompt. The question an operator is
  answering is not "may it write" but "may it write to tasks", and `write` is
  the level that cannot tell the two apart.
- **`sbomify`** splits its writes by sbomify's own roles rather than by verb.
  `--access triage` is the operator: every read plus recording a triage
  decision on a vulnerability. `--access publish` is the CI bot: every read
  plus uploading an SBOM, its provenance and signature, and filing it into a
  release. Products, components, workspace settings, members and billing
  prompt at both, and DELETE is refused. `write` still asks before a plan
  change or a GitHub OIDC binding, because one bills and the other is a
  standing publish grant to a repository the proxy never sees. `sbomify-v1`
  has the same four levels on v1's paths.

## What is in the catalog

Everything the profiles cover is reachable without them — a profile is a
starting point that writes ordinary TOML, not a special case in the proxy.

| Vendor | Profiles |
| --- | --- |
| Google | `google-search-console`, `google-analytics-data`, `google-analytics-admin`, `google-indexing`, `google-bigquery`, `google-drive`, `google-sheets`, `google-cloud-logging`, `google-cloud-storage` — all one service account, all `service_account_jwt`, each taking an optional `--var subject=<email>` for domain-wide delegation |
| Cloudflare | `cloudflare` (the whole `client/v4` surface, `--var account_id=…`), plus `cloudflare-mcp-*` for each of the sixteen hosted MCP servers |
| Asana | `asana` (REST), `asana-mcp` (the V2 MCP server, over `mcp-remote`) |
| PostHog | `posthog` (REST), `posthog-mcp` |
| DataForSEO | `dataforseo`, `dataforseo-mcp` |
| Semrush | `semrush` (v3, `?key=`), `semrush-trends` (the same key, its own allowance), `semrush-v4` (`Authorization: Apikey`), `semrush-mcp` |
| Graylog | `graylog` |
| Sentry | `sentry` (sentry.io, `--var region=us\|de`), `sentry-self-hosted` (`--var host=…`), `sentry-mcp`, `sentry-mcp-self-hosted` |
| sbomify | `sbomify` (API v2), `sbomify-v1` (deprecated, same token, `/sboms` and `team_key` paths), and `sbomify-self-hosted` / `sbomify-v1-self-hosted` for staging or an install of your own (`--var host=…`, `--var scheme=http` for a plain-HTTP one) |
| Spotify | `spotify` (client-credentials; the proxy mints the access token) |
| Object storage | `s3` (`--var region=…`), `r2` (`--var account_id=…`), `s3-compatible` (`--var host=…` — MinIO, B2, Wasabi, Spaces, Ceph, …) — all `aws_sigv4`, all needing `--var access_key_id=…` and `--var bucket=…` |
| GitHub | `github` (the REST API), `github-git` (`git clone`, `fetch` and `push` over HTTPS, `--var repo=owner/name` to narrow it) |
| Others | `anthropic`, `openai`, `xai`, `linear`, `slack`, `stripe` |

`agent-iap profile list --output json` for a machine, `--vendor google` to narrow
it.

The honest limits, all printed by `profile show`:

- **An object-store grant is for one bucket unless you type `*`.** An access
  key routinely reaches every bucket in the account, so `s3`, `r2` and
  `s3-compatible` take `--var bucket=…` with no default, and their rules cover
  `/<bucket>` and `/<bucket>/**`. `read` is GET and HEAD; `write` adds PUT and
  POST on objects — never on the bucket itself, where they are CreateBucket, a
  bucket policy or DeleteObjects — and asks before a DELETE; `full` is every
  method on both. The agent sends its token as `X-IAP-Token`, server-side copy
  is refused, and [§ S3, R2](policy-file.md#s3-r2-and-anything-else-speaking-the-s3-api)
  has the rest.

- **Git is a second GitHub upstream.** An upstream is one base URL, and git's
  smart-HTTP endpoints are on `github.com` rather than `api.github.com` and take
  the token as HTTP Basic `x-access-token:<token>` rather than as a bearer — so
  `github-git` is its own profile, usually on the same `--secret` as `github`.
  `read` allows the two requests a clone or fetch makes, `GET
  /<owner>/<repo>.git/info/refs` and `POST …/git-upload-pack`, and denies `POST
  …/git-receive-pack` by name; `write` allows that too. `--var repo=acme/api`
  (or `acme/*`) narrows every rule to that repository; the default `*/*` is
  every repository the token reaches. Rules match the path and never the query
  string, so `read` cannot refuse `info/refs?service=git-receive-pack` — that
  answers with the ref list a fetch is shown anyway, and the push itself is the
  POST it denies. `agent-iap git-config` points git at the upstream and makes
  `agent-iap git-credential` its credential helper there, so git sends the
  agent's token as Basic and github.com is sent the profile's own in its place
  ([§ Git](agents.md#git)). A push is buffered whole, up to
  `server.max_body_bytes` (10 MiB unless raised); `ssh://` and `git@github.com:`
  remotes are not rewritten, and Git LFS objects live on other hosts the
  profile does not cover. `verify` reads a public repository's refs — a bad
  token is a 401 there — which proves GitHub accepts the token, not that it
  reaches yours; `--path '/<owner>/<repo>.git/info/refs?service=git-upload-pack'`
  asks that.
- **A Cloudflare token is half an address.** Most of `client/v4` lives under
`/accounts/<id>/…`, and an account-owned token (`cfat_`, the durable
service-principal kind) can only be verified at that account's own endpoint —
`/user/tokens/verify` is for user tokens and rejects it. So `cloudflare` asks
for `--var account_id=…` alongside the secret, and writes it into the
`verify_path` the enrolment then calls ([§ Verifying](enrolling.md#verifying)).
The account ID is a path parameter rather than a credential: it goes in the
file in the clear, while the token stays a reference.
- **Cloudflare's hosted MCP servers speak OAuth, not API tokens.** The
  `cloudflare-mcp-*` profiles run them through `npx mcp-remote`, which does the
  browser flow and caches the grant. The proxy still rules on and logs every
  JSON-RPC message, but the credential lives in the child's cache rather than in
  the proxy. The `cloudflare` REST profile covers the same services with a
  credential the proxy holds.
- **An Asana token has no scopes, and one endpoint carries every other one.**
  A personal access token is the whole of what its owner can see, in every
  workspace they belong to, and the ACL cannot cut that down by workspace or
  project: this API addresses objects by gid — `/tasks/<gid>` is the entire
  path — so there is nothing in the path for a rule to match a workspace
  against. Where "which projects" has to be a real limit, it belongs in Asana:
  a service account, or a bot user invited only to the projects you mean, whose
  token is then what the proxy holds. `POST /batch` follows from the same
  shape: it carries up to ten sub-requests, each naming its own method and
  relative path, so one allowed POST is every call the token can make and the
  audit log keeps a single row reading `POST /batch`. `read` and `triage` deny
  it by name — the refusal names a rule rather than `<default>` — and `write`
  allows it, where it grants nothing new but does cost you the detail in the
  log. `write` also reaches `POST /webhooks`, which registers a durable push of
  workspace changes to any URL and does not stop when the agent's token is
  revoked, and the three export endpoints, which dump the domain rather than
  read a record.
- **A Google service account sees only what has been shared with it.** Its
  own Drive is empty, so `google-drive` answers a perfectly good key with an
  empty `files.list` until you share folders with the service-account email or
  add it to a shared drive. The other way in is domain-wide delegation:
  `--var subject=person@example.com` writes `subject` into the upstream's
  `auth`, and the token then sees everything that user can — granted in the
  Workspace Admin console for the client id and the level's scopes first, or
  every token request comes back `unauthorized_client`. It is a variable rather
  than `--subject` because a profile reads no credential flag but `--secret`;
  empty, the default, is no delegation.
- **Drive's one write that leaves the building is sharing.** `google-drive`
  has three levels. `read` is every GET — search (`files?q=`) and export
  included — under `drive.readonly`. `edit` adds creating, uploading, copying,
  renaming, moving and commenting under `drive`, denies DELETE and every
  change to `/files/<id>/permissions` by name, and sends anything else (shared
  drives, revisions, whose `published: true` puts a Doc on the web) to `ask`.
  `write` is all of Drive v3. Below `write`, `/files/<id>/watch` and
  `/changes/watch` are denied — `drive.readonly` is enough to open a push
  channel to any URL, and it outlives the agent's token — and no level allows
  `POST /batch/drive/v3`, whose sub-requests the ACL cannot see. What `edit`
  cannot stop: moving a file into a folder that is already shared more widely,
  and `trashed: true` in a PATCH, which is a delete Google keeps for 30 days.
  Google Docs, Sheets and Slides have no bytes for `?alt=media`;
  `/files/<id>/export` is the read. Shared-drive files need
  `supportsAllDrives=true` (and `includeItemsFromAllDrives=true` on a list) or
  they are silently left out.
- **Asana's MCP server will not take the credential the proxy holds.** It
  issues its own tokens and answers a personal access token with `Invalid token
  signature - token was not issued by Asana OAuth`; its authorization server
  offers only the authorization-code and refresh-token grants, so there is no
  exchange the proxy could perform. `asana-mcp` therefore runs the V2 endpoint
  through `npx mcp-remote`, which does the browser flow, caches the grant in
  `~/.mcp-auth` and reads the app's client id and secret from the file
  `--var client_file=…` names — a file outside the credential inventory, since
  the child reads it rather than the proxy. Every JSON-RPC message is still
  ruled on and logged here. A session is pinned to the one workspace chosen at
  sign-in and carries whatever the authorizing user can see, because MCP apps
  take no scopes either, so the tool rules are the only narrowing. Asana's beta
  server at `mcp.asana.com/sse` shuts down on 11 May 2026 and this profile does
  not use it; Command by Asana has a server of its own that no profile fronts.
- **Tool catalogs move.** PostHog exposes well over a thousand tools, so its
  `read` level allows the read verbs and sends everything else to `ask` rather
  than denying it. Watch the audit log for `ask` rows and promote the ones you
  want.
- **A Sentry region is part of the address.** Every sentry.io organization lives
  in `us` or `de`, and an organization auth token (`sntrys_…`) carries its region
  inside it — point one at the other host and a good token gets a 401 or a
  redirect. So `sentry` writes the region host (`--var region=de`) rather than
  plain `sentry.io`, which routes to either and would hide the mistake. The API
  version does not vary — the `0` in `/api/0` — so `sentry-self-hosted` is the
  same rules at your own host. The release does: an endpoint your version
  predates 404s rather than being denied, which is why the `triage` rules name
  the project-scoped issue path as well as the organization-wide one.
- **An sbomify token can mint another, so that call never goes through.**
  `POST /auth/oidc/github/exchange` trades a GitHub Actions OIDC token for a
  fresh sbomify token and returns it. Through this proxy that is a credential
  handed to the agent, so both sbomify profiles deny it at every level,
  `write` included, along with `/user/**` (account export and deletion). The
  token itself acts as its owner, so their workspace role still applies under
  the ACL, and it can be pinned to one workspace and given an action list when
  it is created, which holds even where the ACL is wide. Two limits the ACL
  cannot fix: publishing a product or component to the Trust Center is a
  field in the same `PATCH` that renames it, so the narrow levels prompt for
  both, and `POST /artifacts/upload-file/…` is session-only, so a token gets a
  401 there and CI uploads go to `/artifacts/cyclonedx/<component>` or
  `/artifacts/spdx/<component>`. v1 has been deprecated since 26 August 2026
  with no sunset date yet; it also mounts `/internal`, which `sbomify-v1`
  denies.
  Staging and self-hosted installs use `sbomify-self-hosted` or
  `sbomify-v1-self-hosted`: the same rules and probe at `--var host=…`, with a
  token from that install. Enrol them `--as sbomify-staging` (or similar) to
  keep them next to production.
- **A Spotify token is app-only, and expires in an hour.** Spotify issues no
  long-lived API key: every call carries an OAuth access token. So `spotify` is
  the one profile whose credential the proxy *spends* rather than forwards — it
  trades the app's client secret for an access token at
  `accounts.spotify.com/api/token` and injects that, which is the whole reason
  a profile can exist for a service whose own credential would have stopped
  working before the agent's next task. The Client ID identifies the app rather
  than authenticating it, so it is a `--var client_id=…` in the clear and only
  the secret is a reference. What that grant does *not* reach is anybody's
  account: `/v1/me/**`, playlists, the library and playback need a listener's
  authorization-code grant with a refresh token, which this proxy does not
  perform, and they come back 401 from Spotify rather than denied by the ACL.
  There is no `write` level for the same reason. Spotify also restricted
  several catalogue endpoints for apps registered after 27 November 2024 — audio
  features, audio analysis, recommendations, related artists and the
  featured/category playlist lists — so the default `catalogue` level names the
  endpoints that survived it rather than `/v1/**`; `--access read` is every GET,
  including the ones a new app will be refused.
- **An xAI key is already scoped, and the proxy can only narrow it.** A key
  made in the xAI console carries its own allow-list of endpoints and models, and that list is checked before this policy is ever consulted: a
  call the ACL allows still comes back 403 if the key was not given the
  endpoint, and no rule written here widens it. So `xai` probes `/v1/api-key`,
  which describes the key — its permissions, and whether it has been blocked
  or disabled — rather than `/v1/models`, which answers for the account. xAI
  rejects a wrong key with `400 invalid-argument` rather than a 401, so
  `verify` calls that `http error` rather than `rejected`; it does not pass,
  and the status is in the detail line, but the word is milder than the
  problem. A Zero Data Retention team cannot use the two paths the `results`
  rule allows, either: `deferred` comes back 400 naming ZDR, `store` reports
  `false` however it was sent, and reading a response by id is a 404. ZDR is a
  property of the team rather than of the API, so the rule stays — but on one
  of those teams it is a rule that never matches. The other thing one key
  covers is spend: text generation, image generation and video generation sit
  behind the same credential under the same `/v1` prefix, and only the first
  is in the default `inference` level. Images and video need `--access all`,
  which is a per-asset bill and therefore something a human types.
  `https://api.x.ai` is the global endpoint; `https://us.api.x.ai` pins
  handling and inference to the United States and is an edit to `base_url`,
  not a second profile. xAI's management API is a different host and a
  different credential — a management key — and no profile fronts it.
- **A path the ACL cannot split.** Semrush's v3 analytics puts every report at
  the same path and names it in a query parameter — `/?type=domain_ranks` — so
  rules can say "reports, read-only" and nothing finer. The credential goes in
  the query string too, enrolled as `query` auth: the proxy appends the key on
  the way out, so it is still never in a URL the agent wrote. v4 is a separate
  key on a separate profile, with both in the ordinary places.
