# Adding or changing a service profile

A profile is not a shortcut for typing an upstream. It is the place the things
somebody had to find out the hard way get written down, so the next enrolment
does not find them out again. Everything a profile writes is ordinary TOML that
a person could have written by hand — the value is entirely in knowing *what* to
write (`src/profiles.rs`, README § Profiles).

## What a profile has to know that a hand-written upstream would not

Work these out against the live service before writing the entry. Each one has
already been a bug.

- **The exact scheme word.** Semrush v4 wants `Authorization: Apikey <key>`, not
  `Bearer`; the trailing space in the prefix is load-bearing and the wrong word
  is a 401 that explains nothing (#41, #42). Graylog authenticates its token as
  basic `<token>:token` — the credential is the *user* field, which is what
  `BasicSecretUser` exists for.
- **That two versions of an API are two credentials.** A working `semrush`
  upstream tells you nothing about `semrush-v4`. Separate profiles.
- **What is yours rather than the vendor's**, as a `Var`: a Cloudflare
  `account_id`, a Sentry `region` (`us` or `de` — an org token carries its own,
  and plain `sentry.io` routes to either, hiding the mismatch until an agent
  hits it), a self-hosted `host`. These are path or address material, not
  credentials, so they go in the file in the clear. Give each one an `about`
  string: the console renders one field per variable and uses it as the hint,
  so a variable with a vague description is a form that never actually asks for
  the value (#38, #48, #57).
- **A `probe`** — the endpoint `verify` calls to prove the credential. It must
  be a GET, free, available on every plan, and it must distinguish a bad
  credential from a merely unentitled one. Cloudflare's root answers identically
  for a perfect token and a garbage one; `/accounts/<id>/tokens/verify` does not
  (#48). Where the vendor documents nothing that qualifies, leave it `None` — a
  probe that 403s on half the accounts holding a good token is worse than none
  (#49).
- **Access levels split by what the operator is actually deciding**, which is
  often cost rather than verbs. `dataforseo` prompts for the `live` endpoints
  and allows the queued ones; `semrush-mcp --access discovery` allows the tools
  that describe reports and prompts for the one that bills; `semrush-trends` is
  the same key as `semrush` on its own upstream because Trends bills against a
  separate allowance and that only becomes legible as a separate row in the
  audit log; `sentry --access triage` is every read plus exactly the PUT that
  resolves an issue, with DELETE denied outright rather than prompted (#41, #42,
  #57). For `service_account_jwt`, levels differ in **scopes** as well as paths
  — no ACL gets a `webmasters.readonly` token to submit a sitemap.
- **A `note` for anything that fails late anyway**: an endpoint that is
  unreachable through the proxy (Semrush's unit balance lives on another host),
  a report surface too coarse for a finer rule than "read-only", a self-hosted
  release that 404s an endpoint it predates.
- **For an MCP profile: where the grant ends up.** Prefer the form that keeps
  the credential on the proxy. A vendor server that offers OAuth first but also
  accepts a token header gets the header (`sentry-mcp`); one that only does
  OAuth means the grant lives in a child process's cache, which is a different
  security story and belongs in the note.

## Mechanics

- HTTP profiles only are offered when adding an upstream; an MCP profile is not
  an upstream and must not be written as one.
- `upstream add --profile <id>` is `profile add <id> --as <name>`. Credential
  flags beyond `--secret` are refused rather than ignored, because the profile
  supplies the scheme.
- `--dry-run` prints the TOML and writes nothing; `--verify` runs after the
  write, never instead of it.
- A new `AuthTemplate` variant must map onto an existing `AuthSpec` — the proxy
  does not learn a scheme for a profile's sake.

## Tests

`tests/profiles_e2e.rs` builds its policy with `profile add` rather than a
fixture, materialises every profile at every access level, runs each through the
daemon's own `validate()`, and asserts every MCP profile admits `initialize`. A
new profile needs, at minimum, a unit test pinning the scheme it enrols as and
the paths its default level allows, plus the note or probe if either is the
point of the profile. Verify against the live vendor as well, and put the status
codes in the PR.
