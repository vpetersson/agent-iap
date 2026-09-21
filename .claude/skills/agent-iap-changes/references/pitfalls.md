# Traps this repo has already paid for

Specific things that are easy to get wrong here, each already the subject of a
fix. Check the relevant ones before claiming a change is done.

## Policy and the ACL

- **First match wins, so rule order is the policy.** Anything that appends a
  rule appends it *last*; anything that prints rules prints them in file order.
  A wide rule written in front of `deny` is how a default-deny proxy became
  allow-all on the documented setup path (#55).
- **An empty `targets` list means every target, not none.** A removal that would
  empty it is an escalation performed during a removal — refuse it (#31).
- **`acl_default` is `deny` from `init`, `ask` after `acl reset`, never `allow`
  unless a human wrote it.** Anything that describes the effect of an empty rule
  list must read `acl_default` rather than asserting "everything is denied"
  (#60).
- **`ask` with nobody attached denies.** Headless startup warns; the audit line
  is `ask:no-approver-denied`, not a silent `policy_denied`. Any new surface
  that can park a request has to account for the headless case.
- **`--lockdown` decides before the rule list** and lives outside everything a
  reload swaps. A kill switch that the agent's own `acl add` or a
  config-management tool could lift is not one (#59).
- **Paths are percent-decoded before the check**, and split on `\` as well as
  `/`; `build_url` then refuses if the parsed path is not literally what policy
  approved. `%2e%2e` once passed a `..` guard, matched an ordinary allow rule and
  resolved to `/admin/keys` upstream (#10). Any new path handling inherits this
  requirement.

## MCP

- **`initialize` names no tool**, so it matches only a rule that leaves `paths`
  unconstrained. A tool-scoped rule alone validates, starts, and then never
  opens a session — the agent sees a server that never came up and the audit row
  blames `<default>` (#21). `check` and `verify` warn about it; keep that warning
  working.
- **The stdio bridge is not a process boundary.** The child holds the credential
  in its environment. It buys policy and audit, not isolation — do not describe
  it as a sandbox.
- One shared stdout so two writers cannot interleave a frame; a denied batch
  answers with one array, not N loose objects (#10).

## Secrets and credentials

- **A reference is trimmed of surrounding whitespace in `SecretRef::parse`** —
  one place — but whitespace *inside* one is significant (vault, item and field
  names have spaces). `literal:` keeps its payload verbatim: silently shortening
  a credential is not a parser's call (#52).
- **`op` is only invoked for `op://` references.** Do not attach a 1Password
  hint to an error that has nothing to do with 1Password, and report every
  failed reference rather than the first (#15).
- **Resolution is cached for the process.** A reload re-reads *every* reference
  through `refresh`, not `resolve`, or a credential rotated behind an unchanged
  reference goes on serving the old value — this shipped, and cost a real
  deployment two days of 401s (#40). `refresh` is non-evicting: a read that
  fails leaves the last good value in place.
- **Minting is single-flight and cached per target.** A burst on a cold cache
  mints one token, not one per waiting request (#9).
- **Never log the error's text for an upstream failure.** Describe it from its
  category; reqwest's `Display` embeds the post-injection URL, query-string
  credential and all (#10).

## Startup, paths and process

- Certificates, keys, CA bundles and service-account keys are resolved and
  parsed **before anything binds**, including material this process will not
  itself read (a bridge started later still needs its CA reference to have
  failed where somebody was watching) (#9, #17, #25).
- Config lives in `$XDG_CONFIG_HOME/agent-iap/`, state (audit log,
  `admin-token`, diagnostics) in `$XDG_STATE_HOME/agent-iap/`; `IAP_CONFIG`,
  `IAP_CONFIG_DIR` and `IAP_STATE_DIR` override, and `./iap.toml` still wins for
  *reading* so a checkout carrying its own policy keeps working (#45).
- The proxy and the control plane may not share an address (port 0 exempted —
  it asks the OS for a free port) (#14).
- Control-plane authentication is a `route_layer`, so it runs before axum's
  extractors. Inside a handler it runs after the body has been deserialized on
  an anonymous caller's behalf (#19). `/health` stays open; `/authorize` and
  `/event` authenticate as an *agent*, not an operator.
- Audit writes are fallible: the chain does not advance past a line that never
  reached the file, and a request that is permitted but not recordable is
  refused (#10).

## The console (`src/tui/`)

- **A modal holding a secret ignores clicks** and closes only on `esc`, `enter`
  or `q`. A left press over text is how a person starts selecting it, and that
  gesture used to throw the token away (#53).
- **Copying is OSC 52 to `/dev/tty`**, so `gen-token > token.txt` stays clean and
  the "copied" line goes to stderr. Send both the bare sequence and the tmux DCS
  passthrough — passthrough is off by default since tmux 3.3, so the wrapped form
  alone silently does nothing. No false confirmation: the write succeeding is
  all that can honestly be claimed (#36, #53).
- **A refresh's error must not be overwritten by the caller's success message**
  (#53). Every write is followed by a reload, and a reload re-resolves every
  credential — so an unrelated relocked vault can refuse an otherwise fine
  policy.
- **Forms are derived from `enroll::AuthInput::fields_for`**, in both
  directions: an edit form opens prefilled by `AuthInput::of`, because a form
  that opens blank writes `auth = none` over a live credential the first time
  somebody corrects a base URL (#37). One field per profile variable, keyed
  `var:<name>` (#38).
- **Which fields offer the file picker is held against
  `AuthConfig::secret_fields` by a test**, so a scheme that grows a sixth
  reference cannot be left off one list (#43). The picker reads nothing — it
  lists names and hands back `file:<path>`.
- An affordance is announced on the focused field's line *and* in the key row,
  because the field line is also where a save error lands (#47), and the inline
  offer comes off a field that already has a value (#50).
- Anything drawn with a key on it is a button and must be clickable; every rect
  reported as a hit box is covered by a test.

## Naming and compatibility

- `mcp` on its own is never renamed: the protocol, the `mcp`/`mcp-server`
  subcommands and `[[mcp_servers]]` are named for MCP, not for this project.
  Renaming them is the one change that breaks a policy file (#29).
- The workload token's `iss` and the audit `proxy` field are signed/chained
  values — changing either invalidates old tokens or splits the log's history.
- CalVer, unpadded month; `scripts/check-version.sh` enforces it and on a tag
  requires the tag and `Cargo.toml` to agree.
