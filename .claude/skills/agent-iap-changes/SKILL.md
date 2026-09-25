---
name: agent-iap-changes
description: What a change to agent-iap has to do before it counts as done — where a feature's scope comes from, the rules that decide its design, the verification bar, and the shape of the PR. Read this before writing code in this repo, changing a default, adding a service profile, touching the policy file or the console, or opening a PR.
---

This repository is a credential broker. One process holds every upstream
credential in a deployment, behind one ACL, in front of agents that are not
trusted with those credentials. That premise decides most arguments about a
change, and the repeated mistakes below are all the same mistake: shipping the
mechanism somebody asked for without shipping the thing that makes it safe,
findable or diagnosable.

Read `references/pitfalls.md` for the specific traps that have already cost a
PR, and `references/profiles.md` before adding or editing a service profile.

## Scope comes from the failure, not from the request

An issue names a feature. The change is sized by the failure that feature
prevents, which is usually wider than the sentence asked for and occasionally
narrower.

- Reproduce the failure first, in the real thing, and quote what it actually
  printed. Every PR body here opens with that (#15, #49, #53, #55). If you
  cannot reproduce it, say so in the PR rather than fixing what you assume.
- Ask what else is broken for the same reason. "Stop blaming 1Password for a
  failed `env:` reference" (#15) was one string; reporting *every* broken
  reference instead of the first was the same defect seen properly.
- **Fix the state, not the command that happens to produce it.** #60 changed
  what `acl reset` writes and closed the issue; the reported state — no rules,
  `acl_default = "deny"`, every call refused by `<default>` with nobody asked —
  was still reachable, and still the default, because `init` wrote it and most
  files come from `init`. It was reported again within the hour. When a fix
  lands on one path into a bad state, enumerate the others before calling it
  done, and ask what tells an operator they are in that state at all (#62).
- Say what you deliberately did not do, and why it is its own issue (#30, #34).
  A PR that quietly widens is as hard to review as one that quietly narrows.
- If the work turns up a design wart next to the bug, either fix it in the same
  PR and say so in the opening line (#25), or leave it and name it. Never
  silently.

**The worst class of bug in this repo is the one with no error at the point it
bites.** A tool-scoped MCP rule that blocks `initialize`, an agent scoped to an
upstream that does not exist, a credential that resolves to the wrong thing, a
probe that answers identically for a good token and a garbage one — the file
parses, the daemon starts, and the failure arrives later as a 401 or a silence.
When you find one, the fix is to make it fail where it is typed.

## The rules that decide the design

**1. A default never widens access, and the convenient spelling least of all.**
`acl add` on bare defaults once wrote `allow * ** on * for *` in front of the
`deny` it was meant to be backed by (#55). `--listen 9000` keeps the configured
interface, because only a full `HOST:PORT` should be able to put this process on
every interface — and it does not silently narrow either (#14). `--prune`
refuses when dropping the last `targets` entry, because empty means *any* target
(#31). The widest rule any surface writes is `ask`, never `allow` (#55, #60).
When a change touches a default, state in the PR whether any existing policy
file changes meaning; the answer should almost always be no.

**2. Fail at startup or at enrolment, not on the first live call.** Service
account keys, TLS certificates, keys and CA bundles are resolved *and parsed*
before anything binds (#9, #17, #25) — a proxy that comes up and then cannot
complete a handshake is worse than one that refused to start. Policy edits are
validated before they are written (#18). `verify` asks the service at the other
end, because "does the file parse" is only half of "did the enrolment work"
(#46).

**3. Credentials are references; values never surface.** `literal:` is refused
where a file is meant to be committable. No credential value is drawn in the
console, echoed by `check`, written to the audit log or embedded in an error —
a reqwest `Display` once carried `?key=<secret>` into the hash-chained log
(#10), and `check` once printed `literal:` references raw (#52). A minted token
is shown once, through one `show_token`, and only its sha256 is stored.
Something that only *points* at a credential (an account id, a region, a host)
goes in the clear and should be a `--var`, not a secret.

**4. One decision, one implementation.** The proxy and the MCP gateway both call
`gate::clear`; the console and the CLI both call `enroll` and `profiles`; which
fields a scheme reads is answered once by `enroll::AuthInput` and held against
`AuthConfig::secret_fields` by a test (#32, #35, #43). Two spellings of "may
this happen" drift, and the drift is a rule that stops a call one way and waves
it through the other. If you find yourself writing the second one, wire it to
the first instead — and delete the summary, headline or helper that no longer
has a caller (#51).

**5. Every policy-file write is validated, in place, and whole.** Edits go
through `toml_edit` so the comments survive, are applied in memory, parsed back
through `Config`, run through the proxy's own `validate()`, and only then
written. A rejected edit leaves the file byte-for-byte untouched, and nothing is
half-applied on the way to an error (#14, #18, #31). A removal may not strand a
reference or widen a grant, and says what it orphaned.

**6. An affordance nobody can find does not exist.** The file picker was
reachable by two routes and announced in exactly the one place an error message
covered up (#47); the offer then had to come off a field that already had a
value (#50). The approval console was behind a flag you had to already know
about (#26). A `VERIFIED` column that is amber for a healthy fleet is one an
operator learns to skip within a day (#49, #51). A key that copies a secret must
not also be the key that dismisses it (#36, #53). Status by shape before colour.

**7. Errors name the real cause, all of them, and survive.** Not the first
broken reference — every one (#15). Not a tool the config never mentions. Not
"unrecognised secret reference ` op:***`" when the problem is a leading space
(#52). And a success message must not overwrite the error printed a line
earlier (#53).

**8. An empty surface has to distinguish "nothing yet" from "never".** The
console answered an unaskable policy with "Requests matching an `ask` rule
appear here" — true of a policy that can ask, and a promise this one could not
keep, on the one screen its operator was watching (#62). Same shape as the
amber `VERIFIED` column (#49): a state that renders as the healthy one teaches
its reader to stop looking.

**9. State the limits in the same change that ships the capability.** README
§ Security model has a "what it does not give you" list, `docs/agents.md`
§ Multiple agents names what does not scale with what it costs, README § Not
built yet is honest, and a profile
note says which endpoints are unreachable through the proxy rather than letting
an agent discover it as a 404 (#13, #28, #41). A capability whose limits are not
written down will be relied on past them.

## Where things live

| | |
| --- | --- |
| `src/config.rs` | the policy file: shape, `validate()`, defaults |
| `src/gate.rs` | the one decision — targets, workload scope, ACL, human |
| `src/acl.rs` `src/approval.rs` | rule matching; the ask queue and session answers |
| `src/proxy.rs` `src/gateway.rs` `src/mcp.rs` | data plane, MCP gateway, stdio bridge |
| `src/enroll.rs` | every write to the policy file, from both front ends |
| `src/profiles.rs` | the service catalog (`references/profiles.md`) |
| `src/verify.rs` `src/discovery.rs` | probing a real service; what `check`/`verify` report |
| `src/secrets.rs` `src/credentials.rs` | reference parsing, resolution, caching, injection |
| `src/audit.rs` | the hash-chained log and its reader |
| `src/tui/` | the console: `form.rs` fields, `browse.rs` picker, `approve.rs` dialogue |
| `src/paths.rs` | XDG config/state locations and the env overrides |
| `tests/*_e2e.rs` | a real proxy in front of a mock upstream, per surface |

## The verification bar

Run all of these locally and report the numbers in the PR. CI runs the same on
Linux and macOS, so a skipped one is only a slower way of finding out.

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
./scripts/check-version.sh
cargo audit                      # a known advisory fails the build here
brew style Formula/agent-iap.rb  # if the formula or its generator changed
```

Beyond green:

- **A regression test must fail on `master` and pass on the branch.** Check it
  both ways and say that you did (#19). A test that would have passed before the
  fix is not a regression test.
- **Test the real bypass, not a narrower denial.** The path-traversal test
  grants `/v1/**` so it reproduces the actual escalation (#10).
- **Exercise it end to end against a running proxy** when the property only
  exists in a live process: streaming, reload, the ask queue, a rotated
  credential, a real vendor endpoint. Paste the result.
- **Do not let the shipped example config drift** — it is parsed and validated
  by a test, and the same discipline covers profiles: `tests/profiles_e2e.rs`
  materialises every profile at every access level through the daemon's own
  `validate()`.

## The PR

- One commit per PR, message and PR body in the same voice: what was broken,
  what changed, what it is careful about, how it was verified. Sentence titles
  that name the behaviour ("A reset should leave it asking"), not
  `type(scope):` prefixes — recent history has moved off those.
- **Release notes are generated from PR titles.** A change that stops an
  existing `iap.toml` loading has to say so in its title.
- Close the issue from the body (`Closes SIRI-123`).
- Update the docs in the same PR as the behaviour — the README is the landing
  page and `docs/` is the reference, so most behaviour changes land in `docs/`.
  Docs that lag are how the short form of `audit tail` came to be documented
  before it worked (#24).
- Sign every commit (SSH), keep PII out of messages and PRs, branch off and back
  onto `master`, and watch the PR for Copilot review comments — fix them and
  resolve the threads.
- Never commit a policy file, an audit log, a token, or your own scratch files.
  `.gitignore` covers the first three at any depth; the fourth is on you.
- Group Dependabot bumps into one pass rather than merging them serially — each
  one rewrites `Cargo.lock` (#8).
