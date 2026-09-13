# Security policy

`agent-iap` is a credential broker. A deployment holds every upstream credential
it fronts, in one process, behind one ACL — so a bug here is not a bug in one
service, it is a bug in all of them at once. Please report what you find
privately, and give us a chance to ship a fix before it is public.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting:**
[report a vulnerability](https://github.com/vpetersson/agent-iap/security/advisories/new).
It opens a private thread visible only to the maintainers, and it is the same
place the advisory and the CVE are issued from if one is warranted.

**Please do not open a public issue for a security report.** The issue tracker
is world-readable and indexed, and a working description of how to get past the
ACL is a usable exploit against every deployment that has not upgraded yet.

A useful report says what an attacker starts with — an agent token, a policy
file, a position on the network, a compromised MCP server — and what they end up
with. The version (`agent-iap --version`), a minimal `iap.toml` that reproduces it
with the real secret references stripped, and the request or sequence that
triggers it are what make a report actionable fastest. If you only have a
suspicion and no reproduction, send it anyway; a wrong hunch costs an hour, an
unreported one costs more.

## What to expect

- **Acknowledgement within 3 business days.** If you have not heard anything by
  then, assume the notification was missed rather than ignored, and ping the
  thread.
- **An assessment within 7 days** — whether we can reproduce it, what we think
  the severity is, and whether it is in scope as described below. If we disagree
  that it is a vulnerability, you get the reasoning, not silence.
- **A fix in the next release** for anything confirmed, cut as a new CalVer
  version rather than held for a scheduled one. High-severity issues are cut as
  soon as the fix is verified.
- **Disclosure when the fix ships**, via a GitHub Security Advisory and the
  notes on the [release](https://github.com/vpetersson/agent-iap/releases) that
  carries the fix. Ninety days from the report is the default deadline if a fix
  is taking longer than that; if you need a different timeline, say so in the
  report and we will agree one.
- **Credit in the advisory and the release notes**, under whatever name and link
  you want, or none if you would rather stay anonymous. There is no bug bounty —
  this is an unfunded open-source project, and paying in credit is the only
  honest offer.

## Supported versions

Versions are CalVer, `YYYY.MM.PATCH` (README § Versioning). Cargo reads the year
as the major, so every new month looks like a breaking change to a `^`
constraint — which means the usual "supported major versions" table would list
one row per month and say nothing.

**The most recent release is the supported one.** There are no maintenance
branches and nothing is backported: a security fix lands on `master` and goes
out as the next CalVer version, and upgrading to it is the remedy. The
compatibility surface is the policy file, so the
[release notes](https://github.com/vpetersson/agent-iap/releases) call out
anything that stops an existing `iap.toml` loading — a security upgrade tells
you up front whether it is a restart or an edit.

Reports against an older version are still welcome. We will reproduce against
the current release first; if the bug is already fixed there, the answer is the
upgrade, and the advisory will say which version fixed it.

## Scope

In scope — these are the properties this proxy exists to provide, and anything
that breaks one is a vulnerability:

- An agent reaching an upstream, path, method or MCP tool the ACL does not
  allow it, including via encoding, normalisation or request smuggling.
- An upstream credential — or a minted access token, or a TLS private key —
  reaching an agent, the audit log, stderr, the TUI, or a process argument.
- Forging, replaying or escalating an agent token or a workload token; a
  workload scope that widens rather than narrows; a token that outlives its
  lineage or the process that signed it.
- Bypassing control-plane authentication, or getting a `decide` answer to
  release a call it was not for.
- Tampering with the audit log in a way that `audit verify` still accepts, or
  suppressing a record for a request that was served.
- A dependency with a known advisory that is reachable in practice. (CI already
  fails on `cargo audit`, so this usually means one that is not yet published.)
- A published release artifact or container image that does not correspond to
  what the tagged source builds, or a `SHA256SUMS` that does not describe the
  assets published beside it.

Out of scope — these are documented limitations rather than bugs. README
§ Security model states each one and why:

- **The stdio MCP bridge is not a process boundary.** The child holds the
  credential in its environment, and a same-user process can read it. It buys
  policy and audit, not isolation.
- **Both credentials are bearer tokens: possession is proof.** Neither is bound
  to a channel. mTLS is what would fix that and is not built yet.
- **Workload scopes are the agent's own declaration.** They narrow under the
  ACL; they never widen it. An agent asking for everything it is entitled to
  gets a token as broad as its ACL entry.
- **The ACL sees method, path and tool name, not intent.** It cannot tell a
  reasonable `POST /v1/messages` from an expensive one; `ask` rules exist for
  where that distinction matters.
- **Response bodies are not inspected.** Nothing here stops an upstream from
  returning data the agent should not have.
- An operator writing a policy that grants more than they meant to, a
  `literal:` secret committed despite the tooling refusing to write one, or a
  host on which the attacker already has the proxy's own user.

If you think one of those limitations is worse in practice than the README
claims — that it is reachable in a way we have not written down — that is a
report we want, not an out-of-scope one. Send it.
