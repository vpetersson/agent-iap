# Development

```bash
cargo test        # 605 tests: unit + end-to-end through a real proxy, plain and over TLS
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

The end-to-end suite starts a proxy in front of a mock upstream and asserts the
properties that matter: the upstream receives the real key, the agent's token
stops at the proxy, denied calls never reach the network, an `ask` releases only
when a human answers, and the log verifies.

`tests/gateway_e2e.rs` holds the MCP gateway to the same properties over its own
surface, and asserts the one that spans both: the same call, refused through the
proxy, is refused through the gateway with the same sentence.

`tests/revoke_e2e.rs` covers the other direction: it revokes and rotates through
the enrolment API, restarts the proxy from the edited file, and asserts that the
token stopped working — and that the process still running has not noticed,
which is the caveat those commands print.

`tests/profiles_e2e.rs` does the same for the profiles, and builds its policy
with `profile add` rather than a fixture — so a profile whose base URL, scheme
or rules are wrong fails in CI rather than against the vendor. Every profile at
every access level is materialised and run through the daemon's own
`validate()`, and every MCP profile is asserted to admit `initialize`.

CI runs exactly the three commands above on Linux and macOS, plus `cargo audit`
over the dependency tree — a dependency with a known advisory fails the build —
`scripts/check-version.sh`, and `brew style` over the Homebrew formula, which is
the only thing here that is Ruby. Dependabot opens weekly grouped PRs for Cargo
and for the actions. Windows is not covered: the credential file permissions and
the MCP stdio bridge are Unix-shaped today.

`.github/workflows/release.yml` is the other half, and it runs the suite again
per target rather than trusting CI's: the Linux artifacts link musl, which is
not the libc CI's Linux job builds against, so passing there is not the same
claim as passing in what ships.

## Versioning

CalVer, `YYYY.MM.PATCH`: `2026.9.0`, then `2026.9.1` for the next release that
month, then `2026.10.0`. A version says when a build was cut, which is the
question you actually have about something you deployed six weeks ago.

The month is not zero-padded: Cargo requires a semver-shaped version and semver
forbids leading zeros, so `2026.09.0` is not a version and `2026.9.0` is. Cargo
therefore reads the year as the major, and every new month looks like a breaking
change to a `^` constraint — which is honest enough for a daemon you deploy
rather than a library you link. The compatibility surface that matters is the
policy file, and changes that stop an existing `iap.toml` loading are called out
in the [release notes](https://github.com/vpetersson/agent-iap/releases). Those
are generated from pull request titles, so such a change has to say so in its
title.

Cutting a release:

```bash
scripts/bump-version.sh                  # today's CalVer → Cargo.toml + Cargo.lock
git commit -am "chore: release 2026.9.1"
git tag v2026.9.1 && git push && git push --tags
```

`scripts/bump-version.sh` works out the next version itself — the patch
continues within a month and resets when the month rolls over — and refuses to
leave the tree edited if what it produced is not valid.

The tag is the whole trigger: pushing it runs
[`.github/workflows/release.yml`](../.github/workflows/release.yml), which
builds the four platforms in [§ Install](../README.md#install), runs the test
suite on each target the runner can execute, attaches the tarballs and a
`SHA256SUMS` to a GitHub Release, pushes the container image built from those
same binaries, and rewrites `Formula/agent-iap.rb` from the checksums it just
published. Nothing in it starts until `scripts/check-version.sh` has passed: it
runs in CI on every push and pull request, and on a `v…` tag it additionally
requires the tag and `Cargo.toml` to agree — so a release cannot report a
version that is nowhere in the history.
