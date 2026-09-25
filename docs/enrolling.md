# Enrolment

Everything the enrolment commands write, what they refuse to write, and how to
take it all back. [§ Quickstart](../README.md#quickstart) is the short version
of the first two.

## Starting the file

`init` writes the proxy and nothing else, on purpose: a starter file that
guesses at an upstream has to be read before it can be trusted, and a token
minted for an agent you may never create is a live credential in your
scrollback. Everything else is added by the command that names it, validated
against the same schema the proxy loads — a rejected flag leaves the file
untouched.

If you would rather start from something already filled in, two templates do:

```bash
agent-iap init --template starter                      # one agent, Anthropic, one rule
agent-iap init --template full --agent claude-code     # the annotated example, every pattern
agent-iap init --force                                 # replace an existing file
```

`--template full` carries its own copy of `iap.example.toml`, so it works from an
installed binary with no checkout.

For a service that already has a profile, the enrolment is one command — the
base URL, the credential scheme and the scopes, all worked out — see
[§ Profiles](profiles.md):

```bash
agent-iap profile add cloudflare --secret op://Private/Cloudflare/token \
    --var account_id=3f1c…
agent-iap upstream add gh --profile github --secret op://Private/GitHub/token
```

It grants nothing. The service is enrolled and no rule permits it, so the first
call an agent makes falls through to `acl_default` and stops at the console,
where answering it writes the rule — for the agent that asked and the call it
asked for. `--grant` writes the profile's reviewed rules up front instead.

## Nothing is granted by default

The enrolment commands compose the same way for everything else:

```bash
agent-iap upstream add github --base-url https://api.github.com \
    --auth bearer --secret op://Private/GitHub/token
agent-iap acl add --agent 'ci-*' --target github --methods GET --paths '/repos/**' \
    --action allow
agent-iap acl add --target github --methods DELETE --paths '/**' --action ask
agent-iap agent add ci-runner --name "CI" --target github
```

**No command here grants anything by default.** `acl add --action` defaults to
`ask`, not `allow`: every other flag on it defaults to the widest thing it can
mean — every agent, kind, target, method and path — so a default `allow` would
let the bare command grant everything to everyone, ahead of the `acl_default`
this is all built on. The widest rule it can write stops on a human instead; to
grant, say `--action allow`.

**And a grant has to be about a service.** `--target` defaults to `*` like the
rest, so `--action allow` with nothing else would be a rule about every service
the proxy will ever front — including the one enrolled next week, which nobody
would be asked about, because a rule written before it existed already says
yes. That is refused rather than written:

```bash
agent-iap acl add --target github --action allow    # this service
agent-iap acl add --action allow --any-target       # all of them, said out loud
agent-iap acl add --action allow                    # refused: which service?
```

`ask` and `deny` over a pattern are untouched — neither widens as the file
grows. A blanket grant already in the file is named by `agent-iap check`, and
by the enrolment that walks into one:

```console
$ agent-iap upstream add stripe --base-url https://api.stripe.com --auth bearer \
    --secret op://Private/Stripe/key
Added upstream `stripe` to /home/you/.config/agent-iap/iap.toml.
Agents reach it at `/stripe/<path>`.

WARNING: `stripe` is already allowed, and nothing here granted it: acl[0]
`console-allow-claude-code-*` allows every target matching `*`, which now
includes this one. Its first call goes out with the credential attached and
nobody asked. Narrow that rule to the services it is about, or take it out:
  agent-iap acl rm 0
```

The same goes for enrolment. `upstream add`, `mcp-server add` and `profile add`
write the service and nothing else: what an agent may do with it is a separate
decision, and the default is that a human makes it when the agent actually
calls. `profile add --grant` is the advanced option — the profile's reviewed
rules, written up front, because somebody typed the flag that writes them.

`agent add` asks the same question about the gate in *front* of the ACL. An
agent's `targets` is what it may address at all, and an absent one means every
upstream and every MCP server this proxy fronts, including ones added later —
so a bare `agent add` is not allowed to write one:

```bash
agent-iap agent add ci-runner --target github        # this, and nothing else
agent-iap agent add ci-runner --any-target           # all of them, said out loud
agent-iap agent add ci-runner                        # refused: say which
```

The blanket grant is still there; it is a decision rather than the thing you
get for not mentioning it. The *file* is unchanged — an absent `targets` still
reads as "any", so every policy already written goes on meaning what it meant,
and `agent-iap check` names the agents that hold one so an existing blanket
grant is something you are told about rather than something to go looking for.

Rules are **appended**, never inserted, because first match wins — a new rule can
never silently shadow one already in the file, and `acl add` prints the position
it landed in. `agent add --target` refuses a target that names no upstream or MCP
server: that mistake leaves a valid file, an agent that looks scoped, and every
one of its calls denied by a rule that never mentions it.

Each of those has an `rm` — see [§ Revoking and removing](#revoking-and-removing).

`agent-iap gen-token <id>` still prints an `[[agents]]` block to paste, for the
cases where the policy file is generated by something other than this CLI.

## Enrolling anything else

The enrolment commands cover every scheme the proxy supports, including the two
that mint a token rather than forwarding a secret:

```bash
# A Google service account, no editor and no JSON key in the file.
agent-iap upstream add gsc --base-url https://searchconsole.googleapis.com \
    --auth service-account-jwt --key-file op://Private/GCP/credential \
    --scope https://www.googleapis.com/auth/webmasters.readonly

# An API whose *user* field is the credential.
agent-iap upstream add graylog --base-url https://graylog.example.com/api \
    --auth basic --username-secret op://Private/Graylog/token --secret literal:token

# MCP servers, remote and local.
agent-iap mcp-server add posthog --url https://mcp.posthog.com/mcp \
    --auth bearer --secret op://Private/PostHog/key
agent-iap mcp-server add notes --command notes-mcp --arg --stdio \
    --env NOTES_TOKEN=op://Private/Notes/token
```

A rule can be given a deadline, from the console's dialogue or from here:

```bash
# Access for the length of the job, and not a minute more.
agent-iap acl add --name migration-window --agent claude-code \
    --target github --methods POST --paths '/repos/acme/**' \
    --action allow --expires-in 90m
```

`--expires-in` takes `30s`, `5m`, `1h`, `7d` — never a bare number, because
being wrong about the unit by a factor of sixty only goes one way. The deadline
is written into the rule as a UTC timestamp and checked on every request, so it
survives a restart. Expired rules are not swept out of the file: they stay
listed as `expired`, because a grant that was made and has run out is worth a
record.

`--username-secret` is for the APIs that put the credential in the user half of
basic auth — Graylog's `<token>:token`. A plain `--username` would mean the token
living in a file meant to be committable, so the user field takes a reference
and the password takes the scheme's documented constant. That constant is the
one `literal:` the loader does not complain about, and only there: a `literal:`
in `--username-secret` is still refused.

### Verifying

`check` asks the file a question: does it parse, does every reference resolve,
do the rules make sense. The other half is only answerable by the service:

```bash
agent-iap upstream verify github --path /user     # one upstream, at a real endpoint
agent-iap upstream verify                         # every upstream in the file
agent-iap mcp-server verify posthog               # the handshake, and the tool list
```

It makes the call. The credential is attached exactly the way the proxy attaches
it — same injector, same URL construction — so an OAuth or service-account
upstream is verified by *minting* the token rather than by assuming a mintable
one. What comes back is a step at a time, because "it failed" and "it failed at
the credential" are different problems:

```
upstream `github` → https://api.github.com
  ok       endpoint    GET https://api.github.com/user
  ok       credential  bearer token resolved from op://Private/GitHub/token
  FAILED   reach       the service rejected the credential — 401 Unauthorized in 94ms
  warn     policy      no ACL rule reaches it — agent calls will be denied by
                       `<default>`. Add one: agent-iap acl add --kind http
                       --target github --methods GET --paths '/**' --action allow
```

The last step catches the enrolment that looked like it worked. A service can be
in the file, resolve its credential, answer the probe — and still be unreachable
by every agent, because nothing in the ACL names it and the fallthrough is a
`deny`. For
an MCP server it catches the narrower version: rules that scope `tools/call` and
never admit `initialize`, so the session never opens.

What the answer is worth depends on where the probe was aimed, so the verdicts
split on it:

- **A 401 fails, wherever it was aimed.** The service looked at this credential
  and said no; being pointed at the root does not soften that.
- **Any other 4xx from the root passes**, reported as *reachable, credential not
  exercised*. Almost no API serves anything at its root, so that 404 proves the
  host is real and nothing else.
- **A 404 from a real endpoint warns.** The base URL is wrong, or the API moved.
- **A 403 from a real endpoint warns** — accepted but not entitled, usually a
  missing scope.

A redirect is reported rather than followed, since a 302 to a login page reads
as a 200 to anything that follows it. Exit status is zero unless something
failed.

A conclusive answer needs a real endpoint, and passing `--path` every time is
the part nobody remembers — so an upstream can carry it:

```toml
[[upstreams]]
name = "cloudflare"
base_url = "https://api.cloudflare.com/client/v4"
verify_path = "/accounts/3f1c…/tokens/verify"
```

`verify_path` is what a verify calls when nobody passed `--path` — on the
enrolment, on `v` in the console, and on an `upstream verify` months later. An
explicit `--path` still wins. An upstream carrying none falls back to the
profile whose base URL matches it, so nothing has to be re-enrolled to become
verifiable.

Profiles write it for the services that have somewhere safe to send it, and
`agent-iap profile show` says which those are:

```
verify      GET /webmasters/v3/sites
verify      nothing cheap and safe on file — `upstream verify` will reach this
            service without exercising the credential unless you pass --path
```

An endpoint earns that line by being a **GET**, being **free**, and having **no
side effect** — a verify runs on a keystroke, so a probe that bills a unit or
writes something is worse than no probe at all. Several vendors have nothing
that qualifies: the GA4 Data API is POST-only, Semrush bills per call, Slack
answers `200 OK` with `"ok": false` in the body. Those are left blank on
purpose.

`--verify` runs the same thing as the last step of an enrolment:

```bash
agent-iap upstream add linear --profile linear --secret op://Private/Linear/key --verify
agent-iap mcp-server add notes --command notes-mcp --env NOTES_TOKEN=op://… --verify
```

After the write, never instead of it: the entry is in the file whatever comes
back, because the fix for a mistyped base URL is `upstream edit`, not the whole
enrolment again. Only the exit status carries the verdict. Nothing is verified
without being asked — the call is real and so is the credential, so it happens
on a flag or a keystroke and never on a timer.

In the console it is `v` on the upstreams or `mcp` pane, and a switch on the add
and edit forms that is on by default. The answer lands in a `VERIFIED` column
beside the row:

```
NAME                   BASE URL                             VERIFIED
dataforseo             https://api.dataforseo.com           ✓ credential ok
google-search-console  https://searchconsole.googleapis.com ! not entitled
semrush-v4             https://api.semrush.com/apis/v4      ✓ reachable
posthog                https://eu.posthog.com               ✗ rejected
linear                 https://api.linear.app               · not checked
```

`✓` passed, `!` worth a look, `✗` broken, `·` nobody has asked yet — by shape
before colour, so the column works for anyone who cannot tell the green from the
red. `✓ credential ok` means the service accepted it; `✓ reachable` means the
host answered and the credential was never put to the question.

### Getting the token out

Every command that mints a token — `init`, `agent add`, `agent rotate`,
`gen-token` — prints it once and puts it on your clipboard: a token with one
character missing authenticates nothing, and the plaintext it came from is
already gone.

It uses OSC 52, the escape sequence that asks the *terminal* to set the
clipboard, which is what makes it work over SSH, from inside a container, or
from a tmux pane on a jump host — none of which have a clipboard for `pbcopy` to
reach. Every terminal in common use implements it; tmux and screen forward it.
In the console, the modal that shows a token copies it on `c` and closes on
`esc`, `enter` or `q` — a named key rather than any key, because it is the only
time that token is on a screen.

Inside tmux the sequence is sent both ways it can be sent: bare, which tmux
forwards when `set-clipboard` is `on` or `external` (the default), and wrapped
in tmux's DCS passthrough, which needs `allow-passthrough on` (off by default
since tmux 3.3). If a copy from inside tmux still arrives nowhere, that pane has
turned off both:

```bash
tmux set -g set-clipboard on
```

```bash
agent-iap agent rotate ci-runner --no-clipboard   # just print it
export IAP_NO_CLIPBOARD=1                         # never copy, any command
```

The sequence is one-way, so nothing here can confirm the clipboard changed —
paste it somewhere before closing the terminal. And a desktop clipboard is
shared with everything else on that desktop, often kept in a history by a
clipboard manager; a fair trade for a token that buys nothing off this proxy and
rotates with one command, but yours to refuse. Nothing is copied when neither
stream is a terminal — a pipe, a file, a unit's journal — and never without a
line saying so. The sequence goes to the terminal rather than to stdout, so
`agent-iap gen-token > token.txt` still writes a file with a token in it and
nothing else.

### Revoking and removing

Every enrolment has an inverse, and the one that matters is the one you run at
2am:

```bash
# A token leaked. Mint the agent a new one, print it once, keep the id.
agent-iap agent rotate ci-runner

# Or retire the agent outright, taking the rules that named it.
agent-iap agent rm ci-runner --prune

agent-iap upstream rm github --prune     # also drops it from agents' `targets`
agent-iap mcp-server rm notes --prune
agent-iap acl rm 3                       # the `#` column of `agent-iap list acl`
```

`rotate` is the leaked-token path: a new token, the same agent id, and an audit
log that still reads as one agent rather than two. It refuses an agent whose
`token_ref` points into 1Password or a file — the token lives there, so that is
where it rotates.

A removal is validated exactly as an add is, so it cannot leave a file the proxy
would refuse to load: `upstream rm` will not strand a `targets` entry that names
it, and `--prune` will not empty an agent's `targets` altogether, because empty
means *any* target rather than none. A removal must not widen a grant on its way
past.

Without `--prune`, whatever named the removed thing stays and is printed by
number, so a rule matching nothing is something you were told about. Only rules
that name it *outright* are pruned: `agent = "ci-*"` covers a fleet, and one
member leaving is not that rule ending.

**With a console attached, these land within a second** — it watches the policy
file. Without one, nothing is reading the file, and a rotated token is not a
revoked one until the proxy restarts: every one of these commands says which you
are getting, because a revocation that has not taken effect is worse than one
you know is pending.

### Stopping everything

The inverses above each take one thing away. Sometimes the thing you want is
not one of them — an agent is behaving in a way you do not understand, a
credential may be out, or you simply want it all to stop while you go and look.
There are two ways to say that, and the difference between them is what they
outlive.

```bash
# Right now, for as long as this process runs. Writes nothing.
agent-iap run --lockdown

# For keeps. Deletes every rule and puts `acl_default` to `deny`.
agent-iap acl reset --deny
```

**Lockdown** is the switch on the console: `L` engages it, `L` lifts it, and
the header says `LOCKDOWN` in red for as long as it is on. Every request is
denied — including the ones an `ask` rule would have parked, because a prompt
nobody can answer with anything but "no" is a prompt worth not raising. It
decides *before* the rule list, so no rule can get in front of it, and it is
deliberately outside everything a reload swaps: a kill switch that the agent's
own `acl add`, or a config-management tool rewriting the file a minute later,
could lift without anybody deciding to is not a kill switch. The audit log
records the refusals against `<lockdown>` rather than a rule, so an hour later
it is clear what stopped them, and `/status` on the control plane reports it —
read-only, because the switch belongs on your terminal rather than behind an
admin token.

It writes nothing, which is the point: the file is still the record of what the
policy is, and lifting the switch serves that policy again with no window in
between and no restart.

**`acl reset --deny`** is the other half — the same state, written down. It
deletes every `[[acl]]` rule and sets `acl_default` to `deny`, which is the
pair the floor needs: rules under an `allow` default grant everything, and one
surviving `allow` rule over a `deny` default grants everything too. The next
`agent-iap run` starts from it, and because nothing in that file can ask,
startup says so.

```console
$ agent-iap acl reset --deny
Delete all 6 rules from /home/you/.config/agent-iap/iap.toml and set
`acl_default` to `deny`? [y/N] y
Removed 6 rules from /home/you/.config/agent-iap/iap.toml:
  acl[0] `anthropic-inference`
  acl[1] `gh-read`
  …
`acl_default` was `allow`, and is now `deny`.
Nothing matches now, so every request is denied, and nothing is asked.
Build it back up with `agent-iap acl add` — the audit log has what was being used.
```

**Without `--deny`, the same command means "start over" rather than "stop".**
It is the state `agent-iap init` writes, put back. It empties the rule list
exactly the same way, and writes `acl_default = "ask"`:
nothing matches, so every request stops on a human at the console instead of
being refused in silence. That is the state to reach for when the rule list has
grown past what anybody can reason about and the answer is to rebuild it from
what actually shows up — answer the calls as they arrive, and a standing answer
writes the rule back in.

```console
$ agent-iap acl reset
Delete all 6 rules from /home/you/.config/agent-iap/iap.toml and set
`acl_default` to `ask`? [y/N] y
Removed 6 rules from /home/you/.config/agent-iap/iap.toml:
  acl[0] `anthropic-inference`
  …
`acl_default` was `allow`, and is now `ask`.
Nothing matches now, so every request stops on a human at the console.
Answer them as they arrive — `a` allows one, and a standing answer writes the rule
back. `agent-iap acl add` still does too.
```

An `ask` nobody answers still denies, and a proxy running headless has nobody
to ask — `agent-iap run` says so on startup when the policy can ask and no
console is drawn. Reset without `--deny` is for the console; `--deny` is what a
unit file wants.

It asks first, and with stdin redirected it refuses rather than assuming:
`--yes` is how a script says it means it. The agents, upstreams, MCP servers
and credentials all stay — a panic button that also revoked everything would be
one nobody presses, and the state it left behind would take an afternoon to
rebuild rather than a command. What it does not do is reach into a proxy that
is already running: an answer given earlier in that session lives in the
process, not the file, so `--lockdown` is the one for right now.

The names of what was removed are printed because that is the last place those
rules exist. Getting back up is `agent-iap acl add`, and the audit log is the
record of which of them were being used.
