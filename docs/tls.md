# TLS

`[server.tls]` puts the proxy on HTTPS. Absent, it speaks plain HTTP exactly as
before, so nothing existing changes by upgrading.

```toml
[server.tls]
cert = "file:/etc/agent-iap/fullchain.pem"     # PEM chain, leaf first
key  = "op://Infra/agent-iap tls/private key"  # PEM key: PKCS#8, PKCS#1 or SEC1
ca   = "file:/etc/agent-iap/root_ca.crt"       # optional: the CA that signed it
```

All three are *references*, resolved the way every other credential is — a key
is a credential, and this file stays safe to commit. All three are resolved
**and parsed** at startup, before anything binds: a mismatched pair, a malformed
PEM or a locked vault stops the process rather than failing the first handshake.
`agent-iap check` runs the same load.

`ca` is for the one client this project runs itself — `agent-iap mcp`, dialling
the control plane. Public CAs need nothing here. A private CA wants its root
named, so the trust anchor is the CA rather than whatever the served chain
happens to contain. Leave it out and the bridge verifies against `cert` itself,
which is right for a self-signed certificate. It buys agents nothing: they are
other processes on other hosts, and get the root the way they get everything
else — see [§ Small Step](#small-step) below.

The control plane follows the proxy onto TLS without being named twice — it
carries the admin token and is no less sensitive. Give it a certificate of its
own only if it needs one:

```toml
[server.admin_tls]
cert = "file:/etc/agent-iap/admin-fullchain.pem"
key  = "file:/etc/agent-iap/admin-key.pem"
ca   = "file:/etc/agent-iap/root_ca.crt"
```

The listener offers ALPN `h2` and `http/1.1`, so an agent that speaks HTTP/2
keeps speaking it. Versions and cipher suites are rustls's defaults and there is
no knob for them: a policy file that can select TLS 1.0 is a liability.

The MCP bridge reads the same policy file, so `agent-iap mcp` finds the control
plane on `https://` by itself and verifies it against `ca`, or against `cert`
when there is no `ca`. Verification is never turned off — which is why the
certificate the control plane serves has to name the address it is reached at;
see below.

Renewal does not mean a restart. A reload re-reads `cert` and `key` from source
and serves the new one from the next handshake; connections already up keep
what they negotiated. What it needs is a *trigger*, and the trigger is `SIGHUP`
or the console's `r` — not the certificate file itself, and not a policy file
that merely changed, which serves the material this process already parsed ([§
Reloading](policy-file.md#reloading)). So pair the renewal with `systemctl
reload agent-iap`. Client certificates are not an identity here either: agents
are still the bearer token.

## Where the certificate comes from

Nothing above is provider-specific. `cert` and `key` are a PEM chain and a PEM
key, `ca` is a PEM bundle, so ACME, an internal CA, a corporate PKI or a
certificate someone handed you on a USB stick all work identically — the proxy
never asks who signed it.

Two are worth writing down: they are the shortest paths from "loopback only" to
"an agent on another host", and they differ on the thing that actually costs you
something — who has to be told to trust the result.

| | Tailscale | Small Step (`step-ca`) |
| --- | --- | --- |
| Signed by | Let's Encrypt, via Tailscale — a public root | a CA you run |
| Clients need a CA certificate | no, the system trust store already has it | yes, your root, on every host an agent runs on |
| `ca` in the policy file | leave it out | name your root |
| The name it is valid for | `host.tailnet-name.ts.net`, not yours to choose | whatever you issue for |
| Lifetime | 90 days | 24 hours by default, and yours to set |
| Also answers | how the agent reaches the host at all | nothing — bring your own network |

Tailscale is for getting an agent off this host talking to the proxy this
afternoon: trusted everywhere with no client-side step, and the tailnet also
answers how an agent on a laptop reaches a proxy in a rack. Small Step looks
like the rest of a company's internal x509 — you run the CA, set the lifetimes
and the naming, and point every client at your root. That extra step is the
difference, and the reason it scales to things other than this proxy.

A self-signed certificate is a third path, legitimate for a single host: the
same client-side work as a private CA, none of its reach.

## Tailscale

Enable HTTPS for the tailnet once, in the admin console under **DNS → HTTPS
Certificates**, then on the host that runs the proxy:

```bash
# The machine's own MagicDNS name; `tailscale status` prints it.
sudo tailscale cert \
  --cert-file /etc/agent-iap/fullchain.pem \
  --key-file  /etc/agent-iap/key.pem \
  iap.tailnet-name.ts.net
```

```toml
[server]
listen = "100.x.y.z:8080"     # the tailnet address — see below

[server.tls]
cert = "file:/etc/agent-iap/fullchain.pem"
key  = "file:/etc/agent-iap/key.pem"
```

No `ca`: Let's Encrypt is already in every trust store there is.

Agents use `https://iap.tailnet-name.ts.net:8080` and need nothing else: the
chain ends at a public root, so `curl`, `requests` and `node` verify it with no
configuration and no bundle to distribute.

Bind `listen` to the tailnet address rather than `0.0.0.0`. The certificate is
valid for the `ts.net` name only, so a LAN client gets a name mismatch — and the
process holding every upstream credential has no reason to accept connections on
an interface whose callers it cannot serve.

The certificate lasts 90 days. Re-running the same `tailscale cert` command
renews it; the renewal and whatever makes the proxy pick it up belong in one
unit. Headless, that is a restart:

```bash
tailscale cert --cert-file /etc/agent-iap/fullchain.pem \
               --key-file  /etc/agent-iap/key.pem \
               iap.tailnet-name.ts.net \
  && systemctl restart agent-iap
```

Or `systemctl reload agent-iap` instead of `restart`: the new certificate is
served from the next handshake and nothing in flight is dropped ([§
Reloading](policy-file.md#reloading)).

## Small Step

`step-ca` issues from a CA you run, which is the arrangement most companies
already have for internal services. With a CA up and this host bootstrapped
against it (`step ca bootstrap --ca-url … --fingerprint …`):

```bash
# Writes the leaf first and then the intermediate, which is the order `cert` wants.
step ca certificate iap.internal.example.com \
  /etc/agent-iap/fullchain.pem /etc/agent-iap/key.pem

# The root every agent will have to trust.
step ca root /etc/agent-iap/root_ca.crt
```

```toml
[server.tls]
cert = "file:/etc/agent-iap/fullchain.pem"
key  = "file:/etc/agent-iap/key.pem"
ca   = "file:/etc/agent-iap/root_ca.crt"
```

`step ca certificate` writes the leaf *and* the issuing intermediate into the
crt file, which is exactly what `cert` wants: the intermediate is what lets an
agent build a path from the leaf to your root. Serving a bare leaf extracted
from that file is the mistake to avoid.

`ca` is about verifying rather than serving: it names the root that
`agent-iap mcp` checks the control plane against. Without it the bridge treats
the served chain as its own anchor, which works by coincidence and stops working
the moment someone splits the file.

Then the half Tailscale does not have, and the one `ca` does not help with:
`ca` is read by this process, and agents are other processes on other hosts.
Every host an agent runs on needs the root, by whichever of these the client
reads:

```bash
curl --cacert /etc/agent-iap/root_ca.crt https://iap.internal.example.com:8080/…

export SSL_CERT_FILE=/etc/agent-iap/root_ca.crt        # curl, and most of C
export REQUESTS_CA_BUNDLE=/etc/agent-iap/root_ca.crt   # python-requests
export NODE_EXTRA_CA_CERTS=/etc/agent-iap/root_ca.crt  # node

# Or install it once into the host's trust store and let every client find it:
step certificate install /etc/agent-iap/root_ca.crt
```

The failure mode to plan for is an agent that cannot verify and is "fixed" with
`curl -k` or `verify=False`. It is now handing its bearer token to whatever
answers the address, which is the attack TLS was added to stop — so ship the
root with the agent's image or its config, and treat a verification failure as a
deployment bug rather than a flag to add.

`step-ca` issues short certificates on purpose — 24 hours by default, and the
provisioner caps what you may ask for. At that rate you want a reload rather
than a restart, and `step ca renew` can own both ends of it:

```bash
step ca renew --daemon \
  --exec "systemctl reload agent-iap" \
  /etc/agent-iap/fullchain.pem /etc/agent-iap/key.pem
```

## The control plane's certificate has to match the address

The control plane inherits `[server.tls]` when `[server.admin_tls]` is absent,
but it is *reached* at `admin_listen`, usually `127.0.0.1:8081`. A certificate
issued for `iap.tailnet-name.ts.net` or `iap.internal.example.com` is not valid
for `127.0.0.1`, and `agent-iap mcp` still checks the name — so the mismatch
surfaces as a refused handshake, not a quiet downgrade.

Give the control plane a certificate that names the address it is actually
reached at:

```bash
step ca certificate localhost --san localhost --san 127.0.0.1 \
  /etc/agent-iap/admin-fullchain.pem /etc/agent-iap/admin-key.pem
```

```toml
[server.admin_tls]
cert = "file:/etc/agent-iap/admin-fullchain.pem"
key  = "file:/etc/agent-iap/admin-key.pem"
ca   = "file:/etc/agent-iap/root_ca.crt"
```

Tailscale cannot issue that one — it signs `ts.net` names only — so a proxy
fronted by Tailscale wants a separate `step-ca` or self-signed certificate for
its control plane. The alternative is `--admin-url https://…ts.net:8081` against
an `admin_listen` on the tailnet address, which moves the admin token onto the
tailnet to save a certificate. Prefer the certificate.
