# The release image, assembled from the binaries `.github/workflows/release.yml`
# has already built and checksummed. Nothing is compiled here on purpose: the
# image and the tarball on the release page are then the same bytes, and both
# architectures build on one runner with no emulation.
#
# It therefore needs `dist/<arch>/agent-iap` in the context, which a fresh
# checkout does not have. To build it by hand:
#
#   cargo build --release --target x86_64-unknown-linux-musl
#   mkdir -p dist/amd64 && cp target/x86_64-unknown-linux-musl/release/agent-iap dist/amd64/
#   docker build -t agent-iap .

# Pinned to the build platform so its `RUN` is native whichever architecture
# the image is for — it only moves files around, and emulating that would be
# the one slow step in an otherwise instant build.
FROM --platform=$BUILDPLATFORM busybox:stable-musl AS layout
ARG TARGETARCH
COPY dist/$TARGETARCH/agent-iap /rootfs/usr/local/bin/agent-iap
# The state directory is where the audit log and the `admin-token` beside it
# land, so it is the one path the proxy writes to and the one that has to be
# owned by the user it runs as.
RUN chmod 0755 /rootfs/usr/local/bin/agent-iap \
    && mkdir -p /rootfs/etc/agent-iap /rootfs/var/lib/agent-iap \
    && chown -R 65532:65532 /rootfs/var/lib/agent-iap \
    && chmod 0700 /rootfs/var/lib/agent-iap

# No shell, no package manager, no libc: this process holds every upstream
# credential the policy file names, and a distroless base is most of what keeps
# a compromised proxy from being a place to run anything else. The binary is
# static and its TLS roots are compiled in, so it needs nothing from the image.
#
# The cost is in docs/deployment.md: `op://` secret references shell out to
# the 1Password CLI, and stdio MCP servers are child processes — neither exists
# in here. Use `env:`/`file:` references and MCP servers over HTTP, or build on
# a base that carries the tools.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=layout /rootfs/ /

LABEL org.opencontainers.image.title="agent-iap" \
      org.opencontainers.image.description="Identity-aware proxy for LLM agents: authenticated, ACL-gated, audited access to APIs and MCP servers without handing over the credential." \
      org.opencontainers.image.source="https://github.com/vpetersson/agent-iap" \
      org.opencontainers.image.licenses="MIT"

# `--config` still overrides it; this is the path docs/deployment.md uses,
# applied to every subcommand rather than just to `run`.
ENV IAP_CONFIG=/etc/agent-iap/iap.toml

# The audit log, the `admin-token` beside it and the console's diagnostics log.
# The nonroot user in this image has no home directory for the default
# `~/.local/state/agent-iap` to resolve against, so say where instead.
ENV IAP_STATE_DIR=/var/lib/agent-iap

# The data plane agents connect to, and the loopback control plane. Both are
# whatever the policy file says — these are the defaults `init` writes.
EXPOSE 8080 8081

WORKDIR /var/lib/agent-iap
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/agent-iap"]
# With no terminal to draw on, `run` starts without the console and answers an
# `ask` over the control plane or not at all — so this needs no TTY.
CMD ["run"]
