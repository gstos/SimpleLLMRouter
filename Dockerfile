# syntax=docker/dockerfile:1

# ---- build ----
# Runs on the build machine's own architecture and cross-compiles for the target,
# so multi-arch builds (linux/amd64, linux/arm64) need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev COMMIT=none
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -o /out/simple-router \
      -ldflags="-s -w -X github.com/gstos/SimpleLLMRouter/cmd.version=$VERSION -X github.com/gstos/SimpleLLMRouter/cmd.commit=$COMMIT" . && \
    mkdir -p /out/etc/simple-router

# ---- lego (only used by the "acme" target) ----
# lego v5, the ACME client the router drives in TLS mode "acme".
FROM --platform=$BUILDPLATFORM golang:1.27 AS lego
ARG TARGETOS TARGETARCH
ARG LEGO_VERSION=v5.6.0
# Cross-compiled installs land in /go/bin/<os>_<arch>/, native ones in /go/bin/.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go install -trimpath -ldflags="-s -w" github.com/go-acme/lego/v5@$LEGO_VERSION && \
    { cp /go/bin/${TARGETOS}_${TARGETARCH}/lego /lego 2>/dev/null || cp /go/bin/lego /lego; }

# ---- base runtime (shared by both images) ----
FROM gcr.io/distroless/static-debian12:nonroot AS base
COPY --from=build /out/simple-router /usr/local/bin/simple-router
# Owned by the runtime user so the CLI helpers (key add, rotate...) can write here
# when a named volume is used. 65532 is distroless' nonroot.
COPY --from=build --chown=65532:65532 /out/etc/simple-router /etc/simple-router

# Config directory. Mount a directory here, not a single file: config edits are
# atomic renames, which a single-file bind mount doesn't follow, so hot reload
# would miss them. The master key comes as a secret file at the path below; if
# none is mounted, the router starts sealed (`docker exec -it <c> simple-router unseal`).
VOLUME ["/etc/simple-router"]
ENV SIMPLE_ROUTER_CONFIG=/etc/simple-router/config.yaml \
    SIMPLE_ROUTER_MASTER_KEY_FILE=/run/secrets/master_key

EXPOSE 8080
USER nonroot:nonroot

# Calls the router's own /healthz over loopback; no curl/shell needed.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/simple-router", "ping"]

ENTRYPOINT ["/usr/local/bin/simple-router"]
CMD ["serve"]

# ---- acme: the router plus lego ----
# docker build --target acme -t simplellmrouter:acme .
FROM base AS acme
COPY --from=lego /lego /usr/local/bin/lego

# ---- default: the router only (last stage, so a plain `docker build` gives this) ----
FROM base AS runtime
