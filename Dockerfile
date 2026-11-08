# syntax=docker/dockerfile:1

# ---- build ----
# Runs on the build machine's own architecture and cross-compiles for the target,
# so multi-arch builds (linux/amd64, linux/arm64) need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/simple-router .

# ---- runtime ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/simple-router /usr/local/bin/simple-router

# Mount the config here; supply the master key as a secret file (or SIMPLE_ROUTER_MASTER_KEY).
ENV SIMPLE_ROUTER_CONFIG=/etc/simple-router/config.yaml \
    SIMPLE_ROUTER_MASTER_KEY_FILE=/run/secrets/master_key

EXPOSE 8080
USER nonroot:nonroot

# Calls the router's own /healthz over loopback; no curl/shell needed.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/simple-router", "ping"]

ENTRYPOINT ["/usr/local/bin/simple-router"]
CMD ["serve"]
