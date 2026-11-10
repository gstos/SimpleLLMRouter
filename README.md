# simple-router

An OpenRouter-compatible LLM router in Go.

- **OpenRouter/OpenAI-compatible API**: chat completions (with streaming), completions,
  embeddings and rerank, under both `/api/v1` and `/v1`.
- **Anthropic Messages API** (`/v1/messages`), routed natively to Anthropic-compatible providers
  with the same priorities, failover and sticky routing.
- **Priority lists per model**: lower priority first, round robin within a priority,
  failover to the next target when a provider fails.
- **Sticky routing**: follow-up requests in a conversation stay on the same provider, so its
  prompt cache keeps working, including after a failover.
- **Health checks**: background probes, a CLI check and an admin endpoint.
- **Encrypted provider credentials** (AES-256-GCM) under a master key; the router starts
  **sealed** and waits for the key if none is provided.
- **Direct provider access** (`/provider/<name>/...`): any path and API format on one provider,
  either with router keys (the router holds the provider's key) or with the client's own credentials.
- **Per-conversation session header** for providers that require one (e.g. OpenCode Go).
- **Client API keys** with access to all models or to glob patterns, stored only as hashes.
- **HTTPS** with automatic certificates from Let's Encrypt or any ACME CA (via
  [lego](https://go-acme.github.io/lego/), HTTP-01 or DNS-01 with wildcards), your own
  certificates (renewed by any tool), or a generated self-signed one, all swapped in live.
- **Client IP allowlist** (`server.allow_cidrs`) for every route, enforced before the TLS handshake.
- **Hot reload** of the config, live key rotation, and a CLI to manage it all.

## Install

**Release binaries** for Linux, macOS and Windows (amd64 and arm64) are attached to each
[GitHub release](https://github.com/gstos/SimpleLLMRouter/releases), with `checksums.txt`:

```sh
# e.g. macOS on Apple Silicon
curl -LO https://github.com/gstos/SimpleLLMRouter/releases/download/v0.2.1/simple-router_0.2.1_darwin_arm64.tar.gz
tar xzf simple-router_0.2.1_darwin_arm64.tar.gz
./simple-router version
```

The macOS binaries aren't signed: if macOS blocks the first run, clear the download flag with
`xattr -d com.apple.quarantine simple-router`.

**Container image** (`linux/amd64` and `linux/arm64`, so it runs natively on Apple Silicon):

```sh
docker pull ghcr.io/gstos/simplellmrouter:0.2.1    # or :latest
docker pull ghcr.io/gstos/simplellmrouter:0.2.1-acme   # with lego, for TLS mode acme
```

**From source** (Go 1.27+):

```sh
go build -o bin/simple-router .
# or: go install github.com/gstos/SimpleLLMRouter@latest   (installs the binary as SimpleLLMRouter)
```

## Quick start

```sh
simple-router init                           # master.key + config.yaml (HTTPS, self-signed) + admin key (printed once)
export SIMPLE_ROUTER_MASTER_KEY_FILE=$PWD/master.key

simple-router provider add openai --base-url https://api.openai.com/v1   # prompts for the key (hidden)
simple-router key add my-app --models 'openai/*'                          # prints the client key once
# add models[] to config.yaml (see "Configuration"), then:
simple-router validate
simple-router serve
```

```sh
curl --cacert tls/selfsigned.crt https://localhost:8080/api/v1/chat/completions \
  -H "Authorization: Bearer $CLIENT_KEY" \
  -d '{"model": "openai/gpt-4o", "messages": [{"role": "user", "content": "Hi"}]}'
```

The starter config serves HTTPS with a self-signed certificate, created on first start in `tls/`
next to the config. It covers `localhost`, `127.0.0.1` and `::1`; add other names with
`server.tls.domains` (see [HTTPS](#https)), and have clients trust `tls/selfsigned.crt`. For plain
HTTP (e.g. behind a reverse proxy that terminates TLS), run `init --no-tls` or set
`server.tls.mode: off`.

Any OpenAI or OpenRouter SDK works: point its base URL at `https://localhost:8080/api/v1` (or `/v1`).

## Configuration

One YAML file (`config.yaml` by default; `-c` or `SIMPLE_ROUTER_CONFIG` to change it).
[`config.example.yaml`](config.example.yaml) shows every setting. Settings can be overridden by
env vars, e.g. `SIMPLE_ROUTER_SERVER_LISTEN=:9000`.

```yaml
master_key_check: kcv:v1:...       # fingerprint of the master key (not secret); written by init

server:
  listen: ":8080"
  request_timeout: 5m              # whole request, including failover attempts
  max_body_bytes: 33554432         # 32 MiB
  sticky_ttl: 10m                  # conversation pinning (sliding); negative disables
  failure_cooldown: 30s            # a failed target is moved to the back for this long
  health_interval: 60s             # background provider probes; 0 disables
  health_timeout: 10s
  tls:                             # see "HTTPS"
    mode: off                      # off | file | self-signed

providers:                         # OpenAI-compatible upstreams
  - name: openai
    base_url: https://api.openai.com/v1
    api_key: enc:v1:...            # `provider add` encrypts it; omit for no auth
    # auth_header: api-key         # default Authorization
    # auth_scheme: none            # default Bearer; "none" sends the raw key
    # headers: {X-Title: my-app}   # extra headers on every request
    # paths: {rerank: /v2/rerank, health: /models}   # per-endpoint path overrides
    # base_urls: {rerank: https://api.openai.com/v2} # per-endpoint base URL (same host; see below)
    # session_header: X-Opencode-Session            # send a per-conversation id (see below)
    # auth: managed                # or passthrough: client credentials forwarded (see "Direct provider access")
    # allow_paths: ["/v1/*"]       # limit /provider/openai/... to these paths
    # external: true               # outside this deployment (paid/remote API): never used for a forwarded request
    # peer: true                   # another simple-router (see "Peer routers"); no api_key, client credentials forwarded
    # ca_file: /etc/sr/ca.pem      # PEM bundle trusted (only it) for this provider's HTTPS: requests and probes

models:
  - name: openai/gpt-4o            # the id clients send
    aliases: [gpt-4o]              # other ids that route the same way (optional)
    type: chat                     # chat (default) | embedding | rerank | messages (Anthropic) | systemone
    targets:
      - {provider: openai, model: gpt-4o, priority: 1}
      - {provider: azure,  model: gpt-4o, priority: 1}         # same priority: round robin
      - {provider: openrouter, model: openai/gpt-4o, priority: 2}   # fallback

api_keys:                          # client keys; only hashes are stored
  - name: admin
    hash: sha256:...
    models: ["*"]                  # glob patterns; ["*"] or empty = all models
    admin: true                    # may call /admin endpoints
    providers: ["*"]               # may use /provider/<name>/ for these (default: none)
```

**Per-endpoint base URL.** The upstream URL is `base_url` plus the endpoint's path (`paths`, or
the default: `/chat/completions`, `/embeddings`, `/models` for health...). When one account serves
APIs under different prefixes (System One on OpenCode Go, a local server with a separate embeddings
path...), `base_urls` replaces `base_url` for the endpoints it names (`chat`, `completions`,
`embeddings`, `rerank`, `messages`, `count_tokens`, `systemone`, `health`), so a single provider
keeps one key, one header set and one health entry instead of a copy per prefix:

```yaml
  - name: example
    base_url: https://api.example.com/v1        # chat, completions, health...
    base_urls:
      embeddings: https://api.example.com/inference/v1
    paths: {embeddings: /embed}                 # -> https://api.example.com/inference/v1/embed
```

Each entry must use the same scheme and host (and port) as `base_url`, so the provider's key never
goes to another host; use a separate provider for that. Direct access (`/provider/<name>/<path>`)
always uses `base_url`.

**Session header.** Some providers want an id tying requests to a conversation. OpenCode Go
(`https://opencode.ai/zen/go/v1`) rejects third-party requests without `X-Opencode-Session`
(HTTP 400 `MissingSessionID`). With `session_header` set, the router sends that header on every
request to the provider, with an id that stays the same for every turn of a conversation: 32 hex
characters hashed from the [sticky routing](#routing) key (client key, model and conversation), so
the conversation and the key name aren't revealed. A value the client sends in that header is
passed through instead, and requests that belong to no conversation (most embeddings, health
probes) get a random id. Clients just use the router's URL and key; nothing else is needed:

```sh
simple-router provider add opencode-go --base-url https://opencode.ai/zen/go/v1 \
  --session-header X-Opencode-Session
```

**Aliases.** A model's `aliases` are other ids clients may send for it, e.g. `bge-m3` and
`baai/bge-m3`. They share the model's targets, round robin and sticky sessions: a conversation
keeps its provider whichever name it uses. Access is decided on the model's own name: a key may use
an alias exactly when its `models` patterns allow the model, so adding an alias never grants a key
anything new. `GET /v1/models` lists aliases as entries of their own. Names and aliases must be
unique across all models.

The config is validated as a whole: unknown providers, duplicate names, plaintext credentials
and malformed hashes are reported together, with `simple-router validate`.

## CLI

All commands take `-c/--config` and the master key options (see [Master key](#master-key)).

| Command | Does |
|---|---|
| `serve [--watch=false] [--master-key-stdin] [--allow-remote-key-admin] [--lego PATH]` | Run the router. `--lego` (env `SIMPLE_ROUTER_LEGO`) picks the lego binary for TLS mode `acme`. |
| `init [--listen ADDR] [--no-tls]` | First use: creates the master key file (0600), a starter config with `master_key_check` and HTTPS with a self-signed certificate (`--no-tls`: plain HTTP), and an `admin` client key (printed once). Never overwrites. |
| `provider add <name> --base-url URL [--api-key K \| --no-auth] [--auth-header H] [--auth-scheme S] [--session-header H] [--auth managed\|passthrough] [--external] [--peer] [--ca-file PEM]` | Encrypts the provider key with the master key and adds the provider. `--peer` takes no key and refuses `--api-key`, `--auth-*`, `--external` and `--auth passthrough`. Without `--api-key`, the key is read from piped stdin or a hidden prompt. |
| `provider list` / `provider remove <name>` | Remove is refused while a model still targets the provider. |
| `key add <name> [--models a,b*] [--admin] [--providers p,q*]` | Generates a client key, stores only its hash, prints the key once. Default access: all models, no `/provider/` access. |
| `key list` / `key remove <name>` | Names and access only; keys can't be recovered. |
| `rotate master-key [--out FILE] [--api [--ca-file F] [--insecure]]` | New master key; every provider credential is re-encrypted. See [Rotation](#rotation). |
| `rotate key <name>` | New client key with the same access; the old one stops working. |
| `rotate provider <name> [--api-key K]` | Replaces an upstream credential (prompted or piped like `provider add`). |
| `acme env set <NAME> [--value V] [--plain]` | Sets a DNS provider variable for lego (e.g. `CLOUDFLARE_DNS_API_TOKEN`), encrypted with the master key unless `--plain`. Without `--value`, read from piped stdin or a hidden prompt. |
| `acme env list` / `acme env remove <NAME>` | List shows encrypted values as `(encrypted)` and `--plain` ones as they are. |
| `unseal [--url URL] [--ca-file F] [--insecure]` | Sends the master key to a running, sealed router. |
| `health [--json]` | Probes every provider; exits non-zero if any is down. |
| `validate` | Checks the config; with a master key, also that every secret decrypts. |
| `ping [--url URL]` | Checks a running router's `/healthz` (used by the container health check). |
| `version` | Prints version, commit and platform. |
| `encrypt`, `apikey`, `keygen` | Lower level: print an encrypted value, a client key and its hash, or a master key, without touching the config. |

The helpers edit the YAML in place. Comments are kept, though their alignment may change. A
running router picks up their changes automatically (see [Hot reload](#hot-reload)).

Commands that need the master key verify it before changing anything: against
`master_key_check`, and by decrypting the existing `enc:v1:` values. When no key is configured
and you're at a terminal, they prompt for it (hidden). `key add` needs no master key, since client
keys are hashed, not encrypted.

## API

Served under both `/api/v1` (OpenRouter) and `/v1` (OpenAI). Auth: `Authorization: Bearer <key>`
or `X-Api-Key`. Errors use OpenRouter's shape: `{"error": {"code": 404, "message": "..."}}`.

| Method | Path | Notes |
|---|---|---|
| POST | `/chat/completions` | chat models; `"stream": true` supported |
| POST | `/completions` | chat models |
| POST | `/embeddings` | embedding models |
| POST | `/rerank` | rerank models (Cohere/Jina style `{model, query, documents}`) |
| GET | `/models` | the models this key can use |
| POST | `/messages` | `messages` models (Anthropic Messages API); streaming supported |
| POST | `/messages/count_tokens` | `messages` models |
| POST | `/systemone` | `systemone` models (System One decisions); see [System One](#system-one-decisions) |
| GET | `/admin/health[?refresh=1]` | provider health and the served TLS certificate; admin keys; 503 if any provider is down |
| POST | `/admin/unseal` | `{"master_key"}`; admin key, localhost only |
| POST | `/admin/rotate-master-key` | `{"master_key", "new_master_key"?}` returns the new key; admin key, localhost only |
| GET | `/healthz` | liveness, no auth: `ok`, or `sealed` (still 200) |
| any | `/provider/<name>/<path>` | forwarded unchanged to one provider, with a router key (`auth: managed`) or the client's own credentials (`auth: passthrough`); see [Direct provider access](#direct-provider-access) |

A model a key can't use gets the same 404 as an unknown model, so keys can't discover which models
exist. Responses carry `X-Router-Provider` and `X-Router-Upstream-Model`; when the target is a
[peer router](#peer-routers), the peer's own values come as `X-Router-Peer-Provider` and
`X-Router-Peer-Model`. A request carrying `X-Router-Hop` is served by local targets only.

### Anthropic Messages API

`POST /v1/messages` (and `/v1/messages/count_tokens`) serves models of `type: messages`, with the
same priorities, round robin, failover and sticky routing as chat. Requests and responses
(streamed events included) are passed through in Anthropic's format: there is **no conversion**,
so every target of a `messages` model must speak the Anthropic API (Anthropic itself, or
compatible endpoints such as OpenCode Go's `/messages` models), and a `messages` model can't
fall back to an OpenAI-format provider.

```yaml
providers:
  - name: anthropic
    base_url: https://api.anthropic.com/v1
    api_key: enc:v1:...
    auth_header: x-api-key
    auth_scheme: none

models:
  - name: claude-sonnet-4-5        # the id clients send
    type: messages
    targets:
      - {provider: anthropic, model: claude-sonnet-4-5, priority: 1}
      - {provider: other-anthropic-compatible, model: claude-sonnet-4-5, priority: 2}
```

- Clients authenticate with their router key in `X-Api-Key` (the Anthropic SDKs' default) or
  `Authorization: Bearer`. Point an Anthropic SDK or tool at `http://router:8080` (it adds
  `/v1/messages`). Name the router's models after the ids the client sends.
- `anthropic-version` and `anthropic-beta` are forwarded. A request without `anthropic-version`
  gets `2023-06-01` (Anthropic rejects requests without one). The sticky key includes the top-level
  `system` prompt. Overloaded (529) and other 5xx responses fail over.
- The router's own errors use Anthropic's shape (`{"type": "error", "error": {"type":
  "not_found_error", ...}}`); upstream errors are relayed as they are.
- Health probes send `anthropic-version: 2023-06-01`, which Anthropic requires on `/models` and
  other providers ignore; set it in a provider's `headers` to change it.

### System One (decisions)

`POST /v1/systemone` serves models of `type: systemone`: decision models that answer typed
questions about a `state` (`{"model", "state", "questions": {...}}` in, `{"answers": {...},
"usage": {...}}` out), such as OpenCode Go's `jev-*` models or a self-hosted System One server.
Routing is the same as chat (priorities, round robin, failover including 402 and 429, cooldown,
sticky routing). The body is forwarded as is with `model` rewritten, and the response is relayed
unchanged; non-streaming. The sticky key uses `X-Session-Id`, else a hash of `state`.

The upstream URL is `base_url` + `/systemone`. OpenCode Go serves it under another prefix of the
same host, so one provider, one key, can serve chat and System One with `base_urls`:

```yaml
providers:
  - name: opencode-go
    base_url: https://opencode.ai/zen/go/v1                  # chat, messages, health
    base_urls:
      systemone: https://opencode.ai/inference/systemone/v1  # -> .../v1/systemone
    api_key: enc:v1:...
    session_header: X-Opencode-Session

models:
  - name: jev-1.13
    type: systemone
    targets:
      - {provider: opencode-go, model: jev-1.13-free, priority: 1}   # free tier first
      - {provider: opencode-go, model: jev-1.13,      priority: 2}   # paid fallback
```

Only the System One format is supported. OpenRouter's alpha decisions API
(`/api/alpha/decisions`) uses a different format; reach it through
[direct provider access](#direct-provider-access) instead.

### Direct provider access

`/provider/<name>/<path>` forwards a request to one provider's `<base_url>/<path>`: any method,
path and query, request and response streamed unchanged, with no model routing or failover. It
reaches what the model routes don't: Anthropic `/messages` or OpenAI `/responses` on any provider,
llama-swap's own endpoints (`/running`, `/upstream/<model>/...`), or a non-LLM service on
`localhost`. A provider's `auth` decides whose credentials are used:

| `auth` | Client sends | Router checks | Provider receives |
|---|---|---|---|
| `managed` (default) | a router key (`Authorization: Bearer` or `X-Api-Key`) | the key, and that its `providers` grant this provider | the provider's `api_key` via `auth_header`/`auth_scheme` (nothing if it has none); the router key is removed |
| `passthrough` | its own provider credentials | nothing | the client's credentials, untouched |

```yaml
providers:
  - name: llama-swap               # managed: router keys; no stored key, none sent
    base_url: http://127.0.0.1:8080
    allow_paths: ["/v1/*", "/upstream/*", "/running"]   # optional: keep /unload, /logs, the UI out
  - name: laya                     # managed: clients use router keys, the router holds the service's key
    base_url: http://127.0.0.1:8000
    api_key: enc:v1:...
  - name: opencode-go              # passthrough: each client brings its own OpenCode Go key
    base_url: https://opencode.ai/zen/go/v1
    auth: passthrough
    session_header: X-Opencode-Session

api_keys:
  - {name: notes-app, hash: sha256:..., models: [bge-m3], providers: [laya]}
  - {name: ops,       hash: sha256:..., models: ["*"],   providers: ["*"]}
```

```sh
simple-router provider add opencode-go --base-url https://opencode.ai/zen/go/v1 \
  --auth passthrough --session-header X-Opencode-Session
simple-router key add notes-app --models bge-m3 --providers laya
# clients: base URL https://router/provider/laya with their router key,
#          or https://router/provider/opencode-go with their own OpenCode Go key
```

- **Managed providers are closed by default.** A key reaches `/provider/<name>/` only when its
  `providers` list (glob patterns, `"*"` = all) names it; `models: ["*"]` doesn't grant it. Without a
  valid key the answer is 401, and a provider the key may not use gets the same 404 as an unknown one,
  so keys can't discover providers. Managed access returns 503 while the router is sealed.
- **Passthrough providers are open to anyone who can connect**: the router doesn't authenticate the
  client, never adds a stored key (so `api_key`, `auth_header` and `auth_scheme` are refused there),
  and works while sealed. They can't be targets of `models` (whose clients present router keys), and
  they're left out of health checks, since probing them needs a client's key.
- **`allow_paths`** (both modes) limits the paths: exact entries, or prefixes ending in `*`. Other
  paths get 403. `..` is resolved first, so a path can't climb above `base_url` or out of the list.
- Only configured providers are reachable, never an arbitrary URL. A provider's `headers` are sent;
  no `X-Forwarded-*` is added. Redirects are returned to the client, not followed. A managed provider
  can be a model target and reachable at `/provider/` at the same time.
- **`session_header`** works here too: the id is hashed from the system prompt / `instructions`
  and the messages (or `input`) up to the first user message, so every turn of a chat shares it.
  A client-sent value wins; requests with no conversation get a random one.
- `server.max_body_bytes` and `server.request_timeout` apply, including to streams. A timeout
  before response headers returns 504 (408 while reading a body for session derivation); after
  streaming starts, the connection is terminated.
- Each request is logged with provider, auth mode, key name, method, path, status and duration,
  never credentials.

Since `passthrough` providers have no router authentication, anyone who can reach the router can
relay through it to them (with their own provider key). Restrict who can connect with
[`server.allow_cidrs`](#client-allowlist), keep it on a trusted network, or put it behind a proxy
that restricts access.

## Peer routers

Two or more routers can share model names and client keys while running on different machines and
backends (say one with a GPU and one CPU-only), so a model can fall back between them in any order.
Mark the other router as a `peer`; it is an ordinary target, so priorities, round robin, failover,
cooldown and sticky routing work as usual and the order is set per model.

```yaml
providers:
  - name: gpu-local
    base_url: http://127.0.0.1:8080/v1
  - name: openrouter
    base_url: https://openrouter.ai/api/v1
    api_key: enc:v1:...
    external: true
  - name: router-b
    base_url: https://router-b.lan:8443/v1
    peer: true
    ca_file: /etc/sr/router-b.pem      # pin a self-signed peer certificate

models:
  - name: qwen3-coder
    targets:
      - {provider: gpu-local,  model: qwen3-coder,      priority: 1}  # local GPU
      - {provider: openrouter, model: qwen/qwen3-coder, priority: 2}  # external
      - {provider: router-b,                            priority: 3}  # peer; model defaults to the model's name
```

- **Client credentials are forwarded.** To a peer the router sends the client's own `Authorization`
  and/or `X-Api-Key` exactly as received (plus `X-Session-Id` if sent, so conversations stay sticky
  inside the peer, and the provider's `headers`), instead of a stored key. `api_key`, `auth_header`,
  `auth_scheme`, `external: true` and `auth: passthrough` are refused on a peer. Client keys are
  sent only to peers, never to other providers.
- **The key must be valid on both routers.** Keys decide which models a client may use, not how
  they are served. The peer checks the forwarded key against its own `api_keys`; its 401/404 is
  a failure like any other, and the next target is tried. Peers are expected to share client keys;
  `validate` can't check that.
- **One hop, local targets only.** Requests to a peer carry `X-Router-Hop: 1`. A router receiving
  that header (any non-empty value) uses only its local targets, skipping `peer` and `external`
  providers, and answers 503 (in its usual error shape, Anthropic's on `/v1/messages`) when none
  can serve the model, so the sender moves on. This rules out loops (A to B to A), duplicate calls
  to external providers, and a peer spending its credits on another router's requests. Spoofing the
  header only narrows the sender's own routing; authentication and model access are unchanged.
- **Health.** A peer is probed at `GET <scheme://host[:port] of base_url>/healthz` with no
  credentials; it is healthy only on 200 with body `ok`. `sealed` counts as down.
- **TLS.** `ca_file` (any provider, not only peers) is a PEM bundle: only its certificates are
  trusted for that provider's requests and health probes. It must exist and hold a certificate
  when the config loads (validation names the provider). Use it to pin a private or self-signed
  certificate, or for a local HTTPS server.
- **Direct access** (`/provider/<name>/`) to a peer is unchanged: it uses `base_url` and the
  provider's own settings, and sends no client credentials.
- **Trust.** A peer is as trusted as the router itself: it sees client keys and prompts. Use HTTPS
  (pinned with `ca_file` when self-signed) or loopback.

## Client allowlist

`server.allow_cidrs` limits which client addresses may use the router at all. It covers every
route: the API, `/provider/`, `/admin/` and `/healthz`.

```yaml
server:
  allow_cidrs:           # CIDRs or bare IPs (a bare IP is /32 or /128); empty = allow everyone
    - 10.0.0.0/8
    - 192.168.0.0/16
  trusted_proxies: []    # optional, see below
```

- **Empty or omitted allows everyone** (the default). Invalid entries are reported by
  `simple-router validate` and rejected on reload.
- **Loopback is always allowed** (`127.0.0.0/8`, `::1`), on every route, so `unseal`, key rotation
  over the API and the container health check (`simple-router ping`) keep working.
- **Enforced at connect time.** A peer that is not loopback, not in `allow_cidrs` and not in
  `trusted_proxies` is disconnected right after `accept`, before the TLS handshake, so it never
  sees the certificate. The same applies to the `server.tls.http_listen` redirect listener.
- **Behind a reverse proxy**, list the proxy's address in `trusted_proxies`. For requests whose TCP
  peer is a trusted proxy, the client is taken from `X-Forwarded-For`, read from **right to
  left**: entries that are themselves trusted proxies are skipped and the first other entry is
  the client (the left side is supplied by the client and can't be trusted). A missing or empty
  header means the proxy itself is the client. A malformed entry counts as untrusted and the
  request is denied. The resolved client must be in `allow_cidrs` (or loopback); a proxy is
  therefore not automatically allowed as a client. Without `trusted_proxies`, `X-Forwarded-For`
  is ignored. Denied requests get `403` with the usual JSON error before any auth or routing.
  Note that a proxy running on the same host connects from loopback: put its address in
  `trusted_proxies` too, or everything it forwards is allowed.
- **ACME HTTP-01 exemption**: with `tls.mode: acme` and `acme.challenge: http`, the
  `http_listen` listener can't filter connections (Let's Encrypt validators connect from the
  internet). It filters per request instead and exempts only `/.well-known/acme-challenge/`;
  everything else from a disallowed client gets `403`. The main HTTPS listener stays filtered at
  connect time.
- **Live reload**: `allow_cidrs` and `trusted_proxies` apply on reload without a restart (see
  [Hot reload](#hot-reload)).
- **Logging**: rejected peers are logged at most once per address per minute, never per
  connection.
- **Docker**: with published ports on the default bridge network, the peer the router sees is
  usually the Docker gateway (e.g. `172.17.0.1`), not the real client. Either use host networking,
  include the gateway in `allow_cidrs` (which then allows everything that reaches the published
  port, so it protects nothing), or put a proxy in front and list it in `trusted_proxies`.

## Routing

1. Targets are tried by `priority` (lower first); equal priorities take turns (round robin).
2. On a network error or a status of 401/402/403/404/408/409/425/429/5xx, the next target is tried
   and the failed one is moved to the back for `failure_cooldown`. Other 4xx (e.g. 400) are
   returned as is, since every provider would reject them the same way. Failover happens only
   before the response starts; a stream that breaks midway is not retried.
3. **Sticky routing**: after a success, the conversation is pinned to that target for
   `sticky_ttl`, renewed on each request. A conversation is identified by client key + model +
   session, where the session is the `X-Session-Id` header, else the body's `user` field, else a
   hash of the messages through the first user message (for completions, of the prompt's start;
   for System One, of the whole `state`). Follow-ups stay on the
   same provider, even after a failover, while separate conversations still spread across providers.
4. Providers that fail the background health check (`GET <base_url>/models`, or `base_urls.health` and `paths.health` if set; a peer is probed at `GET <origin>/healthz`), and targets on
   cooldown, go to the back of the list. They are still tried as a last resort.

A provider is **local** unless marked `external: true` (a paid or remote API) or `peer: true`
(another router). Priorities decide the order per model, whatever the kind: for example local GPU
(1), external (2), peer (3).

Upstream redirects are never followed, so provider credentials can't be forwarded to another host:
a redirect counts as a failure (and fails over). Set `base_url` to the provider's final URL. The
same applies to the CLI's calls to the router (`unseal`, `rotate master-key --api`, `ping`).

## Master key

`serve` gets the master key from, in order:

| Source | Lifetime |
|---|---|
| `--master-key-file` / `SIMPLE_ROUTER_MASTER_KEY_FILE` | re-read on every reload, so a key file rotated with the CLI applies live |
| `--master-key` / `SIMPLE_ROUTER_MASTER_KEY` | read once at startup, then kept only in memory. The env var is removed from the process, but `docker inspect` still shows it: prefer the other options |
| `--master-key-stdin` | read once, kept only in memory |
| **none of the above** | the router starts **sealed** and waits for the key over the API |

A key that is provided but wrong is a startup error.

### Sealed mode

API calls get `503`, and `/healthz` answers `sealed` with a 200 so orchestrators don't restart the
router, until the key is posted:

```sh
simple-router unseal                                 # prompts for the master key and an admin client key
docker exec -it <container> simple-router unseal     # same, inside the container
curl --cacert tls/selfsigned.crt -X POST https://localhost:8080/admin/unseal \
  -H "Authorization: Bearer $ADMIN_KEY" -d '{"master_key":"..."}'
```

The key then lives only in the router's memory. A key file that appears later (e.g. a secret
mounted afterwards) also unseals it. `unseal` takes the admin client key from `--api-key`,
`SIMPLE_ROUTER_API_KEY` or a prompt.

### Rotation

- **`rotate master-key --api [--out new.key]`** asks the running router to rotate: it checks the
  current key, re-encrypts the credentials, saves the config and switches over without a restart.
  It returns the new key once (written to `--out`, or printed). If the router uses a key file it
  replaces it safely; a read-only one (e.g. a Docker secret) makes it refuse, with nothing changed.
  The endpoint requires the **current master key** as well as an admin client key, so a leaked
  client key can neither read nor change the master key.
- **`rotate master-key`** without `--api` works on the files directly. It replaces the key file in
  use (writing `<file>.new`, then the config, then renaming, so an interruption never loses the key
  that matches the config), or writes to `--out`. A router using that key file switches
  automatically; otherwise give it the new key with `unseal`.
- `rotate key` and `rotate provider` replace a client key or an upstream credential; a running
  router applies them on its next reload, which is automatic.

`/admin/unseal` and `/admin/rotate-master-key` accept only localhost clients unless `serve` runs with
`--allow-remote-key-admin`. Enable that only behind TLS, since the key travels in the request body.
Behind a reverse proxy on the same host every request looks local, so keep these paths off the proxy.

### What the encryption protects

Credentials are encrypted at rest: the config is safe in backups, git and volume snapshots. The
master key and the decrypted credentials necessarily live in the router's memory while it runs. To
make that harder to read, `serve` disables core dumps at startup and, on Linux, marks itself
non-dumpable, so other processes of the same user can't attach to it or read its memory. Root on
the host can still do so. Limit the damage of a leak with scoped provider keys, spending caps and
regular rotation.

## Hot reload

`serve` reloads the config without dropping connections:

- automatically when `config.yaml` or the master key file changes (turn off with `--watch=false`);
- on `SIGHUP` (`docker kill -s HUP <container>`).

A config that fails to parse, validate or decrypt is logged and ignored, and the running one keeps
serving. Requests in progress finish on the config they started with; sticky sessions, cooldowns
and health state carry over. Without a key file, reloads use the in-memory key. Only changes to
`server.listen` and `server.tls` settings need a restart (`allow_cidrs` and `trusted_proxies` apply live); certificate files rotate live (see
[HTTPS](#https)).

## HTTPS

Set `server.tls.mode` (a restart is needed to change the mode; certificates themselves rotate live):

| Mode | Certificate |
|---|---|
| `off` (default) | plain HTTP |
| `file` | `cert_file` + `key_file` (PEM, chain allowed), written by any tool: lego, certbot, acme.sh, cert-manager, a script |
| `self-signed` | generated on first start, stored in `dir` (default `tls/` next to the config), renewed 30 days before expiry. Covers `localhost`, `127.0.0.1`, `::1` and `domains` |
| `acme` | obtained and renewed by the router running [lego](https://go-acme.github.io/lego/) against Let's Encrypt or any ACME CA. See [ACME](#acme-lets-encrypt) |

```yaml
server:
  listen: ":8443"
  tls:
    mode: file
    cert_file: certs/router.crt
    key_file: certs/router.key
    http_listen: ":80"          # optional: redirect plain HTTP to HTTPS
```

**Live rotation.** Every new connection gets the current certificate, so it's replaced without a
restart and without dropping open connections. In `file` mode the router watches the certificate
files (and checks them every minute, which also covers directories that don't exist yet). A new pair
is used only if it parses, the key matches the certificate, and it isn't expired. A half-written or
broken pair is logged and the current certificate keeps serving, so tools that write the key and
the certificate in two steps are fine. No deploy hook or signal is needed; `SIGHUP` also reloads.
A warning is logged when the certificate is within 14 days of expiry.

**Before the first certificate exists** (e.g. while an ACME client issues it), `file` mode serves the
self-signed certificate instead and switches over as soon as a valid pair appears. A sealed router
can therefore be unsealed over HTTPS from the start. Set `fallback_self_signed: false` to refuse to
start without the files.

**Clients.** For a self-signed router, trust `tls/selfsigned.crt`, e.g.
`curl --cacert tls/selfsigned.crt https://localhost:8443/healthz`; the router logs its SHA-256
fingerprint. `unseal` and `rotate master-key --api` verify the certificate since they send the master
key: they trust the system CAs, the router's self-signed certificate (found from the config) and
`--ca-file`. For a local router in `file` mode, they check the certificate against the name it was
issued for. `--insecure` skips verification and is accepted only for localhost URLs. `ping` uses
HTTPS automatically. `/admin/health` shows the served certificate: source, names, expiry and
fingerprint.

### ACME (Let's Encrypt)

In `acme` mode the router drives [lego](https://go-acme.github.io/lego/) v5, the official certificate
manager for simple-router. lego must be in `PATH` (or set `--lego` / `SIMPLE_ROUTER_LEGO`); the
`-acme` container image includes it. `serve` checks for lego at startup and refuses to start without
it, rather than failing at the first renewal.

```yaml
server:
  listen: ":8443"
  tls:
    mode: acme
    acme:
      email: admin@example.com
      domains: [router.example.com, "*.router.example.com"]
      challenge: dns                   # default; or http
      dns_provider: cloudflare         # any lego DNS provider: `lego dnshelp`
      dns_env:
        CLOUDFLARE_DNS_API_TOKEN: enc:v1:...   # set with `simple-router acme env set`
```

```sh
simple-router acme env set CLOUDFLARE_DNS_API_TOKEN      # prompts, stores it encrypted
simple-router acme env set AWS_REGION --value eu-west-1 --plain
```

| Setting | Default | |
|---|---|---|
| `email`, `domains` | required | account contact and certificate names |
| `server` | `letsencrypt` | `letsencrypt-staging` (use it while testing: production has strict rate limits), `zerossl`, or a directory URL |
| `ca_file` | | PEM bundle to trust a private ACME server (step-ca, Pebble) |
| `key_type` | `EC256` | `EC384`, `RSA2048`, `RSA3072`, `RSA4096` |
| `challenge` | `dns` | `dns`: no inbound port, allows wildcards. `http`: needs `http_listen` reachable on port 80 for every domain |
| `dns_provider`, `dns_env` | | lego's provider code and its variables (`lego dnshelp -c <provider>` lists them) |
| `dns_resolvers`, `dns_propagation_wait` | | optional propagation-check tuning |
| `check_interval` | `12h` | how often lego is run |

**How it works.** lego runs at startup and then every `check_interval`; `lego run` renews only when
the certificate is due, otherwise it does nothing. Failures are retried with backoff (1 minute
doubling to 1 hour) and lego's log lines are relayed into the router's log. The account and
certificates live in `<dir>/lego/` (default `tls/lego/` next to the config). Each new certificate
is swapped in live, as in `file` mode. Until the first one is issued, the self-signed fallback is
served. With `challenge: http`, the router answers `/.well-known/acme-challenge/` on `http_listen`
and redirects everything else to HTTPS. `SIGHUP` triggers a run immediately.

**Sealed start.** Encrypted `dns_env` values are decrypted with the master key, so on a sealed start
lego waits; it runs as soon as the router is unsealed. Rotating the master key re-encrypts them along
with the provider credentials.

**What lego can see.** lego gets a minimal environment: `PATH`, `HOME` (its own directory),
`LEGO_CA_CERTIFICATES` when `ca_file` is set, and the `dns_env` variables. Nothing else from the
router's environment is passed, the master key included. lego's arguments are built by the router
from the settings above. The config can't add arguments, `LEGO_*` variables (which can set hooks
that run commands), loader or shell variables (`LD_*`, `DYLD_*`, `PATH`, `BASH_ENV`...) or Go runtime
settings (`GODEBUG`, `GOMAXPROCS`...), and the
`exec` DNS provider is refused. So write access to the config can't be turned into running commands.

Changing `server.tls` (including `acme`) needs a restart; `dns_env` values are read on reload.

## Docker

```sh
# Key never on disk in the container: start sealed, then unseal.
docker run -d --name router -p 8080:8080 -v $PWD/conf:/etc/simple-router ghcr.io/gstos/simplellmrouter
docker exec -it router simple-router unseal

# Or with a key file (a Docker/Compose secret lives on an in-memory filesystem):
docker run -d -p 8080:8080 \
  -v $PWD/conf:/etc/simple-router \
  -v $PWD/master.key:/run/secrets/master_key:ro \
  ghcr.io/gstos/simplellmrouter
```

- `/etc/simple-router` is a declared volume holding `config.yaml`. Mount the **directory**, not the
  file: edits (including the CLI helpers) replace the file, and a single-file bind mount keeps
  showing the old one, so hot reload would never see the change. Keep `server.listen` on all
  interfaces (e.g. `:8080`).
- The image is distroless and runs as the non-root user `nonroot` (UID/GID 65532). To have files
  written by the helpers owned by you on a bind mount, run it as your own user:
  `docker run --user "$(id -u):$(id -g)" ...`. The config directory must be writable by that user.
- With nothing at `/run/secrets/master_key` and no `SIMPLE_ROUTER_MASTER_KEY`, the container starts
  sealed. Rotating over the API needs that setup or a writable key file, since the router can't
  replace a read-only secret.
- The `HEALTHCHECK` runs `simple-router ping`, which calls `/healthz` over loopback on the port from
  `server.listen`, over HTTPS when TLS is on. It needs no master key.
- For HTTPS, publish the TLS port (e.g. `-p 8443:8443` with `listen: ":8443"`) and keep
  certificates in the config volume, e.g. `cert_file: certs/router.crt`, so a tool writing into
  `conf/certs/` on the host (or a sidecar sharing the volume) rotates them live.

Two images are published:

| Image | Contents |
|---|---|
| `ghcr.io/gstos/simplellmrouter:<tag>` | the router only |
| `ghcr.io/gstos/simplellmrouter:<tag>-acme` (e.g. `latest-acme`, `0.2.1-acme`) | the router plus lego v5, for TLS mode `acme` |

```sh
docker run -d --name router -p 443:8443 \
  -v $PWD/conf:/etc/simple-router ghcr.io/gstos/simplellmrouter:latest-acme
```

lego keeps its account and certificates in the config volume (`tls/lego/`), so they survive
container restarts. For `challenge: http`, also publish port 80 to `http_listen`.

Build locally with `docker build -t simple-router .`, or `docker build --target acme -t simple-router:acme .`
for the lego image (`--build-arg VERSION=...` stamps a version, `--build-arg LEGO_VERSION=v5.x.y` picks lego).

## CI and releases

- **`.github/workflows/ci.yml`**, on every push and pull request: gofmt, `go vet`,
  `go test -race`; an end-to-end ACME test (`scripts/e2e-acme.sh`: HTTP-01, and DNS-01 with a
  wildcard and an encrypted credential on a sealed start, against
  [Pebble](https://github.com/letsencrypt/pebble)); then both multi-arch images (`linux/amd64`,
  `linux/arm64`). Pushes to `main` and `v*` tags publish them to `ghcr.io/gstos/simplellmrouter` as
  `latest`, `main`, `sha-…`, and `0.2.0`/`0.2` for tags, each also with an `-acme` suffix. Pull
  requests build without publishing.
- **`.github/workflows/release.yml`**, when a GitHub release is published: runs the tests, then
  [GoReleaser](https://goreleaser.com) (`.goreleaser.yaml`) attaches archives for
  linux/darwin/windows × amd64/arm64 and `checksums.txt`, keeping the release's own notes.

To release, publish a release with a new `v*` tag, e.g. `gh release create v0.3.0 --generate-notes`.
To run the ACME test locally, install lego v5, `pebble` and `pebble-challtestsrv`
(`go install github.com/letsencrypt/pebble/v2/cmd/...@v2.10.1`), then
`go build -o bin/simple-router . && scripts/e2e-acme.sh bin/simple-router`.
To try the release build locally: `go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean`.

## Intended use

> [!WARNING]
> **simple-router is meant to be an internal tool**: a gateway for your own apps, services and
> network (a homelab, a team, a VPC). It is **not** built to route requests from the open internet.
> It has no rate limiting, quotas, abuse protection or DDoS hardening, and `auth: passthrough`
> providers accept requests without router authentication. Keep it on a private network, restrict
> clients with [`server.allow_cidrs`](#client-allowlist), and don't expose it publicly.

## License

MIT, see [LICENSE](LICENSE).
