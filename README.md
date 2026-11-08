# simple-router

An OpenRouter-compatible LLM router in Go.

- **OpenRouter/OpenAI-compatible API**: chat completions (with streaming), completions,
  embeddings and rerank, under both `/api/v1` and `/v1`.
- **Priority lists per model**: lower priority first, round robin within a priority,
  failover to the next target when a provider fails.
- **Sticky routing**: follow-up requests in a conversation stay on the same provider, so its
  prompt cache keeps working, including after a failover.
- **Health checks**: background probes, a CLI check and an admin endpoint.
- **Encrypted provider credentials** (AES-256-GCM) under a master key; the router starts
  **sealed** and waits for the key if none is provided.
- **Client API keys** with access to all models or to glob patterns, stored only as hashes.
- **Hot reload** of the config, live key rotation, and a CLI to manage it all.

## Install

**Release binaries** for Linux, macOS and Windows (amd64 and arm64) are attached to each
[GitHub release](https://github.com/gstos/SimpleLLMRouter/releases), with `checksums.txt`:

```sh
# e.g. macOS on Apple Silicon
curl -LO https://github.com/gstos/SimpleLLMRouter/releases/download/v0.1.0/simple-router_0.1.0_darwin_arm64.tar.gz
tar xzf simple-router_0.1.0_darwin_arm64.tar.gz
./simple-router version
```

The macOS binaries aren't signed: if macOS blocks the first run, clear the download flag with
`xattr -d com.apple.quarantine simple-router`.

**Container image** (`linux/amd64` and `linux/arm64`, so it runs natively on Apple Silicon):

```sh
docker pull ghcr.io/gstos/simplellmrouter:0.1.0    # or :latest
```

**From source** (Go 1.27+):

```sh
go build -o bin/simple-router .
# or: go install github.com/gstos/SimpleLLMRouter@latest   (installs the binary as SimpleLLMRouter)
```

## Quick start

```sh
simple-router init                           # master.key + config.yaml + admin key (printed once)
export SIMPLE_ROUTER_MASTER_KEY_FILE=$PWD/master.key

simple-router provider add openai --base-url https://api.openai.com/v1   # prompts for the key (hidden)
simple-router key add my-app --models 'openai/*'                          # prints the client key once
# add models[] to config.yaml (see "Configuration"), then:
simple-router validate
simple-router serve
```

```sh
curl localhost:8080/api/v1/chat/completions -H "Authorization: Bearer $CLIENT_KEY" \
  -d '{"model": "openai/gpt-4o", "messages": [{"role": "user", "content": "Hi"}]}'
```

Any OpenAI or OpenRouter SDK works: point its base URL at `http://localhost:8080/api/v1` (or `/v1`).

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

providers:                         # OpenAI-compatible upstreams
  - name: openai
    base_url: https://api.openai.com/v1
    api_key: enc:v1:...            # `provider add` encrypts it; omit for no auth
    # auth_header: api-key         # default Authorization
    # auth_scheme: none            # default Bearer; "none" sends the raw key
    # headers: {X-Title: my-app}   # extra headers on every request
    # paths: {rerank: /v2/rerank, health: /models}   # per-endpoint path overrides

models:
  - name: openai/gpt-4o            # the id clients send
    type: chat                     # chat (default) | embedding | rerank
    targets:
      - {provider: openai, model: gpt-4o, priority: 1}
      - {provider: azure,  model: gpt-4o, priority: 1}         # same priority: round robin
      - {provider: openrouter, model: openai/gpt-4o, priority: 2}   # fallback

api_keys:                          # client keys; only hashes are stored
  - name: admin
    hash: sha256:...
    models: ["*"]                  # glob patterns; ["*"] or empty = all models
    admin: true                    # may call /admin endpoints
```

The config is validated as a whole: unknown providers, duplicate names, plaintext credentials
and malformed hashes are reported together, with `simple-router validate`.

## CLI

All commands take `-c/--config` and the master key options (see [Master key](#master-key)).

| Command | Does |
|---|---|
| `serve [--watch=false] [--master-key-stdin] [--allow-remote-key-admin]` | Run the router. |
| `init [--listen ADDR]` | First use: creates the master key file (0600), a starter config with `master_key_check`, and an `admin` client key (printed once). Never overwrites. |
| `provider add <name> --base-url URL [--api-key K \| --no-auth] [--auth-header H] [--auth-scheme S]` | Encrypts the provider key with the master key and adds the provider. Without `--api-key`, the key is read from piped stdin or a hidden prompt. |
| `provider list` / `provider remove <name>` | Remove is refused while a model still targets the provider. |
| `key add <name> [--models a,b*] [--admin]` | Generates a client key, stores only its hash, prints the key once. Default access: all models. |
| `key list` / `key remove <name>` | Names and access only; keys can't be recovered. |
| `rotate master-key [--out FILE] [--api]` | New master key; every provider credential is re-encrypted. See [Rotation](#rotation). |
| `rotate key <name>` | New client key with the same access; the old one stops working. |
| `rotate provider <name> [--api-key K]` | Replaces an upstream credential (prompted or piped like `provider add`). |
| `unseal [--url URL]` | Sends the master key to a running, sealed router. |
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
| GET | `/admin/health[?refresh=1]` | provider health; admin keys; 503 if any provider is down |
| POST | `/admin/unseal` | `{"master_key"}`; admin key, localhost only |
| POST | `/admin/rotate-master-key` | `{"master_key", "new_master_key"?}` returns the new key; admin key, localhost only |
| GET | `/healthz` | liveness, no auth: `ok`, or `sealed` (still 200) |

A model a key can't use gets the same 404 as an unknown model, so keys can't discover which models
exist. Responses carry `X-Router-Provider` and `X-Router-Upstream-Model`.

## Routing

1. Targets are tried by `priority` (lower first); equal priorities take turns (round robin).
2. On a network error or a status of 401/402/403/404/408/409/425/429/5xx, the next target is tried
   and the failed one is moved to the back for `failure_cooldown`. Other 4xx (e.g. 400) are
   returned as is, since every provider would reject them the same way. Failover happens only
   before the response starts; a stream that breaks midway is not retried.
3. **Sticky routing**: after a success, the conversation is pinned to that target for
   `sticky_ttl`, renewed on each request. A conversation is identified by client key + model +
   session, where the session is the `X-Session-Id` header, else the body's `user` field, else a
   hash of the first two messages (or the prompt). Follow-ups stay on the same provider, even after
   a failover, while separate conversations still spread across providers.
4. Providers that fail the background health check (`GET <base_url>/models`), and targets on
   cooldown, go to the back of the list. They are still tried as a last resort.

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
curl -X POST localhost:8080/admin/unseal -H "Authorization: Bearer $ADMIN_KEY" -d '{"master_key":"..."}'
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
and health state carry over. Without a key file, reloads use the in-memory key. Only a
`server.listen` change needs a restart.

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
  `server.listen`. It needs no master key.

Build locally with `docker build -t simple-router .` (pass `--build-arg VERSION=...` to stamp a version).

## CI and releases

- **`.github/workflows/ci.yml`**, on every push and pull request: gofmt, `go vet`,
  `go test -race`, then a multi-arch image (`linux/amd64`, `linux/arm64`). Pushes to `main` and
  `v*` tags publish it to `ghcr.io/gstos/simplellmrouter` as `latest`, `main`, `sha-…`, and
  `0.1.0`/`0.1` for tags. Pull requests build without publishing.
- **`.github/workflows/release.yml`**, when a GitHub release is published: runs the tests, then
  [GoReleaser](https://goreleaser.com) (`.goreleaser.yaml`) attaches archives for
  linux/darwin/windows × amd64/arm64 and `checksums.txt`, keeping the release's own notes.

To release, publish a release with a new `v*` tag, e.g. `gh release create v0.2.0 --generate-notes`.
To try the build locally: `go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean`.

## License

MIT, see [LICENSE](LICENSE).
