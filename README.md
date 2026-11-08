# simple-router

An OpenRouter-compatible LLM router: priority lists per model, round robin within a
priority, failover, sticky routing for prompt-cache reuse, encrypted provider
credentials and per-key model access.

## Quick start

```sh
go build -o bin/simple-router .
bin/simple-router init                         # master.key + config.yaml + admin key (printed once)
export SIMPLE_ROUTER_MASTER_KEY_FILE=$PWD/master.key

bin/simple-router provider add openai --base-url https://api.openai.com/v1   # prompts for the key (hidden)
bin/simple-router key add my-app --models 'openai/*'                          # prints the client key once
# add models[] entries pointing at your providers, then:
bin/simple-router validate
bin/simple-router serve
```

### Config helpers

Commands that encrypt (`provider add`, `encrypt`) take the master key from the flags/env above, or
prompt for it (hidden) when none is set and you're at a terminal. Before encrypting anything they verify
the key: against `master_key_check` (an HMAC fingerprint of the key, written on the first `provider add`)
and by test-decrypting the existing `enc:v1:` values. `serve` and `validate` also reject a key that
doesn't match `master_key_check`. `key add` needs no master key: client keys are hashed, not encrypted.

They edit the YAML in place (comments are kept; alignment of inline comments may be normalised).
Restart the server after changes.

| Command | Does |
|---|---|
| `provider add <name> --base-url URL [--api-key K \| --no-auth] [--auth-header H] [--auth-scheme S]` | Encrypts the provider key with the master key and appends the provider. Without `--api-key` the key is read from piped stdin or prompted for with hidden input. |
| `provider list` / `provider remove <name>` | Remove is refused while a model still targets the provider. |
| `key add <name> [--models a,b*] [--admin]` | Generates a client key, stores only its hash, prints the key once. Default access: all models. |
| `key list` / `key remove <name>` | Names and access only; keys can't be recovered. |
| `init [--listen ADDR]` | First use: creates the master key file (0600), a starter config with `master_key_check`, and an `admin` client key (printed once). Never overwrites. |
| `rotate master-key [--out FILE]` | Verifies the current key, re-encrypts every provider credential under a new one, updates `master_key_check`. Replaces the current key file safely (`<file>.new` → config → rename); pass `--out` if the key came from an env var. |
| `rotate key <name>` | New client key with the same access; the old one stops working on restart. |
| `rotate provider <name> [--api-key K]` | Replaces an upstream credential (prompted/piped like `provider add`). |
| `encrypt`, `apikey` | Lower-level: print an encrypted value / a key+hash without touching the config. |

The master key can also come from `SIMPLE_ROUTER_MASTER_KEY` or `SIMPLE_ROUTER_MASTER_KEY_FILE`.
The server will not start without it, or if any credential fails to decrypt.
Config values can be overridden by env, e.g. `SIMPLE_ROUTER_SERVER_LISTEN=:9000`.

## API

Served under both `/api/v1` (OpenRouter) and `/v1` (OpenAI). Auth: `Authorization: Bearer <key>` or `X-Api-Key`.

| Method | Path | Model type |
|---|---|---|
| POST | `/chat/completions` (streaming supported) | chat |
| POST | `/completions` | chat |
| POST | `/embeddings` | embedding |
| POST | `/rerank` | rerank |
| GET | `/models` | lists the models the key can use |
| GET | `/admin/health[?refresh=1]` | provider health; admin keys only (503 if any provider is down) |
| GET | `/healthz` | router liveness, no auth |

Responses carry `X-Router-Provider` and `X-Router-Upstream-Model`.

## Routing

1. Targets are tried by `priority` (lower first); equal priorities rotate round robin.
2. On a transport error or a status of 401/402/403/404/408/409/425/429/5xx the next target is tried
   and the failed one is deprioritised for `failure_cooldown`. Other 4xx (e.g. 400) are returned as is.
   Failover happens only before the response starts; a stream that breaks midway is not retried.
3. **Sticky routing**: after a success, the conversation is pinned to that target for `sticky_ttl`
   (sliding). The conversation is identified by API key + model + session, where session is the
   `X-Session-Id` header, else the body's `user` field, else a hash of the first two messages
   (or the prompt). Follow-ups therefore stay on the same provider, including after a failover.
4. Providers that fail the background health check (`GET <base_url>/models`) or are on cooldown go
   to the back of the list; they are still tried as a last resort.

## CLI

`serve`, `health` (probe all providers; exits non-zero if any is down, `--json`), `validate`,
`ping`, `init`, `rotate master-key|key|provider`, `keygen`, `encrypt`, `apikey`,
`provider add|list|remove`, `key add|list|remove`.

## Docker

CI (`.github/workflows/ci.yml`) runs gofmt, vet and `go test -race` on every push and pull request,
then builds a multi-arch image for `linux/amd64` and `linux/arm64` (Apple Silicon Macs run the
arm64 one natively). Pushes to `main` and `v*` tags publish it to
`ghcr.io/gstos/simplellmrouter` (`latest`, `main`, `sha-…`, and `1.2.3`/`1.2` for tags);
pull requests build without publishing.

```sh
docker pull ghcr.io/gstos/simplellmrouter:latest
```

To build locally:

```sh
docker build -t simple-router .
docker run -d -p 8080:8080 \
  -v $PWD/config.yaml:/etc/simple-router/config.yaml:ro \
  -v $PWD/master.key:/run/secrets/master_key:ro \
  simple-router
```

The image is distroless and runs as non-root. Its `HEALTHCHECK` runs `simple-router ping`, which
calls `/healthz` over loopback on the port from `server.listen` (no master key needed; override
with `ping --url ...`). Keep `server.listen` on all interfaces (e.g. `:8080`) inside the container.
