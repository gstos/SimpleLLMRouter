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

Config values can be overridden by env, e.g. `SIMPLE_ROUTER_SERVER_LISTEN=:9000`.

## Master key

`serve` gets the master key from, in order:

| Source | Lifetime |
|---|---|
| `--master-key-file` / `SIMPLE_ROUTER_MASTER_KEY_FILE` | re-read on every reload (a key file rotated with the CLI applies live) |
| `--master-key` / `SIMPLE_ROUTER_MASTER_KEY` | read once at startup, then only kept in memory (the env var is removed from the process environment; `docker inspect` still shows it, so prefer the others) |
| `--master-key-stdin` | read once, in memory only |
| **none of the above** | the router starts **sealed** and waits for the key over the API |

A key that is provided but wrong is a startup error.

**Sealed mode.** API calls get `503` and `/healthz` answers `sealed` (still 200, so orchestrators
don't restart it) until the key is posted:

```sh
simple-router unseal                                   # prompts for the master key and an admin client key
docker exec -it <container> simple-router unseal       # same, inside the container
curl -X POST localhost:8080/admin/unseal -H "Authorization: Bearer $ADMIN_KEY" -d '{"master_key":"..."}'
```

The key then lives only in the router's memory. A key file that appears later (e.g. a secret mounted
afterwards) also unseals it.

**Live rotation.** `simple-router rotate master-key --api [--out new.key]` asks the running router
to rotate: it verifies the current key, re-encrypts the credentials, saves the config and switches
over without a restart, returning the new key once. If the router uses a key file it replaces it
safely; a read-only one (e.g. a Docker secret) makes it refuse, with nothing changed. The endpoint
requires the **current master key** as well as an admin client key, so a leaked client key can
neither read nor change the master key. Without `--api`, `rotate master-key` works on the files
directly (the router picks up a rotated key file automatically).

Both `/admin/unseal` and `/admin/rotate-master-key` accept only localhost clients unless `serve` runs
with `--allow-remote-key-admin`; enable that only behind TLS, since the key is in the request body.
Behind a reverse proxy on the same host every request looks local, so keep these paths off the proxy.

**Process hardening.** At startup `serve` disables core dumps and, on Linux, marks itself
non-dumpable, so other processes of the same user can't attach to it or read its memory. This
doesn't stop root on the host: the master key and decrypted provider credentials necessarily live
in the router's memory. Encryption protects the config at rest (backups, git, snapshots).

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
| POST | `/admin/unseal` | `{"master_key"}`; admin key, localhost only (see [Master key](#master-key)) |
| POST | `/admin/rotate-master-key` | `{"master_key", "new_master_key"?}` → new key; admin key, localhost only |
| GET | `/healthz` | router liveness, no auth (`ok` or `sealed`) |

Responses carry `X-Router-Provider` and `X-Router-Upstream-Model`.

## Hot reload

`serve` reloads the config without dropping connections:

- automatically when `config.yaml` or the master key file changes (disable with `--watch=false`);
- on `SIGHUP` (`docker kill -s HUP <container>`).

The master key file is re-read too, so a key file rotated with the CLI applies live; without a
key file, reloads use the in-memory key. A config that fails to
parse, validate or decrypt is logged and ignored; the running one keeps serving. In-flight requests
finish on the config they started with; sticky sessions, cooldowns and health state carry over.
`server.listen` changes need a restart.

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
`ping`, `unseal`, `init`, `rotate master-key|key|provider`, `keygen`, `encrypt`, `apikey`,
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

# Key never on disk in the container: start sealed, then unseal.
docker run -d --name router -p 8080:8080 -v $PWD/conf:/etc/simple-router simple-router
docker exec -it router simple-router unseal

# Or with a key file (Docker/Compose secret, in-memory filesystem):
docker run -d -p 8080:8080 \
  -v $PWD/conf:/etc/simple-router \
  -v $PWD/master.key:/run/secrets/master_key:ro \
  simple-router
```

`/etc/simple-router` is a declared volume holding `config.yaml`. Mount the **directory**, not the
file: edits (including the CLI helpers) replace the file atomically, and a single-file bind mount
keeps showing the old one, so hot reload would never see the change.

If nothing is mounted at `/run/secrets/master_key` (and `SIMPLE_ROUTER_MASTER_KEY` is unset), the
container starts sealed. Live rotation over the API needs the sealed setup (or a writable key
file): a read-only secret can't be replaced by the router.

The image is distroless and runs as non-root. Its `HEALTHCHECK` runs `simple-router ping`, which
calls `/healthz` over loopback on the port from `server.listen` (no master key needed; override
with `ping --url ...`). Keep `server.listen` on all interfaces (e.g. `:8080`) inside the container.
