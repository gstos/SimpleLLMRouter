# simple-router

An OpenRouter-compatible LLM router: priority lists per model, round robin within a
priority, failover, sticky routing for prompt-cache reuse, encrypted provider
credentials and per-key model access.

## Quick start

```sh
go build -o bin/simple-router .
bin/simple-router keygen > master.key                     # keep this secret
printf %s "$OPENAI_API_KEY" | bin/simple-router encrypt --master-key-file master.key
bin/simple-router apikey                                  # client key + hash for api_keys[]
cp config.example.yaml config.yaml                        # paste the enc:v1:... and sha256:... values
bin/simple-router validate --master-key-file master.key
bin/simple-router serve    --master-key-file master.key
```

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
`keygen`, `encrypt`, `apikey`.

## Docker

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
