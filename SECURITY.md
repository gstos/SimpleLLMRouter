# Security policy

## Supported versions

simple-router is pre-1.0. Security fixes go into the latest release only; there are no backports.

| Version | Supported |
|---|---|
| latest `0.x` release | yes |
| older releases | no: please upgrade |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub:
[**Security → Report a vulnerability**](https://github.com/gstos/SimpleLLMRouter/security/advisories/new).

Include what you can of:

- the version (`simple-router version`) and how it runs (binary, container image tag);
- the relevant config, with secrets, `enc:v1:` values and key hashes removed;
- steps to reproduce, and what an attacker gains (e.g. reads a provider key, bypasses
  `allow_cidrs`, reaches a provider without a grant).

This is a small project maintained in spare time. Expect an acknowledgement within a week, and
a fix or a decision as soon as practical, depending on severity. Once a fix is released, the
advisory is published with credit to the reporter, unless you'd rather stay anonymous.

## Intended deployment

simple-router is an **internal tool**: a gateway for your own apps, services and private network.
It is not designed to route requests from the open internet: there is no rate limiting, quota or
abuse protection, and `auth: passthrough` providers accept requests without router
authentication. Reports that only apply to a deployment exposed to the internet against this
advice are still welcome, but they are treated as hardening, not as vulnerabilities.

## What counts as a vulnerability

In scope, for example:

- **Authentication and authorization:** a client key used beyond its `models` or `providers`; an
  unauthenticated request reaching a `managed` provider; `/admin/` endpoints reachable without an
  admin key, or remotely when they should be localhost-only.
- **Client allowlist:** bypassing `server.allow_cidrs`, including by spoofing `X-Forwarded-For`
  from an untrusted peer.
- **Secrets:** the master key, decrypted provider keys, DNS credentials (`dns_env`) or client keys
  leaking: to logs, error messages, other providers, redirect targets, lego, or `/admin/health`.
  Weaknesses in how secrets are encrypted at rest (`enc:v1:`) or in `master_key_check`.
- **Request forwarding:** reaching a host or path other than the configured provider's `base_url`
  (path traversal, `allow_paths` bypass, open-proxy behaviour).
- **TLS:** the router serving an invalid, mismatched or expired certificate when a valid one is
  available; CLI commands that send the master key accepting an unverified certificate for a
  non-loopback URL.
- **Config handling:** a config the router accepts that silently disables a security check.

Out of scope:

- Anything that needs the master key, root on the host, or write access to the config, the key file
  or the binary. The README's "What the encryption protects" section describes the limits: the master
  key and decrypted credentials necessarily live in the router's memory while it runs.
- Behaviour documented as intended: `auth: passthrough` forwarding clients' own credentials without
  checking them; providers' responses being relayed unchanged.
- Denial of service through volume, slow clients or expensive upstream calls (see "Intended
  deployment"). Bugs that let one request crash the router are in scope.
- Vulnerabilities in providers, in lego, or in Go itself, unless simple-router uses them unsafely.
  Please report those upstream.

## Security-relevant design, for reviewers

- Provider credentials (and `dns_env` values) are stored as AES-256-GCM `enc:v1:` values under a
  master key. The config holds only a fingerprint of that key (`master_key_check`).
- Client keys are stored only as SHA-256 hashes.
- Without a master key, the router starts sealed and returns 503 to API calls until it receives one
  (`/admin/unseal`, localhost-only by default).
- At startup `serve` disables core dumps and, on Linux, marks itself non-dumpable.
- Upstream redirects are never followed, so credentials can't be forwarded to another host.
- lego runs with a minimal environment: it never sees the master key, and the config can't set
  hooks or `LEGO_*` variables.
- Release binaries come with `checksums.txt`. Container images are built by GitHub Actions from
  this repository.
