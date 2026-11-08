#!/usr/bin/env bash
# End-to-end test of TLS mode acme: the router drives lego against Pebble
# (Let's Encrypt's test CA) with pebble-challtestsrv as DNS.
#   1. HTTP-01: router serves lego's challenge files on http_listen.
#   2. DNS-01 + wildcard, sealed start: the DNS credential is encrypted, so
#      lego waits for unseal, then gets the decrypted value.
# Usage: scripts/e2e-acme.sh <router-binary>
# Needs lego (v5), pebble and pebble-challtestsrv in PATH, plus curl, openssl, python3.
set -euo pipefail

ROUTER=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
HERE=$(cd "$(dirname "$0")" && pwd)
PEBBLE_SRC=$(go list -m -f '{{.Dir}}' github.com/letsencrypt/pebble/v2 2>/dev/null || true)
if [ -z "$PEBBLE_SRC" ]; then
  PEBBLE_SRC=$(ls -d "$(go env GOMODCACHE)"/github.com/letsencrypt/pebble/v2@* | tail -1)
fi
W=$(mktemp -d)
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$W"; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- router log:"; cat "$W"/router*.log 2>/dev/null | tail -40; exit 1; }

# --- Pebble + challtestsrv -------------------------------------------------
cp "$PEBBLE_SRC/test/certs/pebble.minica.pem" "$W/minica.pem"
sed -e "s#test/certs/localhost#$PEBBLE_SRC/test/certs/localhost#g" \
    "$PEBBLE_SRC/test/config/pebble-config.json" > "$W/pebble.json"
pebble-challtestsrv -defaultIPv4 127.0.0.1 -defaultIPv6 "" -dnsserver 127.0.0.1:8053 \
  -http01 "" -https01 "" -doh "" -tlsalpn01 "" -management 127.0.0.1:8055 >"$W/chall.log" 2>&1 & PIDS+=($!)
PEBBLE_VA_NOSLEEP=1 pebble -config "$W/pebble.json" -dnsserver 127.0.0.1:8053 >"$W/pebble.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do curl -sk https://127.0.0.1:14000/dir >/dev/null && break; sleep 0.2; done
curl -sk https://127.0.0.1:15000/roots/0 > "$W/pebble-root.pem"   # root CA of issued certs

# --- router setup ------------------------------------------------------------
cd "$W"
export SIMPLE_ROUTER_CONFIG=$W/config.yaml
ADMIN=$("$ROUTER" init --listen 127.0.0.1:18443 2>/dev/null)
mv master.key "$W/mk"

set_tls() { # replace server.tls in config.yaml with the block on stdin
  python3 - "$W/config.yaml" "$(cat)" <<'PY'
import sys
path, block = sys.argv[1], sys.argv[2].rstrip("\n").split("\n")
lines = open(path).read().split("\n")
out, skip = [], False
for ln in lines:
    if ln.startswith("  tls:"):
        skip = True
        continue
    if skip and (ln.startswith("   ") or ln == ""):
        continue
    skip = False
    out.append(ln)
    if ln.startswith("  listen:"):
        out.extend(block)
open(path, "w").write("\n".join(out))
PY
}

wait_for_issuer() { # $1 = SNI name; waits until the served certificate comes from Pebble
  for _ in $(seq 150); do
    if echo | openssl s_client -connect 127.0.0.1:18443 -servername "$1" 2>/dev/null \
        | openssl x509 -noout -issuer 2>/dev/null | grep -qi pebble; then return 0; fi
    sleep 0.2
  done
  return 1
}

# --- 1. HTTP-01 ---------------------------------------------------------------
set_tls <<YAML
  tls:
    mode: acme
    http_listen: 127.0.0.1:5002        # where Pebble validates HTTP-01
    acme:
      email: e2e@example.com
      domains: [router.test]
      server: https://127.0.0.1:14000/dir
      ca_file: $W/minica.pem
      challenge: http
YAML
"$ROUTER" --master-key-file "$W/mk" serve 2>"$W/router-http.log" & RP=$!; PIDS+=($RP)
wait_for_issuer router.test || fail "HTTP-01: certificate not issued"
curl -sf --cacert "$W/pebble-root.pem" --resolve router.test:18443:127.0.0.1 https://router.test:18443/healthz >/dev/null \
  || fail "HTTP-01: issued certificate does not verify"
echo "ok: HTTP-01 issued and served (verified against Pebble's root)"
kill $RP; wait $RP 2>/dev/null || true

# --- 2. DNS-01, wildcard, sealed start, encrypted credential ------------------
rm -rf tls
python3 "$HERE/e2e/dns-adapter.py" 8099 http://127.0.0.1:8055 e2e s3cret & PIDS+=($!)
set_tls <<YAML
  tls:
    mode: acme
    acme:
      email: e2e@example.com
      domains: [router.test, "*.router.test"]
      server: https://127.0.0.1:14000/dir
      ca_file: $W/minica.pem
      challenge: dns
      dns_provider: httpreq
      dns_resolvers: ["127.0.0.1:8053"]
      dns_propagation_wait: 2s
YAML
"$ROUTER" acme env set HTTPREQ_ENDPOINT --plain --value http://127.0.0.1:8099 >/dev/null
"$ROUTER" acme env set HTTPREQ_USERNAME --plain --value e2e >/dev/null
echo s3cret | "$ROUTER" --master-key-file "$W/mk" acme env set HTTPREQ_PASSWORD >/dev/null
grep -q 'HTTPREQ_PASSWORD: enc:v1:' config.yaml || fail "DNS credential not encrypted"
"$ROUTER" validate >/dev/null || fail "config invalid"

"$ROUTER" serve 2>"$W/router-dns.log" & RP=$!; PIDS+=($RP)   # no key: sealed
sleep 2
grep -q "waiting for the router to be unsealed" "$W/router-dns.log" || fail "lego did not wait for unseal"
wait_for_issuer router.test && fail "certificate issued while sealed"
SIMPLE_ROUTER_API_KEY=$ADMIN "$ROUTER" --master-key-file "$W/mk" unseal >/dev/null || fail "unseal"
wait_for_issuer anything.router.test || fail "DNS-01: certificate not issued after unseal"
curl -sf --cacert "$W/pebble-root.pem" --resolve api.router.test:18443:127.0.0.1 https://api.router.test:18443/healthz >/dev/null \
  || fail "DNS-01: wildcard certificate does not verify"
echo "ok: DNS-01 wildcard issued after unseal with the decrypted credential"
kill $RP; wait $RP 2>/dev/null || true
echo "PASS"
