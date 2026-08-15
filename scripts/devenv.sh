# Sourced by dev.sh and verify.sh. Exports the environment a local run needs.
#
# Every value here is EPHEMERAL and generated per invocation. Nothing in this
# file reads a real secret, and nothing it produces is usable anywhere: the
# keypair lives for one process lifetime, and the LiveKit credentials are
# syntactically valid nonsense. That is deliberate — a dev loop that needs the
# production .env is a dev loop nobody runs before committing.

set -euo pipefail

# ES256 (P-256), matching what the exchange handler signs with in production.
_key_dir="$(mktemp -d)"
trap 'rm -rf "$_key_dir"' EXIT
openssl ecparam -name prime256v1 -genkey -noout -out "$_key_dir/key.pem" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in "$_key_dir/key.pem" -out "$_key_dir/private.pem"
openssl ec -in "$_key_dir/key.pem" -pubout -out "$_key_dir/public.pem" 2>/dev/null

export REALM_JWT_PRIVATE_KEY="$(cat "$_key_dir/private.pem")"
export REALM_JWT_PUBLIC_KEY="$(cat "$_key_dir/public.pem")"

# Real project id: verifyIdToken needs no credential, only the id it checks the
# token's `aud` against, so a local run reaches the same code path as production
# and fails the same way on a bad token.
export FIREBASE_PROJECT_ID="${FIREBASE_PROJECT_ID:-tech-world-dev}"

export LIVEKIT_API_KEY="${LIVEKIT_API_KEY:-devkey}"
export LIVEKIT_API_SECRET="${LIVEKIT_API_SECRET:-devsecret-devsecret-devsecret-32b}"

# NOT production: the localhost opt-in below is refused under NODE_ENV=production
# and TRUST_PROXY_HOPS becomes mandatory. Both of those are correct there and
# wrong here, and this is the one place that difference is stated.
export NODE_ENV="${NODE_ENV:-development}"
export CORS_ALLOWED_ORIGINS="${CORS_ALLOWED_ORIGINS:-http://localhost:5000}"
export CORS_ALLOW_LOCALHOST="${CORS_ALLOW_LOCALHOST:-true}"

# Nothing in front of this process locally. The deploy sets 1 for Caddy.
export TRUST_PROXY_HOPS="${TRUST_PROXY_HOPS:-0}"
