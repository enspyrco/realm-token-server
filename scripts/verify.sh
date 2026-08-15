#!/usr/bin/env bash
# Verify the REAL artifact before committing.
#
#   ./scripts/verify.sh
#
# `npm test` exercises the app in-process with injected fakes. This boots the
# actual `npm start` entrypoint — the same env parsing, the same boot-time
# refusals, the same express instance the container runs — and asserts over real
# HTTP. It is the cheap loop that catches what a green unit suite cannot: an
# entrypoint that no longer boots, a middleware mounted in the wrong order, a
# header that never reaches the wire.
#
# Run it before `git commit`, not after a reviewer asks.

set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/devenv.sh
source scripts/devenv.sh

PORT="${PORT:-8781}"
export PORT
BASE="http://127.0.0.1:$PORT"
LOG="$(mktemp)"

failures=0
check() {
  local label="$1" want="$2" got="$3"
  if [ "$want" = "$got" ]; then
    printf '  ok   %s\n' "$label"
  else
    printf '  FAIL %s — want %s, got %s\n' "$label" "$want" "$got"
    failures=$((failures + 1))
  fi
}

# Kill whatever owns the port, never a process-name pattern: a pattern miss
# leaves the old process holding the port while the new one dies at bind, and
# the stale build then serves every assertion below under the new one's name.
free_port() {
  local pids
  pids="$(lsof -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null || true)"
  [ -n "$pids" ] && kill $pids 2>/dev/null || true
}
cleanup() {
  free_port
  if [ "$failures" -ne 0 ]; then
    echo
    echo "--- server log ---"
    cat "$LOG"
  fi
  rm -f "$LOG"
}
trap cleanup EXIT

free_port
npm start >"$LOG" 2>&1 &

# Boot, or say what the server said. A silent timeout here is the same
# indistinguishable-silence problem the request log exists to solve.
for _ in $(seq 1 50); do
  if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.2
done
if ! curl -fsS "$BASE/healthz" >/dev/null 2>&1; then
  echo "FAIL server did not come up on $PORT"
  cat "$LOG"
  exit 1
fi

status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
post_exchange() {
  curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/exchange" \
    -H 'content-type: application/json' -d '{"idToken":"nope"}'
}

echo "verifying $BASE"

check 'healthz serves' 200 "$(status "$BASE/healthz")"

check 'a bad token is refused, not thrown' 401 "$(post_exchange)"

check 'an allowed origin gets a preflight' 204 \
  "$(status -X OPTIONS "$BASE/exchange" -H "Origin: $CORS_ALLOWED_ORIGINS" -H 'Access-Control-Request-Method: POST')"

check 'an allowed origin is echoed back' "$CORS_ALLOWED_ORIGINS" \
  "$(curl -s -o /dev/null -D - -X OPTIONS "$BASE/exchange" \
      -H "Origin: $CORS_ALLOWED_ORIGINS" -H 'Access-Control-Request-Method: POST' \
      | grep -i '^access-control-allow-origin:' | cut -d' ' -f2- | tr -d '\r')"

check 'a disallowed origin is refused' 403 \
  "$(status -X POST "$BASE/exchange" -H 'Origin: https://evil.example' \
      -H 'content-type: application/json' -d '{}')"

# The rate limit, over the wire. One request is already spent above, so this
# takes the per-IP window to its ceiling and one past it.
for _ in $(seq 1 29); do post_exchange >/dev/null; done
check 'the per-IP ceiling refuses the next request' 429 "$(post_exchange)"

check 'a refusal tells the caller when to come back' 1 \
  "$(curl -s -o /dev/null -D - -X POST "$BASE/exchange" \
      -H 'content-type: application/json' -d '{"idToken":"nope"}' \
      | grep -ic '^retry-after:' || true)"

check 'the healthcheck still passes while a caller is throttled' 200 "$(status "$BASE/healthz")"

# Verify the INSTRUMENT, not only the behaviour: `proxied` is the only signal
# that says whether the limiter above is keyed per client or bucketing everyone
# together, so a run that never emits it has a limiter nobody can audit.
check 'the request log reports whether the client IP came via a proxy' 1 \
  "$(grep -c '"proxied":false' "$LOG" >/dev/null && echo 1 || echo 0)"

echo
if [ "$failures" -eq 0 ]; then
  echo "all checks passed"
else
  echo "$failures check(s) failed"
fi
exit "$failures"
