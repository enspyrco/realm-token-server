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

port_listener() { listener_on "$PORT"; }
# Any port, not just the main one. The boot-refusal and enforcement checks below
# run children on PORT+1 / PORT+2, and cleanup has to be able to reach those too:
# `timeout` SIGTERMs `npm`, not necessarily the `node` it spawned, and the
# enforcement server is DESIGNED to still be serving when its timeout fires. An
# orphan on :PORT+2 would make the next run's ON server die at bind — after
# createApp had already emitted its policy line — so a log-grep check would stay
# green against last week's corpse. (Tesla, PR #6 round 6.)
listener_on() { lsof -tiTCP:"$1" -sTCP:LISTEN 2>/dev/null || true; }

SERVER_PID=""
cleanup() {
  # Kill OUR child by pid. Then, only if the port is still held, kill its actual
  # listener — never a process-name pattern, because a pattern miss leaves the
  # old process holding the port while the next run dies at bind and the stale
  # build serves every assertion under the new one's name.
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  local held p
  # Every port this script may have bound, not only the main one.
  for p in "$PORT" $((PORT + 1)) $((PORT + 2)); do
    held="$(listener_on "$p")"
    [ -n "$held" ] && kill $held 2>/dev/null || true
  done
  if [ "$failures" -ne 0 ]; then
    echo
    echo "--- server log ---"
    cat "$LOG"
  fi
  rm -f "$LOG"
}
trap cleanup EXIT

# Refuse rather than evict. An earlier version killed the port's listener up
# front, which is the right TEARDOWN discipline for a process we started and the
# wrong STARTUP discipline for one we did not: on entry the listener is by
# definition somebody else's, and a verification script has no business killing a
# developer's running work without asking.
if [ -n "$(port_listener)" ]; then
  echo "FAIL port $PORT is already in use by pid(s) $(port_listener | tr '\n' ' ')"
  echo "     Stop it, or run with a different port: PORT=8899 ./scripts/verify.sh"
  exit 1
fi

npm start >"$LOG" 2>&1 &
SERVER_PID=$!

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

# The mint route has its own ceiling and its own budget. Exercised separately
# because it is the route that dispatches an agent into a room — the amplification
# this whole ceiling exists for — and a check that only ever walks /exchange would
# report green with the mint route wide open.
check 'the mint route still has its own budget' 401 \
  "$(status -X POST "$BASE/livekit-token" -H 'content-type: application/json' -d '{"roomName":"r"}')"
# 29, not 30: the check above already spent one, so this takes the window to
# exactly the ceiling and the assertion below is the FIRST refusal rather than
# some request after it. A probe that lands past the boundary still goes red when
# the limiter is missing, but it no longer measures where the boundary is.
for _ in $(seq 1 29); do
  curl -s -o /dev/null -X POST "$BASE/livekit-token" -H 'content-type: application/json' -d '{"roomName":"r"}'
done
check 'the mint route enforces its own ceiling' 429 \
  "$(status -X POST "$BASE/livekit-token" -H 'content-type: application/json' -d '{"roomName":"r"}')"

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

# A boot-time refusal only counts if it happens to a REAL process. The unit suite
# can assert resolveRefuseAnonymous throws; only this loop can assert that the
# throw actually reaches `npm start` and stops the container coming up. Raised by
# Tesla on PR #6: the new throw is exactly the class this script exists for, and
# without this check the first bad value would be discovered by a real deploy.
#
# Runs on its own port so it cannot collide with the server still under test above.
BOOT_LOG=$(mktemp)
set +e
REALM_REFUSE_ANONYMOUS=yes PORT=$((PORT + 1)) timeout 10 npm start >"$BOOT_LOG" 2>&1
BOOT_RC=$?
set -e

# Assert the CORPSE, not a substring in a log. Three distinct outcomes, and only
# one is a pass (Tesla, PR #6: "you measured a substring, not a corpse"):
#   0   -> it booted and exited cleanly. Not a refusal.
#   124 -> `timeout` killed it, meaning it was still SERVING. Log-the-error-and-
#          listen-anyway is the false green this check exists to prevent.
#   else-> it died on its own, which is the refusal we want.
if [ "$BOOT_RC" -eq 124 ]; then
  check 'a bad REALM_REFUSE_ANONYMOUS refuses to boot' 'died' 'still serving after 10s'
elif [ "$BOOT_RC" -eq 0 ]; then
  check 'a bad REALM_REFUSE_ANONYMOUS refuses to boot' 'died' 'exited 0 without refusing'
else
  check 'a bad REALM_REFUSE_ANONYMOUS refuses to boot' 'died' 'died'
  # And it must say WHY: a service that dies silently on a typo is
  # indistinguishable from one that crashed for an unrelated reason.
  check 'the boot refusal names the variable' 1 \
    "$(grep -c 'REALM_REFUSE_ANONYMOUS' "$BOOT_LOG" >/dev/null && echo 1 || echo 0)"
fi
rm -f "$BOOT_LOG"

# The ON path through the REAL entrypoint. The check above proves a bad value
# kills the process; nothing proved a GOOD value reaches the handler. Delete the
# `...appOptionsFromEnv(process.env)` spread from index.js and every unit test
# plus the corpse check above stay green while production runs permissive
# (Tesla, PR #6 round 4 — the untested-wiring class one layer up from Carnot's
# round-1 finding).
#
# The ON path, proven at the WIRE — the corpse, not the press release.
#
# An earlier version grepped the boot log for the policy line and claimed a real
# 403 was unreachable "without a real anonymous Firebase credential". That was a
# manufactured blocker, and a wrong picture of the machine: /livekit-token never
# speaks to Firebase. It verifies a Realm JWT with the ES256 public key already in
# this process's environment, and devenv.sh has already exported the matching
# PRIVATE key. So the credentials can simply be minted here. (Tesla, PR #6 round
# 6 — an impossibility claim that consumed its own falsifier.)
#
# A log line is the same class as the substring buried above: createApp could
# print refuseAnonymous:true and still hand `false` to makeMintHandler. These
# three probes cannot be satisfied that way.
ON_PORT=$((PORT + 2))
ON_LOG=$(mktemp)
REALM_REFUSE_ANONYMOUS=true PORT=$ON_PORT npm start >"$ON_LOG" 2>&1 &
ON_PID=$!
ON_BASE="http://127.0.0.1:$ON_PORT"
for _ in $(seq 1 50); do curl -fsS "$ON_BASE/healthz" >/dev/null 2>&1 && break; sleep 0.2; done

# Sign against the SAME ephemeral private key the server verifies with.
mint_cred() {  # $1 = prov ('' for a credential with no prov claim); $2 = 'forge' to sign with a foreign key
  node -e '
    const jwt = require("jsonwebtoken");
    const crypto = require("crypto");
    const prov = process.argv[1];
    const key = process.argv[2] === "forge"
      ? crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ type: "pkcs8", format: "pem" })
      : process.env.REALM_JWT_PRIVATE_KEY;
    const payload = prov ? { prov } : {};
    process.stdout.write(jwt.sign(payload, key, {
      algorithm: "ES256", issuer: "realm", audience: "realm:livekit-mint",
      subject: "verify-sh", expiresIn: 3600,
    }));
  ' "$1" "${2:-}"
}
mint_status() {  # $1 = bearer
  curl -s -o /dev/null -w '%{http_code}' -X POST "$ON_BASE/livekit-token" \
    -H 'content-type: application/json' -H "authorization: Bearer $1" \
    -d '{"roomName":"verify_room"}'
}

check 'ON: an anonymous principal is refused at the wire' 403 "$(mint_status "$(mint_cred anonymous)")"
check 'ON: an unknown provider is refused at the wire'    403 "$(mint_status "$(mint_cred firebase)")"
check 'ON: a credential with no prov is refused'          403 "$(mint_status "$(mint_cred '')")"
check 'ON: a signed-in principal still mints'             200 "$(mint_status "$(mint_cred google)")"
check 'ON: a forged credential is 401, never 403'         401 "$(mint_status "$(mint_cred anonymous forge)")"

kill "$ON_PID" 2>/dev/null || true
wait "$ON_PID" 2>/dev/null || true
held="$(listener_on "$ON_PORT")"; [ -n "$held" ] && kill $held 2>/dev/null || true
rm -f "$ON_LOG"

echo
if [ "$failures" -eq 0 ]; then
  echo "all checks passed"
else
  echo "$failures check(s) failed"
fi
exit "$failures"
