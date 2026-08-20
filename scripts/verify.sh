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
# Main + every probe port, in one place. Adding a probe means adding its offset
# HERE, and cleanup follows automatically.
PROBE_PORTS="$PORT $((PORT + 1)) $((PORT + 2)) $((PORT + 3))"
# Ports this run has actually bound. Cleanup kills listeners on THESE only, so an
# early exit caused by somebody else's server cannot evict it.
STARTED_PORTS=""
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
  # ONLY ports this run actually BOUND — never the full PROBE_PORTS list.
  #
  # `trap cleanup EXIT` is installed before the occupied-port refusals, so the
  # "port already in use — stop it, or use PORT=8899" exit path still runs
  # cleanup. Against a static list it then killed the listener it had just
  # politely declined to touch: the script contradicting its own "Refuse rather
  # than evict" contract and terminating a developer's running work.
  # (Carnot, PR #11 round 3.)
  #
  # STARTED_PORTS is appended at each successful launch, so a port we refused to
  # bind is not in it and cannot be killed. Adding a probe means adding its
  # offset to PROBE_PORTS (for the occupancy checks) and recording it here when
  # it actually starts.
  for p in $STARTED_PORTS; do
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
STARTED_PORTS="$STARTED_PORTS $PORT"

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

# The THIRD state of the switch, at the real entrypoint. The corpse check binds
# the typo case and the ON probes bind "true"; this binds UNSET — the default, and
# the one the README promises is behaviour-identical. Hardcode the flag on after
# the index.js spread and every other check here stays green while that promise
# shatters (Tesla, PR #6 round 8 — availability, not fail-open, hence not a
# blocker, but it closes the triad).
#
# Deliberately BEFORE the rate-limit section: those checks deliberately exhaust
# the mint ceiling, and a 429 here would be indistinguishable from a refusal.
mint_cred_main() {
  node -e '
    const jwt = require("jsonwebtoken");
    process.stdout.write(jwt.sign({ prov: process.argv[1] }, process.env.REALM_JWT_PRIVATE_KEY, {
      algorithm: "ES256", issuer: "realm", audience: "realm:livekit-mint",
      subject: "verify-sh-default", expiresIn: 3600,
    }));
  ' "$1"
}
check 'UNSET: an anonymous principal still mints (default is off)' 200 \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/livekit-token" \
      -H 'content-type: application/json' \
      -H "authorization: Bearer $(mint_cred_main anonymous)" \
      -d '{"roomName":"default_room"}')"

check 'an allowed origin gets a preflight' 204 \
  "$(status -X OPTIONS "$BASE/exchange" -H "Origin: $CORS_ALLOWED_ORIGINS" -H 'Access-Control-Request-Method: POST')"

check 'an allowed origin is echoed back' "$CORS_ALLOWED_ORIGINS" \
  "$(curl -s -o /dev/null -D - -X OPTIONS "$BASE/exchange" \
      -H "Origin: $CORS_ALLOWED_ORIGINS" -H 'Access-Control-Request-Method: POST' \
      | grep -i '^access-control-allow-origin:' | cut -d' ' -f2- | tr -d '\r')"

check 'a disallowed origin is refused' 403 \
  "$(status -X POST "$BASE/exchange" -H 'Origin: https://evil.example' \
      -H 'content-type: application/json' -d '{}')"

# UNSET, at the real entrypoint: the behaviour-identical promise. devenv.sh sets
# TRUST_PROXY_HOPS=0, so XFF is ignored regardless — what this binds is narrower
# than it looks and is written narrowly on purpose: the middleware never REFUSES a
# request, only a claim.
#
# SCOPE, corrected by Carnot in PR #11 round 1: an earlier version of this comment
# claimed the probe proved the env var reached createApp AND that the middleware was
# mounted before req.ip is read. It proves neither — with hops=0 and no secret, the
# result is identical whether the middleware is mounted, misordered, or absent. The
# probe that actually binds those is the ENFORCED one further down (PORT+3), which
# needs a secret set and hops=1 before the assertion can distinguish anything.
check 'UNSET: a request carrying a proxy-secret header is still served' 401 \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/exchange" \
      -H 'content-type: application/json' \
      -H 'x-realm-proxy-secret: not-configured-here' \
      -H 'x-forwarded-for: 203.0.113.7' \
      -d '{"idToken":"nope"}')"

# The rate limit, over the wire. TWO /exchange requests are already spent above
# (the bad-token check and the proxy-secret probe), so this takes the per-IP
# window to its ceiling and one past it.
# KEEP IN SYNC: every /exchange request added above must come off this count.
for _ in $(seq 1 28); do post_exchange >/dev/null; done
check 'the per-IP ceiling refuses the next request' 429 "$(post_exchange)"

# The mint route has its own ceiling and its own budget. Exercised separately
# because it is the route that dispatches an agent into a room — the amplification
# this whole ceiling exists for — and a check that only ever walks /exchange would
# report green with the mint route wide open.
check 'the mint route still has its own budget' 401 \
  "$(status -X POST "$BASE/livekit-token" -H 'content-type: application/json' -d '{"roomName":"r"}')"
# 28, not 30: TWO checks above already spent one mint request each — the budget
# check, and the UNSET default-off probe added in PR #6 — so this takes the window
# to exactly the ceiling and the assertion below is the FIRST refusal rather than
# some request after it. A probe that lands past the boundary still goes red when
# the limiter is missing, but it no longer measures where the boundary is.
# KEEP THIS IN SYNC: every mint-route request added above must come off this count.
for _ in $(seq 1 28); do
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
# can assert resolveRequireKnownProvider throws; only this loop can assert that the
# throw actually reaches `npm start` and stops the container coming up. Raised by
# Tesla on PR #6: the new throw is exactly the class this script exists for, and
# without this check the first bad value would be discovered by a real deploy.
#
# Runs on its own port so it cannot collide with the server still under test above.
# Same occupancy discipline as the main port and the enforcement port. A held
# PORT+1 would make this child die at bind — which still exits non-zero, so the
# corpse check would pass for the WRONG REASON. (The follow-up assertion that the
# log names the variable does catch it, so this fails loudly either way; the
# explicit check just says which of the two happened.)
if [ -n "$(listener_on $((PORT + 1)))" ]; then
  echo "FAIL port $((PORT + 1)) (boot-refusal probe) is already in use by pid(s) $(listener_on $((PORT + 1)) | tr '\n' ' ')"
  exit 1
fi

BOOT_LOG=$(mktemp)
set +e
STARTED_PORTS="$STARTED_PORTS $((PORT + 1))"
REALM_REQUIRE_KNOWN_PROVIDER=yes PORT=$((PORT + 1)) timeout 10 npm start >"$BOOT_LOG" 2>&1
BOOT_RC=$?
set -e

# Assert the CORPSE, not a substring in a log. Three distinct outcomes, and only
# one is a pass (Tesla, PR #6: "you measured a substring, not a corpse"):
#   0   -> it booted and exited cleanly. Not a refusal.
#   124 -> `timeout` killed it, meaning it was still SERVING. Log-the-error-and-
#          listen-anyway is the false green this check exists to prevent.
#   else-> it died on its own, which is the refusal we want.
if [ "$BOOT_RC" -eq 124 ]; then
  check 'a bad REALM_REQUIRE_KNOWN_PROVIDER refuses to boot' 'died' 'still serving after 10s'
elif [ "$BOOT_RC" -eq 0 ]; then
  check 'a bad REALM_REQUIRE_KNOWN_PROVIDER refuses to boot' 'died' 'exited 0 without refusing'
else
  check 'a bad REALM_REQUIRE_KNOWN_PROVIDER refuses to boot' 'died' 'died'
  # And it must say WHY: a service that dies silently on a typo is
  # indistinguishable from one that crashed for an unrelated reason.
  check 'the boot refusal names the variable' 1 \
    "$(grep -c 'REALM_REQUIRE_KNOWN_PROVIDER' "$BOOT_LOG" >/dev/null && echo 1 || echo 0)"
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
# print requireKnownProvider:true and still hand `false` to makeMintHandler. These
# three probes cannot be satisfied that way.
ON_PORT=$((PORT + 2))
ON_LOG=$(mktemp)

# Refuse an occupied port, exactly as the main server does on entry. Without this
# the failure is silent and inverted: a leftover listener (a SIGKILLed run, a node
# that outlived the `timeout` which SIGTERMed only `npm`) means our `npm start`
# dies at bind, the healthz loop answers the STRANGER, and the five probes below
# measure someone else's process. If that stranger happens to refuse anonymous,
# the load-bearing proof that THIS commit's wiring reached makeMintHandler goes
# green in the dark. (Tesla, PR #6 round 7 — a frequency this script named for
# PORT+2 and then only guarded on PORT.)
if [ -n "$(listener_on "$ON_PORT")" ]; then
  echo "FAIL port $ON_PORT (enforcement probe) is already in use by pid(s) $(listener_on "$ON_PORT" | tr '\n' ' ')"
  echo "     Stop it, or run with a different port: PORT=8899 ./scripts/verify.sh"
  exit 1
fi

REALM_REQUIRE_KNOWN_PROVIDER=true PORT=$ON_PORT npm start >"$ON_LOG" 2>&1 &
ON_PID=$!
STARTED_PORTS="$STARTED_PORTS $ON_PORT"
ON_BASE="http://127.0.0.1:$ON_PORT"
for _ in $(seq 1 50); do curl -fsS "$ON_BASE/healthz" >/dev/null 2>&1 && break; sleep 0.2; done

# And confirm the thing answering is OURS. A healthz 200 proves something is
# listening, not that it is the process we started with this commit's code.
if ! kill -0 "$ON_PID" 2>/dev/null; then
  echo "FAIL enforcement server (pid $ON_PID) is not running — the probes below would measure a stranger"
  cat "$ON_LOG"
  exit 1
fi

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

# The ENFORCED path at the real entrypoint — the probe Carnot's round-1 finding
# said was missing. It needs a real secret AND hops=1 before a forged
# X-Forwarded-For means anything, so it is the only check here that can tell a
# mounted middleware from an absent one at the wire.
#
# SCOPE, measured rather than asserted (the first draft of this comment claimed it
# distinguished a correctly-ORDERED mount, which it does not): deleting the
# app.use turns this RED; moving the app.use below the request logger leaves it
# GREEN. So it binds PRESENCE and position-ahead-of-the-rate-limiters. It does not
# bind position relative to the logger — and it needn't, because the logger reads
# req.ip on 'finish', after this has already run either way.
#
# The assertion is the vulnerability itself, inverted. Rotate a forged client
# address past the per-IP ceiling: unauthenticated, every address is discarded and
# they all key on one socket, so the limiter bites (429). Delete the app.use, or
# mount it after the logger where req.ip is already computed, and each forged
# address gets its own bucket — no 429, and this goes red.
#
# Own port so it cannot collide with the servers above, and the same
# occupancy-refusal discipline as the others.
ENF_PORT=$((PORT + 3))
if [ -n "$(listener_on "$ENF_PORT")" ]; then
  echo "FAIL port $ENF_PORT (proxy-auth probe) is already in use by pid(s) $(listener_on "$ENF_PORT" | tr '\n' ' ')"
  exit 1
fi

ENF_SECRET="verify-sh-proxy-secret-0123456789abcdef"
ENF_LOG=$(mktemp)
REALM_TRUSTED_PROXY_SECRET="$ENF_SECRET" TRUST_PROXY_HOPS=1 PORT=$ENF_PORT npm start >"$ENF_LOG" 2>&1 &
ENF_PID=$!
STARTED_PORTS="$STARTED_PORTS $ENF_PORT"
ENF_BASE="http://127.0.0.1:$ENF_PORT"
for _ in $(seq 1 50); do curl -fsS "$ENF_BASE/healthz" >/dev/null 2>&1 && break; sleep 0.2; done

# Confirm the thing answering is OURS, not a stranger that won the bind.
if ! kill -0 "$ENF_PID" 2>/dev/null; then
  echo "FAIL proxy-auth server (pid $ENF_PID) is not running — the probes below would measure a stranger"
  cat "$ENF_LOG"
  exit 1
fi

enf_post() {  # $1 = forged client address; $2 = 'auth' to present the secret
  if [ "${2:-}" = "auth" ]; then
    curl -s -o /dev/null -w '%{http_code}' -X POST "$ENF_BASE/exchange" \
      -H 'content-type: application/json' -H "x-forwarded-for: $1" \
      -H "x-realm-proxy-secret: $ENF_SECRET" -d '{"idToken":"nope"}'
  else
    curl -s -o /dev/null -w '%{http_code}' -X POST "$ENF_BASE/exchange" \
      -H 'content-type: application/json' -H "x-forwarded-for: $1" -d '{"idToken":"nope"}'
  fi
}

check 'ENFORCED: the boot line announces the policy' 1 \
  "$(grep -c '"proxyAuth":"enforced"' "$ENF_LOG" >/dev/null && echo 1 || echo 0)"

# 30 rotating forged addresses. Unauthenticated they all key on the socket, so the
# ceiling is reached; if the strip were not happening each would be its own bucket.
enf_seen_429=0
for i in $(seq 1 31); do
  [ "$(enf_post "203.0.113.$i")" = "429" ] && { enf_seen_429=1; break; }
done
check 'ENFORCED: rotating a forged X-Forwarded-For cannot evade the ceiling' 1 "$enf_seen_429"

# The OTHER terminal, at the wire. The check above binds fail-OPEN (a forgery must
# not buy a fresh bucket). It is deaf to fail-closed-too-hard: invert the `if (!ok)`
# to always-strip and it stays green while every real client collapses onto one
# bucket — the outage a naive address-based fix would have shipped. Only an
# in-process test caught that, in the chamber this file exists because it cannot
# witness wiring. `enf_post ... auth` existed and was never driven; a helper that
# cannot fire is a press release. (Tesla, PR #11 round 3.)
#
# The ceiling is already spent by the loop above, so an AUTHENTICATED caller
# presenting a fresh client address must still be served: its bucket is its own.
check 'ENFORCED: an authenticated proxy still gets a fresh bucket past the ceiling' 401 \
  "$(enf_post "198.51.100.42" auth)"

kill "$ENF_PID" 2>/dev/null || true
wait "$ENF_PID" 2>/dev/null || true
held="$(listener_on "$ENF_PORT")"; [ -n "$held" ] && kill $held 2>/dev/null || true
rm -f "$ENF_LOG"

echo
if [ "$failures" -eq 0 ]; then
  echo "all checks passed"
else
  echo "$failures check(s) failed"
fi
exit "$failures"
