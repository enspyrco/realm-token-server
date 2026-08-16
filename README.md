# realm-token-server

The Realm **credential-exchange + LiveKit token-mint** server. Production home for
the token endpoint decided in `enspyrco/tech_world` — `packages/realm/DESIGN.md`,
"Credential exchange boundary" (resolved 2026-08-10). Replaces the Firebase Cloud
Function `retrieveLiveKitToken`; runs as a small Node service on OCI next to
LiveKit (which already holds the LiveKit API secret).

## Why this exists

LiveKit is self-hosted on OCI, so minting tokens is "hold the API secret, sign a
JWT" — no Firebase needed. Verifying a Firebase **ID token** *does* want the
Firebase Admin SDK (first-class in Node, mature nowhere in Dart), so the server
is Node. Firebase shrinks to being an *identity provider*; everything real-time
is ours.

**No Firebase service account needed.** `verifyIdToken` (checkRevoked=false)
fetches only Google's public signing certs, so the Admin SDK initialises from
`FIREBASE_PROJECT_ID` alone — there is no JSON key to store or rotate.

## Two endpoints, one service

```
POST /exchange          { idToken }                              -> { token, expiresAt }
POST /livekit-token     { roomName }  Authorization: Bearer <token>  -> { token }
GET  /healthz
```

1. **`/exchange`** — the sole trust-establishment point. Verifies the provider
   ID token (Firebase Admin SDK) and mints an opaque **Realm credential**
   (ES256). Holds the ES256 **private** key.
2. **`/livekit-token`** — verifies the Realm credential (public key only) and
   mints a LiveKit access token with agent dispatch embedded. Accepts **only** a
   Realm credential — never a raw ID token — so the *authentication* boundary
   can't be bypassed.

**Asymmetric signing is load-bearing:** the mint handler holds only the public
key, so no mint-side bug can forge a credential. Enforced structurally by which
closure receives which key (`src/server.js`).

**Not yet enforced: room authorization.** `/livekit-token` answers *who are
you*, not *may you enter this room* — any authenticated caller can currently
mint a token for any `roomName`. Private rooms need an admission predicate the
Realm data model does not yet have (rooms carry `editorIds`/`canEdit`, which is
edit rights, not a join roster). Tracked in `nickmeinhold/claude-tasks#2850`.

## CORS

The deployed client is Flutter **web**, so both endpoints are cross-origin and
unreachable from the browser without CORS headers — while curl and the native
builds keep working, which is how this failure hides. `CORS_ALLOWED_ORIGINS` is
a **required**, comma-separated, exact-match allowlist (`src/cors.js`); never
`*`. Set `CORS_ALLOW_LOCALHOST=true` in dev only — Flutter's dev server picks a
random port per run.

When `NODE_ENV=production` (which the Dockerfile sets), two rules apply, both
resolved in one place — `corsConfigFromEnv` in `src/cors.js`:

1. **Every allowlisted origin must be an `https` DNS name.** Both halves are
   required and neither implies the other. `https` alone still admits
   `https://app.localhost` and `https://[::ffff:7f00:1]`; the host rule alone
   would still admit a plaintext downgrade of the real origin
   (`http://world.imagineering.cc`). The host rule is stated as a requirement —
   *a real deployment's origin is a DNS name* — rather than as a denylist of
   loopback aliases, because loopback has more names than anyone enumerates
   (`localhost`, `127.0.0.0/8`, `[::1]`, `[::ffff:7f00:1]`, `app.localhost` per
   RFC 6761, `0.0.0.0`) and two successive denylists here were both incomplete.
   IP literals in either family are refused outright via `net.isIP`.
2. **`CORS_ALLOW_LOCALHOST=true` is refused outright**, because the opt-in admits
   any port on loopback — harmless on a laptop, and on a public mint it would let
   any page a developer's machine loads read `/exchange` and `/livekit-token`.

A request carrying **no** `Origin` is served normally (curl, the bot, health
checks). A **disallowed** `Origin` is handled differently by request kind: a
preflight gets `204` *without* the allow headers, which is what makes the browser
block the real request; a non-preflight request gets `403`. That second rule is
not authentication — `Origin` is forgeable off-browser and the bearer credential
remains the only thing that authorises — it closes the window where an honest
browser still reaches the handler via a preflight cached from before an origin
was revoked.

Entries are validated at boot: each must be exactly `scheme://host[:port]`, and
`*`, `null`, a trailing slash, a path, or an explicit default port are all
rejected with the offending value named. Every one of those matches no `Origin`
a browser will ever send, so accepting them would boot a server that is green on
`/healthz`, fine under curl, and dead in the browser — the precise failure this
allowlist exists to remove.

The exact-match rule is defence in depth rather than the only thing standing
between a page and a session: the bearer credential is not ambient authority, so
unlike a cookie a hostile origin cannot make the browser attach it. What the
allowlist buys is denying cross-origin reconnaissance, and staying correct if
this service ever gains a cookie or `Access-Control-Allow-Credentials`.

## Logging

One structured JSON line per request (`src/requestLog.js`) — method, path,
status, duration, `origin`, and whether CORS admitted it. Mounted before CORS,
so refused requests (403s, denied preflights) are logged too: a denial that
leaves no trace is indistinguishable from no traffic.

**Transport facts only, and the path is normalised rather than echoed.** Nothing
derived from a request body, an `Authorization` header, or a minted token is
logged — and because a URL carries secrets just as readily (a copied link, a
proxy rewrite, a client appending a token to `/exchange/…`), an unrecognised
path is recorded as `other`. Excluding bodies and headers alone was not "by
construction"; this is. There is deliberately no subject, so correlation costs a
considered change rather than leaking a uid by default. A test asserts the ID
token, the presented credential, the minted token and the subject are all absent.

**A throwing log sink cannot take down the mint.** The write happens in an
`EventEmitter` listener after the response is sent, so an escaping throw would be
an uncaught exception. It is wrapped, and a test asserts a *subsequent logged
request* still succeeds while the sink throws.

Stated precisely, because the weaker claim is the true one: this covers
**exceptions**, not backpressure. `console.log` is a synchronous write, so a
backed-up Docker logging driver blocks the event loop rather than throwing — and
this raises the write rate from one line per process to one per request. The sink
must also be synchronous: a function returning a rejected promise escapes the
`try` entirely.

Both `finish` and `close` are handled (guarded to write once), so an aborted
connection or a slowloris hold is logged with `completed: false` rather than
vanishing — the same silence this module exists to end, on the path that matters
most. `origin` is truncated to 256 chars, and `originAllowed` is `null` rather
than `false` when no `Origin` was sent, since those requests are served.

`proxied` is carried for one reason: it is the only signal that says whether the
per-IP rate limit is keyed on a real client address or on the proxy in front of
it. It records *whether* the address came from a trusted proxy header, never the
address — the fact is transport, the address is a person, and this log has no
subject on purpose.

`Origin` is attacker-controlled, so lines are emitted via `JSON.stringify`: a
raw-string format would let a newline in `Origin` forge whole log entries.

`/healthz` is skipped — the container healthcheck fires every 30s and
`docker inspect` already answers what those lines would say.

## Rate limiting

Both POST routes do real work for a caller they have not yet authenticated:
`/exchange` calls Firebase `verifyIdToken` (a network round trip, plus a cert
fetch on the first call after a container start — 227ms cold vs 4ms warm), and
`/livekit-token` mints a token carrying a `RoomAgentDispatch`, so hammering it
amplifies into rooms rather than merely burning CPU here.

Two fixed-window layers, per route, in this order (`src/rateLimit.js`):

| layer | key | ceiling |
| --- | --- | --- |
| per-IP | client address | 30/min on `/exchange`, 30/min on `/livekit-token` |
| service-wide | none | 600/min across both |

Per-IP runs first, so one abusive source is refused out of its own bucket
without first spending the budget everyone shares. `/healthz` and unknown paths
are never throttled — the healthcheck must not be able to 429 itself into a
restart loop — and preflights never reach the limiter, because CORS answers them
upstream. A refusal is `429` with `Retry-After`. The JSON body parser is mounted
per route *after* the limiters, so a refused request never pays for its parse and
a malformed body still consumes budget rather than escaping the count.

Read the global number precisely: 600/min is 600 requests that got *past* the
per-IP layer, not 600 POST attempts — a caller refused per-IP never reaches it.

**The 403 on a disallowed origin is not a throttle.** Anything outside a browser
omits `Origin` and is served normally, by design. Origin is a browser-honesty
check; this is the volume check.

**`TRUST_PROXY_HOPS` decides whether the per-IP layer is per-IP.** Caddy fronts
this service, so every request arrives from the docker bridge gateway: at `0`
the whole internet shares one bucket and any single caller throttles everyone,
while too high a value lets a caller name its own address per request. Neither
failure raises an error, fails a test, or reddens the healthcheck — so the value
is **required at boot under `NODE_ENV=production`**, **capped at 1** (the number
of proxies actually in front of this service — requiring the value stops the
too-low failure, and nothing else stopped the too-high one), and each request
logs `proxied`.

Read `proxied` as a necessary condition, not a proof, and note which direction it
covers. It detects hops-too-**low** (an all-`false` log means either the limiter
is mis-keyed *or* nothing reached the service through Caddy — both worth looking
at). It is **deaf to hops-too-high**: a caller trusted as a hop writes its own
`X-Forwarded-For`, `proxied` stays `true`, and the log looks healthy while the
per-IP layer has dissolved. That direction is not closed by this field, and it is
closed only *partially* elsewhere — state the boundary exactly:

- **From the internet: closed.** The process listens on all interfaces, but
  `docker-compose.yml` publishes it as `127.0.0.1:8791:8080`, so the only route
  in from outside the box is through Caddy — which is the one hop `trust proxy`
  is set for. The cap of 1 keeps it that way.
- **From inside the box: open, and accepted.** Anything that can already reach
  the container's `:8080` directly — a sibling service on the docker network, a
  process on the host — is trusted as the proxy and may name its own client
  address, dissolving the per-IP layer for itself. The service-wide ceiling still
  holds. This is accepted rather than solved: a caller with that position already
  shares a host with the ES256 signing key. Narrowing `trust proxy` from a hop
  count to the gateway address would close it (claude-tasks#3190).

Raising the cap is a code change, not a config change, and that is on purpose:
adding a second proxy alters who is allowed to name the client, which is not a
decision an env var should be able to make on its own. A `429` also records which ceiling refused it
(`rateLimited`), because a per-IP refusal and a service-wide one are opposite
events wearing the same status code.

Stated at its proven scope: this is a ceiling on accidental and single-source
abuse. A caller with many source addresses can churn the bounded per-key table
and evade the per-IP layer — which is why the service-wide layer is keyed on
nothing, and so cannot be evaded *by rotating source addresses*. Both layers are
in-memory and process-local: a restart resets both windows, and a second replica
would carry its own independent ceilings. Neither layer is a defence against a
distributed attack.

It is also **not** authorization. `/livekit-token` still mints a token for any
`roomName` to any holder of a valid credential; admission control does not exist
yet (claude-tasks#2850).

## Contract parity

The credential format (`iss=realm`, `aud=realm:livekit-mint`, `sub`, `prov`
claim, ES256) matches the Dart reference at
`enspyrco/tech_world:examples/livekit-token-server/lib/src/realm_credential_jwt.dart`
and the client `FirebaseAuthProvider` in `packages/realm_firebase`. A credential
minted here verifies against that Dart verifier and vice versa. Keep the two in
lockstep.

## Run

```bash
npm install
cp .env.example .env   # fill in — see comments
npm start              # :8080
npm test               # node --test (no real credentials needed)

./scripts/dev.sh       # the real server on ephemeral keys — no .env needed
./scripts/verify.sh    # boot it and assert over real HTTP — run before commit
```

`npm test` exercises the app in-process with injected fakes. `scripts/verify.sh`
boots the actual `npm start` entrypoint and asserts on the wire: the same env
parsing, the same boot-time refusals, the same middleware order the container
runs. It catches what a green unit suite cannot — an entrypoint that no longer
boots, middleware mounted in the wrong order, a header that never reaches the
wire — and it is the loop to run *before* `git commit`, so review and CI are not
doing verification's job at ten times the cost.

## Deploy (OCI)

Runs beside LiveKit + the bot as a Docker container. Secrets are injected as env
and never baked into the image (see the `Dockerfile` header); the LiveKit
key/secret are the same pair already in the box's `livekit.yaml`.

**The box never builds and never sees the source.** CI publishes a versioned
image to GHCR; the host pulls a pinned version.

### Release — publish an image

1. Bump `version` in `package.json`.
2. Merge to `main`. `.github/workflows/publish.yml` runs the tests, then pushes
   `ghcr.io/enspyrco/realm-token-server:<version>` and `:sha-<commit>`.

Publishing is **not** deploying: nothing running changes. A version tag is
immutable — the workflow fails rather than overwrite one, so merging without
bumping `version` is caught in CI instead of silently replacing a released
artifact.

### Promote — deploy that version

```bash
ssh <box>
cd ~/apps/realm-token-server
$EDITOR docker-compose.yml          # bump the image tag
docker compose pull && docker compose up -d
docker compose ps                   # wait for healthy (healthcheck hits /healthz)
```

Rollback is the same three commands with the previous tag — the old image is
still in the registry and still immutable.

Deliberately a human step. This service mints credentials, so an auth boundary
should not redeploy itself on merge. Switching to reactive CD later (the
`cd-bus` fleet template in `enspyrco/infra`) means pointing the compose `image:`
at a moving tag — a one-line change, not a rework.

### Registry auth

The package is **private**, so a pull needs credentials. The host stores none:
the deploy pipes a short-lived token in over stdin and logs out immediately, so
no credential is left behind and nothing has to be rotated.

```bash
gh auth token | ssh <box> '
  cd ~/apps/realm-token-server
  docker login ghcr.io -u <github-user> --password-stdin
  docker compose pull realm-token-server
  docker logout ghcr.io
'
```

Making the package **public** would remove this step entirely — it is how every
other GHCR service on that box works (`downstream-server`, `aiko-chat-island`
are both public packages and the host holds no docker credentials at all). The
image carries no secrets: config is injected as env and `/app` contains only
`src`, `node_modules`, and the package files. Package visibility can only be
changed in the GitHub UI — there is no REST or GraphQL endpoint for it
(checked) — so it stays private until someone flips it at
`https://github.com/orgs/enspyrco/packages/container/realm-token-server/settings`.

### Host prerequisites

The box's `.env` must contain every variable in `.env.example` — including
`CORS_ALLOWED_ORIGINS` and `TRUST_PROXY_HOPS`, both required at startup. A
container that boots without them exits immediately rather than serving a
web-broken deployment or a rate limiter that buckets the whole internet
together. The Dockerfile sets `NODE_ENV=production`, so allowlist entries must
be https DNS names.

> **Deploy order matters for `TRUST_PROXY_HOPS`.** Add `TRUST_PROXY_HOPS=1` to
> the box's `.env` *before* bumping the image tag. It is absent from the current
> `.env`, so an image from this version pulled first will refuse to boot and the
> container will restart-loop — loudly and by design, but only recoverable by
> editing `.env` on the box.
