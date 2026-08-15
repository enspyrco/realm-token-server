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
```

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
`CORS_ALLOWED_ORIGINS`, which is required at startup. A container that boots
without it exits immediately rather than serving a web-broken deployment. The
Dockerfile sets `NODE_ENV=production`, so allowlist entries must be https DNS
names.
