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
`*`, because callers send a bearer credential. Set `CORS_ALLOW_LOCALHOST=true`
in dev only — Flutter's dev server picks a random port per run.

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

### One-time host setup

The registry is private, so the host needs a GHCR read token:

```bash
echo "$GHCR_READ_PAT" | docker login ghcr.io -u <github-user> --password-stdin
```

The box's `.env` must contain every variable in `.env.example` — including
`CORS_ALLOWED_ORIGINS`, which is required at startup. A container that boots
without it exits immediately rather than serving a web-broken deployment.
