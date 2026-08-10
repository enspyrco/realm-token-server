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
   Realm credential — never a raw ID token — so the exchange boundary can't be
   bypassed.

**Asymmetric signing is load-bearing:** the mint handler holds only the public
key, so no mint-side bug can forge a credential. Enforced structurally by which
closure receives which key (`src/server.js`).

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

Built as a Docker image, run beside LiveKit + the bot. Secrets are injected as
env (never baked into the image) — see the `Dockerfile` header. The LiveKit
key/secret are the same pair already in the box's `livekit.yaml`.
