import express from 'express';
import { makeExchangeHandler } from './exchange.js';
import { makeMintHandler } from './mint.js';
import { makeCorsMiddleware } from './cors.js';

// Builds the express app. Every dependency is injected so tests supply fakes for
// the provider verifier and the LiveKit minter — no real credentials needed to
// exercise the full request path.
//
// One service, two handlers (DESIGN.md, resolved 2026-08-10). The private key is
// handed only to the exchange handler; the mint handler gets only the public
// key. Key scope is enforced by which closure receives which key, here.
export function createApp({
  verifyProviderIdToken,
  privateKeyPem,
  publicKeyPem,
  mintLiveKitToken,
  ttlSeconds = 3600,
  allowedOrigins = [],
  allowLocalhost = false,
}) {
  const app = express();
  // Before the body parser so a preflight never pays for JSON parsing it has no
  // body for. Note it does NOT stop a disallowed origin from reaching the
  // handlers: CORS is browser-enforced, so a denied cross-origin POST still runs
  // and is merely unreadable by the caller (see the comment in cors.js).
  app.use(makeCorsMiddleware({ allowedOrigins, allowLocalhost }));
  app.use(express.json({ limit: '16kb' }));

  // Service-wide, not per-route: the token responses carry a credential in their
  // body, and an intermediary may store and replay them (Caddy already fronts
  // this service, so "nothing caches it" is a fact about today only). Applying
  // it once here means a future route cannot forget it — which a per-route
  // wiring, having to be remembered, eventually would.
  app.use((_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  app.get('/healthz', (_req, res) => res.json({ ok: true }));
  app.post('/exchange', makeExchangeHandler({ verifyProviderIdToken, privateKeyPem, ttlSeconds }));
  app.post('/livekit-token', makeMintHandler({ publicKeyPem, mintLiveKitToken }));

  return app;
}
