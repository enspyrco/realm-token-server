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

  // Both token responses carry a credential in their body. Without an explicit
  // directive an intermediary may store and replay them; Caddy already fronts
  // this service, so "no cache sits in front of it" is a fact about today only.
  const noStore = (_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  };

  app.get('/healthz', (_req, res) => res.json({ ok: true }));
  app.post('/exchange', noStore, makeExchangeHandler({ verifyProviderIdToken, privateKeyPem, ttlSeconds }));
  app.post('/livekit-token', noStore, makeMintHandler({ publicKeyPem, mintLiveKitToken }));

  return app;
}
