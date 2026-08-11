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
  // Before the body parser: a preflight carries no body, and a denied origin
  // should not reach the parser at all.
  app.use(makeCorsMiddleware({ allowedOrigins, allowLocalhost }));
  app.use(express.json({ limit: '16kb' }));

  app.get('/healthz', (_req, res) => res.json({ ok: true }));
  app.post('/exchange', makeExchangeHandler({ verifyProviderIdToken, privateKeyPem, ttlSeconds }));
  app.post('/livekit-token', makeMintHandler({ publicKeyPem, mintLiveKitToken }));

  return app;
}
