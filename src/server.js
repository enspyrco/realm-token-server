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
  allowedOrigins,
  allowLocalhost = false,
}) {
  // Required, not defaulted. A default of [] builds a server that is green on
  // /healthz, fine under curl, and refuses every honest browser — the silent
  // web-only failure this module exists to remove, reachable by any caller that
  // isn't src/index.js. Pass [] explicitly to mean "serves no browser".
  if (!Array.isArray(allowedOrigins)) {
    throw new Error('createApp: allowedOrigins is required (pass [] to serve no browser)');
  }

  const app = express();

  // FIRST, ahead of CORS: the preflight short-circuits with a 204 inside the
  // CORS middleware, so anything mounted after it never sees an OPTIONS. A
  // preflight is the one response class designed to be cached, which makes it
  // the one that most needs the directive. Service-wide rather than per-route so
  // a future route cannot forget it.
  app.use((_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  // Before the body parser so a preflight never pays for JSON parsing it has no
  // body for.
  app.use(makeCorsMiddleware({ allowedOrigins, allowLocalhost }));
  app.use(express.json({ limit: '16kb' }));

  app.get('/healthz', (_req, res) => res.json({ ok: true }));
  app.post('/exchange', makeExchangeHandler({ verifyProviderIdToken, privateKeyPem, ttlSeconds }));
  app.post('/livekit-token', makeMintHandler({ publicKeyPem, mintLiveKitToken }));

  return app;
}
