import express from 'express';
import { makeExchangeHandler } from './exchange.js';
import { makeMintHandler } from './mint.js';
import { makeCorsMiddleware } from './cors.js';
import { makeRequestLogger } from './requestLog.js';
import { makeRateLimiter } from './rateLimit.js';

const MINUTE_MS = 60_000;

// Per-IP ceilings, in requests per minute. An honest client exchanges once per
// sign-in and mints once per room join, so both of these are orders of magnitude
// above real use — deliberately, because the address seen here can be a shared
// NAT carrying many legitimate users, and throttling a household or an office
// down to one person's rate would be a worse bug than the abuse being prevented.
// These are ceilings on abuse, not a fair-use policy.
const EXCHANGE_PER_IP_PER_MINUTE = 30;
const MINT_PER_IP_PER_MINUTE = 30;

// A service-wide circuit breaker across BOTH mint routes, keyed on nothing so it
// cannot be evaded by rotating source addresses the way the per-IP layer can.
// This is the number that actually bounds how much of the Firebase project's
// quota a bad afternoon can spend. Set far above plausible legitimate volume:
// crossing it should mean something is wrong, not that the service got popular.
const GLOBAL_PER_MINUTE = 600;

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
  log,
  // How many proxy hops in front of this process wrote X-Forwarded-For. 0 means
  // "this process is reached directly", which is true of a local `npm start` and
  // of every test in this repo, and false of the deploy. index.js resolves it
  // from the environment via resolveTrustProxyHops, which refuses to guess in
  // production. See rateLimit.js for why both wrong values fail silently.
  trustProxyHops = 0,
  now = Date.now,
}) {
  // Required, not defaulted. A default of [] builds a server that is green on
  // /healthz, fine under curl, and refuses every honest browser — the silent
  // web-only failure this module exists to remove, reachable by any caller that
  // isn't src/index.js. Pass [] explicitly to mean "serves no browser".
  if (!Array.isArray(allowedOrigins)) {
    throw new Error('createApp: allowedOrigins is required (pass [] to serve no browser)');
  }

  if (!Number.isInteger(trustProxyHops) || trustProxyHops < 0) {
    throw new TypeError('createApp: trustProxyHops must be a non-negative integer');
  }

  const app = express();

  // Decides what req.ip means, which is the whole of whether the per-IP limiter
  // is per-IP. Express reads X-Forwarded-For right-to-left and treats the first
  // address beyond `trustProxyHops` trusted hops as the client, so a forged
  // prefix from an untrusted caller is ignored at the correct setting.
  app.set('trust proxy', trustProxyHops);

  // Before everything, so the log sees requests CORS refuses (403s, denied
  // preflights) — those are exactly the ones worth seeing. It writes on
  // 'finish', so the status it records is the one actually sent.
  app.use(makeRequestLogger(log ? { log } : {}));

  // Ahead of CORS: the preflight short-circuits with a 204 inside the
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
  // Note the ordering cost, since it is a deliberate choice and not an oversight:
  // this runs app-wide, so a request the per-route limiters below will refuse
  // has already paid for its body parse. That parse is bounded at 16kb and is
  // not the expense worth rationing — verifyIdToken's network round trip and the
  // dispatch-carrying mint are, and both sit behind the limiters.
  app.use(express.json({ limit: '16kb' }));

  // Mounted per-route rather than app-wide, so /healthz and any unknown path
  // stay unthrottled by construction: the healthcheck must never be able to
  // 429 itself into a restart loop, and a 404 costs nothing worth rationing.
  // OPTIONS never arrives here either — cors.js answers every preflight with a
  // 204 upstream — so a browser's preflight cannot consume a caller's budget.
  //
  // Per-IP runs BEFORE global so that one abusive source is refused out of its
  // own bucket without first spending the service-wide budget everyone shares;
  // reversing these would let a single caller push the whole service to its
  // ceiling, which is the outage the global limiter exists to prevent.
  const globalLimit = makeRateLimiter({
    limit: GLOBAL_PER_MINUTE,
    windowMs: MINUTE_MS,
    key: () => 'global',
    // One key, so the table cannot grow and eviction can never discard it.
    maxKeys: 1,
    now,
  });
  const exchangeLimit = makeRateLimiter({
    limit: EXCHANGE_PER_IP_PER_MINUTE,
    windowMs: MINUTE_MS,
    now,
  });
  const mintLimit = makeRateLimiter({
    limit: MINT_PER_IP_PER_MINUTE,
    windowMs: MINUTE_MS,
    now,
  });

  app.get('/healthz', (_req, res) => res.json({ ok: true }));
  app.post(
    '/exchange',
    exchangeLimit,
    globalLimit,
    makeExchangeHandler({ verifyProviderIdToken, privateKeyPem, ttlSeconds }),
  );
  app.post(
    '/livekit-token',
    mintLimit,
    globalLimit,
    makeMintHandler({ publicKeyPem, mintLiveKitToken }),
  );

  return app;
}
