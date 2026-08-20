import express from 'express';
import { makeExchangeHandler } from './exchange.js';
import { makeMintHandler } from './mint.js';
import { makeCorsMiddleware } from './cors.js';
import { makeRequestLogger } from './requestLog.js';
import { makeProxyAuthMiddleware, assertValidProxySecret } from './proxyAuth.js';
import { makeRateLimiter, RateLimitScope } from './rateLimit.js';

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
  // Shared secret the reverse proxy presents to have its X-Forwarded-For
  // believed. null means unenforced — see proxyAuth.js. Authenticating the proxy
  // is the only thing that separates it from any other local process, because on
  // this deploy they arrive from the same address.
  trustedProxySecret = null,
  // Deployment-wide requirement that a principal's `prov` be a KNOWN sign-in
  // provider (isSignedInProvider / SIGNED_IN_PROVIDERS) — an allowlist. It refuses
  // anonymous guests, and equally refuses phone auth, custom tokens and anything
  // else not in that set. Describing it as "refuse anonymous" is the denylist
  // utterance that this PR has already had to un-restore once. Defaults OFF so
  // this is behaviour-identical until a deployment opts in. index.js resolves it
  // from the environment via resolveRequireKnownProvider, which refuses to boot on an
  // unrecognised value rather than reading it as off.
  requireKnownProvider = false,
  // Left undefined so rateLimit.js's monotonic default applies; tests inject a
  // frozen clock so no assertion can straddle a window boundary.
  now,
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

  // Same rule as the env resolver, from the same function — createApp is the
  // public constructor and inherits none of appOptionsFromEnv's validation.
  // A bare `typeof === 'string'` check here passed the EMPTY string, which then
  // took the enforcing branch and authenticated any caller sending a bare
  // header (`matches('', '')` is true) while the boot line printed `enforced`.
  // A control that reports enforced while admitting everyone is the exact
  // failure this option exists to remove.
  if (trustedProxySecret !== null) {
    assertValidProxySecret(trustedProxySecret);
  }

  const app = express();

  // Decides what req.ip means, which is the whole of whether the per-IP limiter
  // is per-IP. Express reads X-Forwarded-For right-to-left and treats the first
  // address beyond `trustProxyHops` trusted hops as the client, so a forged
  // prefix from an untrusted caller is ignored at the correct setting.
  app.set('trust proxy', trustProxyHops);

  // MUST precede the RATE LIMITERS. They read req.ip during the request, so a
  // forwarding claim still standing at that point is the one the per-IP bucket
  // is keyed on — which is the entire vulnerability.
  //
  // Corrected 2026-08-20 (PR #11 round 1): an earlier version of this comment
  // said "ahead of the logger, because express computes req.ip lazily on FIRST
  // read and the logger reads it." That mechanism is wrong. requestLog reads
  // req.ip inside res.on('finish') (requestLog.js:120) — after the response, by
  // which time this has run regardless of their relative order. MEASURED: moving
  // this below the logger keeps all 153 unit tests AND the enforced wire probe
  // green; deleting it reddens the wire probe. So the probe binds PRESENCE and
  // position-before-the-limiters, not position-before-the-logger.
  //
  // It stays above the logger anyway, for a smaller and honest reason: the log
  // line then describes post-strip state. That is legibility, not safety.
  //
  // Measured 2026-08-20: a host process forging X-Forwarded-For against the
  // published port was believed, because Caddy runs network_mode: host and is
  // therefore indistinguishable from it by address.
  app.use(makeProxyAuthMiddleware({ secret: trustedProxySecret }));

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

  // Mounted PER ROUTE, after the limiters, not app-wide before them. App-wide it
  // sat ahead of every limiter, which had two consequences: a request destined
  // for a 429 still paid for its body parse, and — worse — a POST with a
  // malformed body was rejected by the parser before any limiter ran, so it
  // consumed no budget and could be repeated without limit. Both disappear when
  // the parse happens after admission rather than before it.
  const parseBody = express.json({ limit: '16kb' });

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
    scope: RateLimitScope.GLOBAL,
    // One key, so the table cannot grow and eviction can never discard it.
    maxKeys: 1,
    now,
  });
  const exchangeLimit = makeRateLimiter({
    limit: EXCHANGE_PER_IP_PER_MINUTE,
    windowMs: MINUTE_MS,
    scope: RateLimitScope.EXCHANGE_PER_IP,
    now,
  });
  const mintLimit = makeRateLimiter({
    limit: MINT_PER_IP_PER_MINUTE,
    windowMs: MINUTE_MS,
    scope: RateLimitScope.MINT_PER_IP,
    now,
  });

  app.get('/healthz', (_req, res) => res.json({ ok: true }));
  app.post(
    '/exchange',
    exchangeLimit,
    globalLimit,
    parseBody,
    makeExchangeHandler({ verifyProviderIdToken, privateKeyPem, ttlSeconds }),
  );
  app.post(
    '/livekit-token',
    mintLimit,
    globalLimit,
    parseBody,
    makeMintHandler({ publicKeyPem, mintLiveKitToken, requireKnownProvider }),
  );

  // Announce the security posture createApp RECEIVED, so an operator can answer
  // "is it actually on?" without guessing — the question the whole switch turns on.
  //
  // SCOPE, stated exactly: this reports createApp's argument. It does NOT witness
  // the handler. Delete `requireKnownProvider` from the makeMintHandler({...}) call
  // above and this line still publishes `true` while the handler's default
  // parameter fails OPEN. An earlier version of this comment claimed the line
  // "cannot stay truthful if the wiring is cut", which is false in exactly that
  // direction (Tesla, PR #6 round 7).
  //
  // The witnesses for HANDLER behaviour are the HTTP tests — the in-process
  // 'env string reaches the handler → 403' case, and the five wire probes in
  // scripts/verify.sh against the real entrypoint. This log covers only what
  // those cannot: what a RUNNING deployment believes its own posture to be.
  // Swallowed, like every other write through this sink: the repo's standing
  // contract is that a throwing log sink cannot take down the service, and an
  // existing test pins it. A boot-time announcement is the last thing that should
  // be able to prevent a boot.
  try {
    (log ?? console.log)(
      // proxyAuth reports whether the secret is SET, never its value. Unenforced
      // is the state an operator most needs to see, and it is the silent one.
      // SAME SCOPE CAVEAT as requireKnownProvider above: this reports createApp's
      // ARGUMENT. Delete the app.use(makeProxyAuthMiddleware(...)) line and this
      // still prints `enforced`. The witness for the MOUNT is the enforced wire
      // probe in scripts/verify.sh, not this line.
      JSON.stringify({
        event: 'policy',
        requireKnownProvider,
        trustProxyHops,
        proxyAuth: trustedProxySecret === null ? 'unenforced' : 'enforced',
      }),
    );
  } catch { /* a broken sink must not stop the service starting */ }

  return app;
}
