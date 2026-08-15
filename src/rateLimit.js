// Rate limiting for the credential mint.
//
// Both POST routes do real work on behalf of an unauthenticated caller before
// they know whether the caller is legitimate: /exchange calls Firebase Admin
// `verifyIdToken` (network, and a cert fetch on the first call after a container
// start — measured 227ms cold vs 4ms warm), and /livekit-token mints a token
// carrying a `RoomAgentDispatch`, so hammering it amplifies into rooms rather
// than merely burning CPU here.
//
// The 403-on-disallowed-origin in cors.js is not a throttle and must not be read
// as one: anything outside a browser omits `Origin` and is served normally, by
// design (curl, the bot, the healthcheck). Origin is a browser-honesty check;
// this is the volume check.
//
// WHAT THIS IS, stated at its proven scope: a ceiling on accidental and
// single-source abuse. A caller with many source addresses can churn the per-key
// table (see `maxKeys` below) and evade the per-IP layer entirely — which is why
// the global layer exists and why it is keyed on nothing. This is not a defence
// against a distributed attack, and no number in this file makes it one.

// Fixed window rather than a token bucket: one integer and one timestamp per
// key, no refill arithmetic, and the reset instant is a number we can hand the
// caller in `Retry-After`. The cost is a burst of up to 2*limit across a window
// boundary, which is irrelevant at these ceilings.
export function makeRateLimiter({
  limit,
  windowMs,
  // Bounded so a caller rotating source addresses cannot grow this Map until the
  // process dies — an OOM on a credential mint is a worse outcome than the
  // throttling it was protecting. At the cap the OLDEST entry is evicted, so
  // table churn degrades this layer toward fail-open (an evicted client gets a
  // fresh allowance) rather than toward refusing traffic it cannot account for.
  // Availability is the right direction here because the global limiter below
  // cannot be churned at all, and it is the one holding the quota ceiling.
  maxKeys = 4096,
  now = Date.now,
  // A constant key makes this same primitive the global limiter. Per-IP and
  // service-wide are the same counter with a different notion of "who".
  key = (req) => req.ip,
} = {}) {
  if (!Number.isInteger(limit) || limit < 1) {
    throw new TypeError('makeRateLimiter: limit must be a positive integer');
  }
  if (!Number.isInteger(windowMs) || windowMs < 1) {
    throw new TypeError('makeRateLimiter: windowMs must be a positive integer');
  }

  // Insertion-ordered by construction (JS Map), which is what makes the eviction
  // below O(1) without a second data structure.
  const windows = new Map();

  return function rateLimit(req, res, next) {
    const k = key(req);

    // A key we cannot compute is a request we cannot account for. Bucket it with
    // every other such request under one name instead of skipping the check —
    // `undefined` as a Map key would otherwise be a single shared bucket by
    // accident, and this way it is one by decision.
    const id = k === undefined || k === null ? 'unknown' : String(k);

    const t = now();
    let entry = windows.get(id);

    if (entry === undefined || t >= entry.resetAt) {
      entry = { count: 0, resetAt: t + windowMs };
    } else {
      // Re-insert so the eviction order is "least recently STARTED a window"
      // rather than "first ever seen"; without the delete, a client active for
      // hours keeps its original position and is evicted ahead of a one-shot
      // caller that arrived later.
      windows.delete(id);
    }
    entry.count += 1;
    windows.set(id, entry);

    while (windows.size > maxKeys) {
      // Map iteration is insertion order, so this is the oldest window.
      const oldest = windows.keys().next().value;
      windows.delete(oldest);
    }

    if (entry.count > limit) {
      // Seconds, rounded up, and never 0 — a `Retry-After: 0` invites an
      // immediate retry, which is precisely the behaviour being limited.
      const retryAfter = Math.max(1, Math.ceil((entry.resetAt - t) / 1000));
      res.setHeader('Retry-After', String(retryAfter));
      return res.status(429).json({ error: 'rate limited' });
    }

    return next();
  };
}

/**
 * Thrown at startup when TRUST_PROXY_HOPS is unusable or absent in production.
 *
 * This is the setting that decides whether the per-IP limiter is per-IP at all,
 * and BOTH ways of getting it wrong are silent:
 *
 *  - too low (0 behind Caddy): every request arrives from the docker bridge
 *    gateway, so the whole internet shares one bucket and any single caller
 *    throttles every other user of the service;
 *  - too high: an untrusted hop's `X-Forwarded-For` is believed, so a caller
 *    supplies a fresh address per request and the limiter is a no-op.
 *
 * Neither shows up as an error, a failed test, or a red healthcheck — so it is
 * refused at boot rather than defaulted, exactly as CORS_ALLOWED_ORIGINS is.
 */
export class InvalidTrustProxyHops extends Error {
  constructor(reason) {
    super(`TRUST_PROXY_HOPS ${reason}`);
    this.name = 'InvalidTrustProxyHops';
  }
}

/**
 * Resolves how many proxy hops in front of this process are trusted to have
 * written `X-Forwarded-For`.
 *
 * The deployed topology is exactly one: Caddy terminates TLS on the host and
 * reverse-proxies to 127.0.0.1:8791, appending the peer address to any inbound
 * X-Forwarded-For. So the real client is the LAST entry and `1` is correct —
 * but "correct" is a property of the deployment, not of this code, so the
 * deployment states it.
 *
 * Unset is allowed off-production (a local `npm start` has no proxy) and refused
 * under NODE_ENV=production, where the container is never reached directly.
 */
export function resolveTrustProxyHops(env = {}) {
  const raw = env.TRUST_PROXY_HOPS;
  const isProduction = env.NODE_ENV === 'production';

  if (raw === undefined || raw === '') {
    if (isProduction) {
      throw new InvalidTrustProxyHops(
        'is required when NODE_ENV=production — set 1 for the Caddy-fronted deploy, or 0 only if this process is directly internet-facing',
      );
    }
    return 0;
  }

  // Number() alone accepts '1.5', ' 1 ', '0x1' and '' — each of which would
  // reach app.set('trust proxy', …) as something express interprets differently
  // from what the operator wrote.
  if (!/^\d+$/.test(raw)) {
    throw new InvalidTrustProxyHops(`must be a non-negative integer, got "${raw}"`);
  }
  return Number(raw);
}
