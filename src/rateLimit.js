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

/**
 * The closed set of ceilings this service has. The `scope` a limiter reports is
 * drawn from here rather than written inline at each call site: it is read back
 * out of the logs as a diagnostic, and a diagnostic that can silently disagree
 * with itself over a typo is worse than no diagnostic — an operator would filter
 * on `mint-per-ip` and find nothing while the mint was being hammered.
 */
export const RateLimitScope = Object.freeze({
  GLOBAL: 'global',
  EXCHANGE_PER_IP: 'exchange-per-ip',
  MINT_PER_IP: 'mint-per-ip',
});

const KNOWN_SCOPES = new Set(Object.values(RateLimitScope));

// Longer than any address express can hand back (an IPv6 literal with a zone id
// tops out well under this), short enough that maxKeys entries is a memory
// budget rather than a header-sized surprise.
const MAX_KEY_LENGTH = 64;

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
  // MONOTONIC, not wall-clock. Every window here is a duration, never a date,
  // and Date.now() steps: an NTP correction backwards extends a live window by
  // the size of the step, locking a caller out for as long as the jump lasted,
  // and a step forwards ends every window early. performance.now() counts from
  // process start and cannot be stepped, which removes the failure rather than
  // bounding it. Nothing in this module is ever compared against a wall time.
  now = () => performance.now(),
  // A constant key makes this same primitive the global limiter. Per-IP and
  // service-wide are the same counter with a different notion of "who".
  key = (req) => req.ip,
  // Which ceiling this is, recorded on the request when it refuses. A per-IP 429
  // and a service-wide 429 are opposite events — one is the system working on a
  // single noisy caller, the other is the circuit breaker turning away everybody
  // — and both otherwise land in the log as an indistinguishable status 429.
  // Never sent to the caller: telling an attacker they reached the global
  // ceiling confirms the service-wide effect they were testing for.
  scope,
} = {}) {
  if (!Number.isInteger(limit) || limit < 1) {
    throw new TypeError('makeRateLimiter: limit must be a positive integer');
  }
  if (!Number.isInteger(windowMs) || windowMs < 1) {
    throw new TypeError('makeRateLimiter: windowMs must be a positive integer');
  }
  // Validated with its siblings, because it is the argument whose bad value is
  // SILENT: maxKeys of 0 makes the eviction loop discard every entry the instant
  // it is written, so every request sees a fresh window and nothing is ever
  // limited. A limiter that returns 200 forever is indistinguishable from no
  // limiter, which is the failure class this module exists to close.
  if (!Number.isInteger(maxKeys) || maxKeys < 1) {
    throw new TypeError('makeRateLimiter: maxKeys must be a positive integer');
  }
  // A closed set, checked at the door like every other argument here. The old
  // default of 'unnamed' meant a forgotten scope produced a log line that parsed
  // fine and told an operator nothing.
  if (!KNOWN_SCOPES.has(scope)) {
    throw new TypeError(
      `makeRateLimiter: scope must be one of ${[...KNOWN_SCOPES].join(', ')} (see RateLimitScope)`,
    );
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
    // Truncated, because the table is bounded in ENTRIES and the key is not
    // always an address we chose. On the accepted inside-the-box path a caller
    // supplies its own X-Forwarded-For, and express hands back whatever it finds
    // there — so maxKeys entries of header-sized junk is a much larger number
    // than maxKeys entries of "203.0.113.7". No real address is close to this
    // long, so truncation costs nothing and turns an entry bound into a byte
    // bound.
    const id = k === undefined || k === null ? 'unknown' : String(k).slice(0, MAX_KEY_LENGTH);

    const t = now();
    let entry = windows.get(id);

    if (entry === undefined || t >= entry.resetAt) {
      entry = { count: 0, resetAt: t + windowMs };
    }

    // UNCONDITIONAL, and that is the whole point. Map.set on an existing key
    // leaves its insertion position untouched, so this delete is what actually
    // moves a key to the back of the eviction queue. Doing it only for requests
    // inside a live window — as this first did — selected exactly the wrong
    // victim: a caller whose window had expired kept its original ancient
    // position and was evicted ahead of a burst client that kept refreshing
    // its own, so table pressure preferentially discarded the quiet clients and
    // preserved the noisy ones. Delete on every request and the order is a true
    // least-recently-seen. (A delete of an absent key is a no-op, so the
    // first-arrival case needs no branch of its own.)
    windows.delete(id);
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
      req.rateLimited = scope;
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
// One: Caddy. See the check in resolveTrustProxyHops for why this is a ceiling
// and not merely a default.
const MAX_TRUST_PROXY_HOPS = 1;

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
  const hops = Number(raw);
  // Bounded by the topology this service actually has. Requiring the value in
  // production stops the too-LOW failure; nothing stopped the too-HIGH one, and
  // a typo'd 2 or 11 walks straight through the boot gate into exactly the mode
  // the gate exists to prevent — every hop beyond a real proxy is one an
  // arbitrary caller can write, so req.ip becomes attacker-chosen and the per-IP
  // limit stops existing, silently. There is one proxy in front of this service
  // (Caddy). Adding a second is a deployment change that should be made here, in
  // a reviewed commit, rather than absorbed by an env var at 3am.
  if (hops > MAX_TRUST_PROXY_HOPS) {
    throw new InvalidTrustProxyHops(
      `is ${hops}, but this service sits behind at most ${MAX_TRUST_PROXY_HOPS} proxy (Caddy) — a higher value lets an untrusted caller choose its own client address. If the topology genuinely changed, raise MAX_TRUST_PROXY_HOPS in src/rateLimit.js in the same commit.`,
    );
  }
  return hops;
}
