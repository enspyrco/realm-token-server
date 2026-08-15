// CORS for the browser clients. The deployed target is Flutter *web*, so both
// endpoints are cross-origin from the app's hosting domain and unreachable
// without these headers — a same-origin-only server silently breaks web while
// macOS/mobile keep working.
//
// Exact-match allowlist, never `*`. Note what this does and does not buy: the
// bearer credential is NOT ambient authority (unlike a cookie, a hostile page
// cannot make the browser attach it), so `*` would not by itself let evil.com
// spend a signed-in session — it would still need to steal the token. What an
// allowlist does buy is defence in depth: it denies cross-origin reconnaissance
// against an auth boundary, and it stays correct if this service ever gains a
// cookie or `Access-Control-Allow-Credentials`, at which point `*` becomes an
// actual account-takeover vector rather than a theoretical one.
//
// No `Access-Control-Allow-Credentials`: the client authenticates with an
// `Authorization` header, not cookies, so the credentialed-request mode is not
// needed and enabling it would only widen what a permitted origin can do.

// Flutter's dev server picks a random port per run, so dev origins can't be
// enumerated ahead of time. Port optional (a default-port dev server sends no
// `:80`), IPv6 loopback included. Opt-in, and off in production.
const LOCALHOST = /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/;

function isAllowed(origin, allowedOrigins, allowLocalhost) {
  if (allowedOrigins.includes(origin)) return true;
  return allowLocalhost && LOCALHOST.test(origin);
}

export function makeCorsMiddleware({ allowedOrigins = [], allowLocalhost = false } = {}) {
  return function cors(req, res, next) {
    const origin = req.get('origin');

    // `res.vary()` APPENDS; `setHeader('Vary', …)` would replace. The response
    // differs per origin, so a shared cache must not serve one origin's response
    // to another — and that guarantee has to survive any other middleware that
    // also varies (compression sets `Vary: Accept-Encoding`). Set even on a
    // denial, since the denial is itself origin-specific.
    res.vary('Origin');

    if (origin && isAllowed(origin, allowedOrigins, allowLocalhost)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'content-type, authorization');
      // Short deliberately. A cached preflight lets a since-revoked origin keep
      // reaching the handler (the browser blocks only the *reading* of the
      // response), so this is the lag between revoking an origin and it going
      // quiet. Ten minutes costs a preflight per origin per 10 min — nothing.
      res.setHeader('Access-Control-Max-Age', '600');
    }

    // Preflight terminates here either way. A denied preflight returns 204
    // WITHOUT the allow headers — the browser blocks the real request, and we
    // leak nothing about what is or isn't a known origin.
    if (req.method === 'OPTIONS') return res.status(204).end();

    // A request with NO Origin passes untouched: server-to-server callers (curl,
    // the bot, health checks) send none, and refusing them would break every
    // non-browser client while stopping no attacker — anything outside a browser
    // omits or forges Origin at will.
    //
    // A request with a PRESENT but disallowed Origin is refused. This is not
    // authentication (the header is trivially forgeable off-browser, and the
    // bearer credential remains the only thing that actually authorises); it
    // closes the narrow window where an *honest* browser still reaches the
    // handler despite the allowlist — a preflight cached from before the origin
    // was revoked, or a simple request that never triggers one. Cheap, and it
    // costs a credential mint nothing to decline work it would refuse to let the
    // caller read anyway.
    if (origin && !isAllowed(origin, allowedOrigins, allowLocalhost)) {
      return res.status(403).json({ error: 'origin not allowed' });
    }

    return next();
  };
}

/**
 * Thrown at startup when CORS_ALLOWED_ORIGINS is unusable. Boot-time and loud:
 * every malformed value below parses to an allowlist that matches nothing, which
 * is indistinguishable at runtime from having no CORS at all — the silent
 * web-only breakage this module exists to remove.
 */
export class InvalidAllowedOrigins extends Error {
  constructor(reason) {
    super(`CORS_ALLOWED_ORIGINS ${reason}`);
    this.name = 'InvalidAllowedOrigins';
  }
}

// Splits the comma-separated env value. Shape validation is the caller's job
// (requireAllowedOrigins) so this stays a pure parser.
export function parseAllowedOrigins(raw) {
  return (raw || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Parses AND validates the CORS_ALLOWED_ORIGINS env value, throwing rather than
 * booting a server that will refuse every browser it was deployed to serve.
 *
 * Rejects, with the offending value named:
 *  - nothing usable (`""`, `"  "`, `",,,"`) — present-but-empty is the failure
 *    `requireEnv` alone cannot see;
 *  - `*` and `null` — neither can ever equal a real Origin here, and `null` in
 *    an allowlist would admit every sandboxed iframe;
 *  - anything that is not exactly `scheme://host[:port]` — a trailing slash or
 *    path (`https://x.example/`, straight off a browser address bar) matches no
 *    Origin a browser will ever send. An explicit default port (`:80`/`:443`)
 *    is rejected by the same rule, since browsers omit it.
 */
export function requireAllowedOrigins(raw) {
  const origins = parseAllowedOrigins(raw);
  if (origins.length === 0) {
    throw new InvalidAllowedOrigins('is empty — set at least one browser origin');
  }
  for (const o of origins) {
    let url;
    try {
      url = new URL(o);
    } catch {
      throw new InvalidAllowedOrigins(`entry "${o}" is not a valid origin (want scheme://host[:port])`);
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new InvalidAllowedOrigins(`entry "${o}" must be http(s)`);
    }
    // `new URL` happily accepts `https://*` and `https://*.example` — and both
    // survive the Origin-form check below, because their `origin` round-trips
    // unchanged. They match no Origin a browser will ever send, so an operator
    // reaching for a wildcard subdomain would boot green and break web exactly
    // as if CORS were absent. There is no wildcard support here by design; say
    // so at boot rather than at 3am. Hostname is already punycode-normalised, so
    // a real host is [a-z0-9.-] (or a bracketed IPv6 literal).
    if (!/^[a-z0-9.-]+$/.test(url.hostname) && !/^\[[0-9a-f:]+\]$/.test(url.hostname)) {
      throw new InvalidAllowedOrigins(
        `entry "${o}" has an invalid host "${url.hostname}" — wildcards are not supported; list each origin`,
      );
    }
    // url.origin drops any path, trailing slash, and default port — so equality
    // is an exact "this is already in Origin-header form" check.
    if (url.origin !== o) {
      throw new InvalidAllowedOrigins(`entry "${o}" is not in Origin form — use "${url.origin}"`);
    }
  }
  return origins;
}

/**
 * Resolves the localhost opt-in, refusing it in production.
 *
 * The opt-in admits any port on loopback — fine on a laptop, a hole on a public
 * mint, where any page a developer's machine can be induced to load would be
 * free to read /exchange and /livekit-token responses. "Dev only" was stated in
 * the README and .env.example and enforced in neither. The Dockerfile sets
 * NODE_ENV=production, so the deployed default is refusal.
 */
export function resolveAllowLocalhost(env = {}) {
  const enabled = env.CORS_ALLOW_LOCALHOST === 'true';
  if (enabled && env.NODE_ENV === 'production') {
    throw new Error('CORS_ALLOW_LOCALHOST=true is refused when NODE_ENV=production');
  }
  return enabled;
}
