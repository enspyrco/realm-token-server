// CORS for the browser clients. The deployed target is Flutter *web*, so both
// endpoints are cross-origin from the app's hosting domain and unreachable
// without these headers — a same-origin-only server silently breaks web while
// macOS/mobile keep working.
//
// Exact-match allowlist, never `*`: this is an auth boundary and callers send a
// bearer credential. `*` would let any page on the internet spend a signed-in
// user's session.
//
// No `Access-Control-Allow-Credentials`: the client authenticates with an
// `Authorization` header, not cookies, so the credentialed-request mode is not
// needed and enabling it would only widen what a permitted origin can do.

// Flutter's dev server picks a random port per run, so dev origins can't be
// enumerated ahead of time. Opt-in, and off in production.
const LOCALHOST = /^http:\/\/(localhost|127\.0\.0\.1):\d+$/;

function isAllowed(origin, allowedOrigins, allowLocalhost) {
  if (allowedOrigins.includes(origin)) return true;
  return allowLocalhost && LOCALHOST.test(origin);
}

export function makeCorsMiddleware({ allowedOrigins = [], allowLocalhost = false } = {}) {
  return function cors(req, res, next) {
    const origin = req.get('origin');

    // `Vary: Origin` regardless of the verdict: the response body/headers differ
    // per origin, so a shared cache must not serve one origin's response to
    // another. Set even on a denial, since the denial is itself origin-specific.
    res.setHeader('Vary', 'Origin');

    if (origin && isAllowed(origin, allowedOrigins, allowLocalhost)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'content-type, authorization');
      res.setHeader('Access-Control-Max-Age', '86400');
    }

    // Preflight terminates here either way. A denied preflight returns 204
    // WITHOUT the allow headers — the browser blocks the real request, and we
    // leak nothing about what is or isn't a known origin.
    if (req.method === 'OPTIONS') return res.status(204).end();

    // Non-preflight requests are never rejected on Origin. CORS is enforced by
    // the browser, and server-to-server callers (curl, the bot, health checks)
    // send no Origin at all — refusing here would break them while stopping no
    // attacker, who can forge any Origin outside a browser anyway.
    return next();
  };
}

// Parses the comma-separated CORS_ALLOWED_ORIGINS env value.
export function parseAllowedOrigins(raw) {
  return (raw || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}
