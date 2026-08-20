import { createHash, timingSafeEqual } from 'node:crypto';

export const PROXY_SECRET_HEADER = 'x-realm-proxy-secret';

// A shorter shared secret is worse than none: it reads as protection while being
// guessable by the local process it exists to exclude.
export const MIN_PROXY_SECRET_LENGTH = 32;

export class InvalidProxySecret extends Error {
  constructor(detail) {
    super(`REALM_TRUSTED_PROXY_SECRET ${detail}`);
    this.name = 'InvalidProxySecret';
  }
}

/**
 * The ONE definition of "an acceptable proxy secret". Exported because
 * `createApp` must apply the identical rule: it is the public constructor and
 * does not inherit the env resolver's validation.
 *
 * Two chambers with different floors is how `createApp({ trustedProxySecret: '' })`
 * boots announcing `proxyAuth: "enforced"` and then authenticates anyone who
 * sends a bare header — `matches('', '')` is true. Same rule, one place.
 * (Carnot and Maxwell, PR #11 round 1, independently.)
 *
 * @throws {InvalidProxySecret} on anything a deployment must not run with.
 */
export function assertValidProxySecret(value) {
  if (typeof value !== 'string') {
    throw new InvalidProxySecret(`must be a string or null, got ${typeof value}`);
  }
  if (value.trim() !== value) {
    throw new InvalidProxySecret('must not have leading or trailing whitespace — a copy-paste artefact would silently never match');
  }
  if (value.length < MIN_PROXY_SECRET_LENGTH) {
    throw new InvalidProxySecret(`must be at least ${MIN_PROXY_SECRET_LENGTH} characters, got ${value.length}`);
  }
  return value;
}

/**
 * Reads the optional shared secret that authenticates the reverse proxy.
 *
 * Unset means unenforced — `X-Forwarded-For` is believed from any peer the hop
 * count trusts, which is this service's behaviour prior to this option and is
 * why the caller must announce it (see server.js).
 */
export function resolveProxySecret(env = {}) {
  const raw = env.REALM_TRUSTED_PROXY_SECRET;
  if (raw === undefined || raw === '') return null;
  return assertValidProxySecret(raw);
}

// SHA-256 both sides so timingSafeEqual gets equal lengths without leaking the
// secret's length through a fast-path length check.
function matches(presented, secret) {
  if (typeof presented !== 'string') return false;
  const a = createHash('sha256').update(presented).digest();
  const b = createHash('sha256').update(secret).digest();
  return timingSafeEqual(a, b);
}

/**
 * Authenticates the proxy rather than locating it.
 *
 * MUST be mounted before the RATE LIMITERS — they read `req.ip` during the
 * request, so a forwarding claim still standing at that point is what the
 * per-IP bucket keys on. (Not "before the logger": requestLog reads req.ip on
 * 'finish', after the response. See the mount site in server.js for the
 * measurement that corrected this.)
 *
 * On a failed or absent presentation the request is served normally; only its
 * claim about who it is speaking for is discarded.
 */
export function makeProxyAuthMiddleware({ secret = null } = {}) {
  return function proxyAuth(req, _res, next) {
    const presented = req.headers[PROXY_SECRET_HEADER];
    // Keep it out of anything downstream that walks req.headers — this service's
    // request log, an error dump, a future outbound call.
    // SCOPE: `delete` clears req.headers only. req.rawHeaders (and Node's
    // headersDistinct) still hold the value; nothing here reads either, but
    // "never reaches a log" would overclaim — a future raw-header dump would
    // still see it. (Tesla, PR #11 round 1.)
    delete req.headers[PROXY_SECRET_HEADER];

    if (secret === null) {
      req.proxyAuthenticated = null;
      return next();
    }

    const ok = matches(presented, secret);
    req.proxyAuthenticated = ok;
    if (!ok) {
      // Discard EVERY forwarding claim, not only the one this service reads
      // today. `x-forwarded-for` is what `req.ip` derives from — but express
      // also derives req.protocol/req.secure from `x-forwarded-proto` and
      // req.hostname from `x-forwarded-host` whenever trust proxy is set. Only
      // XFF is read here right now, so stripping just it would be correct and
      // would silently stop being correct the first time someone adds an
      // absolute-URL builder or an HTTPS redirect. A list of what is forbidden
      // is wrong on every future addition; the rule is that an unauthenticated
      // caller speaks for nobody but its socket.
      for (const h of Object.keys(req.headers)) {
        if (h.startsWith('x-forwarded-') || h === 'x-real-ip') delete req.headers[h];
      }
    }
    return next();
  };
}
