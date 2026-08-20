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
 * Reads the optional shared secret that authenticates the reverse proxy.
 *
 * Unset means unenforced — `X-Forwarded-For` is believed from any peer the hop
 * count trusts, which is this service's behaviour prior to this option and is
 * why the caller must announce it (see server.js).
 */
export function resolveProxySecret(env = {}) {
  const raw = env.REALM_TRUSTED_PROXY_SECRET;
  if (raw === undefined || raw === '') return null;
  if (raw.trim() !== raw) {
    throw new InvalidProxySecret('must not have leading or trailing whitespace — a copy-paste artefact would silently never match');
  }
  if (raw.length < MIN_PROXY_SECRET_LENGTH) {
    throw new InvalidProxySecret(`must be at least ${MIN_PROXY_SECRET_LENGTH} characters, got ${raw.length}`);
  }
  return raw;
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
 * MUST be mounted before anything reads `req.ip` — express computes it lazily
 * from the headers as they stand when first accessed.
 *
 * On a failed or absent presentation the request is served normally; only its
 * claim about who it is speaking for is discarded.
 */
export function makeProxyAuthMiddleware({ secret = null } = {}) {
  return function proxyAuth(req, _res, next) {
    const presented = req.headers[PROXY_SECRET_HEADER];
    // Never let it reach a log, an error report, or an upstream request.
    delete req.headers[PROXY_SECRET_HEADER];

    if (secret === null) {
      req.proxyAuthenticated = null;
      return next();
    }

    const ok = matches(presented, secret);
    req.proxyAuthenticated = ok;
    if (!ok) {
      // express reads X-Forwarded-For right-to-left; with the header gone it
      // falls back to the socket address, which the caller cannot choose.
      delete req.headers['x-forwarded-for'];
    }
    return next();
  };
}
