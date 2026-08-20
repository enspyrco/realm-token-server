import { corsConfigFromEnv } from './cors.js';
import { resolveTrustProxyHops } from './rateLimit.js';
import { resolveRequireKnownProvider } from './mint.js';

// The single door between the environment and createApp's options.
//
// Why this exists (CarnotCodeCarver, PR #6): the env resolvers were unit-tested
// and createApp was tested with options injected directly, but NOTHING tested
// that the resolver's output actually reached the handler. Deleting
// `requireKnownProvider: resolveRequireKnownProvider(process.env)` from the entrypoint left
// the whole suite green while production silently ran permissive — the security
// switch's own wiring was the least-witnessed thing in the change that existed to
// add it. Testing beside the mechanism, not on it.
//
// So the env→options mapping lives here as one pure function, index.js spreads it
// verbatim, and test/configFromEnv.test.js pins each key. A dropped key now fails
// a test instead of failing quietly in production.

/**
 * Derives every environment-driven createApp option. Pure: no process.env access,
 * no side effects — pass the env in.
 *
 * Throws (refusing boot) if any security-relevant variable is set to a value it
 * cannot interpret, rather than falling through to a default. See
 * resolveTrustProxyHops and resolveRequireKnownProvider for the individual contracts.
 *
 * @param {Record<string, string|undefined>} env
 */
export function appOptionsFromEnv(env) {
  return {
    ttlSeconds: Number(env.REALM_CREDENTIAL_TTL_SECONDS || 3600),
    trustProxyHops: resolveTrustProxyHops(env),
    requireKnownProvider: resolveRequireKnownProvider(env),
    ...corsConfigFromEnv(env),
  };
}
