// The Realm AuthProviderId wire strings. ONE definition, shared by the module
// that PRODUCES them (firebase.js mapProvider, at exchange time) and the module
// that ACTS on them (mint.js, at admission time).
//
// Why a separate module rather than exporting from firebase.js: mint.js must not
// import firebase-admin. The mint handler holds only the ES256 public key and has
// no provider dependency — that separation is load-bearing (see realmCredential.js
// "Asymmetric by construction"), so the shared constant gets its own dependency-free
// home rather than dragging the Admin SDK across the boundary.
//
// These strings must match packages/realm AuthProviderId in enspyrco/tech_world.

export const ANONYMOUS_PROVIDER = 'anonymous';

/**
 * The providers that constitute PROOF that a principal signed in.
 *
 * This is an allowlist, and it has to be, because the producer fails OPEN:
 * mapProvider's `default` arm returns the string `'firebase'` for any missing or
 * unrecognised `sign_in_provider`. Under a "not the anonymous sentinel" rule that
 * fallback reads as proof of signing in — so a token with no `sign_in_provider`
 * would be admitted. Carnot and Tesla found this independently on PR #6; the
 * check was still a denylist, relabelled at exchange time.
 *
 * Membership here is the only proof. `'firebase'` is deliberately ABSENT: it means
 * "we do not know how this principal signed in", which is not an answer.
 *
 * Consequence, and it is the intended direction: enabling REALM_REFUSE_ANONYMOUS on
 * a deployment using a provider not listed here (phone auth, a custom token, a new
 * OIDC provider) refuses those users until the provider is added — mapProvider must
 * gain a case and this set must gain an entry, together. A security switch that
 * silently admits an unrecognised sign-in method is the failure worth avoiding; an
 * opt-in switch that refuses one is a loud, fixable inconvenience.
 */
export const SIGNED_IN_PROVIDERS = Object.freeze([
  'google',
  'apple',
  'github',
  'email_password',
]);

// The lookup set is module-PRIVATE and the predicate is the only way in.
//
// `Object.freeze(new Set([...]))` — the obvious spelling, and what this file
// shipped for one review round — freezes the bottle, not the lightning: freeze
// does not touch a Set's internal [[SetData]], so `SIGNED_IN_PROVIDERS.add(...)`
// still mutates admission process-wide for the life of the isolate. A debug
// import or a "temporary" test helper could grow the allowlist in the only
// direction that matters. Tesla caught this on PR #6.
//
// The exported array IS genuinely frozen (ESM modules are strict mode, so a
// mutating call throws), and it exists so tests can enumerate the set.
const SIGNED_IN = new Set(SIGNED_IN_PROVIDERS);

/**
 * The admission predicate. True only for a provider that is PROOF the principal
 * signed in — never for the anonymous sentinel, never for the `'firebase'`
 * don't-know fallback, and never for a value of any other type.
 */
export function isSignedInProvider(provider) {
  return SIGNED_IN.has(provider);
}
