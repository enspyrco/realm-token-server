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
export const SIGNED_IN_PROVIDERS = Object.freeze(new Set([
  'google',
  'apple',
  'github',
  'email_password',
]));
