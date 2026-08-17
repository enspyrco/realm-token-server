import admin from 'firebase-admin';
import { ANONYMOUS_PROVIDER } from './providers.js';

// Provider-native ID-token verification via the Firebase Admin SDK. This is the
// external dependency the whole "Node, not Dart" decision turned on — verifying
// a Firebase ID token against Google's signing authority is first-class here and
// mature nowhere in Dart.
//
// NO SERVICE ACCOUNT REQUIRED. verifyIdToken (with checkRevoked=false, the
// default) only fetches Google's PUBLIC signing certs and checks the token's
// aud against the project id — it never calls an authenticated API. So the SDK
// initialises from FIREBASE_PROJECT_ID alone, with no credential. Verified
// empirically: init({projectId}) + verify reaches token-decoding, not a
// credential error. This removes an entire secret (no JSON to store/rotate).
// checkRevoked is intentionally NOT used; adding it would require a credential.

let app;
function ensureApp() {
  if (!app) {
    const projectId = process.env.FIREBASE_PROJECT_ID;
    if (!projectId) throw new Error('missing required env FIREBASE_PROJECT_ID');
    app = admin.initializeApp({ projectId });
  }
  return app;
}

// Maps Firebase's sign_in_provider to a Realm AuthProviderId wire string
// (must match packages/realm AuthProviderId constants).
//
// EXPORTED so its arms can be pinned by a test. Under REALM_REFUSE_ANONYMOUS,
// mint.js admits a principal only if `isSignedInProvider(prov)` — an ALLOWLIST
// (src/providers.js), not a comparison against the anonymous sentinel. So this
// mapper is the producer of an admission fact, and two of its arms are
// load-bearing in opposite directions:
//
//   - the `anonymous` arm must keep returning ANONYMOUS_PROVIDER, which is
//     deliberately absent from the allowlist;
//   - the `default` arm returns 'firebase', meaning "we do not know how this
//     principal signed in", which is likewise absent — absence of evidence must
//     not become evidence.
//
// Adding a sign-in method therefore means adding a case HERE and an entry in
// SIGNED_IN_PROVIDERS, together; a case added alone is refused, which is the
// safe direction. (This comment previously described a sentinel comparison that
// mint.js no longer does — a fossil that would have licensed putting the
// denylist back "to match the comment". Tesla, PR #6 round 4.)
export function mapProvider(signInProvider) {
  switch (signInProvider) {
    case 'google.com': return 'google';
    case 'apple.com': return 'apple';
    case 'github.com': return 'github';
    case 'password': return 'email_password';
    case 'anonymous': return ANONYMOUS_PROVIDER;
    default: return 'firebase';
  }
}

/**
 * Verifies a Firebase ID token and returns the Realm identity it attests.
 * Throws (caught by the exchange handler → 401) if the token is invalid.
 */
export async function verifyFirebaseIdToken(idToken) {
  const decoded = await ensureApp().auth().verifyIdToken(idToken);
  return {
    uid: decoded.uid,
    provider: mapProvider(decoded.firebase?.sign_in_provider),
  };
}
