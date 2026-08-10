import admin from 'firebase-admin';

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
function mapProvider(signInProvider) {
  switch (signInProvider) {
    case 'google.com': return 'google';
    case 'apple.com': return 'apple';
    case 'github.com': return 'github';
    case 'password': return 'email_password';
    case 'anonymous': return 'anonymous';
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
