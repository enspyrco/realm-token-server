import admin from 'firebase-admin';

// Provider-native ID-token verification via the Firebase Admin SDK. This is the
// external dependency the whole "Node, not Dart" decision turned on — verifying
// a Firebase ID token against Google's signing authority is first-class here and
// mature nowhere in Dart. Initialised lazily from ADC / GOOGLE_APPLICATION_
// CREDENTIALS so importing this module in tests (which inject a fake verifier)
// never requires real credentials.

let app;
function ensureApp() {
  app ??= admin.initializeApp();
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
