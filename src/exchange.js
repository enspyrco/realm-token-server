import { issueRealmCredential } from './realmCredential.js';

// POST /exchange  { idToken }  ->  { token, expiresAt }
//
// The credential-exchange handler: THE sole trust-establishment point. It
// verifies the provider-native ID token against the provider's real signing
// authority, then mints an opaque Realm credential. The ES256 PRIVATE key is
// captured in this closure and nowhere else — the mint handler never receives
// it, so no mint-side defect can forge a credential.
export function makeExchangeHandler({ verifyProviderIdToken, privateKeyPem, ttlSeconds }) {
  return async function exchange(req, res) {
    const idToken = req.body?.idToken;
    if (typeof idToken !== 'string' || idToken.length === 0) {
      return res.status(400).json({ error: 'idToken required' });
    }

    let identity;
    try {
      identity = await verifyProviderIdToken(idToken); // { uid, provider }
    } catch {
      // Provider rejected the token. Return a generic 401 — never echo the
      // verifier's reason to an unauthenticated caller.
      return res.status(401).json({ error: 'invalid id token' });
    }

    const cred = issueRealmCredential(privateKeyPem, {
      subject: identity.uid,
      provider: identity.provider,
      ttlSeconds,
    });
    return res.status(200).json(cred);
  };
}
