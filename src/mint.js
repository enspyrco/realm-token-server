import { verifyRealmCredential, RealmCredentialRejected } from './realmCredential.js';

// POST /livekit-token  { roomName }  Authorization: Bearer <RealmCredential>
//
// The LiveKit mint handler. Holds ONLY the ES256 public key. It accepts nothing
// but a valid Realm credential — never a raw provider ID token — so the exchange
// boundary cannot be bypassed by presenting a Firebase token directly here.
export function makeMintHandler({ publicKeyPem, mintLiveKitToken }) {
  return async function mint(req, res) {
    const auth = req.get('authorization') || '';
    const match = /^Bearer (.+)$/.exec(auth);
    if (!match) {
      return res.status(401).json({ error: 'missing bearer credential' });
    }

    let claims;
    try {
      claims = verifyRealmCredential(publicKeyPem, match[1]);
    } catch (err) {
      if (err instanceof RealmCredentialRejected) {
        return res.status(401).json({ error: 'invalid credential' });
      }
      throw err;
    }

    const roomName = req.body?.roomName;
    if (typeof roomName !== 'string' || roomName.length === 0) {
      return res.status(400).json({ error: 'roomName required' });
    }

    const token = await mintLiveKitToken({ identity: claims.subject, roomName });
    return res.status(200).json({ token });
  };
}
