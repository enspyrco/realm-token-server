import { verifyRealmCredential, RealmCredentialRejected } from './realmCredential.js';

// The wire value Firebase's `anonymous` sign-in provider maps to (see
// mapProvider in firebase.js). Anything else is a principal that signed in.
const ANONYMOUS_PROVIDER = 'anonymous';

/**
 * Reads the deployment-wide anonymous-refusal switch. Unset means OFF, which
 * preserves current behaviour exactly; anything unrecognised REFUSES TO START
 * rather than being read as off. A security switch that silently accepts "yes"
 * or "1" as false fails silently in the one direction that matters. Same
 * contract as resolveTrustProxyHops: refuse to boot rather than run mis-set.
 */
export function resolveRefuseAnonymous(env) {
  const raw = env.REALM_REFUSE_ANONYMOUS;
  if (raw === undefined) return false;
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  throw new Error(
    `REALM_REFUSE_ANONYMOUS must be exactly "true" or "false" (got ${JSON.stringify(raw)})`,
  );
}

// POST /livekit-token  { roomName }  Authorization: Bearer <RealmCredential>
//
// The LiveKit mint handler. Holds ONLY the ES256 public key. It accepts nothing
// but a valid Realm credential — never a raw provider ID token — so the exchange
// boundary cannot be bypassed by presenting a Firebase token directly here.
//
// STILL NOT ROOM AUTHORIZATION. Any signed-in caller may name any room; the
// admission predicate belongs to the engine and does not exist yet
// (claude-tasks#2850, docs/crucible/room-admission/DESIGN.md). refuseAnonymous
// is step 0 of that design and is a RISK TRIM, not the fix: it removes the
// throwaway-uid caller, not the arbitrary-room capability. It is superseded by
// per-room `permissions.allowAnonymous` once the engine ships it.
export function makeMintHandler({ publicKeyPem, mintLiveKitToken, refuseAnonymous = false }) {
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

    // Authorization, decided only after authentication succeeded — so a forged
    // credential still gets 401 and never learns this policy exists.
    //
    // Positive form: admit only a principal that can PROVE it is not anonymous.
    // A credential with no `prov` claim is refused, because "not known to be
    // anonymous" is a denylist and this must not become one.
    if (refuseAnonymous) {
      const provenNonAnonymous =
        claims.provider !== undefined && claims.provider !== ANONYMOUS_PROVIDER;
      if (!provenNonAnonymous) {
        return res.status(403).json({ error: 'anonymous principals are not admitted' });
      }
    }

    const roomName = req.body?.roomName;
    if (typeof roomName !== 'string' || roomName.length === 0) {
      return res.status(400).json({ error: 'roomName required' });
    }

    const token = await mintLiveKitToken({ identity: claims.subject, roomName });
    return res.status(200).json({ token });
  };
}
