import { verifyRealmCredential, RealmCredentialRejected } from './realmCredential.js';

import { SIGNED_IN_PROVIDERS } from './providers.js';

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
  // Reject a non-boolean at CONSTRUCTION rather than coercing at request time.
  // Gating on `=== true` alone is safe against the string "false" (truthy, would
  // have enforced in the dark) but silently permissive against the string "true" —
  // the complementary 3am, "I set it to true and nothing happened" (Tesla, PR #6).
  // Neither direction should be guessed: a caller that hands this a string has a
  // wiring bug, and a wiring bug in a security switch must be loud.
  if (typeof refuseAnonymous !== 'boolean') {
    throw new TypeError(
      `makeMintHandler: refuseAnonymous must be a boolean, got ${typeof refuseAnonymous} `
      + `(${JSON.stringify(refuseAnonymous)}) — resolve it via appOptionsFromEnv, not raw env`,
    );
  }
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
    // Positive form: admit only a principal whose provider is PROOF that it signed
    // in. Membership in SIGNED_IN_PROVIDERS is the whole test.
    //
    // Two weaker forms were tried on this PR and both were denylists in disguise:
    // `!== undefined` admitted null/''/0/non-strings, and "a non-empty string that
    // is not the sentinel" admitted `'firebase'` — which is exactly what
    // mapProvider returns for a MISSING or unrecognised sign_in_provider, so
    // absence of evidence was reading as evidence. An allowlist cannot fail that
    // way: an unknown provider is simply not in the set.
    if (refuseAnonymous === true && !SIGNED_IN_PROVIDERS.has(claims.provider)) {
      return res.status(403).json({ error: 'anonymous principals are not admitted' });
    }

    const roomName = req.body?.roomName;
    if (typeof roomName !== 'string' || roomName.length === 0) {
      return res.status(400).json({ error: 'roomName required' });
    }

    const token = await mintLiveKitToken({ identity: claims.subject, roomName });
    return res.status(200).json({ token });
  };
}
