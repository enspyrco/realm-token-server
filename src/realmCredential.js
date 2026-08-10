import jwt from 'jsonwebtoken';

// The Realm-issued credential JWT — production port of the Dart reference at
// enspyrco/tech_world:examples/livekit-token-server/lib/src/realm_credential_jwt.dart.
// The two MUST agree on these constants and claim names: a credential minted by
// this server verifies against the Dart verifier and vice versa.
//
// Asymmetric by construction (ES256): the /exchange handler holds the PRIVATE
// key and signs; the /livekit-token (mint) handler holds only the PUBLIC key and
// verifies. A bug in the mint handler therefore cannot forge a credential — it
// never possesses the signing key. See DESIGN.md "Credential exchange boundary".

export const REALM_ISSUER = 'realm';
export const REALM_LIVEKIT_AUDIENCE = 'realm:livekit-mint';

/**
 * Mints a Realm credential. EXCHANGE-SIDE ONLY — requires the ES256 private key.
 * @param {string} privateKeyPem  ES256 (P-256) private key, PEM.
 * @param {{subject: string, provider: string, ttlSeconds?: number}} claims
 * @returns {{token: string, expiresAt: string}} opaque token + ISO-8601 expiry.
 */
export function issueRealmCredential(privateKeyPem, { subject, provider, ttlSeconds = 3600 }) {
  if (!subject) throw new Error('issueRealmCredential: subject is required');
  if (!(ttlSeconds > 0)) throw new Error('issueRealmCredential: ttlSeconds must be positive');
  // Compute whole-second iat/exp FIRST and derive expiresAt back from exp, so the
  // advertised expiresAt is byte-for-byte the token's exp — no sub-second tail
  // where a client believes a rejected token is still live. (noTimestamp: we set
  // iat ourselves; passing exp in the payload means no expiresIn option.)
  const iatSeconds = Math.floor(Date.now() / 1000);
  const expSeconds = iatSeconds + Math.floor(ttlSeconds);
  const token = jwt.sign(
    { prov: provider, iat: iatSeconds, exp: expSeconds },
    privateKeyPem,
    {
      algorithm: 'ES256',
      issuer: REALM_ISSUER,
      audience: REALM_LIVEKIT_AUDIENCE,
      subject,
      noTimestamp: true,
    },
  );
  return { token, expiresAt: new Date(expSeconds * 1000).toISOString() };
}

/**
 * Thrown when a credential fails verification. The reason is safe to log; never
 * echo it to an unauthenticated caller as anything but a generic 401.
 */
export class RealmCredentialRejected extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'RealmCredentialRejected';
  }
}

/**
 * Verifies a Realm credential. MINT-SIDE ONLY — holds the ES256 PUBLIC key,
 * never the private key. Fail-closed: any defect (bad signature, expiry, wrong
 * issuer/audience, malformed, missing claims) throws RealmCredentialRejected.
 * @param {string} publicKeyPem  ES256 public key, PEM.
 * @param {string} token
 * @returns {{subject: string, provider: string|undefined}}
 */
export function verifyRealmCredential(publicKeyPem, token) {
  let decoded;
  try {
    decoded = jwt.verify(token, publicKeyPem, {
      algorithms: ['ES256'], // pin the algorithm — never trust the token header's alg
      issuer: REALM_ISSUER,
      audience: REALM_LIVEKIT_AUDIENCE,
    });
  } catch (err) {
    throw new RealmCredentialRejected(err.message);
  }
  if (!decoded.sub) {
    throw new RealmCredentialRejected('missing subject claim');
  }
  return { subject: decoded.sub, provider: decoded.prov };
}
