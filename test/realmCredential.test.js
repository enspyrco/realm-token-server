import { test } from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';

import {
  issueRealmCredential,
  verifyRealmCredential,
  RealmCredentialRejected,
  REALM_ISSUER,
  REALM_LIVEKIT_AUDIENCE,
} from '../src/realmCredential.js';
import { es256Keys } from './helpers.js';

const keys = es256Keys();
const attacker = es256Keys();

test('round-trip: a minted credential verifies to its subject + provider', () => {
  const cred = issueRealmCredential(keys.privateKeyPem, {
    subject: 'user-abc',
    provider: 'google',
  });
  const claims = verifyRealmCredential(keys.publicKeyPem, cred.token);
  assert.equal(claims.subject, 'user-abc');
  assert.equal(claims.provider, 'google');
  assert.ok(new Date(cred.expiresAt) > new Date());
});

test('expiresAt is byte-for-byte the token exp (no sub-second drift)', () => {
  const cred = issueRealmCredential(keys.privateKeyPem, { subject: 'u', provider: 'google' });
  const decoded = jwt.decode(cred.token);
  assert.equal(new Date(cred.expiresAt).getTime(), decoded.exp * 1000);
});

test('a non-positive or sub-second ttl is rejected', () => {
  for (const bad of [0, -10, 0.5]) {
    assert.throws(
      () => issueRealmCredential(keys.privateKeyPem, { subject: 'u', provider: 'google', ttlSeconds: bad }),
      />= 1/,
      `ttlSeconds ${bad} should be rejected`,
    );
  }
});

test('a token signed by a DIFFERENT key is rejected (mint cannot forge)', () => {
  // The mint handler has only the public key; even a full attacker-controlled
  // issuer cannot mint a credential the real verifier accepts.
  const forged = issueRealmCredential(attacker.privateKeyPem, {
    subject: 'mallory',
    provider: 'google',
  });
  assert.throws(
    () => verifyRealmCredential(keys.publicKeyPem, forged.token),
    RealmCredentialRejected,
  );
});

test('a tampered token is rejected', () => {
  const cred = issueRealmCredential(keys.privateKeyPem, { subject: 'u', provider: 'google' });
  const parts = cred.token.split('.');
  const sig = parts[2];
  // Flip the FIRST signature char — it encodes real high bits of byte 0. (The
  // LAST char holds don't-care padding bits, so flipping it can be a no-op.)
  const tampered = `${parts[0]}.${parts[1]}.${sig[0] === 'A' ? 'B' : 'A'}${sig.slice(1)}`;
  assert.throws(() => verifyRealmCredential(keys.publicKeyPem, tampered), RealmCredentialRejected);
});

test('an expired credential is rejected', () => {
  const now = Math.floor(Date.now() / 1000);
  const token = jwt.sign(
    { prov: 'google', iat: now - 7200, exp: now - 3600 }, // expired an hour ago
    keys.privateKeyPem,
    { algorithm: 'ES256', issuer: REALM_ISSUER, audience: REALM_LIVEKIT_AUDIENCE, subject: 'u', noTimestamp: true },
  );
  assert.throws(() => verifyRealmCredential(keys.publicKeyPem, token), RealmCredentialRejected);
});

test('a validly-signed token with no exp is rejected (no immortal creds)', () => {
  const token = jwt.sign(
    { prov: 'google', iat: Math.floor(Date.now() / 1000) }, // no exp
    keys.privateKeyPem,
    { algorithm: 'ES256', issuer: REALM_ISSUER, audience: REALM_LIVEKIT_AUDIENCE, subject: 'u', noTimestamp: true },
  );
  assert.throws(() => verifyRealmCredential(keys.publicKeyPem, token), RealmCredentialRejected);
});

test('a wrong-audience token is rejected', () => {
  const token = jwt.sign({ prov: 'google' }, keys.privateKeyPem, {
    algorithm: 'ES256',
    issuer: REALM_ISSUER,
    audience: 'realm:some-other-endpoint',
    subject: 'u',
    expiresIn: 3600,
  });
  assert.throws(() => verifyRealmCredential(keys.publicKeyPem, token), RealmCredentialRejected);
});

test('a wrong-issuer token is rejected', () => {
  const token = jwt.sign({ prov: 'google' }, keys.privateKeyPem, {
    algorithm: 'ES256',
    issuer: 'not-realm',
    audience: REALM_LIVEKIT_AUDIENCE,
    subject: 'u',
    expiresIn: 3600,
  });
  assert.throws(() => verifyRealmCredential(keys.publicKeyPem, token), RealmCredentialRejected);
});

test('an alg:none token is rejected (algorithm is pinned)', () => {
  // The classic JWT downgrade: a token claiming alg=none. Pinning
  // algorithms:['ES256'] in verify must reject it.
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({
    sub: 'mallory', prov: 'google', iss: REALM_ISSUER, aud: REALM_LIVEKIT_AUDIENCE,
    exp: Math.floor(Date.now() / 1000) + 3600,
  })).toString('base64url');
  const noneToken = `${header}.${body}.`;
  assert.throws(() => verifyRealmCredential(keys.publicKeyPem, noneToken), RealmCredentialRejected);
});

test('garbage input is rejected, not crashed on', () => {
  assert.throws(() => verifyRealmCredential(keys.publicKeyPem, 'not-a-jwt'), RealmCredentialRejected);
});
