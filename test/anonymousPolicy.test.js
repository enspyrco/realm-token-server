import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';

import { createApp } from '../src/server.js';
import { resolveRefuseAnonymous } from '../src/mint.js';
import { es256Keys } from './helpers.js';

// Step 0 of docs/crucible/room-admission/DESIGN.md — the deployment-wide refusal
// of anonymous principals at the mint. This is a RISK TRIM, not admission control:
// it closes "any anonymous guest can enter any room" for a deployment willing to
// require sign-in. An authenticated user can still request any room; that is the
// engine's job (step 2) and these tests deliberately do not claim otherwise.

const keys = es256Keys();

// Provider verifier keyed by the id token, so a test can mint either an
// anonymous or a signed-in credential through the real /exchange path.
async function fakeVerify(idToken) {
  if (idToken === 'google') return { uid: 'user-1', provider: 'google' };
  if (idToken === 'anon') return { uid: 'guest-1', provider: 'anonymous' };
  throw new Error('bad token');
}
async function fakeMint({ identity, roomName }) {
  return `lk-token:${identity}:${roomName}`;
}

function makeServer(opts) {
  const app = createApp({
    verifyProviderIdToken: fakeVerify,
    privateKeyPem: keys.privateKeyPem,
    publicKeyPem: keys.publicKeyPem,
    mintLiveKitToken: fakeMint,
    allowedOrigins: [],
    ...opts,
  });
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      const base = `http://localhost:${server.address().port}`;
      resolve({ server, base });
    });
  });
}

function post(base, path, { body, headers } = {}) {
  return fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body ?? {}),
  });
}

async function credentialFor(base, idToken) {
  const res = await post(base, '/exchange', { body: { idToken } });
  assert.equal(res.status, 200, `exchange should succeed for ${idToken}`);
  return (await res.json()).token;
}

let enforcing;
let permissive;

before(async () => {
  enforcing = await makeServer({ refuseAnonymous: true });
  permissive = await makeServer({ refuseAnonymous: false });
});
after(() => Promise.all([
  new Promise((r) => enforcing.server.close(r)),
  new Promise((r) => permissive.server.close(r)),
]));

// ---------------------------------------------------------------------------
// The capability this exists to remove.
// ---------------------------------------------------------------------------

test('enforcing: an anonymous principal is refused at the mint → 403', async () => {
  const token = await credentialFor(enforcing.base, 'anon');
  const res = await post(enforcing.base, '/livekit-token', {
    body: { roomName: 'any_room' },
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(res.status, 403);
  // 403 not 401: the credential is VALID and was verified. This is an
  // authorization refusal, and conflating it with 401 would tell a caller to
  // go re-authenticate, which would not help.
  const body = await res.json();
  assert.match(body.error, /anonymous/i);
});

test('enforcing: a signed-in principal is unaffected → 200', async () => {
  const token = await credentialFor(enforcing.base, 'google');
  const res = await post(enforcing.base, '/livekit-token', {
    body: { roomName: 'any_room' },
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).token, 'lk-token:user-1:any_room');
});

// ---------------------------------------------------------------------------
// Fail-closed: the refusal must not depend on a claim an attacker can omit.
// ---------------------------------------------------------------------------

test('enforcing: a credential with NO provider claim is refused → 403', async () => {
  // A credential that cannot PROVE it is non-anonymous must not be admitted.
  // Positive rule: admit only what is demonstrably permitted. If this ever
  // returns 200, the check has become "refuse the known-bad" — a denylist.
  const jwt = (await import('jsonwebtoken')).default;
  const noProv = jwt.sign({}, keys.privateKeyPem, {
    algorithm: 'ES256', issuer: 'realm', audience: 'realm:livekit-mint',
    subject: 'user-x', expiresIn: 3600,
  });
  const res = await post(enforcing.base, '/livekit-token', {
    body: { roomName: 'any_room' },
    headers: { authorization: `Bearer ${noProv}` },
  });
  assert.equal(res.status, 403);
});

test('enforcing: an invalid credential is still 401, not 403', async () => {
  // Ordering matters: authentication is decided before authorization, so a
  // forged token must not leak the policy's existence via a 403.
  const res = await post(enforcing.base, '/livekit-token', {
    body: { roomName: 'any_room' },
    headers: { authorization: 'Bearer not-a-token' },
  });
  assert.equal(res.status, 401);
});

// ---------------------------------------------------------------------------
// Off by default: the switch must be genuinely opt-in.
// ---------------------------------------------------------------------------

test('permissive (the default): an anonymous principal still mints → 200', async () => {
  // This is today's behaviour and MUST be preserved when the flag is unset —
  // the deploy of step 0 is behaviour-identical until someone turns it on.
  const token = await credentialFor(permissive.base, 'anon');
  const res = await post(permissive.base, '/livekit-token', {
    body: { roomName: 'any_room' },
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).token, 'lk-token:guest-1:any_room');
});

// ---------------------------------------------------------------------------
// The env parse fails closed on anything it does not recognise.
// ---------------------------------------------------------------------------

test('resolveRefuseAnonymous: unset → false (off by default)', () => {
  assert.equal(resolveRefuseAnonymous({}), false);
});

test('resolveRefuseAnonymous: "true"/"false" parse exactly', () => {
  assert.equal(resolveRefuseAnonymous({ REALM_REFUSE_ANONYMOUS: 'true' }), true);
  assert.equal(resolveRefuseAnonymous({ REALM_REFUSE_ANONYMOUS: 'false' }), false);
});

test('resolveRefuseAnonymous: an unrecognised value REFUSES TO START', () => {
  // A security switch that silently reads "yes"/"1"/"TRUE" as off would fail
  // silently in the direction that matters. Refuse to boot instead — same
  // contract as resolveTrustProxyHops.
  for (const v of ['yes', '1', 'TRUE', 'on', '']) {
    assert.throws(
      () => resolveRefuseAnonymous({ REALM_REFUSE_ANONYMOUS: v }),
      /REALM_REFUSE_ANONYMOUS/,
      `"${v}" must not be silently accepted`,
    );
  }
});
