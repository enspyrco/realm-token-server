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
// Records every invocation. A refused request must never reach the minter at all:
// mintLiveKitToken embeds RoomAgentDispatch (src/livekit.js:22-24), so minting for a
// principal we then refuse would dispatch three agents into the room on every 403.
// Asserting only the status code would let a reorder (mint, then refuse) stay green
// while doing exactly that. Raised by Tesla on PR #6.
const mintCalls = [];
async function fakeMint({ identity, roomName }) {
  mintCalls.push({ identity, roomName });
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
let omitted;   // the key absent entirely — the real production default path
let stringy;   // refuseAnonymous: "false", the truthiness trap

before(async () => {
  enforcing = await makeServer({ refuseAnonymous: true });
  permissive = await makeServer({ refuseAnonymous: false });
  omitted = await makeServer({});
  stringy = await makeServer({ refuseAnonymous: 'false' });
});
after(() => Promise.all([enforcing, permissive, omitted, stringy].map(
  (s) => new Promise((r) => s.server.close(r)),
)));

// ---------------------------------------------------------------------------
// The capability this exists to remove.
// ---------------------------------------------------------------------------

test('enforcing: an anonymous principal is refused at the mint → 403, and NO token is minted', async () => {
  const token = await credentialFor(enforcing.base, 'anon');
  mintCalls.length = 0;
  const res = await post(enforcing.base, '/livekit-token', {
    body: { roomName: 'any_room' },
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(res.status, 403);
  // The side effect, not just the status. A reorder that minted first and refused
  // after would still return 403 while dispatching agents for every rejected guest.
  assert.deepEqual(mintCalls, [], 'the LiveKit minter must not run for a refused principal');
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

test('enforcing: a credential whose prov claim is not a usable string is refused → 403', async () => {
  // A credential that cannot PROVE it is non-anonymous must not be admitted.
  // Positive rule: admit only what is demonstrably permitted.
  //
  // `prov !== undefined` alone would be a TWO-VALUE DENYLIST wearing a positive
  // robe — null, "", 0 and any non-string would all sail through as "proven
  // non-anonymous". Tesla raised exactly this on PR #6, and the values below are
  // the ones a future signer (or a Dart twin) could plausibly emit. Each must be
  // refused, because none of them is proof of anything.
  //
  // Note on scope: this asserts the mint's policy over whatever shape a validly
  // SIGNED credential carries. It is deliberately not a credential-format test —
  // if verifyRealmCredential later makes `prov` mandatory, these become
  // unreachable-by-construction rather than wrong, and should be revisited then
  // (CarnotCodeCarver's concern on PR #6).
  const jwt = (await import('jsonwebtoken')).default;
  for (const prov of [undefined, null, '', 0, 42, true, ['google'], { p: 'google' }]) {
    const payload = prov === undefined ? {} : { prov };
    const token = jwt.sign(payload, keys.privateKeyPem, {
      algorithm: 'ES256', issuer: 'realm', audience: 'realm:livekit-mint',
      subject: 'user-x', expiresIn: 3600,
    });
    mintCalls.length = 0;
    const res = await post(enforcing.base, '/livekit-token', {
      body: { roomName: 'any_room' },
      headers: { authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 403, `prov=${JSON.stringify(prov)} must be refused`);
    assert.deepEqual(mintCalls, [], `prov=${JSON.stringify(prov)} must not reach the minter`);
  }
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

test('the createApp default is off when the option is OMITTED, not just passed false', async () => {
  // Raised by Tesla on PR #6: the permissive case was only ever tested with an
  // explicit `{refuseAnonymous: false}`. Flip createApp's default parameter to
  // `true` and that test still smiles while every deployment that never sets the
  // option starts refusing guests. Pin the default itself.
  const token = await credentialFor(omitted.base, 'anon');
  const res = await post(omitted.base, '/livekit-token', {
    body: { roomName: 'any_room' },
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(res.status, 200);
});

test('a STRING "false" does not enable enforcement (truthiness trap)', async () => {
  // "false" is truthy. An entrypoint passing process.env through raw would enforce
  // in the dark while its operator believed the switch was off — the 3am boot Tesla
  // named: "I set it to false and guests vanished." The handler gates on === true,
  // so the only way to enable it is an actual boolean.
  const token = await credentialFor(stringy.base, 'anon');
  const res = await post(stringy.base, '/livekit-token', {
    body: { roomName: 'any_room' },
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(res.status, 200);
});

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
