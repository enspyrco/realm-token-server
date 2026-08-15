import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';

import { createApp } from '../src/server.js';
import { verifyRealmCredential } from '../src/realmCredential.js';
import { es256Keys } from './helpers.js';

const keys = es256Keys();
const attacker = es256Keys();

// Fake provider verifier: 'good' authenticates, anything else throws (→ 401).
async function fakeVerify(idToken) {
  if (idToken === 'good') return { uid: 'user-1', provider: 'google' };
  throw new Error('bad token');
}

// Fake LiveKit minter: deterministic, no real API keys.
async function fakeMint({ identity, roomName }) {
  return `lk-token:${identity}:${roomName}`;
}

const app = createApp({
  verifyProviderIdToken: fakeVerify,
  privateKeyPem: keys.privateKeyPem,
  publicKeyPem: keys.publicKeyPem,
  mintLiveKitToken: fakeMint,
  // This suite exercises the handlers, not CORS; [] is the explicit "serves no
  // browser" choice createApp now requires rather than silently defaulting to.
  allowedOrigins: [],
});

let server;
let base;

before(() => new Promise((resolve) => {
  server = app.listen(0, () => {
    base = `http://localhost:${server.address().port}`;
    resolve();
  });
}));
after(() => new Promise((resolve) => server.close(resolve)));

function post(path, { body, headers } = {}) {
  return fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body ?? {}),
  });
}

test('POST /exchange with a valid id token mints a verifiable credential', async () => {
  const res = await post('/exchange', { body: { idToken: 'good' } });
  assert.equal(res.status, 200);
  const { token, expiresAt } = await res.json();
  const claims = verifyRealmCredential(keys.publicKeyPem, token);
  assert.equal(claims.subject, 'user-1');
  assert.equal(claims.provider, 'google');
  assert.ok(new Date(expiresAt) > new Date());
});

test('POST /exchange with a bad id token → 401', async () => {
  const res = await post('/exchange', { body: { idToken: 'bad' } });
  assert.equal(res.status, 401);
});

test('POST /exchange with no id token → 400', async () => {
  const res = await post('/exchange', { body: {} });
  assert.equal(res.status, 400);
});

test('full flow: exchange → livekit-token returns a LiveKit token', async () => {
  const ex = await post('/exchange', { body: { idToken: 'good' } });
  const { token } = await ex.json();
  const res = await post('/livekit-token', {
    body: { roomName: 'l_room' },
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(res.status, 200);
  const { token: lkToken } = await res.json();
  assert.equal(lkToken, 'lk-token:user-1:l_room');
});

test('POST /livekit-token with no bearer → 401', async () => {
  const res = await post('/livekit-token', { body: { roomName: 'l_room' } });
  assert.equal(res.status, 401);
});

test('POST /livekit-token with a FORGED bearer → 401 (exchange boundary holds)', async () => {
  // A credential signed by an attacker key must not mint a LiveKit token.
  const forged = jwt.sign({ prov: 'google' }, attacker.privateKeyPem, {
    algorithm: 'ES256', issuer: 'realm', audience: 'realm:livekit-mint',
    subject: 'mallory', expiresIn: 3600,
  });
  const res = await post('/livekit-token', {
    body: { roomName: 'l_room' },
    headers: { authorization: `Bearer ${forged}` },
  });
  assert.equal(res.status, 401);
});

test('POST /livekit-token cannot be bypassed with a raw id token as bearer → 401', async () => {
  // Presenting the provider ID token directly at the mint endpoint must fail —
  // only a Realm credential is accepted.
  const res = await post('/livekit-token', {
    body: { roomName: 'l_room' },
    headers: { authorization: 'Bearer good' },
  });
  assert.equal(res.status, 401);
});

test('POST /livekit-token with valid bearer but no roomName → 400', async () => {
  const ex = await post('/exchange', { body: { idToken: 'good' } });
  const { token } = await ex.json();
  const res = await post('/livekit-token', {
    body: {},
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(res.status, 400);
});
