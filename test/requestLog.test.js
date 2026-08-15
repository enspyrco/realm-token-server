import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import { createApp } from '../src/server.js';
import { makeRequestLogger } from '../src/requestLog.js';
import { issueRealmCredential } from '../src/realmCredential.js';
import { es256Keys } from './helpers.js';

const keys = es256Keys();
const ALLOWED = 'https://world.imagineering.cc';

async function fakeVerify(idToken) {
  if (idToken === 'good-id-token-SECRET') return { uid: 'user-1', provider: 'google' };
  throw new Error('bad token');
}
async function fakeMint({ identity, roomName }) {
  return `lk-token-SECRET:${identity}:${roomName}`;
}

let lines = [];
let server;
let base;

before(() => new Promise((resolve) => {
  const app = createApp({
    verifyProviderIdToken: fakeVerify,
    privateKeyPem: keys.privateKeyPem,
    publicKeyPem: keys.publicKeyPem,
    mintLiveKitToken: fakeMint,
    allowedOrigins: [ALLOWED],
    log: (line) => lines.push(line),
  });
  server = app.listen(0, () => {
    base = `http://localhost:${server.address().port}`;
    resolve();
  });
}));
after(() => new Promise((resolve) => server.close(resolve)));

function drain() {
  const out = lines.map((l) => JSON.parse(l));
  lines = [];
  return out;
}

test('a request emits one structured line with the transport facts', async () => {
  drain();
  await fetch(`${base}/exchange`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: ALLOWED },
    body: JSON.stringify({ idToken: 'good-id-token-SECRET' }),
  });
  const [entry, ...rest] = drain();
  assert.equal(rest.length, 0, 'exactly one line per request');
  assert.equal(entry.msg, 'request');
  assert.equal(entry.method, 'POST');
  assert.equal(entry.path, '/exchange');
  assert.equal(entry.status, 200);
  assert.equal(entry.origin, ALLOWED);
  assert.equal(entry.originAllowed, true);
  assert.ok(Number.isFinite(entry.durationMs));
});

// The refused ones are the whole point — a denied origin that leaves no trace is
// indistinguishable from no traffic at all.
test('refused requests are logged, not silently dropped', async () => {
  drain();
  await fetch(`${base}/exchange`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'https://evil.example' },
    body: JSON.stringify({ idToken: 'good-id-token-SECRET' }),
  });
  const [entry] = drain();
  assert.equal(entry.status, 403);
  assert.equal(entry.origin, 'https://evil.example');
  assert.equal(entry.originAllowed, false);
});

test('a denied preflight is logged too', async () => {
  drain();
  await fetch(`${base}/livekit-token`, {
    method: 'OPTIONS',
    headers: { origin: 'https://evil.example', 'access-control-request-method': 'POST' },
  });
  const [entry] = drain();
  assert.equal(entry.method, 'OPTIONS');
  assert.equal(entry.status, 204);
  assert.equal(entry.originAllowed, false);
});

// The healthcheck fires every 30s; logging it would add ~2900 lines a day that
// say nothing `docker inspect` doesn't already.
test('/healthz is not logged', async () => {
  drain();
  await fetch(`${base}/healthz`);
  assert.deepEqual(drain(), []);
});

// THE test. Nothing derived from a body, an Authorization header, or a minted
// token may reach the log — on a credential mint that is the whole safety
// property, and it must hold for the request that carries the most material.
test('no credential material ever reaches the log', async () => {
  drain();

  await fetch(`${base}/exchange`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: ALLOWED },
    body: JSON.stringify({ idToken: 'good-id-token-SECRET' }),
  });

  const cred = issueRealmCredential(keys.privateKeyPem, {
    subject: 'user-1',
    provider: 'google',
    ttlSeconds: 60,
  });
  const res = await fetch(`${base}/livekit-token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: ALLOWED,
      authorization: `Bearer ${cred.token}`,
    },
    body: JSON.stringify({ roomName: 'room-1' }),
  });
  const { token: minted } = await res.json();

  const logged = drain().map((e) => JSON.stringify(e)).join('\n');
  for (const secret of [
    'good-id-token-SECRET', // the provider ID token
    cred.token, // the Realm credential presented
    minted, // the LiveKit token handed back
    'lk-token-SECRET',
    keys.privateKeyPem,
    'user-1', // the subject — PII, deliberately absent
  ]) {
    assert.equal(logged.includes(secret), false, `log leaked: ${secret.slice(0, 24)}`);
  }
});

// Origin is attacker-controlled. A raw-string log format would let a newline in
// it forge whole entries; JSON escaping is what prevents that, so pin it.
test('a newline in Origin cannot forge a log line', () => {
  const out = [];
  const mw = makeRequestLogger({ log: (l) => out.push(l), now: () => 0 });

  const res = new EventEmitter();
  res.statusCode = 200;
  res.getHeader = () => undefined;
  const req = {
    method: 'POST',
    path: '/exchange',
    get: () => 'https://evil.example\n{"msg":"request","status":200,"forged":true}',
  };

  mw(req, res, () => {});
  res.emit('finish');

  assert.equal(out.length, 1);
  assert.equal(out[0].includes('\n'), false, 'the raw newline must be escaped');
  const parsed = JSON.parse(out[0]);
  assert.equal(parsed.forged, undefined);
  assert.match(parsed.origin, /evil\.example/);
});
