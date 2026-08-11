import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';

import { createApp } from '../src/server.js';
import { parseAllowedOrigins } from '../src/cors.js';
import { es256Keys } from './helpers.js';

const keys = es256Keys();
const ALLOWED = 'https://world.imagineering.cc';

async function fakeVerify(idToken) {
  if (idToken === 'good') return { uid: 'user-1', provider: 'google' };
  throw new Error('bad token');
}
async function fakeMint({ identity, roomName }) {
  return `lk-token:${identity}:${roomName}`;
}

function appWith(opts) {
  return createApp({
    verifyProviderIdToken: fakeVerify,
    privateKeyPem: keys.privateKeyPem,
    publicKeyPem: keys.publicKeyPem,
    mintLiveKitToken: fakeMint,
    ...opts,
  });
}

let server;
let base;
let localhostServer;
let localhostBase;

before(() => Promise.all([
  new Promise((resolve) => {
    server = appWith({ allowedOrigins: [ALLOWED] }).listen(0, () => {
      base = `http://localhost:${server.address().port}`;
      resolve();
    });
  }),
  new Promise((resolve) => {
    localhostServer = appWith({ allowedOrigins: [ALLOWED], allowLocalhost: true })
      .listen(0, () => {
        localhostBase = `http://localhost:${localhostServer.address().port}`;
        resolve();
      });
  }),
]));
after(() => Promise.all([
  new Promise((resolve) => server.close(resolve)),
  new Promise((resolve) => localhostServer.close(resolve)),
]));

// Both endpoints must be covered: the web client calls /exchange then
// /livekit-token, so CORS on only one of them still leaves web broken.
for (const path of ['/exchange', '/livekit-token']) {
  test(`OPTIONS ${path} preflight from an allowed origin returns the allow headers`, async () => {
    const res = await fetch(`${base}${path}`, {
      method: 'OPTIONS',
      headers: {
        origin: ALLOWED,
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'authorization',
      },
    });
    assert.equal(res.status, 204);
    assert.equal(res.headers.get('access-control-allow-origin'), ALLOWED);
    assert.match(res.headers.get('access-control-allow-methods'), /POST/);
    assert.match(res.headers.get('access-control-allow-headers'), /authorization/);
    assert.match(res.headers.get('access-control-allow-headers'), /content-type/);
  });

  test(`OPTIONS ${path} preflight from a disallowed origin omits the allow headers`, async () => {
    const res = await fetch(`${base}${path}`, {
      method: 'OPTIONS',
      headers: { origin: 'https://evil.example', 'access-control-request-method': 'POST' },
    });
    assert.equal(res.headers.get('access-control-allow-origin'), null);
  });
}

test('POST /exchange from an allowed origin echoes that origin on the real response', async () => {
  const res = await fetch(`${base}/exchange`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: ALLOWED },
    body: JSON.stringify({ idToken: 'good' }),
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), ALLOWED);
});

test('POST /exchange from a disallowed origin omits the header (browser blocks it)', async () => {
  const res = await fetch(`${base}/exchange`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'https://evil.example' },
    body: JSON.stringify({ idToken: 'good' }),
  });
  assert.equal(res.headers.get('access-control-allow-origin'), null);
});

// Regression guard for the server-to-server path: CORS is browser-enforced, so
// gating requests on Origin would break curl / the bot / health checks while
// stopping no attacker (anything outside a browser can forge Origin).
test('a request with no Origin is served normally', async () => {
  const res = await fetch(`${base}/exchange`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ idToken: 'good' }),
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), null);
});

test('every response carries Vary: Origin so caches cannot cross origins', async () => {
  const res = await fetch(`${base}/healthz`, { headers: { origin: 'https://evil.example' } });
  assert.match(res.headers.get('vary'), /Origin/i);
});

test('localhost is rejected by default and accepted only when opted in', async () => {
  const devOrigin = 'http://localhost:54345';
  const off = await fetch(`${base}/exchange`, {
    method: 'OPTIONS',
    headers: { origin: devOrigin, 'access-control-request-method': 'POST' },
  });
  assert.equal(off.headers.get('access-control-allow-origin'), null);

  const on = await fetch(`${localhostBase}/exchange`, {
    method: 'OPTIONS',
    headers: { origin: devOrigin, 'access-control-request-method': 'POST' },
  });
  assert.equal(on.headers.get('access-control-allow-origin'), devOrigin);
});

// The localhost opt-in must not become a wildcard: an attacker-controlled host
// whose name merely contains "localhost" has to stay out.
test('localhost opt-in does not admit lookalike hosts', async () => {
  for (const origin of [
    'https://localhost.evil.example',
    'http://evil.example',
    'http://notlocalhost:8080',
  ]) {
    const res = await fetch(`${localhostBase}/exchange`, {
      method: 'OPTIONS',
      headers: { origin, 'access-control-request-method': 'POST' },
    });
    assert.equal(res.headers.get('access-control-allow-origin'), null, origin);
  }
});

test('parseAllowedOrigins trims and drops empties', () => {
  assert.deepEqual(
    parseAllowedOrigins(' https://a.example , ,https://b.example '),
    ['https://a.example', 'https://b.example'],
  );
  assert.deepEqual(parseAllowedOrigins(''), []);
  assert.deepEqual(parseAllowedOrigins(undefined), []);
});
