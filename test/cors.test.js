import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';

import express from 'express';

import { createApp } from '../src/server.js';
import {
  parseAllowedOrigins,
  requireAllowedOrigins,
  InvalidAllowedOrigins,
  makeCorsMiddleware,
} from '../src/cors.js';
import { issueRealmCredential } from '../src/realmCredential.js';
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

// The mint response is the one whose absence IS "LiveKit never connected", so
// assert its real (non-preflight) response carries the header — a preflight-only
// test would stay green through a regression that only broke this path.
test('POST /livekit-token echoes the allowed origin on the real response', async () => {
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
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), ALLOWED);
});

test('POST /livekit-token from a disallowed origin omits the header', async () => {
  const cred = issueRealmCredential(keys.privateKeyPem, {
    subject: 'user-1',
    provider: 'google',
    ttlSeconds: 60,
  });
  const res = await fetch(`${base}/livekit-token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: 'https://evil.example',
      authorization: `Bearer ${cred.token}`,
    },
    body: JSON.stringify({ roomName: 'room-1' }),
  });
  assert.equal(res.headers.get('access-control-allow-origin'), null);
});

// Both token responses carry a credential in the body; an intermediary must not
// store and replay them.
test('token responses are marked no-store', async () => {
  const res = await fetch(`${base}/exchange`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: ALLOWED },
    body: JSON.stringify({ idToken: 'good' }),
  });
  assert.match(res.headers.get('cache-control'), /no-store/);
});

// Vary must survive a peer that also varies. setHeader('Vary','Origin') would
// have silently deleted Accept-Encoding here; res.vary() merges. RED-proving
// this needs a real upstream middleware, so mount the CORS middleware directly.
test('Vary: Origin appends rather than replacing an existing value', async () => {
  const peerApp = express();
  peerApp.use((_req, res, next) => {
    res.setHeader('Vary', 'Accept-Encoding'); // stand-in for compression
    next();
  });
  peerApp.use(makeCorsMiddleware({ allowedOrigins: [ALLOWED] }));
  peerApp.get('/probe', (_req, res) => res.json({ ok: true }));

  const srv = peerApp.listen(0);
  await new Promise((r) => srv.once('listening', r));
  try {
    const res = await fetch(`http://localhost:${srv.address().port}/probe`, {
      headers: { origin: ALLOWED },
    });
    const vary = res.headers.get('vary');
    assert.match(vary, /Accept-Encoding/i);
    assert.match(vary, /Origin/i);
  } finally {
    await new Promise((r) => srv.close(r));
  }
});

// Every rejected value below parses to an allowlist that matches nothing, which
// at runtime is indistinguishable from having no CORS at all — the silent
// web-only breakage this module exists to remove. Fail at boot instead.
test('requireAllowedOrigins rejects present-but-unusable values', () => {
  for (const raw of ['', '   ', ',,,', ' , ']) {
    assert.throws(() => requireAllowedOrigins(raw), InvalidAllowedOrigins, `expected throw for ${JSON.stringify(raw)}`);
  }
});

test('requireAllowedOrigins rejects wildcard and null', () => {
  assert.throws(() => requireAllowedOrigins('*'), InvalidAllowedOrigins);
  assert.throws(() => requireAllowedOrigins('null'), InvalidAllowedOrigins);
});

test('requireAllowedOrigins rejects anything not in Origin form', () => {
  // A trailing slash is what you get copying from a browser address bar, and it
  // can never equal an Origin header.
  assert.throws(() => requireAllowedOrigins('https://world.imagineering.cc/'), InvalidAllowedOrigins);
  assert.throws(() => requireAllowedOrigins('https://world.imagineering.cc/path'), InvalidAllowedOrigins);
  // Browsers omit default ports, so an explicit one would never match either.
  assert.throws(() => requireAllowedOrigins('https://world.imagineering.cc:443'), InvalidAllowedOrigins);
  assert.throws(() => requireAllowedOrigins('ftp://world.imagineering.cc'), InvalidAllowedOrigins);
  assert.throws(() => requireAllowedOrigins('world.imagineering.cc'), InvalidAllowedOrigins);
});

test('requireAllowedOrigins accepts well-formed origins', () => {
  assert.deepEqual(
    requireAllowedOrigins('https://world.imagineering.cc, http://localhost:8080'),
    ['https://world.imagineering.cc', 'http://localhost:8080'],
  );
});

test('localhost opt-in covers a default port and IPv6 loopback', async () => {
  for (const origin of ['http://localhost', 'http://[::1]:5000', 'http://127.0.0.1:3000']) {
    const res = await fetch(`${localhostBase}/exchange`, {
      method: 'OPTIONS',
      headers: { origin, 'access-control-request-method': 'POST' },
    });
    assert.equal(res.headers.get('access-control-allow-origin'), origin, origin);
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
