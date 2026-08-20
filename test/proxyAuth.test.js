// The per-IP limiter is only per-IP if req.ip is a value the caller cannot
// choose. On this deploy Caddy runs network_mode: host and reaches the container
// through the published port, so it arrives from the same address as any other
// local process — measured 2026-08-20, where a host-process curl with a forged
// X-Forwarded-For was believed in production. Address cannot separate them.
// A secret can.
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveProxySecret,
  makeProxyAuthMiddleware,
  InvalidProxySecret,
  PROXY_SECRET_HEADER,
  MIN_PROXY_SECRET_LENGTH,
  assertValidProxySecret,
} from '../src/proxyAuth.js';
import { createApp } from '../src/server.js';
import { es256Keys } from './helpers.js';

const SECRET = 'a'.repeat(MIN_PROXY_SECRET_LENGTH);

function run(middleware, headers) {
  const req = { headers: { ...headers } };
  let called = false;
  middleware(req, {}, () => { called = true; });
  assert.ok(called, 'middleware must always call next() — it never refuses a request');
  return req;
}

test('unset is unenforced, and preserves the header', () => {
  assert.equal(resolveProxySecret({}), null);
  assert.equal(resolveProxySecret({ REALM_TRUSTED_PROXY_SECRET: '' }), null);
  const req = run(makeProxyAuthMiddleware({ secret: null }), { 'x-forwarded-for': '203.0.113.9' });
  assert.equal(req.headers['x-forwarded-for'], '203.0.113.9');
  assert.equal(req.proxyAuthenticated, null);
});

test('a too-short secret refuses to boot rather than protecting weakly', () => {
  assert.throws(
    () => resolveProxySecret({ REALM_TRUSTED_PROXY_SECRET: 'short' }),
    InvalidProxySecret,
  );
});

test('surrounding whitespace refuses to boot — it would never match', () => {
  assert.throws(
    () => resolveProxySecret({ REALM_TRUSTED_PROXY_SECRET: ` ${SECRET} ` }),
    InvalidProxySecret,
  );
});

test('a correctly-presented secret keeps X-Forwarded-For', () => {
  const req = run(makeProxyAuthMiddleware({ secret: SECRET }), {
    [PROXY_SECRET_HEADER]: SECRET,
    'x-forwarded-for': '203.0.113.9',
  });
  assert.equal(req.headers['x-forwarded-for'], '203.0.113.9');
  assert.equal(req.proxyAuthenticated, true);
});

// The load-bearing case: this is the production behaviour measured on the box.
test('a forged X-Forwarded-For with NO secret is discarded', () => {
  const req = run(makeProxyAuthMiddleware({ secret: SECRET }), {
    'x-forwarded-for': '203.0.113.99',
  });
  assert.equal(req.headers['x-forwarded-for'], undefined);
  assert.equal(req.proxyAuthenticated, false);
});

test('a forged X-Forwarded-For with a WRONG secret is discarded', () => {
  const req = run(makeProxyAuthMiddleware({ secret: SECRET }), {
    [PROXY_SECRET_HEADER]: 'b'.repeat(MIN_PROXY_SECRET_LENGTH),
    'x-forwarded-for': '203.0.113.99',
  });
  assert.equal(req.headers['x-forwarded-for'], undefined);
  assert.equal(req.proxyAuthenticated, false);
});

// A near-miss must fail like any other miss. Guards against a future
// "startsWith"/prefix comparison, which a same-length wrong secret would not catch.
test('a secret that is a prefix of the real one is refused', () => {
  const req = run(makeProxyAuthMiddleware({ secret: SECRET }), {
    [PROXY_SECRET_HEADER]: SECRET.slice(0, -1),
    'x-forwarded-for': '203.0.113.99',
  });
  assert.equal(req.headers['x-forwarded-for'], undefined);
});

// A header sent twice does NOT arrive as an array — Node HTTP/1.1 joins the
// values with ", " into ONE STRING. Verified against a live node http server:
//   two values AAA, BBB  ->  typeof 'string', value "AAA, BBB"
// An earlier version of this test injected an array, which production never
// produces (Tesla, PR #11 round 1: "you tested the throw that production will
// not throw"). A fake more forgiving than the real API proves nothing.
//
// Fail-CLOSED is the wanted behaviour: a comma-joined value never equals the
// secret, so the claim is discarded and the caller keys on its socket. That is
// correct, and it is also why the Caddy snippet must DELETE the client's copy of
// the header before setting its own — otherwise a client can force this branch
// by simply sending the header.
test('a duplicated secret header arrives comma-joined and fails CLOSED', () => {
  const req = run(makeProxyAuthMiddleware({ secret: SECRET }), {
    [PROXY_SECRET_HEADER]: `${SECRET}, ${SECRET}`,
    'x-forwarded-for': '203.0.113.99',
  });
  assert.equal(req.headers['x-forwarded-for'], undefined);
  assert.equal(req.proxyAuthenticated, false);
});

// Client-prepended value: the shape a missing `header_up -X-...` produces.
test('a client-prepended value cannot ride in on the real secret', () => {
  const req = run(makeProxyAuthMiddleware({ secret: SECRET }), {
    [PROXY_SECRET_HEADER]: `attacker-junk, ${SECRET}`,
    'x-forwarded-for': '203.0.113.99',
  });
  assert.equal(req.headers['x-forwarded-for'], undefined, 'must not authenticate on a substring match');
});

// Defensive: an array can still reach the middleware from a non-HTTP caller or a
// future HTTP/2 path. It must not reach createHash and 500 the request.
test('an array-valued secret header does not throw', () => {
  const req = run(makeProxyAuthMiddleware({ secret: SECRET }), {
    [PROXY_SECRET_HEADER]: [SECRET, SECRET],
    'x-forwarded-for': '203.0.113.99',
  });
  assert.equal(req.headers['x-forwarded-for'], undefined);
  assert.equal(req.proxyAuthenticated, false);
});

// Whatever the outcome, the secret must not survive into a log, an error report
// or an upstream request.
test('the secret header is stripped in every case', () => {
  for (const [secret, presented] of [
    [null, SECRET],
    [SECRET, SECRET],
    [SECRET, 'wrong'],
    [SECRET, undefined],
  ]) {
    const req = run(makeProxyAuthMiddleware({ secret }), {
      ...(presented === undefined ? {} : { [PROXY_SECRET_HEADER]: presented }),
    });
    assert.equal(req.headers[PROXY_SECRET_HEADER], undefined);
  }
});

// ---------------------------------------------------------------------------
// Over real HTTP. Everything above proves the header is stripped; none of it
// proves req.ip CHANGED as a result, which is the only claim that matters. The
// limiter is the observable: rotating a forged X-Forwarded-For either buys you
// a fresh bucket or it does not.

const keys = es256Keys();

async function withServer({ trustedProxySecret = null }, run) {
  const app = createApp({
    verifyProviderIdToken: async () => { throw new Error('bad token'); },
    privateKeyPem: keys.privateKeyPem,
    publicKeyPem: keys.publicKeyPem,
    mintLiveKitToken: async () => 'lk',
    allowedOrigins: [],
    // 1 = the Caddy-fronted deploy. This is the setting the vulnerability lives at.
    trustProxyHops: 1,
    trustedProxySecret,
    now: () => 1_000_000,
    log: () => {},
  });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  try {
    await run(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

const spoof = (base, i) =>
  fetch(`${base}/exchange`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-forwarded-for': `203.0.113.${i}` },
    body: JSON.stringify({ idToken: 'nope' }),
  });

// The production behaviour measured on the box 2026-08-20. Kept as a RED-proof
// of the enforced case below: delete the middleware and this is what remains.
test('UNENFORCED: rotating a forged X-Forwarded-For evades the per-IP limiter', async () => {
  await withServer({ trustedProxySecret: null }, async (base) => {
    let status;
    for (let i = 0; i < 40; i += 1) status = (await spoof(base, i % 250)).status;
    assert.equal(status, 401, 'never throttled — each forged address got its own bucket');
  });
});

test('ENFORCED: rotating a forged X-Forwarded-For cannot evade the per-IP limiter', async () => {
  await withServer({ trustedProxySecret: SECRET }, async (base) => {
    const seen = new Set();
    for (let i = 0; i < 40; i += 1) seen.add((await spoof(base, i % 250)).status);
    assert.ok(seen.has(429), `expected a 429; saw ${[...seen].join(', ')}`);
  });
});

test('ENFORCED: the real proxy still gets per-IP buckets', async () => {
  await withServer({ trustedProxySecret: SECRET }, async (base) => {
    // 40 requests, each a DIFFERENT client, all presented by the authenticated
    // proxy. If the secret path collapsed everyone onto the socket address this
    // would 429 — which is the outage a naive fix would cause.
    let status;
    for (let i = 0; i < 40; i += 1) {
      status = (await fetch(`${base}/exchange`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-forwarded-for': `198.51.100.${i}`,
          [PROXY_SECRET_HEADER]: SECRET,
        },
        body: JSON.stringify({ idToken: 'nope' }),
      })).status;
    }
    assert.equal(status, 401, 'authenticated proxy must still get per-client buckets');
  });
});

test('createApp refuses a non-string secret at construction, not per-request', () => {
  // createHash(number) throws inside the request, so this would 500 every caller
  // presenting the header while the boot log still announced `enforced`.
  assert.throws(() => createApp({
    verifyProviderIdToken: async () => {},
    privateKeyPem: keys.privateKeyPem,
    publicKeyPem: keys.publicKeyPem,
    mintLiveKitToken: async () => 'lk',
    allowedOrigins: [],
    trustedProxySecret: 12345,
    log: () => {},
  }), InvalidProxySecret);
});

test('a discarded claim is visible in the request log, not silent', async () => {
  const lines = [];
  const app = createApp({
    verifyProviderIdToken: async () => { throw new Error('bad'); },
    privateKeyPem: keys.privateKeyPem,
    publicKeyPem: keys.publicKeyPem,
    mintLiveKitToken: async () => 'lk',
    allowedOrigins: [],
    trustProxyHops: 1,
    trustedProxySecret: SECRET,
    log: (l) => lines.push(l),
  });
  const server = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
  try {
    await fetch(`http://127.0.0.1:${server.address().port}/exchange`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.99' },
      body: JSON.stringify({ idToken: 'nope' }),
    });
  } finally {
    await new Promise((r) => server.close(r));
  }
  const entry = lines.map((l) => JSON.parse(l)).find((e) => e.msg === 'request');
  assert.equal(entry.proxyAuthenticated, false, 'a forged claim must leave a trace');
});

// Round-1 cage-match findings (Maxwell + Carnot, independently).
test('createApp refuses an EMPTY secret — it would authenticate everyone', () => {
  // matches('', '') is true, so an empty secret in the enforcing branch admits
  // any caller sending a bare header, while the boot line prints `enforced`.
  assert.throws(() => createApp({
    verifyProviderIdToken: async () => {},
    privateKeyPem: keys.privateKeyPem,
    publicKeyPem: keys.publicKeyPem,
    mintLiveKitToken: async () => 'lk',
    allowedOrigins: [],
    trustedProxySecret: '',
    log: () => {},
  }), InvalidProxySecret);
});

test('createApp applies the SAME floor as the env resolver, not a weaker one', () => {
  for (const bad of ['short', ` ${SECRET} `, 'a'.repeat(MIN_PROXY_SECRET_LENGTH - 1)]) {
    assert.throws(() => createApp({
      verifyProviderIdToken: async () => {},
      privateKeyPem: keys.privateKeyPem,
      publicKeyPem: keys.publicKeyPem,
      mintLiveKitToken: async () => 'lk',
      allowedOrigins: [],
      trustedProxySecret: bad,
      log: () => {},
    }), InvalidProxySecret, `createApp accepted ${JSON.stringify(bad)}`);
  }
});

// The rule is "an unauthenticated caller speaks for nobody", not "we strip the one
// header we currently read". express derives req.protocol/req.secure from
// x-forwarded-proto and req.hostname from x-forwarded-host whenever trust proxy is
// set, so a future absolute-URL builder would inherit a caller-chosen value.
test('an unauthenticated caller loses the whole x-forwarded-* family', () => {
  const req = run(makeProxyAuthMiddleware({ secret: SECRET }), {
    'x-forwarded-for': '203.0.113.99',
    'x-forwarded-proto': 'https',
    'x-forwarded-host': 'evil.example',
    'x-forwarded-port': '443',
    'x-real-ip': '203.0.113.99',
    'content-type': 'application/json',
  });
  for (const h of ['x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host', 'x-forwarded-port', 'x-real-ip']) {
    assert.equal(req.headers[h], undefined, `${h} survived`);
  }
  // Non-forwarding headers are untouched — this discards claims, not requests.
  assert.equal(req.headers['content-type'], 'application/json');
});

test('an AUTHENTICATED proxy keeps the whole family', () => {
  const req = run(makeProxyAuthMiddleware({ secret: SECRET }), {
    [PROXY_SECRET_HEADER]: SECRET,
    'x-forwarded-for': '203.0.113.9',
    'x-forwarded-proto': 'https',
  });
  assert.equal(req.headers['x-forwarded-for'], '203.0.113.9');
  assert.equal(req.headers['x-forwarded-proto'], 'https');
});
