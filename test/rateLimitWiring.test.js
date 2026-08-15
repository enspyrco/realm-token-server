// The limiter primitive is exercised in rateLimit.test.js. This file asserts the
// thing that primitive cannot: that it is MOUNTED correctly — on the routes that
// need it, off the ones that must never be throttled, and keyed on an address
// that survives a proxy in front of the process.
//
// Every assertion here goes over real HTTP against a real express app, because
// the failures worth catching (a limiter mounted after the handler, a `trust
// proxy` that turns the internet into one bucket) are invisible to a unit test
// that calls the middleware directly.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createApp } from '../src/server.js';
import { es256Keys } from './helpers.js';

const keys = es256Keys();

async function fakeVerify() { throw new Error('bad token'); }
async function fakeMint({ identity, roomName }) { return `lk-token:${identity}:${roomName}`; }

// A frozen clock, so no test can flake by straddling a window boundary.
function buildApp({ trustProxyHops = 0, allowedOrigins = [] } = {}) {
  return createApp({
    verifyProviderIdToken: fakeVerify,
    privateKeyPem: keys.privateKeyPem,
    publicKeyPem: keys.publicKeyPem,
    mintLiveKitToken: fakeMint,
    allowedOrigins,
    trustProxyHops,
    now: () => 1_000_000,
    log: () => {},
  });
}

// Each test gets its own server, so one test's spent budget cannot leak into
// another's — the global limiter is service-wide by design and would otherwise
// couple them.
async function withServer(options, run) {
  const server = await new Promise((resolve) => {
    const s = buildApp(options).listen(0, () => resolve(s));
  });
  try {
    await run(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function post(base, path, { forwardedFor } = {}) {
  return fetch(`${base}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(forwardedFor ? { 'x-forwarded-for': forwardedFor } : {}),
    },
    body: JSON.stringify({ idToken: 'nope', roomName: 'room' }),
  });
}

test('a single caller is refused past the per-IP ceiling on /exchange', async () => {
  await withServer({}, async (base) => {
    let lastAllowed;
    for (let i = 0; i < 30; i += 1) lastAllowed = await post(base, '/exchange');
    // The handler still runs for permitted requests — 401 here means the limiter
    // let it through to the verifier, which is the point.
    assert.equal(lastAllowed.status, 401);

    const refused = await post(base, '/exchange');
    assert.equal(refused.status, 429);
    assert.equal(await refused.json().then((b) => b.error), 'rate limited');
    assert.ok(Number(refused.headers.get('retry-after')) >= 1);
  });
});

test('a single caller is refused past the per-IP ceiling on /livekit-token', async () => {
  // The sibling of the /exchange test above, and the one that matters more: this
  // is the route that embeds a RoomAgentDispatch, so an unbounded caller here
  // amplifies into rooms rather than merely burning CPU. Without this, deleting
  // mintLimit from server.js leaves the whole suite green — the ceiling named in
  // the README as the reason for the work would be unwitnessed by any test.
  await withServer({}, async (base) => {
    let lastAllowed;
    for (let i = 0; i < 30; i += 1) lastAllowed = await post(base, '/livekit-token');
    assert.equal(lastAllowed.status, 401);

    const refused = await post(base, '/livekit-token');
    assert.equal(refused.status, 429);
    assert.ok(Number(refused.headers.get('retry-after')) >= 1);
  });
});

test('the two mint routes hold separate per-IP budgets', async () => {
  await withServer({}, async (base) => {
    for (let i = 0; i < 31; i += 1) await post(base, '/exchange');
    assert.equal((await post(base, '/exchange')).status, 429);

    // Exhausting /exchange must not lock a caller out of joining a room.
    assert.equal((await post(base, '/livekit-token')).status, 401);
  });
});

test('/healthz is never throttled', async () => {
  await withServer({}, async (base) => {
    // Well past every per-IP ceiling. The container healthcheck runs every 30s
    // forever; a limiter that could 429 it would restart the service on its own.
    for (let i = 0; i < 200; i += 1) {
      assert.equal((await fetch(`${base}/healthz`)).status, 200);
    }
  });
});

test('with no trusted proxy, a forged X-Forwarded-For buys no extra budget', async () => {
  await withServer({ trustProxyHops: 0 }, async (base) => {
    // Thirty-one requests, every one claiming a different client address. At
    // hops=0 express ignores the header, so they all land in the socket
    // address's single bucket and the last is refused.
    let last;
    for (let i = 0; i < 31; i += 1) {
      last = await post(base, '/exchange', { forwardedFor: `203.0.113.${i}` });
    }
    assert.equal(last.status, 429, 'X-Forwarded-For must not be believed at hops=0');
  });
});

test('with one trusted proxy, distinct clients get distinct budgets', async () => {
  await withServer({ trustProxyHops: 1 }, async (base) => {
    // The test client IS the trusted hop here (it connects over loopback), which
    // is exactly the deployed shape: Caddy is the one process allowed to say who
    // the client is. Thirty from one client, then a different client is served.
    for (let i = 0; i < 31; i += 1) {
      await post(base, '/exchange', { forwardedFor: '203.0.113.1' });
    }
    assert.equal(
      (await post(base, '/exchange', { forwardedFor: '203.0.113.1' })).status,
      429,
    );
    assert.equal(
      (await post(base, '/exchange', { forwardedFor: '198.51.100.7' })).status,
      401,
      'a different client must not inherit the throttled one budget',
    );
  });
});

test('the service-wide ceiling holds when no single caller crosses its own', async () => {
  await withServer({ trustProxyHops: 1 }, async (base) => {
    // 600 requests spread over 60 addresses — ten each, a third of the per-IP
    // ceiling, so nothing here is refused by the per-IP layer. Only the global
    // circuit breaker can refuse the 601st, which is what makes this test a
    // proof that it is wired rather than merely constructed.
    let sent = 0;
    for (let round = 0; round < 10; round += 1) {
      for (let host = 1; host <= 60; host += 1) {
        const res = await post(base, '/exchange', { forwardedFor: `203.0.113.${host}` });
        assert.equal(res.status, 401, `request ${sent} was refused before the global ceiling`);
        sent += 1;
      }
    }
    assert.equal(sent, 600);

    const refused = await post(base, '/exchange', { forwardedFor: '198.51.100.9' });
    assert.equal(refused.status, 429, 'the global ceiling must refuse a fresh, unthrottled caller');
  });
});

test('the global ceiling is shared across both mint routes', async () => {
  await withServer({ trustProxyHops: 1 }, async (base) => {
    for (let round = 0; round < 10; round += 1) {
      for (let host = 1; host <= 60; host += 1) {
        await post(base, '/exchange', { forwardedFor: `203.0.113.${host}` });
      }
    }
    // Budget spent entirely on /exchange; /livekit-token must feel it, or the
    // "service-wide" ceiling is two independent ceilings wearing one name.
    const refused = await post(base, '/livekit-token', { forwardedFor: '198.51.100.9' });
    assert.equal(refused.status, 429);
  });
});

test('a 429 is readable by the browser it was sent to', async () => {
  const origin = 'https://world.example';
  await withServer({ allowedOrigins: [origin] }, async (base) => {
    let res;
    for (let i = 0; i < 31; i += 1) {
      res = await fetch(`${base}/exchange`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', Origin: origin },
        body: '{}',
      });
    }
    assert.equal(res.status, 429);
    // Without this header the browser reports an opaque CORS error instead of
    // "rate limited", and a throttled web client cannot tell being limited from
    // being broken — which is the whole difference between a throttle the client
    // can back off from and an outage it cannot explain.
    assert.equal(res.headers.get('access-control-allow-origin'), origin);
    assert.ok(res.headers.get('retry-after'));
  });
});

test('createApp refuses a nonsense trustProxyHops rather than guessing', () => {
  for (const hops of [-1, 1.5, '1', null]) {
    assert.throws(
      () => buildApp({ trustProxyHops: hops }),
      TypeError,
      `trustProxyHops=${hops} should be refused`,
    );
  }
});
