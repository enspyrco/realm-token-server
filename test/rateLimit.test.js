import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  makeRateLimiter,
  resolveTrustProxyHops,
  InvalidTrustProxyHops,
  RateLimitScope,
} from '../src/rateLimit.js';

// These tests exercise the counting primitive, not the wiring, so the scope is
// noise here — but it is REQUIRED at the real call sites on purpose (a limiter
// with no scope logs a 429 nobody can attribute). One default, stated once.
const makeLimiter = (opts) => makeRateLimiter({ scope: RateLimitScope.GLOBAL, ...opts });

// A minimal express-shaped res: enough to record what the middleware did, and
// nothing that would let a passing test depend on express internals.
function fakeRes() {
  const res = {
    statusCode: null,
    headers: {},
    body: null,
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.body = payload; return this; },
  };
  return res;
}

// Drives the middleware once and reports which way it went. `next` being called
// and a 429 being sent are mutually exclusive outcomes, and the test asserts on
// that rather than on the status code alone — a limiter that sends 429 AND
// calls next would still let the request through.
function hit(limiter, req = {}) {
  const res = fakeRes();
  let passed = false;
  limiter(req, res, () => { passed = true; });
  return { passed, res };
}

test('allows up to the limit, then refuses', () => {
  const limiter = makeLimiter({ limit: 3, windowMs: 60_000, now: () => 1000 });
  const req = { ip: '1.2.3.4' };

  for (let i = 0; i < 3; i += 1) {
    assert.equal(hit(limiter, req).passed, true, `request ${i + 1} should pass`);
  }

  const refused = hit(limiter, req);
  assert.equal(refused.passed, false);
  assert.equal(refused.res.statusCode, 429);
  assert.deepEqual(refused.res.body, { error: 'rate limited' });
});

test('a refusal carries a Retry-After of at least one second', () => {
  let clock = 0;
  const limiter = makeLimiter({ limit: 1, windowMs: 60_000, now: () => clock });

  hit(limiter, { ip: 'a' });

  // 100ms before the window closes: the true remainder rounds to 0, which would
  // invite the immediate retry the limiter exists to stop.
  clock = 59_900;
  const refused = hit(limiter, { ip: 'a' });
  assert.equal(refused.res.statusCode, 429);
  assert.equal(refused.res.headers['retry-after'], '1');

  clock = 0;
  const fresh = makeLimiter({ limit: 1, windowMs: 60_000, now: () => clock });
  fresh({ ip: 'a' }, fakeRes(), () => {});
  clock = 10_000;
  const mid = hit(fresh, { ip: 'a' });
  assert.equal(mid.res.headers['retry-after'], '50');
});

test('the window resets and the caller is served again', () => {
  let clock = 0;
  const limiter = makeLimiter({ limit: 1, windowMs: 60_000, now: () => clock });

  assert.equal(hit(limiter, { ip: 'a' }).passed, true);
  assert.equal(hit(limiter, { ip: 'a' }).passed, false);

  clock = 60_000;
  assert.equal(hit(limiter, { ip: 'a' }).passed, true, 'window boundary should reset the count');
});

test('keys are independent — one caller cannot spend another caller budget', () => {
  const limiter = makeLimiter({ limit: 1, windowMs: 60_000, now: () => 0 });

  assert.equal(hit(limiter, { ip: 'a' }).passed, true);
  assert.equal(hit(limiter, { ip: 'a' }).passed, false);
  assert.equal(hit(limiter, { ip: 'b' }).passed, true, 'b has its own budget');
});

test('a constant key makes one shared bucket — the global limiter shape', () => {
  const limiter = makeLimiter({
    limit: 2,
    windowMs: 60_000,
    key: () => 'global',
    maxKeys: 1,
    now: () => 0,
  });

  assert.equal(hit(limiter, { ip: 'a' }).passed, true);
  assert.equal(hit(limiter, { ip: 'b' }).passed, true);
  assert.equal(hit(limiter, { ip: 'c' }).passed, false, 'a third distinct caller is still refused');
});

test('an unresolvable key is one named bucket, not a bypass', () => {
  const limiter = makeLimiter({ limit: 1, windowMs: 60_000, now: () => 0 });

  assert.equal(hit(limiter, {}).passed, true);
  assert.equal(hit(limiter, {}).passed, false, 'undefined ip must not skip the check');
  assert.equal(hit(limiter, { ip: null }).passed, false, 'null shares the same bucket');
});

test('the key table is bounded, and eviction takes the oldest window', () => {
  const limiter = makeLimiter({ limit: 1, windowMs: 60_000, maxKeys: 2, now: () => 0 });

  assert.equal(hit(limiter, { ip: 'a' }).passed, true);
  assert.equal(hit(limiter, { ip: 'b' }).passed, true);
  // 'a' is still tracked at capacity.
  assert.equal(hit(limiter, { ip: 'a' }).passed, false);

  // A third key evicts the least recently started window, which is 'b' — 'a'
  // re-inserted itself on its last request.
  assert.equal(hit(limiter, { ip: 'c' }).passed, true);
  assert.equal(hit(limiter, { ip: 'a' }).passed, false, 'a survived eviction and is still limited');
  assert.equal(hit(limiter, { ip: 'b' }).passed, true, 'b was evicted and starts fresh');
});

test('eviction discards the least recently SEEN caller, not the least recently busy', () => {
  let clock = 0;
  const limiter = makeLimiter({ limit: 1, windowMs: 60_000, maxKeys: 2, now: () => clock });

  hit(limiter, { ip: 'a' });
  hit(limiter, { ip: 'b' });

  // a's window expires and a returns. Map.set on an existing key does NOT move
  // it, so unless the delete is unconditional, a keeps its original front-of-map
  // position and is evicted ahead of b — the table would preferentially discard
  // whichever caller had been quiet and preserve whichever kept its window warm,
  // which is exactly backwards for a limiter.
  clock = 60_000;
  hit(limiter, { ip: 'a' });

  hit(limiter, { ip: 'c' });

  assert.equal(hit(limiter, { ip: 'a' }).passed, false, 'a was seen most recently and must survive');
  assert.equal(hit(limiter, { ip: 'b' }).passed, true, 'b was the least recently seen and is the correct victim');
});

test('a caller churning the table cannot grow memory without bound', () => {
  const limiter = makeLimiter({ limit: 1, windowMs: 60_000, maxKeys: 8, now: () => 0 });
  for (let i = 0; i < 5000; i += 1) hit(limiter, { ip: `10.0.0.${i}` });

  // Nothing in the middleware's contract exposes the table, so this asserts the
  // observable consequence instead: an early key was evicted, which is only
  // possible if the table stayed bounded.
  assert.equal(hit(limiter, { ip: '10.0.0.0' }).passed, true);
});

test('a nonsense limit is refused at construction, not at 3am', () => {
  assert.throws(() => makeRateLimiter({ limit: 0, windowMs: 1000 }), TypeError);
  assert.throws(() => makeRateLimiter({ limit: 1.5, windowMs: 1000 }), TypeError);
  assert.throws(() => makeRateLimiter({ limit: 1, windowMs: 0 }), TypeError);
  assert.throws(() => makeRateLimiter({}), TypeError);
  // maxKeys is the argument whose bad value is SILENT: 0 evicts every entry as
  // it is written, so nothing is ever limited and the service looks healthy.
  assert.throws(() => makeRateLimiter({ limit: 1, windowMs: 1000, maxKeys: 0 }), TypeError);
  assert.throws(() => makeRateLimiter({ limit: 1, windowMs: 1000, maxKeys: 1.5 }), TypeError);
});

test('resolveTrustProxyHops parses a stated topology', () => {
  assert.equal(resolveTrustProxyHops({ TRUST_PROXY_HOPS: '0' }), 0);
  assert.equal(resolveTrustProxyHops({ TRUST_PROXY_HOPS: '1' }), 1);
  assert.equal(
    resolveTrustProxyHops({ TRUST_PROXY_HOPS: '1', NODE_ENV: 'production' }),
    1,
  );
});

test('resolveTrustProxyHops defaults to no proxy only off production', () => {
  assert.equal(resolveTrustProxyHops({}), 0);
  assert.equal(resolveTrustProxyHops({ NODE_ENV: 'development' }), 0);
});

test('resolveTrustProxyHops refuses to guess in production', () => {
  assert.throws(
    () => resolveTrustProxyHops({ NODE_ENV: 'production' }),
    InvalidTrustProxyHops,
  );
  // Present-but-empty is the failure a bare presence check cannot see — the same
  // class requireAllowedOrigins exists to catch.
  assert.throws(
    () => resolveTrustProxyHops({ NODE_ENV: 'production', TRUST_PROXY_HOPS: '' }),
    InvalidTrustProxyHops,
  );
});

test('resolveTrustProxyHops refuses more hops than the topology has', () => {
  // The boot gate stopped the too-LOW failure. A typo'd 2 or 11 is the too-HIGH
  // one, and it walks into exactly the mode the gate exists to prevent: every
  // hop past a real proxy is one an arbitrary caller can write, so req.ip
  // becomes attacker-chosen and the per-IP limit silently stops existing.
  for (const raw of ['2', '11', '999']) {
    assert.throws(
      () => resolveTrustProxyHops({ TRUST_PROXY_HOPS: raw }),
      InvalidTrustProxyHops,
      `"${raw}" is more proxies than exist and should be refused`,
    );
  }
});

test('resolveTrustProxyHops rejects values Number() would silently accept', () => {
  for (const raw of ['1.5', ' 1 ', '0x1', '-1', 'one', 'true']) {
    assert.throws(
      () => resolveTrustProxyHops({ TRUST_PROXY_HOPS: raw }),
      InvalidTrustProxyHops,
      `"${raw}" should be refused`,
    );
  }
});
