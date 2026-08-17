import { test } from 'node:test';
import assert from 'node:assert/strict';

import { appOptionsFromEnv } from '../src/config.js';
import { mapProvider } from '../src/firebase.js';
import { ANONYMOUS_PROVIDER, isSignedInProvider } from '../src/providers.js';

// Raised by CarnotCodeCarver on PR #6: the env resolvers were tested and the
// handlers were tested with options injected, but nothing tested that a resolver's
// output actually REACHED the handler. Deleting the requireKnownProvider wiring left the
// suite green while production ran permissive. These tests bind the wiring itself.

// The minimum env that boots. CORS_ALLOWED_ORIGINS is required by
// corsConfigFromEnv — a real contract these tests must satisfy rather than
// route around, since appOptionsFromEnv's job is to run every resolver.
const baseEnv = { CORS_ALLOWED_ORIGINS: 'https://example.test' };
const envWith = (extra) => ({ ...baseEnv, ...extra });

test('appOptionsFromEnv carries REALM_REQUIRE_KNOWN_PROVIDER through to the app options', () => {
  assert.equal(appOptionsFromEnv(envWith({ REALM_REQUIRE_KNOWN_PROVIDER: 'true' })).requireKnownProvider, true);
  assert.equal(appOptionsFromEnv(envWith({ REALM_REQUIRE_KNOWN_PROVIDER: 'false' })).requireKnownProvider, false);
});

test('appOptionsFromEnv defaults requireKnownProvider to false when the var is absent', () => {
  assert.equal(appOptionsFromEnv(baseEnv).requireKnownProvider, false);
});

test('appOptionsFromEnv yields a real BOOLEAN, never a string', () => {
  // makeMintHandler gates on `requireKnownProvider === true`, so a string "true" would
  // silently disable the switch. Pin the type, not just the value.
  const v = appOptionsFromEnv(envWith({ REALM_REQUIRE_KNOWN_PROVIDER: 'true' })).requireKnownProvider;
  assert.equal(typeof v, 'boolean');
});

test('appOptionsFromEnv refuses to produce options for an uninterpretable switch', () => {
  // The boot-time refusal has to survive the extraction: if config.js swallowed the
  // throw, `npm start` would come up permissive on a typo'd value.
  assert.throws(
    () => appOptionsFromEnv(envWith({ REALM_REQUIRE_KNOWN_PROVIDER: 'yes' })),
    /REALM_REQUIRE_KNOWN_PROVIDER/,
  );
});

test('appOptionsFromEnv still carries the other env-driven options', () => {
  // Guards against the extraction dropping a key that used to be inline in index.js.
  const opts = appOptionsFromEnv(envWith({ REALM_CREDENTIAL_TTL_SECONDS: '900' }));
  assert.equal(opts.ttlSeconds, 900);
  assert.equal(typeof opts.trustProxyHops, 'number');
  assert.ok('allowedOrigins' in opts, 'CORS config must still be spread in');
});

test('appOptionsFromEnv preserves every OTHER resolver\'s boot refusal too', () => {
  // The extraction must not have quietly become a place where a throw goes to die.
  assert.throws(() => appOptionsFromEnv({}), /CORS_ALLOWED_ORIGINS/);
  assert.throws(() => appOptionsFromEnv(envWith({ TRUST_PROXY_HOPS: '1.5' })), /TRUST_PROXY_HOPS/);
});

// ---------------------------------------------------------------------------
// The sentinel is shared, not spoken.
// ---------------------------------------------------------------------------

test("mapProvider pins Firebase's anonymous sign-in to ANONYMOUS_PROVIDER", () => {
  // Raised by Tesla on PR #6: 'anonymous' was a password shared by three places by
  // convention. If this mapper ever emitted "Anonymous" or "firebase.anonymous",
  // REALM_REQUIRE_KNOWN_PROVIDER would become a placebo — green here, open in production.
  // Both sides now read one constant, and this test fails if they ever diverge.
  assert.equal(mapProvider('anonymous'), ANONYMOUS_PROVIDER);
  assert.ok(!isSignedInProvider(mapProvider('anonymous')));
});

test('every KNOWN sign-in method maps to something the mint accepts as proof', () => {
  for (const p of ['google.com', 'apple.com', 'github.com', 'password']) {
    assert.ok(
      isSignedInProvider(mapProvider(p)),
      `${p} is a real sign-in and must be admissible under enforcement`,
    );
  }
});

test('an UNKNOWN sign_in_provider is NOT proof of signing in', () => {
  // The round-2 fail-open, found independently by Carnot and Tesla, and the
  // previous version of this test canonized it: it asserted only that an unknown
  // provider was "not anonymous", which is exactly the denylist reasoning that let
  // the mapper's `default: 'firebase'` fallback read as proof.
  //
  // The important problem is PROOF, not string drift. Absence of evidence about how
  // someone signed in must not become evidence that they did.
  for (const p of ['something.new', undefined, '', 'phone']) {
    assert.ok(
      !isSignedInProvider(mapProvider(p)),
      `${JSON.stringify(p)} must not be admissible — it is an unknown sign-in method`,
    );
  }
  // Specifically the fallback string itself.
  assert.equal(mapProvider(undefined), 'firebase');
  assert.ok(!isSignedInProvider('firebase'), "'firebase' means 'we don't know', not 'signed in'");
});
