import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';

import { createApp } from '../src/server.js';
import { resolveRefuseAnonymous } from '../src/mint.js';
import { appOptionsFromEnv } from '../src/config.js';
import { SIGNED_IN_PROVIDERS, isSignedInProvider } from '../src/providers.js';
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
  // What mapProvider actually returns for a MISSING or unrecognised
  // sign_in_provider (src/firebase.js `default` arm). This is a real production
  // path, not a synthetic one.
  if (idToken === 'unknown') return { uid: 'user-9', provider: 'firebase' };
  throw new Error('bad token');
}
// A refused request must never reach the minter at all: mintLiveKitToken embeds
// RoomAgentDispatch (src/livekit.js:22-24), so minting for a principal we then
// refuse would dispatch three agents into the room on every 403. Asserting only
// the status code would let a reorder (mint, then refuse) stay green while doing
// exactly that. Raised by Tesla on PR #6.
//
// Each recorder is its OWN array, handed to its OWN server. An earlier version
// used one module-level `mintCalls` shared by four servers and every test, reset
// with `mintCalls.length = 0` — a single mutable slot used as a global "current"
// witness. Node's runner is free to interleave, so another test's reset could land
// between this test's request and its assertion, and the side-effect proof would
// certify the very regression it exists to catch (Tesla, round 5). The witness is
// now bound to the server it witnesses, not to a shared bowl.
function makeRecorder() {
  const calls = [];
  return {
    calls,
    mint: async ({ identity, roomName }) => {
      calls.push({ identity, roomName });
      return `lk-token:${identity}:${roomName}`;
    },
  };
}
const sharedRecorder = makeRecorder();
const fakeMint = sharedRecorder.mint;

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

// A server with its own minter recorder, torn down by the caller. Used by every
// test that asserts the minter was NOT invoked, so no other test can touch the
// witness (see makeRecorder above).
async function isolated(opts, fn) {
  const rec = makeRecorder();
  const app = createApp({
    verifyProviderIdToken: fakeVerify,
    privateKeyPem: keys.privateKeyPem,
    publicKeyPem: keys.publicKeyPem,
    mintLiveKitToken: rec.mint,
    allowedOrigins: [],
    ...opts,
  });
  const { server, base } = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve({ server: s, base: `http://localhost:${s.address().port}` }));
  });
  try {
    return await fn(base, rec.calls);
  } finally {
    await new Promise((r) => server.close(r));
  }
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
let omitted;    // the key absent entirely — the real production default path
let fromEnv;    // built the way index.js builds it: env string -> options -> app

before(async () => {
  enforcing = await makeServer({ refuseAnonymous: true });
  permissive = await makeServer({ refuseAnonymous: false });
  omitted = await makeServer({});
  fromEnv = await makeServer(appOptionsFromEnv({
    REALM_REFUSE_ANONYMOUS: 'true',
    CORS_ALLOWED_ORIGINS: 'https://example.test',
  }));
});
after(() => Promise.all([enforcing, permissive, omitted, fromEnv].map(
  (s) => new Promise((r) => s.server.close(r)),
)));

// ---------------------------------------------------------------------------
// The capability this exists to remove.
// ---------------------------------------------------------------------------

test('enforcing: an anonymous principal is refused at the mint → 403, and NO token is minted', async () => {
  const { res, calls } = await isolated({ refuseAnonymous: true }, async (base, calls) => {
    const token = await credentialFor(base, 'anon');
    const res = await post(base, '/livekit-token', {
      body: { roomName: 'any_room' },
      headers: { authorization: `Bearer ${token}` },
    });
    return { res, calls };
  });
  assert.equal(res.status, 403);
  // The side effect, not just the status. A reorder that minted first and refused
  // after would still return 403 while dispatching agents for every rejected guest.
  assert.deepEqual(calls, [], 'the LiveKit minter must not run for a refused principal');
  // 403 not 401: the credential is VALID and was verified. This is an
  // authorization refusal, and conflating it with 401 would tell a caller to
  // go re-authenticate, which would not help.
  const body = await res.json();
  // The message states the RULE, not this instance of it — the same refusal is
  // returned for a signed-in user on an unlisted method, and telling them they
  // are "anonymous" would be false.
  assert.match(body.error, /recognised signed-in providers/i);
  assert.doesNotMatch(body.error, /anonymous/i);
});

test("enforcing: an UNKNOWN provider ('firebase') is refused → 403", async () => {
  // The round-2 fail-open, found independently by Carnot and Tesla. mapProvider
  // returns 'firebase' for any missing or unrecognised sign_in_provider — a
  // non-empty string that is not the anonymous sentinel. Under the previous
  // "not the sentinel" rule it was ADMITTED, so a token with no sign_in_provider
  // walked through a switch whose whole job was to require proof.
  //
  // Delete SIGNED_IN_PROVIDERS and fall back to a not-the-sentinel check, and this
  // test goes red. That is the point of it.
  await isolated({ refuseAnonymous: true }, async (base, calls) => {
    const token = await credentialFor(base, 'unknown');
    const res = await post(base, '/livekit-token', {
      body: { roomName: 'any_room' },
      headers: { authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 403);
    assert.deepEqual(calls, []);
  });
});

test('enforcing: ANY provider outside the set is refused, not just the known villains → 403', async () => {
  // The law, not the last autopsy. Tesla, PR #6 round 3: every enforcement test so
  // far named a specific refusee (anonymous, firebase, and eight non-string
  // shapes), so a guard rewritten as
  //     provider === 'anonymous' || provider === 'firebase' || typeof provider !== 'string'
  // keeps all of them green while 'phone', 'custom' and 'Google' mint a token and
  // dispatch agents. Nine specimens is still a denylist if none of them is an
  // ORDINARY STRING THAT SIMPLY ISN'T IN THE SET.
  //
  // 'Google' and 'password' are the cruel ones: the first is a case variant of a
  // real member, the second is Firebase's OWN wire string for email/password
  // (which maps to 'email_password'), so both look admissible to a careless reader.
  const jwt = (await import('jsonwebtoken')).default;
  for (const prov of ['phone', 'custom', 'Google', 'GOOGLE', 'password', 'oidc.okta', 'firebase ']) {
    const token = jwt.sign({ prov }, keys.privateKeyPem, {
      algorithm: 'ES256', issuer: 'realm', audience: 'realm:livekit-mint',
      subject: 'user-x', expiresIn: 3600,
    });
    // eslint-disable-next-line no-await-in-loop
    await isolated({ refuseAnonymous: true }, async (base, calls) => {
      const res = await post(base, '/livekit-token', {
        body: { roomName: 'any_room' },
        headers: { authorization: `Bearer ${token}` },
      });
      assert.equal(res.status, 403, `prov=${JSON.stringify(prov)} is not in the set and must be refused`);
      assert.deepEqual(calls, [], `prov=${JSON.stringify(prov)} must not reach the minter`);
    });
  }
});

test('enforcing: EVERY member of the allowlist is admitted at the wire → 200', async () => {
  // The admit path was HTTP-proven only for 'google'; apple, github and
  // email_password were blessed solely by the mapper→set seam, which does not
  // prove the mint reads the set. Inline `claims.provider === 'google'` and the
  // suite would still have smiled (Tesla, PR #6 round 3).
  const jwt = (await import('jsonwebtoken')).default;
  for (const prov of SIGNED_IN_PROVIDERS) {
    const token = jwt.sign({ prov }, keys.privateKeyPem, {
      algorithm: 'ES256', issuer: 'realm', audience: 'realm:livekit-mint',
      subject: `user-${prov}`, expiresIn: 3600,
    });
    const res = await post(enforcing.base, '/livekit-token', {
      body: { roomName: 'any_room' },
      headers: { authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200, `${prov} is a real sign-in and must be admitted`);
  }
});

test('the allowlist cannot be grown at runtime', async () => {
  // Tesla, PR #6 round 4, on the FIRST version of this test: asserting only that
  // `.push` throws does not prove the failure it names. On the old buggy
  // `Object.freeze(new Set([...]))`, `.push` ALSO throws TypeError — because push
  // is not a function on a Set — so that assertion passed identically before and
  // after the fix. A check that cannot distinguish the bug from the fix is not a
  // check.
  //
  // What actually distinguishes them is the mutator that WORKED on the Set:
  assert.equal(typeof SIGNED_IN_PROVIDERS.add, 'undefined',
    'the export must not be a Set — Object.freeze does not protect [[SetData]], so .add would still grow admission process-wide');
  assert.ok(Array.isArray(SIGNED_IN_PROVIDERS));
  assert.ok(Object.isFrozen(SIGNED_IN_PROVIDERS));
  assert.throws(() => { SIGNED_IN_PROVIDERS.push('firebase'); }, TypeError);

  // And the property that matters regardless of how the export is spelled: no
  // reachable handle grows the set the predicate actually consults.
  try { SIGNED_IN_PROVIDERS.push('firebase'); } catch { /* expected */ }
  assert.ok(!isSignedInProvider('firebase'), "the don't-know fallback must stay out");
});

test('permissive: an unknown provider is unaffected when the switch is off → 200', async () => {
  // The allowlist must not leak into the default path — it is only proof-of-signin
  // under enforcement, never a general admission rule.
  const token = await credentialFor(permissive.base, 'unknown');
  const res = await post(permissive.base, '/livekit-token', {
    body: { roomName: 'any_room' },
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(res.status, 200);
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
    // eslint-disable-next-line no-await-in-loop
    await isolated({ refuseAnonymous: true }, async (base, calls) => {
      const res = await post(base, '/livekit-token', {
        body: { roomName: 'any_room' },
        headers: { authorization: `Bearer ${token}` },
      });
      assert.equal(res.status, 403, `prov=${JSON.stringify(prov)} must be refused`);
      assert.deepEqual(calls, [], `prov=${JSON.stringify(prov)} must not reach the minter`);
    });
  }
});

test('enforcing: every UNAUTHENTICATED shape is still 401, not 403', async () => {
  // Ordering matters: authentication is decided before authorization, so an
  // unauthenticated caller must not learn on THIS request that the policy exists.
  //
  // Three shapes, not one. The first version pinned only a garbage bearer, which
  // is one of the three ways to arrive unauthenticated — "you measured only one of
  // the three unauthenticated shapes" (Tesla, PR #6 round 4).
  // Tesla, PR #6 round 5: the first three shapes are all UNPARSEABLE, so they die
  // in the bearer regex or in decoding. None of them is a structurally valid
  // credential that merely fails verification — and that is the one that matters.
  // A decode-then-authorize refactor (jwt.decode for a fast 403, verify after)
  // would keep every unparseable case green while selling the policy to anyone who
  // can sign with a throwaway P-256 key. The forged and expired cases below are
  // what make the 401-before-403 ordering a test instead of a sentence.
  const jwt = (await import('jsonwebtoken')).default;
  const attacker = es256Keys();
  const forged = (prov) => jwt.sign({ prov }, attacker.privateKeyPem, {
    algorithm: 'ES256', issuer: 'realm', audience: 'realm:livekit-mint',
    subject: 'mallory', expiresIn: 3600,
  });
  const expired = jwt.sign({ prov: 'anonymous' }, keys.privateKeyPem, {
    algorithm: 'ES256', issuer: 'realm', audience: 'realm:livekit-mint',
    subject: 'user-x', expiresIn: -60,
  });

  const shapes = [
    ['a garbage bearer', { authorization: 'Bearer not-a-token' }],
    ['an empty bearer', { authorization: 'Bearer ' }],
    ['no Authorization header at all', {}],
    // Well-formed ES256, wrong signing key. Both provider arms, because a
    // decode-first bug would 403 the anonymous one and 200 the google one.
    ['a FORGED credential claiming anonymous', { authorization: `Bearer ${forged('anonymous')}` }],
    ['a FORGED credential claiming google', { authorization: `Bearer ${forged('google')}` }],
    // Correctly signed but expired: authentication fails, so the policy must not
    // be consulted and the caller must be told to re-authenticate, not refused.
    ['a correctly-signed EXPIRED credential', { authorization: `Bearer ${expired}` }],
  ];
  for (const [name, headers] of shapes) {
    const res = await post(enforcing.base, '/livekit-token', {
      body: { roomName: 'any_room' },
      headers,
    });
    assert.equal(res.status, 401, `${name} must be 401, never 403`);
  }
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

test('a NON-BOOLEAN refuseAnonymous is refused at construction, not coerced', async () => {
  // Both string directions are traps and neither should be guessed: "false" is
  // truthy (would enforce in the dark), and "true" would be silently ignored under
  // a `=== true` gate (would NOT enforce while the operator believed it did).
  // Tesla named both 3am postmortems on PR #6. A caller handing this a string has a
  // wiring bug, and a wiring bug in a security switch must be loud.
  // Asserted against createApp, NOT makeServer: createApp constructs the handler
  // (where the throw lives) without opening a socket. An earlier version called
  // makeServer here, so when the guard was mutated away the loop leaked a listening
  // server per iteration and the whole runner HUNG instead of failing — a test that
  // cannot go red cleanly is a test that cannot red-prove its own fix.
  for (const bad of ['true', 'false', 1, 0, null]) {
    assert.throws(
      () => createApp({
        verifyProviderIdToken: fakeVerify,
        privateKeyPem: keys.privateKeyPem,
        publicKeyPem: keys.publicKeyPem,
        mintLiveKitToken: fakeMint,
        allowedOrigins: [],
        refuseAnonymous: bad,
      }),
      /refuseAnonymous must be a boolean/,
      `${JSON.stringify(bad)} must be refused, not coerced`,
    );
  }
});

test('the env string reaches the handler: REALM_REFUSE_ANONYMOUS=true → 403 over HTTP', async () => {
  // Closes the last unbound link Tesla named: every enforcement test injected a
  // boolean directly, so an index.js that CALLED resolveRefuseAnonymous (keeping
  // the boot-refusal green) and then discarded the result would leave the unit
  // suite and verify.sh both green with production permissive.
  //
  // This builds the app exactly as index.js does — raw env string through
  // appOptionsFromEnv into createApp — and asserts the behaviour at the wire.
  await isolated(
    appOptionsFromEnv({
      REALM_REFUSE_ANONYMOUS: 'true',
      CORS_ALLOWED_ORIGINS: 'https://example.test',
    }),
    async (base, calls) => {
      const token = await credentialFor(base, 'anon');
      const res = await post(base, '/livekit-token', {
        body: { roomName: 'any_room' },
        headers: { authorization: `Bearer ${token}` },
      });
      assert.equal(res.status, 403);
      assert.deepEqual(calls, []);
    },
  );
});

test('the env string reaches the handler: a signed-in principal still mints → 200', async () => {
  const token = await credentialFor(fromEnv.base, 'google');
  const res = await post(fromEnv.base, '/livekit-token', {
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
