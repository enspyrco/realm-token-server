# FOLD — the author's adversarial self-pass (pre-temper)

Purpose: raise the floor of what reaches Temper, so the cross-family strike lands on what only a
different inductive bias can see, not on slag I could skim myself. Fold works the metal; it does not
re-grade the ore. Everything below is folded back into `DESIGN.md`.

---

## F1 — **Structural**: the comparison shouldn't exist at all

v2 had `/livekit-token` compare `cred.room === req.body.roomName` and 403 on mismatch. That is a
guard around a window that should not be open.

**Fold:** `/livekit-token` takes the room from the **credential**, not the body, and mints the
LiveKit grant with `room: claims.room`. The body's `roomName` becomes vestigial. There is then no
check to pass, no comparison to get wrong, and no drift between what was authorized and what was
minted — a caller *cannot express* "authorized for A, mint for B", because the request has only one
room in it and it is the signed one.

This is `concept_remove_coupling_not_guard_window` applied to my own design: the mismatch class is
deleted rather than defended.

**Cost to the red-prove.** The brief's acceptance test was "delete the enforcement call, confirm the
test goes red" — but now there is no call to delete. The red-prove is still available and is
arguably sharper: **mutate `src/mint.js` to read `req.body.roomName` instead of `claims.room`, and
the test must go red.** That mutation is exactly the historical bug, so the test proves it stays
dead. Recorded in DESIGN.md §6.

## F2 — **Security**: `roomName` is unvalidated and becomes a Firestore document path

`src/mint.js:27` accepts any non-empty string. Under this design that string becomes a document id
in `rooms/{roomId}/members/{uid}`. A `roomName` of `foo/bar/baz` **changes the path shape** — a
document reference built by string concatenation would address a different collection than intended.

**Fold:** validate `roomName` against a positive charset (`^[A-Za-z0-9_-]{1,64}$` proposed) at the
room-scoped `/exchange` *before* it is used to build any path, and reject otherwise. Positive rule,
consistent with the rest of the design. Note this is a **pre-existing** defect in today's code, not
one this design introduces — it is simply the first design that makes it exploitable in a new way.

## F3 — **Degenerate state**: the room document does not exist

The design never said what happens when `/exchange` is asked to admit someone to a `roomName` with
no room document. The tempting answer — "no config, so nothing to check, admit" — **is the denylist
failure in disguise**, and it is precisely the local precedent the brief warned about.

**Fold:** a missing room document is **refusal**, stated explicitly. Empty means closed, everywhere,
including "empty" meaning "absent."

**Consequence to check in tech_world, not assume:** if any live flow relies on joining a room into
existence (create-by-join), this closes it. `room_service.dart` has an explicit `createRoom`, which
suggests it does not — but this must be verified locally in the handoff, not inferred from a grep I
ran from the outside.

## F4 — **Attack**: `joinCode` is brute-forceable

Guest admission is a capability check against `rooms/{id}/invites/{codeHash}`. Nothing in the design
bounds guessing. The existing rate limiter is per-IP with a service-wide ceiling
(`src/rateLimit.js`), which throttles a single source but does not bound a distributed grind, and it
was designed for a different threat (`claude-tasks#3161`, public mint abuse).

**Fold:** codes must be high-entropy (≥128 bits, generated server-side, never user-chosen), stored
**hashed** so a Firestore read leak is not a key leak, expiring, and use-countable. Per-room attempt
throttling is named as a requirement rather than assumed to fall out of the existing limiter. Entropy
is doing the real work here; the throttle is depth.

## F5 — **Deploy ordering**: steps 2 and 3 are not independently deployable

The build order said each step is independently useful. That is true of *usefulness* and false of
*deployment*. The moment step 3 lands, any client still presenting an **identity** credential (no
`room` claim) is refused — which is every client until step 2's flow is rolled out and adopted.

**Fold:** the build order gains an explicit ordering constraint — ship 2, roll clients forward,
*then* ship 3 — and step 3 must decide, as a named choice, what an identity-scoped credential means
at the mint. Proposed: **refuse** (fail closed, per `feedback_fail_closed_on_unknown_send_flags`),
which makes the client rollout a hard prerequisite rather than a soft one.

## F6 — **Free lever already in hand**: `prov`

The credential already carries `prov` (`src/realmCredential.js:35,86`), which is `anonymous` for
guests. So "closed rooms never admit anonymous principals" is expressible **today**, with no new
data model, no roster, and no lookup.

That is not a substitute for the design — it is coarse, and it cannot express "this specific guest
may enter this specific room." But it is a real lever, and the mechanism should pass `prov` to the
predicate so a world can use it. **Not** hardcoded: that would be the engine choosing a social
policy, which Nick's framing forbids.

## F7 — **Atomicity**: `createRoom` now writes two documents

If the owner must hold a member tuple (open variable 5), `createRoom` writes the room doc *and*
`members/{ownerId}`. A partial failure leaves a closed room whose owner cannot enter and — because
the member-write rule will be gated on room ownership — may not be able to repair.

**Fold:** `createRoom` must write both in a single batch/transaction. Named in the handoff.

---

## Dissolving my own problem: I attacked alternative 5 and it partly held

Alternative 5 is "keep one enum, just add `private` support" — the simplest rejected shape. I argued
it fails because *listed + closed* is unrepresentable and the education tier needs it.

**Honest re-attack:** that need is thinner than I wrote it. A classroom could perfectly well be
`unlisted` and shared by link; "students must be able to *find* it in a directory" is my inference
from `DESIGN.md:170` ("Education tier: private rooms, classroom features"), not a stated requirement.
I have not verified it with Nick or with a user.

The split survives on a second, weaker argument: it keeps the listing query (`where isPublic == true`)
and the admission predicate independent, so neither changes when the other does.

**So C3 is downgraded**: it is the design's most speculative structural claim, and I have flagged it
to the temper as the place to strike hardest. If C3 falls, alternative 5 wins and the design gets
meaningfully smaller — which would be a good outcome, not a failure.

## What I could not fold out

C4 (revocation staleness) remains genuinely unresolved. A removed user keeps a valid room-scoped
credential for up to one TTL, and a live LiveKit session outlives the token that opened it entirely,
so mid-session eviction is out of scope no matter what TTL is chosen. I can bound the *minting*
window; I cannot bound the *session*. Stating it plainly rather than picking a number that hides it.
