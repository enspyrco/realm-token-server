# DESIGN — room admission for Realm (v3, post-temper)

**Status:** recast after a full 4-way strike (`TEMPER.md`, round 1). **This v3 is itself un-struck**
— a substantial post-temper recast is not covered by the strike that produced it. Round 2 required
before build. And a design temper is never a substitute for a `/cage-match` on the eventual diff.

**What changed from v2, and why.** v2's spine was *"`RoomVisibility` is two axes wearing one enum,
so split it."* **All four families killed that independently.** Tesla's blow landed hardest:
`isPublic` **already is** the listing axis, so the independence argument needed a second *field*,
not a breaking public-type split in a repo heading open-source. The 2×2 was a true *diagnosis*
promoted to a *mandate* without argument — a laundered assumption, visible only by reading
`CRUCIBLE.md`'s excitement next to v2's §2.

v3 ships the smaller thing. What survived is the *enforcement location* and the *asymmetry*, not
the taxonomy.

---

## 1. The problem

`src/mint.js:26-32` reads `req.body.roomName`, checks only that it is a non-empty string, and mints
a LiveKit token granting `roomJoin` + `canPublish` for it (`src/livekit.js:15-21`). Any signed-in
user — including an anonymous guest with a throwaway uid — enters any room by typing its name, and
because LiveKit's `room.auto_create` defaults to `true`, can also conjure unbounded new rooms.

Nothing in the system answers *who may be present*. `canEdit` (`room_data.dart:56`) is the nearest
neighbour and is the wrong lattice — a classroom's students must enter and must not edit.

> **Remark (not the spine).** `unlisted` reads as incoherent for *entry* — "the door is unlocked and
> the sign is painted over" — because listing and admission are genuinely different questions, and
> the enum only ever modelled listing. That explains why
> `firestore_room_config_store.dart:21-30` had to **throw** on `private` rather than lie. It is a
> useful diagnosis. **It does not entail splitting the type**, and v2 made exactly that unargued
> leap. `isPublic` already carries listing; admission needs one new field beside it.

## 2. Where admission is enforced

**At token-mint time, and only there** — forced, not chosen. LiveKit has no pre-join admission hook;
webhooks (`participant_joined`) fire *after* the media connection is established. Whatever the mint
grants is granted. Carnot independently searched and found no such hook; Tesla pinned the correct
scope for the claim: *"webhooks + RoomService + Cloud project settings"*, not "we read the webhook
enum." If a Cloud pre-connect authorization callback exists, this location is wrong and v3 recasts.

### Separate the decision from the enforcement

This repo already holds the right shape one level down: `/exchange` holds the ES256 **private** key
and signs; `/livekit-token` holds only the **public** key and verifies, so a bug in the mint cannot
forge a credential (`src/realmCredential.js:8-11`). Apply the same asymmetry to admission.

```
POST /exchange { idToken }                      -> identity credential (today; unchanged)
POST /exchange { idToken, roomName, joinCode? } -> ROOM-SCOPED credential { sub, prov, room, jti, exp }
POST /livekit-token  + room-scoped credential
     -> mints the LiveKit grant with room = claims.room   (the body carries no room at all)
```

**The mint takes the room from the credential, not the body.** Unanimously the strongest surviving
element — Carnot: *"the bug cannot happen because the variable is gone."* This is not a comparison
to get right; a caller **cannot express** "authorized for A, mint for B." A body `roomName` is
**rejected**, not ignored, so a stale client fails loudly.

Two guards that must land with it:

- **`roomName` is validated against a positive charset (`^[A-Za-z0-9_-]{1,64}$`) before it is used
  to build any Firestore path.** Today any non-empty string is accepted; under this design it
  becomes a document id, and `foo/bar/baz` changes the path shape. Pre-existing defect, newly
  reachable.
- **A missing room document is a refusal.** "No config, so nothing to check, admit" is the denylist
  failure wearing a different hat. Empty means closed, including when empty means absent.

## 3. Capability amplification — the flaw that nearly shipped

**This is the most important section in the document, and v2 did not contain it.**

v2 specified a hashed, expiring, **use-counted** `joinCode`, and then had `/exchange` convert it
into a bearer JWT carrying *none* of those properties. `maxUses` died at the first signature: a
one-use exam code minted an unlimited-use publisher pass valid until `exp`. The Fold that hunted
precisely this class (F4) ran and missed it. Tesla found it.

The rule: **a derived credential may never outlive or out-scope the capability that produced it.**

**v3 got the rule right and the mechanism wrong, and round 2 killed the mechanism.** v3 had the
credential carry a `jti` that `/livekit-token` *records*, making code-derived tickets single-use.
All three families struck it: "records it" is not a claim, it is a replica set — an atomic
check-and-set, shared across every token-server process, with TTL eviction — and it makes a
legitimate retry on a flaky network **indistinguishable from a replay**, so a lost response locks
the user out.

Carnot then supplied the dissolution: **single-use tickets buy nothing anyway.** The `joinCode`
itself remains a reusable bearer capability until it expires or is revoked, so a leaked code simply
mints fresh single-use tickets forever. The state store guarded a window that was never closed.

**So v4 deletes the `jti` mechanism rather than implementing it.** The mint stays stateless — the
property that made it safe in the first place. What actually bounds the capability:

- **Expiry and revocation on the code**, which is where the reusability genuinely lives.
- **A 120-second room-scoped credential TTL**, covering pick-a-room → connect and nothing more.
  Re-entry mints a new credential, which **re-runs the admission check** — refresh *is*
  re-authorization.
- **Eviction (§4) for presence**, because — Carnot's correction, and it matters — a LiveKit access
  token's `exp` gates **connection, not continued presence**. v3's `min(livekitTtl, credential exp)`
  binding would therefore not have bounded a live session even if it had worked; it would only have
  broken reconnect. The LiveKit grant TTL stays independent.

**Residual, stated plainly rather than engineered around:** a leaked `joinCode` admits its holder
repeatedly until it expires or an owner revokes it. That is the security model of every
"anyone with the link" share. Worlds needing one-shot admission must issue short-expiry
single-recipient codes; the engine does not pretend to enforce single use.

## 4. Revocation is a separate primitive from admission

v2 said mid-session eviction was "out of scope." Three families called that a fatal gap, and for the
design's own motivating example they are right — Kelvin: *"an evicted participant is not evicted…
mission failure."* v2 rejected `removeParticipant` as an *admission* mechanism (correct: it admits
first, then evicts, so the intruder sees and hears) and then wrongly kept rejecting it as
*revocation*, which is the only vendor lever that exists after connect.

**Admission and eviction are two primitives, not one.**

| | Mechanism | Bounds |
|---|---|---|
| **Admission** | the mint, gated on `canJoin` | who may enter |
| **Eviction** | `RoomService.removeParticipant` | who may remain |

Removing a member SHOULD trigger eviction of that principal's live session. Whether that is
automatic or an owner/moderator action is a **policy** question for consumers; the engine must
expose the lever either way. With 120s credentials, the *minting* window is bounded to two minutes
even if eviction is never wired — but **presence is not**, and §3 no longer pretends otherwise.

**What eviction actually costs (round 2 corrected this in both directions).** Two families claimed
`removeParticipant` needs "a privileged LiveKit credential the design claims not to have." That is
**wrong, and the evidence refutes it**: `src/index.js:23-24` already loads `LIVEKIT_API_KEY` and
`LIVEKIT_API_SECRET`, and `src/livekit.js:9` already signs with them — the server can mint a
`roomAdmin` token today at **zero new secret**. Tesla got this right where the other two did not.

What *is* genuinely undrawn is the **watcher**: something must observe a member tuple being deleted
and call `RoomService`. That is a Firestore-side privileged observer (a Cloud Function, or a
polling worker) — the service-account-shaped component §7 spent its life avoiding, now required on
a different edge. Two further gaps this design does not close:

- **`sub` ≠ LiveKit participant identity** unless the mint pins them equal. It does today
  (`src/mint.js:31` passes `identity: claims.subject`), so eviction can address a principal — but
  that equality is now load-bearing and must be asserted by a test, not left as a coincidence.
- Owner-initiated eviction needs an endpoint with its own authorization, which is a design of its
  own. **Step 8 is scoped as its own design pass, not a line item.**

## 5. The admission primitive (engine-owned, `tech_world`)

One new field beside the existing `isPublic`, and two subcollections. No enum rename, no breaking
public-type change.

```
rooms/{roomId}
  isPublic: bool                    // UNCHANGED — listing. Already shipped, already queried.
  admission: "open" | "closed"      // NEW — entry. Absent is a migration bug, not a default.

rooms/{roomId}/members/{uid}        // identity-based admission
  role: <world-defined string>      // engine does not interpret; worlds do
  addedBy, addedAt

rooms/{roomId}/invites/{codeHash}   // capability-based admission (guests)
  expiresAt, revoked, createdBy     // NOTE: no `uses` counter — see §6
```

Security rules — the load-bearing part:

```
match /rooms/{roomId}/members/{uid} {
  allow read: if request.auth.uid == uid;   // your OWN admission, and only that
}
```

A user may ask "am I admitted?" and cannot enumerate the roster. The fact exposed is **admission**,
not **readability** — the read≠join conflation is closed by construction, not by discipline.

### The predicate

```
canJoin(principal, room, presentedCapability?) :=
     room.admission == "open"
  OR exists(rooms/{room}/members/{principal.uid})
  OR validCapability(presentedCapability, room)
```

**Positive by construction; closed when empty.** Every arm names someone explicitly permitted; no
arm admits by failing to match. A closed room with no members and no invites admits nobody — so
`createRoom` must write the owner's member tuple, **in the same transaction as the room document**
(a partial failure otherwise strands an owner outside their own room, unable to repair).

`prov` is passed to the predicate so a world **may** refuse `anonymous` on closed rooms. The engine
does not hardcode that — it would be the engine choosing a social policy.

### The third lattice: `canPublish`

`src/livekit.js:15-21` grants `canPublish`/`canPublishData` to everyone admitted. But §1's own
motivating student must enter, must not edit — **and must not blast audio.** Admission was modelled
as boolean while the live grant is already a capability set.

**v3's answer was wrong twice and round 2 caught both.** It said "subscribe-only unless the member
tuple's `role` says otherwise", which (a) contradicted the claim that the engine does not interpret
`role` — Carnot: *"a magic string role is coupling by folklore"* — and (b) **muted two of the three
`canJoin` arms**, because guests and open-room joiners have no member tuple at all. Tesla: *"the
visiting speaker with the link, the open lobby: all listen-only."*

**v4 makes it an explicit engine-owned field, not a dialect hidden in a string:**

```
rooms/{roomId}.defaultCanPublish: bool     // applies to open-room joiners and guests
rooms/{roomId}/members/{uid}.canPublish: bool?   // per-member override; null inherits the default
```

`role` returns to being **fully opaque** — worlds interpret it, the engine never reads it. The
migration sets `defaultCanPublish: true` on every existing room, preserving today's behaviour
exactly; a classroom sets it `false` and grants publish per member.

## 6. What a guest is

Anonymous Firebase users get a **fresh uid on every sign-in** (`claude-tasks#3160`), so a uid-keyed
roster is broken *by construction* for guests — a base case, not an edge case.

> **Members are admitted by identity. Guests are admitted by capability.**

A guest presents an unguessable `joinCode`; `/exchange` hashes it and looks up
`rooms/{id}/invites/{codeHash}`. Identity is never consulted, so uid churn is irrelevant — the
question was never "who are you."

**Invites are GET-only.** v2 wanted use-counting, and Tesla showed it is unimplementable safely on
this path: a rule loose enough to let the caller increment `uses` is loose enough to let them set
`maxUses: 999999` or clear `expiresAt`, and a rule tight enough to prevent that cannot count at all
without a privileged writer — the exact thing this design avoided. So **entropy and expiry do the
work**: ≥128-bit server-generated codes, stored hashed, with `expiresAt` and a `revoked` flag.
Revocation is a write by the *owner*, under a rule that permits only owners.

**The invite read rule is part of the design, not an implementation detail.** v3 specified the
member rule and left this one to the implementer, which round 2 correctly called the guest path's
single point of failure — *"round 1 died on a rule that was one bit too loose; v3 deleted the counter
and forgot the read."* Omit it and every guest is dark; write it loose and the collection lists.

```
match /rooms/{roomId}/invites/{codeHash} {
  allow get: if true;    // knowing the hash IS the capability; the doc holds no secret
  allow list: if false;  // MUST be false — listing defeats the entropy entirely
  allow write: if request.auth.uid == get(/databases/$(db)/documents/rooms/$(roomId)).data.ownerId;
}
```

`allow get` without `allow list` is the whole security property: an attacker who cannot enumerate
must guess 128 bits. The invite document must therefore contain **nothing sensitive** — no
`createdBy` identity, no room contents — since possession of the hash grants the read.

Accepted, and written plainly rather than implied: **a capability is transferable — whoever holds it
is admitted.** That is the security model of every "anyone with the link" share on the web. §3's
`jti` single-use rule bounds the *derived ticket*; it does not bound the code itself.

## 7. Failure modes of the caller-ID-token lookup

`/exchange` already holds the caller's Firebase ID token. Firestore REST accepts it as
`Authorization: Bearer` and **enforces Security Rules as that user**; a service-account token
**bypasses rules entirely** via IAM. So the cheap path is also the less privileged one — but it has
three costs v2 did not price:

- **App Check is a hard incompatibility.** If this project, or any OSS consumer, enforces App Check
  on Firestore, a server-side REST GET carrying only an ID token fails **for everyone** — the first
  hardening pass takes every join dark. Documented as a stated limitation.
- **Refusal is overloaded.** Rules-deny, missing document, expired ID token, disabled API, billing
  and App Check all collapse into one refusal. The client may see one status; the server must
  **distinguish and log them separately**, or an availability cliff reads as a clean "not admitted."
- **The ID token becomes load-bearing in a second place**, and `checkRevoked=false`
  (`src/firebase.js:14`) means a revoked account still verifies until token expiry.

If any of these bite, the fallback is a service account — a named, priced retreat, not a surprise.

## 8. Build order (recast; C6 struck)

v2 claimed steps 2+3 could land before the engine data model. **All three adversaries called that a
stand-in predicate by another name**, and they are right: with no `admission` field written,
`/exchange` either defaults missing→open (policy in the token server — the very failure F3 forbids)
or missing→refuse (a global outage). There is no third path.

| # | Step | Repo | Gate |
|---|---|---|---|
| **0** | **Deployment-wide** switch: refuse `prov == "anonymous"` at the mint entirely | `realm-token-server` | ships alone, no new data, no read |
| **1** | **Measure** the LiveKit deployment: Cloud vs self-hosted, actual `auto_create` | infra | **blocking prerequisite** |
| 2 | Engine: `admission` field + `members`/`invites` + rules + `canJoin`; `createRoom` writes the owner tuple transactionally | `tech_world` | **HANDOFF** |
| 3 | **Migration** writes `admission` + `defaultCanPublish` on every live room, and owner member tuples; ships with **backfill verification + stranded-room repair tooling** | `tech_world` | data before code |
| 4 | `/exchange` room-scoped mode: verify ID token → `canJoin` → mint `{room, jti, exp:120s}` | `realm-token-server` | after 3 |
| 5 | Clients adopt the room-scoped flow | `tech_world` | rollout |
| 6 | `/livekit-token` mints from `claims.room`; **refuses** an unscoped credential. **Red-prove.** | `realm-token-server` | `/cage-match` by law |
| 7 | `auto_create: false` + explicit room creation, **if step 1 says it is settable** | infra | else deleted |
| 8 | Eviction: removal triggers `removeParticipant` | either | separate primitive (§4) |

**Step 0, corrected by round 2, and deliberately under-sold.** v3 wrote it as "refuse `anonymous` on
non-public rooms" — which Tesla showed is a poison pill: *publicness is `isPublic`, the listing axis
this whole recast exists to stop using as a door.* Deciding per-room needs a Firestore read, so
step 0 would have reconflated listing with admission **in the very first ship**, and pre-empted open
question 2 before Nick answers it.

So step 0 is a **deployment-wide switch**, off by default: this deployment either accepts anonymous
principals or it does not. No per-room read, no listing axis, no policy baked into a room.

And it is **a risk trim, not admission control** — Carnot's framing, and the honest one. It closes
the worst sentence in `claude-tasks#2850` ("including an anonymous guest") for a deployment willing
to require sign-in. Any authenticated user can still request any room. It is worth shipping because
it is free and reversible, not because it fixes the bug. Naming it that way is the point:
`feedback_prose_overclaims_the_code`.

**Step 6's red-prove.** There is no "enforcement call" to delete (§2 removed the comparison), so the
mutation test is sharper: **change `src/mint.js` to read `req.body.roomName` instead of
`claims.room`, and the test must go red.** That mutation *is* the historical bug. Per
`feedback_priority_inversion_evidence`, the test must exercise the **refusal** path, not the happy
path beside it.

## 9. Blast radius

Breaking Flutter types (avoided in v3 — additive field only), Firestore rules migration, client
exchange-flow change, request-log redaction (`joinCode` must never be logged — auditing
`src/requestLog.js` is part of step 4, not a follow-up), anonymous-guest semantics, room-creation
flow, LiveKit infra config, tests that mutate the historical bug, and support docs explaining why
old identity credentials stop working at step 6.

## 10. Open — Nick's calls, surfaced not tie-broken

1. **Default `admission` for new rooms.** Live code defaults `isPublic: true`; `packages/realm/DESIGN.md:54`
   specifies `NewRoomSpec` defaulting to **`private`**. A genuine two-source conflict.
2. **May guests ever enter closed rooms**, or is a closed room members-only by definition?
3. **Is `listed + closed` a real requirement?** If Nick says yes, v2's split returns and this
   recast was wrong. All four families bet it is not.
4. **Automatic eviction on removal, or an owner action?** (§4)

## 11. Claims to falsify (v3)

- **C1.** No LiveKit pre-join hook, so the mint is the only door. *Held under all four strikes.*
- **C2.** Firestore REST + ID token enforces rules as that user. *Verified in Firebase's docs; not
  yet exercised against this project, and now qualified by App Check (§7).*
- **C3 — WITHDRAWN.** The 2×2 split is dead. Its replacement claim: **one `admission` field beside
  `isPublic` is sufficient**, and the only thing that resurrects the split is open question 3.
- **C4 — quantified, and its scope corrected.** 120s credential TTL bounds **minting**. It does not
  bound presence: a LiveKit token's `exp` gates connection, not continued session, so **eviction
  (§4) is the only presence lever** and v3's `min()` binding was deleted as both ineffective and
  reconnect-breaking. Residual: a live session survives until evicted.
- **C5.** A transferable bearer capability is an acceptable definition of guest admission, with
  use-counting **abandoned** as unimplementable on this path, and single-use `jti` tickets
  **abandoned** as stateful-for-nothing (§3, §6).
- **C8 (new, v4).** The mint remains **stateless**. Any future proposal that gives it a store must
  first answer: what distinguishes a retry from a replay?
- **C6 — WITHDRAWN.** Steps cannot precede the data. Build order reordered accordingly.
- **C7 — promoted to a blocking prerequisite (step 1).** No longer an assumption in a build table.
