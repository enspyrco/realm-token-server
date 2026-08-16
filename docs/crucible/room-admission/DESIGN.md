# DESIGN — room admission for Realm

**Status:** cast, folded, **not yet tempered**. Do not build from this until `TEMPER.md` exists and
records a surviving verdict. A design temper is *not* a substitute for a `/cage-match` on the
eventual diff.

**Cast twice** (per SKILL.md Reference: a second Cast by the same author is where the gain is).
The v1 spine was "add a `canJoin` predicate and call it before the mint." The re-cast found that
predicate was the *second* question, and that the first one — *what does `visibility` actually
mean?* — dissolves most of the difficulty. What follows is v2.

---

## 1. The problem, stated at the right altitude

`POST /livekit-token` mints a LiveKit token for any `roomName` a valid credential holder requests
(`src/mint.js:26-32`). There is no admission check. Every signed-in user, including an anonymous
guest with a throwaway uid, can enter any room in the world by typing its name — and, because
LiveKit's `room.auto_create` defaults to `true` and no `roomCreate` grant is needed for it, can
also conjure unbounded new rooms on the deployment.

But the reason this has survived two hardening sessions is not that it is hard to *check* something
before minting. It is that **there is nothing to check.** The permission vocabulary in this system
answers a different question than the one the risk is about:

| Existing concept | Answers | Location |
|---|---|---|
| `canEdit(userId)` | who may **modify** a room | `room_data.dart:56` |
| `isPublic` | whether a room **appears in listings** | `room_service.dart:101,161` |
| `RoomVisibility` | (intended) who may **see that a room exists** | engine enum |

Nothing answers *who may be present*. `canEdit` is the nearest neighbour and it is the wrong
lattice — a classroom's students must enter and must not edit.

## 2. The spine: `RoomVisibility` is two axes wearing one enum

The tell is `unlisted`. Read as a *listing* state it is perfectly coherent: the room does not appear
in a directory, but anyone with the id can enter. Read as an *entry* state it is incoherent: the
door is unlocked and the sign is just painted over.

It is incoherent because the enum is secretly a product of two independent axes:

|  | **listed** | **unlisted** |
|---|---|---|
| **open** (anyone may enter) | `public` | `unlisted` |
| **closed** (admission required) | ***unrepresentable*** | `private` |

Three of four states have names. The fourth — **listed + closed** — has no name and cannot be
expressed, and it is exactly the education tier's requirement (`packages/realm/DESIGN.md:170`): a
classroom that is *visible* in the directory so students can find it, and *closed* so only enrolled
students enter. That absence is not an oversight in the enum; it is the enum being one-dimensional
about a two-dimensional thing.

**So the primitive is not `canJoin`. It is the split.** `canJoin` follows from it in a few lines;
without it, `canJoin` gets bolted onto a type that already lies.

```
RoomListing   ::= listed | unlisted      // discovery — who learns the room exists
RoomAdmission ::= open   | closed        // entry     — who may be present
```

This also explains, and retires, the engine's existing refusal. `firestore_room_config_store.dart:
21-30` throws on `RoomVisibility.private` because the backend "cannot gate reachability without a
Firestore security-rules change." That diagnosis mislocates the door — **room presence is a LiveKit
session, not a Firestore read**, and Firestore rules have never gated it and cannot. The refusal was
right; its stated reason was wrong; the correct enforcement point is the token mint.

## 3. Where admission is enforced

**At token-mint time, and only there.** This is forced, not chosen: LiveKit has no pre-join hook
(`RESEARCH.md §1`). Webhooks fire after the media connection is up. Whatever the mint grants is
granted.

### The shape: separate the *decision* from the *enforcement*

This repo already has exactly the right structure one level down, and the design copies it upward.
Today `/exchange` holds the ES256 **private** key and signs; `/livekit-token` holds only the
**public** key and verifies, so a bug in the mint cannot forge a credential
(`src/realmCredential.js:8-11`). Apply the same asymmetry to admission:

- **`/exchange` decides.** It has the caller's Firebase ID token, so it can perform an authoritative
  admission lookup, and it holds the private key, so it can sign the result.
- **`/livekit-token` enforces.** It verifies a signed decision and compares one field. It never
  performs a lookup, never holds a credential, never knows a policy.

Concretely, `/exchange` gains a **room-scoped mode**. The existing identity-scoped call is unchanged.

```
POST /exchange { idToken }                      -> identity credential  (today; unchanged)
POST /exchange { idToken, roomName, joinCode? } -> ROOM-SCOPED credential { sub, prov, room, exp }
POST /livekit-token  + room-scoped credential
     -> mints the LiveKit grant with room = claims.room   (the body carries no room at all)
```

**The mint takes the room from the credential, not the request body** (folded in at F1). This is
deliberately *not* a comparison. An earlier cast had `/livekit-token` check
`cred.room === req.body.roomName` and 403 on mismatch — a guard around a window that should never be
open. Reading the room from the signed claim deletes the mismatch class instead of defending it: a
caller **cannot express** "authorized for A, mint for B", because the request contains exactly one
room and it is the signed one. The body's `roomName` becomes vestigial and should be rejected rather
than ignored, so a stale client fails loudly instead of silently getting a room it did not ask for.

Two consequences that must be handled rather than assumed:

- **`roomName` must be validated before it is used to build any Firestore path.** Today
  `src/mint.js:27` accepts any non-empty string; under this design it becomes a document id, and
  `foo/bar/baz` changes the path shape. Positive charset (`^[A-Za-z0-9_-]{1,64}$` proposed), checked
  at the room-scoped `/exchange`. This is a **pre-existing** defect, newly reachable.
- **A missing room document is a refusal.** "No config, so nothing to check, admit" is the denylist
  failure wearing a different hat. Empty means closed everywhere, including when empty means absent.

This answers the brief's constraint 5 precisely. Room rights genuinely cannot be baked into the
*identity* credential — it is minted before the user picks a room. But a **second, room-scoped**
exchange happens *after* the user picks, so the room is known, and a short TTL bounds staleness to a
parameter rather than leaving it a structural flaw.

### The admission lookup costs no new secret

`/exchange` already holds the caller's Firebase ID token. Firebase's REST API accepts that token as
`Authorization: Bearer` and **enforces Security Rules as that user** (`request.auth.uid` populated);
a service-account OAuth2 token, by contrast, **bypasses rules entirely** and uses IAM. So the cheap
path is also the *less privileged* one:

| | New secret to store/rotate/back up | Reads as | Rules enforced |
|---|---|---|---|
| Service account + Admin SDK | **Yes** | admin | **No — bypassed** |
| **Caller's ID token + Firestore REST** ✅ | **No** | the caller | **Yes** |

This preserves the service's "no Firebase service account" property, which `RESEARCH.md §3` shows
was always a claim about *verification* and is now also true of *authorization*.

**The trap this must not fall into:** the check must not be "can this user read the room document."
Read is not join — conflating them is the exact error the whole design exists to fix. The rules must
expose an **explicit admission fact**.

## 4. The membership primitive (engine-owned, `tech_world`)

Mechanism, not policy — per Nick's framing, the engine expresses admission and world builders decide
what it means. Zanzibar's separation is the model at small scale: the engine ships the relation, the
storage shape and the check; the world ships the policy that populates it.

```
rooms/{roomId}
  listing:   "listed" | "unlisted"
  admission: "open"   | "closed"

rooms/{roomId}/members/{uid}      // identity-based admission — a Zanzibar-shaped tuple
  role: <world-defined string>    // engine does not interpret; worlds do
  addedBy, addedAt

rooms/{roomId}/invites/{codeHash} // capability-based admission — for guests
  expiresAt, maxUses, uses, createdBy
```

Security rules — the load-bearing part, because it is what makes the check honest:

```
match /rooms/{roomId}/members/{uid} {
  allow read: if request.auth.uid == uid;   // you may read YOUR OWN admission, and only that
}
```

A user can ask "am I admitted?" and cannot enumerate the roster. The fact exposed is *admission*,
not *readability* — the trap in §3 is closed by construction rather than by discipline.

### The predicate

```
canJoin(principal, room, presentedCapability?) :=
     room.admission == open
  OR exists(rooms/{room}/members/{principal.uid})
  OR validCapability(presentedCapability, room)
```

**Positive by construction, and closed when empty.** Every arm names someone explicitly permitted;
there is no arm that admits by failing to match. A room with no members, no invites and
`admission: closed` admits nobody — including its own owner unless the owner holds a member tuple,
which `createRoom` must write. This matters because of local precedent: the CORS loopback saga in
PR #3 cost three cage-match rounds by being a denylist twice before being a positive definition
(`feedback_repeated_finding_class_wrong_mechanism`).

### What a guest is

An anonymous guest gets a **fresh Firebase uid on every sign-in** (`claude-tasks#3160`). So a roster
keyed on uid is broken *by construction* for guests — a base case, not an edge case. The design
answers it by making the two admission paths structurally different rather than patching one:

> **Members are admitted by identity. Guests are admitted by capability.**

A guest presents an unguessable `joinCode`; `/exchange` hashes it and checks for an unexpired invite
document. Identity is never consulted, so uid churn is irrelevant — the question was never "who are
you." This is the W3C capability-URL model (GitHub private Gists, Flickr Guest Passes), with its
known and accepted cost: **a capability is transferable — whoever holds it is admitted.** It must
therefore be expiring, revocable, use-countable, and it must never be the path into a members-only
room. A world that wants no guests issues no invites; the mechanism does not force a social model.

## 5. Defence in depth: `auto_create: false`

Independently of the predicate, set LiveKit `room.auto_create: false` and create rooms explicitly
server-side. Then an unknown room name fails closed **at the LiveKit layer**, without reference to
the predicate — so a bug in the predicate does not also become unbounded room creation. This is the
only part of the design that holds if everything else is wrong, which is why it is worth its cost.

**Open variable:** whether the deployment is LiveKit Cloud or self-hosted, and whether Cloud exposes
`auto_create`. Not determinable from the repo — it carries only `LIVEKIT_API_KEY`/`SECRET`. Must be
confirmed before this step is planned, not assumed.

## 6. Build order (core first; each step independently useful)

| # | Step | Repo | Useful alone? |
|---|---|---|---|
| 1 | Split `RoomVisibility` → `listing` × `admission`; add `members`/`invites` + rules; implement `canJoin`; make `createRoom` write the owner's member tuple | `tech_world` | Yes — retires the `private`-throws refusal |
| 2 | `/exchange` room-scoped mode: verify ID token, call the admission lookup, mint a credential carrying `room` + short TTL | `realm-token-server` | Yes — a room-scoped credential is strictly stronger than an identity one |
| 3 | `/livekit-token` mints with `room = claims.room`; reject a credential with no `room` claim. **Red-prove.** | `realm-token-server` | Yes — this is the fix |
| 4 | `auto_create: false` + explicit room creation | infra | Yes — independent |

**Deployment ordering is a hard constraint, not a preference** (folded in at F5). Steps 2 and 3 are
independently *useful* but not independently *deployable*: the moment step 3 lands, every client
still presenting an identity-scoped credential is refused — which is every client until step 2's
flow has rolled out and been adopted. Ship 2 → roll clients forward → **then** ship 3. Step 3 fails
closed on a credential with no `room` claim, which makes that rollout a hard prerequisite rather
than a soft one.

**The red-prove, restated.** F1 removed the comparison, so there is no "enforcement call" to delete.
The mutation test is sharper instead: **change `src/mint.js` to read `req.body.roomName` instead of
`claims.room`, and the test must go red.** That mutation *is* the historical bug, so the test proves
it stays dead. Given `feedback_priority_inversion_evidence` — last session's ceiling on this exact
route was the least-witnessed thing in a PR that existed because of this route — the test must
exercise the refusal path itself, not merely the happy path beside it.

**No deadlock between the repos.** Steps 2+3 land against a policy that is initially trivially open
(`admission: open` for every existing room, matching today's behaviour exactly) and get strictly
stricter as step 1's data lands. That is *not* a local stand-in predicate — the token server never
decides policy, it reads whatever the engine's authoritative data says. Step 3's enforcement is a
field comparison whose strength lives entirely in step 1.

**Migration:** existing rooms have `isPublic` defaulting **true** (`room_data.dart:22,98`) → map to
`listed` + `open`, which preserves current behaviour exactly. Nothing breaks on deploy.

## 7. Blast radius and consent spine

- Step 3 changes a **trust boundary** → `/cage-match` by law, not self-review.
- Step 3 can lock users out of rooms they can reach today. The migration in §6 makes the initial
  state behaviour-identical; every subsequent tightening is a deliberate data change by a world
  builder, not a deploy.
- Step 1 changes a **public engine type** in a repo heading open-source → a breaking change for any
  existing consumer. `tech_world` is the only consumer today; confirm before assuming.
- The `joinCode` is a bearer capability appearing in request bodies. It must never be logged.
  `src/requestLog.js` exists and logs requests — **auditing it for capability leakage is part of
  step 2, not a follow-up.**

## 8. Rejected alternatives

1. **Post-hoc eviction** — subscribe to `participant_joined`, evict via `removeParticipant`. Rejected:
   admits first. In a private classroom the intruder is present, sees and hears, then leaves. That is
   reconciliation, not admission.
2. **Service account + Admin SDK lookup at mint time** — rejected: adds a secret to store/rotate/back
   up *and* bypasses Security Rules (strictly more privilege for strictly more cost), and it puts the
   policy read inside the mint, which should stay a pure verifier.
3. **Bake membership into the identity credential at first `/exchange`** — rejected by the brief's
   constraint 5 and correctly: the room is unknown at that point, and any baked grant goes stale the
   moment someone is removed.
4. **Client asserts its own admission** — trivially forged.
5. **Keep one enum, just add `private` support** — the simplest alternative, and the one most worth
   arguing with. Rejected because it leaves *listed + closed* unrepresentable, which is the education
   tier's actual requirement, and because it keeps discovery and entry fused in a type that already
   forced the backend to throw rather than lie.
6. **Re-present the ID token at `/livekit-token` and look up there** — rejected: costs the mint its
   "accepts only a Realm credential" property, which is the boundary most worth keeping pure.

## 9. Claims to falsify (for the temper)

- **C1.** LiveKit offers no pre-join admission hook, so the mint is the only door. *Checked against
  the vendor's webhook list; if wrong, the whole enforcement location is wrong.*
- **C2.** Firestore REST with a Firebase ID token enforces Security Rules as that user, so no service
  account is needed. *Checked against Firebase's own docs. Not yet exercised against this project.*
- **C3. ⚠ WEAKEST STRUCTURAL CLAIM — strike here hardest.** Splitting `RoomVisibility` into two axes
  is the right primitive and not over-engineering. *Downgraded during Fold after I re-attacked it
  myself: the listed+closed requirement is my **inference** from `packages/realm/DESIGN.md:170`
  ("Education tier: private rooms, classroom features"), not a stated need. A classroom could just as
  well be `unlisted` and shared by link. The split survives on a weaker second argument — it keeps
  the listing query and the admission predicate independent. **If C3 falls, alternative 5 wins and
  this design gets meaningfully smaller, which is a good outcome, not a failure.***
- **C4.** A short TTL on the room-scoped credential adequately bounds revocation staleness. **Unquantified
  — no TTL is proposed here, and "short" is not a design.** A removed user stays admitted for up to
  one TTL, and LiveKit sessions outlive the token that opened them, so eviction of an *in-progress*
  session is out of scope entirely. This is the weakest claim in the document.
- **C5.** A transferable bearer capability is an acceptable definition of guest admission.
- **C6.** Steps 2+3 can land before step 1 without becoming a stand-in predicate.
- **C7.** `room.auto_create` is actually `true` on *this* deployment. *Inferred from the vendor default
  plus the absence of any override in the repo. The deployment was not inspected — this is the
  design's least-verified factual premise.*

## 10. Open variables (enumerated, not rounded to "ready")

1. TTL for the room-scoped credential (see C4 — this is a gap, not a detail).
2. LiveKit Cloud vs self-hosted, and whether `auto_create` is settable there.
3. **Default `admission` for newly-created rooms.** Live code defaults `isPublic: true` →
   `open`; `packages/realm/DESIGN.md:54` specifies `NewRoomSpec` defaulting to **`private`**. Those
   disagree. **Surfacing, not tie-breaking** — this is a two-source conflict and the call is Nick's.
4. Whether `role` on a member tuple is engine-opaque (proposed) or an engine enum.
5. Whether an owner is implicitly admitted or must hold a member tuple (proposed: must hold one, so
   the rule stays uniformly positive — but it makes `createRoom` non-atomic across two writes).
6. Invite revocation semantics: delete the doc, or mark and sweep?
7. Per-room throttling for `joinCode` attempts (F4). The existing limiter is per-IP with a
   service-wide ceiling and was built for a different threat; it does not bound a distributed grind.
   Codes must be ≥128-bit, server-generated, stored **hashed**, expiring and use-counted — entropy
   does the real work, the throttle is depth.
8. Whether any live `tech_world` flow relies on create-by-join, which F3's "missing document =
   refusal" would close. `room_service.dart` has an explicit `createRoom`, which suggests not —
   **verify locally in the handoff rather than inferring it from an outside grep.**

## 11. Also folded in from `FOLD.md`

- **F6 — a free lever already in hand.** The credential already carries `prov`, which is `anonymous`
  for guests (`src/realmCredential.js:35,86`). So "closed rooms never admit anonymous principals" is
  expressible **today** with no new data model and no lookup. It is coarse — it cannot say "this
  guest, this room" — so it is not a substitute for the design, but the mechanism should pass `prov`
  to the predicate so a world can use it. **Not hardcoded**: that would be the engine choosing a
  social policy, which the framing forbids.
- **F7 — `createRoom` now writes two documents** (the room, and `members/{ownerId}`). A partial
  failure leaves a closed room whose owner cannot enter and cannot repair. Single batch/transaction,
  named in the handoff.
