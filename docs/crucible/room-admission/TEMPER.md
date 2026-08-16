# TEMPER.md — room admission for Realm (`claude-tasks#2850`)

**Overall verdict: RECAST** — and a substantial one. The *hole* and the *enforcement location*
survived all four strikes. The *structural primitive* did not.

**Struck:** `dt-roomadmission`, 2026-08-17. Families seated: **Maxwell (Claude) + Kelvin (Gemini,
gemini-3-pro-preview) + Carnot (Codex/GPT) + Tesla (Grok)** — full 4-way panel, **no dark seats**
(Wu/Kimi disabled fleet-wide). Bundle 40,626 bytes, inside Carnot's validated range.

## Per-family verdicts

| Family | Verdict | One-line |
|---|---|---|
| Maxwell (Claude) | RECAST | Mistook a beautiful diagnosis for a mandatory structure, then built a mechanism to avoid asking Nick a policy question. |
| Kelvin (Gemini) | RECAST | "Mistakes complexity for rigor, solving a problem of its own invention while freezing at the threshold of a real one." |
| Carnot (Codex/GPT) | **DISSOLVE** *(scoped)* | "Spends most of its entropy budget splitting `RoomVisibility` when the actual irreversible loss is simpler." |
| Tesla (Grok) | RECAST | "The one frequency that shatters the glass is the *derivative* ticket, not the missing enum." |

**On Carnot's DISSOLVE — recorded honestly rather than rounded off.** The synthesis rule makes
DISSOLVE decisive at ≥2 families; only one family voted it, so the candidate is **not invalidated**.
But the label must not be laundered either: Carnot's own summary says *"the enforcement location
survives; the structural primitive does not"*, and it supplied eight concrete fold-backs — which is
RECAST semantics applied to a DISSOLVE-worthy *sub-claim*. Read precisely: **Carnot dissolved C3,
not the candidate.** That reading is corroborated by the other three rather than convenient to me —
all four killed C3 independently.

## Fatal flaws (deduped, most-severe first)

1. **The room-scoped credential is itself an uncounted transferable bearer capability.** — Tesla
   (primary), Maxwell (self-caught after the fact), Carnot (replay/race sub-case). A hashed,
   expiring, **use-counted** `joinCode` is converted by `/exchange` into a bearer JWT with *none* of
   those properties. `maxUses` dies at the first signature; one leaked ticket is an unlimited
   publisher pass until `exp`. **The design's own Fold hunted this exact class (F4) and missed it.**
   → **DISPOSITION: fold.** Bind the derivative to its source — `jti`, single-use at the mint or a
   written-in-one-brutal-sentence acceptance, and TTL pinned to the capability's remaining life.

2. **C3 — the 2×2 split is over-engineering. Unanimous, 4/4.** The `listed+closed` cell is an
   inference from one line of `packages/realm/DESIGN.md:170`, not a stated requirement; a classroom
   shared by link is `unlisted+closed`, which `private` already names. Tesla landed the sharpest
   blow: **`isPublic` already *is* the listing axis** — the independence argument needs a second
   *field*, not a breaking public-type split in a repo heading open-source.
   → **DISPOSITION: fold — delete the spine.** §2 demotes to a remark explaining why `unlisted`
   looked incoherent. Ship `admission: open|closed` beside the existing `isPublic`. Rejected
   alternative 5 is promoted to the surviving design.

3. **C4 — revocation is undesigned, not merely unquantified.** Kelvin ("an evicted participant is
   not evicted… mission failure" for the design's own motivating example), Carnot ("'short TTL'
   without a number is vapor"), Tesla (two unbound clocks). All three note the design rejected
   `removeParticipant` as *admission* — correctly — and then wrongly kept rejecting it as
   *revocation*, which is the only vendor lever that exists after connect.
   → **DISPOSITION: fold.** Pin numbers (60–120s room-cred TTL proposed by Tesla), bind LiveKit
   grant `exp` ≤ remaining credential `exp`, and add `removeParticipant` as a named **eviction**
   primitive distinct from admission. C4 without a number is deleted, not softened.

4. **C6 is false — steps 2+3 before step 1 *are* a stand-in predicate.** Kelvin ("rationalization…
   temporal coupling"), Carnot ("call it a compatibility phase, not authorization delivered early"),
   Tesla ("there is no third path": missing→open is policy in the token server, missing→refuse is a
   global outage).
   → **DISPOSITION: fold — strike C6 and reorder.** Migration writes `admission` + owner tuples
   **first**; then room-scoped `/exchange` against real facts; then clients; then `/livekit-token`
   refuses unscoped credentials. The phase gets its honest name: *compatibility migration*, not
   authorization.

5. **The caller-ID-token lookup has three unpriced failure modes.** Tesla, extending Carnot.
   (a) **Use-counting invites requires a *write* as the caller** — a rule loose enough to increment
   `uses` is loose enough to set `maxUses: 999999`. **The use-counted guest primitive is
   unimplementable safely on the very path that rejected service accounts.** (b) **App Check**: if
   this or any OSS consumer enforces it, a server-side REST GET carrying only an ID token fails for
   *everyone* — first hardening pass takes every join dark. (c) **Overloaded refusal**: rules-deny,
   missing doc, expired token, billing and App Check all collapse to one 403, so an availability
   cliff reads as a clean "not admitted."
   → **DISPOSITION: fold.** Invites become **GET-only** (entropy + expiry do the work; no
   `uses++` as the caller). App Check is documented as a hard incompatibility. Refusal reasons are
   distinguished internally even if the client sees one status.

6. **The third lattice: `canPublish`.** Maxwell, Tesla. `src/livekit.js:15-21` grants
   `canPublish/canPublishData` unconditionally. The motivating classroom student who must enter and
   must not edit must also not blast audio. Admission was modelled as boolean; the live grant is
   already a capability set.
   → **DISPOSITION: fold.** Derive publish rights from admission role, or mint subscribe-only unless
   a member tuple says otherwise.

7. **C7 is load-bearing and least-verified — a priority inversion.** All four. §5 calls it "the only
   part of the design that holds if everything else is wrong" while it rests on a vendor default
   with the deployment never inspected. Tesla: "a load-bearing last door that might be a wall
   painting is worse than no door — it licenses shipping the predicate looser."
   → **DISPOSITION: fold as a blocking prerequisite.** Measure Cloud-vs-self-hosted and the actual
   `auto_create` value **before** it appears in any build table. If unsettable, step 4 disappears.

8. **F6 (`prov`) was the dissolving first ship, buried in a footnote.** Tesla, sharply: the worst
   sentence in the brief — "including an anonymous guest" — is closable *tonight* with no roster, no
   2×2, no REST lookup and no new secret. "Design-for-subtraction failed its own test: the simple
   pick was in your hand and you built the next abstraction."
   → **DISPOSITION: fold — promote F6 to step 0.**

9. **Wrong option-frame: four policy questions were never put to the human who owns them.** Maxwell.
   Default `admission` for new rooms (a live two-source conflict), whether listed+closed is real,
   whether guests may ever enter closed rooms, whether owners are implicitly admitted. A mechanism
   flexible enough to express every policy never has to find out which one is wanted.
   → **DISPOSITION: fold — ask, before the build.** Explicitly *not* a silent tie-break.

## What holds

- **The hole is real, and the enforcement location survives all four strikes.** LiveKit has no
  pre-join hook; webhooks are notifications. The token **is** the admission decision. Carnot
  independently searched and "found no current LiveKit pre-join admission hook."
- **Decision/enforcement asymmetry** mirroring the existing ES256 split — unanimous keep.
- **F1 — taking the room from the signed credential, not the body.** Carnot: "the strongest part of
  the design… the bug cannot happen because the variable is gone." Do not put the window back.
- **Positive predicate, empty = closed, absent document = refusal (F3).** Unanimous keep.
- **Members-by-identity / guests-by-capability** as the base split for uid churn — sound primitive,
  broken derivative (flaw 1), not a broken primitive.
- **F2** (charset validation before path construction) — a real pre-existing defect found in passing.
- **The `room.auto_create` discovery** — unbounded room creation was named by nobody before this run.
- Step 3 remains **`/cage-match`-by-law**. A temper is not that review.

## Disposition

**RECAST** — round 1 of ≤3. Flaws 1-9 folded into `DESIGN.md` (v3); the design that fell out is
materially *smaller* than the one struck, which the author pre-committed to calling a good outcome.

Not invalidated: one DISSOLVE, and it was scoped to C3 rather than the candidate.

---

# ROUND 2 — striking v3 (`dt-roomadmission-r2`)

v3 was a **substantial** recast, which makes it un-struck: the adversaries that killed v2's spine
never saw it. Re-struck fresh, with the brief explicitly forbidding credit for surviving round 1.

**Verdicts: Kelvin RECAST · Carnot RECAST · Tesla RECAST · Maxwell RECAST.** Full panel again, no
dark seats. Round 2 earned its cost — **every finding was a regression the recast itself
introduced**, which is precisely what re-striking exists to catch.

| # | Finding | Raised by | Disposition in v4 |
|---|---|---|---|
| 1 | **`jti` single-use re-statefulizes the stateless mint.** "Records it" is a replica set: atomic check-and-set, shared across processes, TTL eviction. Worse, a lost response makes a legitimate **retry indistinguishable from a replay** — the user is locked out. | all 3 | **Mechanism deleted, not implemented.** Carnot supplied the dissolution: the `joinCode` stays reusable until expiry/revocation regardless, so single-use tickets buy *nothing*. The store guarded a window that was never closed. Residual written plainly instead. |
| 2 | **`min(livekitTtl, cred exp)` does not do what v3 claimed.** A LiveKit token's `exp` gates **connection, not continued presence** — so binding it never bounded a session, it only broke reconnect (ICE restart, backgrounding, a tunnel flapping at 90s). | Carnot, Tesla | Binding deleted. C4's scope corrected: 120s bounds **minting**; **eviction is the only presence lever**. |
| 3 | **"Subscribe-only unless `role` says otherwise" muted two of three `canJoin` arms.** Guests and open-room joiners have no member tuple — the open lobby and the visiting speaker-with-a-link both go deaf-mute. And it contradicted `role` being opaque: *"a magic string role is coupling by folklore."* | Tesla, Carnot, Kelvin | Replaced with explicit engine-owned `defaultCanPublish` (room) + `canPublish` (member override). `role` returns to **fully opaque**. |
| 4 | **Step 0's "on non-public rooms" reconflated listing with admission — in the first ship.** Publicness is `isPublic`; deciding per-room needs a read, and it pre-empts open question 2 before Nick answers. | Tesla | Step 0 becomes a **deployment-wide** switch, no per-room read. Re-labelled *a risk trim, not admission control* (Carnot). |
| 5 | **The invite READ rule was missing entirely.** Members got a closed read; invites got "a hash and a sermon." Omit `allow get` and every guest is dark; permit `list` and the entropy is defeated. | Tesla | Rule written into §6 explicitly, with the `get`-yes / `list`-no property named as *the* security property, and the document required to hold nothing sensitive. |
| 6 | **Eviction under-specified** — needs a privileged Firestore→LiveKit watcher, and `sub` must equal the LiveKit participant identity. | all 3 | Scoped as **its own design pass** (step 8), not a line item. **Correction recorded:** two families claimed it needs a LiveKit credential "the design says it lacks" — refuted by `src/index.js:23-24`, which already loads `LIVEKIT_API_KEY`/`SECRET`. Tesla alone got this right. |
| 7 | **Migration undercounts owner recovery** — absent `admission` = refusal + required owner tuples means old rooms can strand with no repair path. | Carnot | Step 3 now ships backfill verification + stranded-room repair tooling. |

## Disposition after round 2

**Design-complete at the design layer; stopping at round 2 of ≤3.** The remaining open items are
*implementation-shaped* (a TTL confirmed against a real client, the rules text, the watcher's shape)
rather than *design-shaped*, and the arc across two rounds is monotonic toward **smaller**: the 2×2
died, then the `jti` store died, and nothing was added but honesty. Burning round 3 to chase
convergence would be the `feedback_review_loop_grows_own_input` failure — each round adds surface
the reviewers then discover.

**Not "battle-tested."** v4 carries round-2 folds that no adversary has seen. The honest claim is:
*the design survived two full 4-way strikes and got smaller each time; the implementation is
unproven and step 6 remains `/cage-match`-by-law.*

**Four questions remain Nick's** (DESIGN.md §10) and are surfaced, not tie-broken.
