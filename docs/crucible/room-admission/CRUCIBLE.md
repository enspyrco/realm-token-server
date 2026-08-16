# CRUCIBLE — the admission primitive for Realm

**Candidate:** `claude-tasks#2850` — Realm has no admission control. `POST /livekit-token` mints a
LiveKit token for any `roomName` any valid credential holder asks for.

**Selected by:** Nick, explicitly, at invocation (2026-08-17). The scout did not choose this; the
human did, so movement 1's aliveness×impact scoring is recorded for the file rather than used to
select. **Scout memory:** `docs/crucible/*/TEMPER.md` — none exist in this repo. No prior verdict
binds or conflicts.

**Run configuration:** `--no-spark` (critique-only arm). Per SKILL.md's Reference section, Spark is
optional and unsupported as an improvement over a second Cast; this run does the cheaper, better-
evidenced thing — Cast twice, same author.

---

## Aliveness × impact (recorded, not used to select)

| Axis | Score | Evidence (concrete, not affect) |
|---|---|---|
| Aliveness | 3 | Three model families (Maxwell/Kelvin/Carnot) named this unprompted across two consecutive retrospectives in two sessions, in their own vocabulary, without converging by instruction. |
| Impact | 3 | It is the difference between a service that authenticates and a service that authorizes. Any signed-in user — including an anonymous guest — currently enters any room in the world by typing its name. |

Product 9. Not slag on either axis.

## The ore is real (verified, not asserted)

Every claim below was read back from source this session, not carried from a consolidation summary
(`feedback_consolidation_handoff_is_hypothesis` — the handoff that proposed this run is one).

- `src/mint.js:26-32` — reads `req.body.roomName`, checks only that it is a non-empty string, and
  passes it straight to `mintLiveKitToken`. There is no admission check of any kind.
- `src/livekit.js:15-21` — grants `roomJoin: true, room: <caller's string>, canPublish: true,
  canPublishData: true, canSubscribe: true`.
- `src/realmCredential.js:67-87` — the credential carries `sub`, `prov`, `iat`, `exp`. No room.
- `enspyrco/tech_world` (cloned this session) `lib/rooms/room_data.dart:56` — `canEdit(userId) =>
  userId == ownerId || editorIds.contains(userId)`. No `canJoin`. No roster field anywhere.
- `lib/rooms/room_data.dart:22,98` — `isPublic` defaults **true**.
- `lib/rooms/room_service.dart:101,161` — listing queries filter `.where('isPublic', ==, true)`.
  Listing. Never entry.
- `packages/realm_firebase/lib/src/firestore_room_config_store.dart:21-30` — the engine's own
  documented refusal: `RoomVisibility.private` is **deliberately unsupported**, `createRoom` throws
  on it rather than silently downgrading, because the backend "cannot gate reachability without a
  Firestore security-rules change."

The README is already honest about the gap (`README.md:41-43`, `:225-226`). There is no overclaim
to retract — only a hole to fill.

## What makes this thrilling, and what it would actually change

The engine **already refused to lie.** Someone hit this exact wall, saw that `private` would be a
false promise, and made `createRoom` throw instead of downgrading. That is a load-bearing refusal
marking precisely where the axis runs out — and it has been sitting there as a fossil of the right
instinct with no primitive behind it.

And the reason it gives is *one layer off*. "Cannot gate reachability without a Firestore
security-rules change" mislocates the door: room presence is a **LiveKit session**, not a Firestore
read. Firestore rules gate document reads. They have never gated, and cannot gate, who is in a
room. The engine's honest refusal is blocked on a door that was never the door.

What it changes: `private` becomes a shape the engine can actually honour, which unblocks the
education tier (a classroom with students who enter and do not edit), and it closes a hole
describable in one sentence to anyone evaluating the product.

## The falsifier — what would prove this ore is slag

**If LiveKit offered a server-side pre-join admission hook, this whole design is the wrong shape** —
enforcement would belong at that hook (post-token, centrally, revocable mid-session) and the mint
would stay a dumb minter.

**Result: checked, and it does not.** LiveKit's webhooks (`participant_joined`,
`participant_connection_aborted`, …) fire *after* the media connection is established. They are
notifications, not gates. There is no pre-admission callback. The token **is** the admission
decision. The falsifier ran and the ore survived it.

A second, weaker falsifier — *"the membership data might already exist somewhere I did not grep"* —
was run as `rg 'canJoin|roster|memberIds|editorIds|isPublic|RoomVisibility'` across the whole
tech_world tree, Dart and Markdown. It does not exist. Coverage boundary: that grep would miss
membership stored under a name sharing none of those stems (e.g. `participants`, `allowlist`) — I
accept that residual risk and the tech_world handoff should re-check it locally.

## Blast radius, named up front

Nothing in this run is a build. The forge output is a **plan plus a cross-repo handoff**. The
eventual 0b diff touches a live trust boundary (the mint), so it is `/cage-match`-by-law, and a
design temper is explicitly **not** a substitute for that (`feedback_crucible_build_handoff_cage_match`).
