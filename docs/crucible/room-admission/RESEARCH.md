# RESEARCH — where admission can be enforced, and what shape the primitive takes

**Depth: moderate-inline.** No `/deep-research` agent was spawned (standing session constraint on
spawning agents unasked); this is a bounded inline pass against vendor primary sources plus prior
art. Findings below are cited to what was actually fetched. Label Heat *moderate*, not exhaustive.

---

## 1. LiveKit: the token IS the admission decision

**No pre-join server-side hook exists.** LiveKit's webhook set is
`room_started, room_finished, participant_joined, participant_left, participant_connection_aborted,
track_published, track_unpublished, egress_*, ingress_*`. A participant is considered joined
*after* the media connection is established, at which point `participant_joined` fires. These are
**notifications, not gates** — there is no callback that runs before admission and can refuse it.

> Consequence for the design: enforcement cannot be moved "later" to a central hook. The mint is
> not one door among several; it is the only server-side door. Anything the mint grants is granted.

The weaker post-hoc option — subscribe to `participant_joined` and eject via `RoomService.
removeParticipant` — is a *reconciliation* loop, not admission. It admits first and evicts after,
which for a private classroom means the intruder is in the room, sees and hears, and then leaves.
Recorded as a rejected alternative, not a fallback.

**`room.auto_create` defaults to `true`.** From LiveKit's own `config-sample.yaml:207-209`:

```yaml
# room:
#   # allow rooms to be automatically created when participants join, defaults to true
#   # auto_create: false
```

Rooms are created when the first participant joins. `src/livekit.js` grants `roomJoin` but **not**
`roomCreate`, so creation here is governed by that server-side default, not by the token.

> Consequence: today's exposure is strictly larger than "enter a private room." Any credential
> holder can conjure unbounded rooms on the deployment — a quota/cost surface not named in
> `claude-tasks#2850`, in the README, or in either prior retrospective. This is a **new finding**.

`auto_create: false` plus explicit server-side room creation makes "this room exists" a real
precondition, and is genuinely independent of the admission predicate — worth taking as
defence-in-depth precisely because it fails closed even if the predicate has a bug.

**Open variable (must be confirmed before the build, not assumed):** whether the deployment is
LiveKit Cloud or self-hosted, and whether Cloud exposes `auto_create`. The repo carries only
`LIVEKIT_API_KEY`/`LIVEKIT_API_SECRET` (`src/index.js:23-24`) and no URL, so this was not
determinable from source. Per-token auto-create control is an open upstream request
(`livekit/livekit#4504`); implementation status could not be confirmed from the issue page.

## 2. Prior art on the *shape* of the primitive

**Zanzibar / ReBAC (Google).** Relation tuples of the form `object#relation@user` — "user has
relation to object" — with a per-type **namespace configuration** declaring which relations exist
and how they derive (userset rewrites give `owner ⊂ editor ⊂ viewer`). The load-bearing lesson for
an open-source engine: Zanzibar separates the **mechanism** (tuple storage + a `Check` API) from
the **policy** (each service's namespace config). That is exactly Nick's constraint — "the engine
owns private rooms, world builders decide what they do with that" — and it is a solved separation,
not one to invent. What Realm needs is the small end of it: a relation, a check, and a place to
store tuples. Not a Zanzibar.

**Capability URLs / bearer capabilities (W3C TAG).** Access granted by possession of an unguessable
token rather than by identity; in wide production use (GitHub private Gists, Flickr Guest Passes,
every "anyone with the link" share). The TAG's good-practice notes are the relevant constraints:
unguessable, expiring, revocable, and never leaked through `Referer`/logs/URL bars.

This is the answer to the guest problem. An anonymous guest gets a **fresh Firebase uid on every
sign-in** (`claude-tasks#3160`), so *any* roster keyed on uid is broken by construction for guests —
not at the edge, at the base. But a capability does not need identity to be checked. So: members
are admitted **by identity**, guests are admitted **by capability**. Two admission paths, both
positive, neither a denylist.

Known cost, taken deliberately: a bearer capability is transferable — whoever holds it is admitted.
That is the same security model as every "anyone with the link" share on the web, and it is
*honest* about what a guest is. It must be expiring and revocable, and it must never be the path by
which a *member*-only room is entered.

## 3. The credential-read constraint, corrected

`README` and the task brief both carry "no Firebase service account needed" as a property of the
service. `src/firebase.js:7-14` documents *why*, and the reason is narrower than the slogan:

> `verifyIdToken` (with `checkRevoked=false`) only fetches Google's **public** signing certs and
> checks `aud` against the project id — it never calls an authenticated API.

So "no credential" is a fact about **verification**, and says nothing about **reading Firestore**,
which genuinely does need authority. The constraint is real; its stated reason was one layer off.

That matters because it re-frames the fork. It is not "add Firebase auth" (already there, free) —
it is "acquire a **read capability**", and a read capability has more than one shape:

| Shape | New secret? | Reads as | Rules apply? |
|---|---|---|---|
| **A.** Service-account JSON → Admin SDK | **Yes** — store, rotate, back up | the admin (bypasses rules) | No — rules are bypassed entirely |
| **B.** Firestore REST with the caller's Firebase ID token as `Authorization: Bearer` | **No** | *the caller* | **Yes** |

B is materially cheaper and strictly less privileged, and it is available exactly where the ID
token already legitimately exists — the `/exchange` handler. It costs a different property (see
DESIGN.md's tradeoff table) and it carries one sharp trap: **if the check is "can this user read the
room document", the design has re-committed the very error it exists to fix** — read is not join.
The rules must expose an explicit admission fact, not be used as a proxy for one.

## 4. What none of the prior art answers

Nothing above tells us whether `visibility` should stay one enum. That question turned out to be
the design's spine and is argued in DESIGN.md rather than here, because it is a claim about *this*
system, derived from `unlisted` being incoherent as an entry state — not a finding from the corpus.

---

## Sources

- [Webhooks & events | LiveKit Documentation](https://docs.livekit.io/intro/basics/rooms-participants-tracks/webhooks-events/)
- [WebhookEventNames | LiveKit JS Server SDK](https://docs.livekit.io/reference/server-sdk-js/types/WebhookEventNames.html)
- [LiveKit `config-sample.yaml`](https://raw.githubusercontent.com/livekit/livekit/master/config-sample.yaml)
- [Room service API | LiveKit Documentation](https://docs.livekit.io/reference/other/roomservice-api/)
- [Support auto creating rooms on a per token basis · livekit/livekit#4504](https://github.com/livekit/livekit/issues/4504)
- [An Introduction to Google Zanzibar and ReBAC | AuthZed](https://authzed.com/learn/google-zanzibar)
- [What is Google Zanzibar? | WorkOS](https://workos.com/guide/google-zanzibar)
- [Good Practices for Capability URLs | W3C TAG](https://w3ctag.github.io/capability-urls/)
