// The Realm AuthProviderId wire strings. ONE definition, shared by the module
// that PRODUCES them (firebase.js mapProvider, at exchange time) and the module
// that ACTS on them (mint.js, at admission time).
//
// Why a separate module rather than exporting from firebase.js: mint.js must not
// import firebase-admin. The mint handler holds only the ES256 public key and has
// no provider dependency — that separation is load-bearing (see realmCredential.js
// "Asymmetric by construction"), so the shared constant gets its own dependency-free
// home rather than dragging the Admin SDK across the boundary.
//
// These strings must match packages/realm AuthProviderId in enspyrco/tech_world.

export const ANONYMOUS_PROVIDER = 'anonymous';
