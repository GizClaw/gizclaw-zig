# `lib/giznet/noise`

`giznet/noise` is a `giznet`-specific handshake and transport-crypto package.

It is not a standard Noise-pattern implementation and it does not claim wire
compatibility with `lib/net/noise`.

This README is the package's minimal security-oriented specification for
implementation, testing, and external security review.

## Scope

This package owns:

- handshake packet parsing and response generation
- session key derivation
- transport encrypt/decrypt
- replay filtering inside one established session
- local keypair lookup for listeners
- single-threaded peer/session ownership
- current / previous / pending session rotation
- rekey, keepalive, handshake retry, and timeout policy

This package does not own:

- UDP socket lifecycle
- runtime workers or queue wiring
- service / KCP policy

## Security Goals

The current design aims to provide:

- static-key peer identification at the handshake boundary
- confidentiality and integrity for transport payloads after session
establishment
- replay rejection for duplicate transport packets inside one session
- explicit rejection for wrong session index, wrong key phase, and unknown local
listener key

## Explicit Non-Goals

The current design does not claim:

- standard Noise compliance
- interop with `lib/net/noise`
- endpoint binding inside the AEAD payload or handshake transcript
- full forward secrecy guarantees

Forward secrecy needs special care here: the current handshake mixes the
initiator static key and one initiator ephemeral key against the responder
static key, but it does not implement a symmetric two-ephemeral standard Noise
pattern. Reviewers should therefore treat full forward secrecy as unproven
until explicitly reworked and re-reviewed.

## Threat Model Notes

The package is intended for untrusted networks where packets may be:

- dropped
- duplicated
- reordered
- delayed
- tampered
- replayed across a still-live session

The package is not currently specified as resistant to:

- endpoint spoofing at the protocol layer
- cross-session replay once a session is intentionally removed and later reused
- attacks outside the tested handshake/session state machine

## Current Protocol Shape

### Handshake

- The initiator sends:
  - message type
  - initiator local session index
  - initiator static public key
  - initiator ephemeral public key
- The responder derives a root key from:
  - initiator static private x responder static public
  - initiator ephemeral private/public x responder static public/private
  - initiator static public
  - responder static public
  - initiator session index
- The responder replies with:
  - message type
  - initiator session index
  - responder session index
  - response tag derived from the root key

### Session

- A session holds:
  - local index
  - remote index
  - peer key
  - endpoint
  - send key
  - recv key
  - key phase
  - nonce / replay state
- Transport packets carry:
  - packet type
  - receiver session index
  - key phase
  - sender nonce
  - ciphertext + tag

## Authentication And Acceptance Rules

Before handshake completion:

- `beginSession()` requires a known local listener key
- `consumeHandshake(init)` requires:
  - a known local listener key
  - either `allow_unknown_peer = true`
  - or a matching `peer_key_hint`
- `consumeHandshake(response)` requires:
  - an existing pending initiator handshake keyed by initiator session index

After handshake completion:

- `encryptTransport()` requires an established session for the target peer key
- `decryptTransport()` requires:
  - matching local session index
  - matching peer key
  - matching key phase
  - a decryptable AEAD payload

## Replay / Ordering Model

- Nonces are monotonic per sender session.
- Duplicate nonces are rejected.
- Older in-window nonces may still be accepted once if they were not seen
before.
- The replay window is local to one session.
- Session removal resets that local replay context.

## Session Index / Key Phase / Nonce Semantics

- `session_index`
  - routes a transport packet to one established session
  - must match the receiver's local session index
- `key_phase`
  - identifies the current send/recv key family for that session
  - mismatches are rejected before payload acceptance
- `nonce`
  - is part of AEAD processing and replay bookkeeping
  - is not allowed to repeat inside one active session

## AEAD Binding

The transport AEAD currently binds the outer transport header as additional
data:

- packet type
- receiver session index
- key phase
- nonce

The following are not currently bound by AEAD as protocol claims:

- UDP endpoint
- higher-layer peer routing decisions outside the transport header

Reviewers should treat those as explicit design constraints, not accidental
omissions.

## Security Review Checklist

- Is the claimed authentication target clear: local listener key, remote
peer key, or both?
- Does the handshake transcript bind all identities and session context the
design intends to authenticate?
- Are `root-key`, `transport-keys`, and `response-tag` domain-separated well
enough for their distinct purposes?
- Do initiator and responder use the same index ordering when deriving and
validating response tags?
- Does `allow_unknown_peer` only relax the specific behavior it is intended
to relax?
- Are wrong listener keys, wrong peer hints, wrong session indexes, wrong
key phases, and malformed packets rejected before state is committed?
- Can `beginSession`, `consumeHandshake`, `cancelPending`, `removeSession`,
and store/publish failures leave partially committed protocol state?
- Are transport packets cryptographically bound to the fields that must not
be rewritten in transit?
- Is replay handling correct for duplicate, delayed, reordered, and
out-of-window packets?
- Does session expiry use the intended activity model for send-heavy and
recv-heavy peers?
- Are pending handshake slots and session slots reclaimed in a way that
avoids index confusion or stale-state reuse?
- Are unknown or late handshake responses rejected after pending state is
canceled?
- Are key materials and handshake/session remnants handled with acceptable
memory hygiene for the deployment?
- Are protocol claims in this README still aligned with the implementation
and tests?

## Security-Focused Unit Coverage

The unit suite should keep covering at least these attack-style cases:

- tampered response tag
- tampered or truncated handshake packet
- wrong initiator / responder session index
- unknown listener key
- unknown peer when `allow_unknown_peer = false`
- mismatched peer hint
- duplicate transport replay
- reordered transport packets inside the replay window
- wrong key phase
- wrong receiver session index
- tampered transport ciphertext / tag
- canceled pending handshake followed by a late response
- pending/session capacity exhaustion

These tests live in the normal `noise` unit runners so protocol behavior stays
close to the implementation files under review.