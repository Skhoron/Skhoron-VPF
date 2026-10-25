# Skhoron-VBF (VPN Base Framework)

A platform-independent framework for VPN protocols with a balance between
privacy and speed. Not a ready-made VPN product — a foundation on top of
which forkers add their own protocol, their own obfuscation, their own everything.

Analogy: just as one transformer architecture underlies different LLMs,
here one cryptographic/network framework underlies different VPNs.

What is already there (Base) — and actually works

- "core/crypto.rs" — primitives (XChaCha20-Poly1305, X25519, Ed25519, HKDF,
  Argon2id). "SymmetricKey" is not Clone (the secret must not be duplicated), bytes
  are accessible only within the crate ("pub(crate)"), not through public FFI.
- "core/framing.rs" — TLV framing with a version field and a strict "MAX_FRAME_SIZE"
  (16 MiB) — on both encode and decode, including a check before buffer allocation.
- "core/identity.rs" — Identity / Master-ID = SHA-256(Ed25519 pubkey)
- "core/handshake.rs" — minimal handshake: X25519 + Ed25519, the signature
  covers protocol_id/version/ephemeral, HKDF for session keys takes its
  salt from the hash of the full transcript (protocol_id + version + both identities +
  both ephemeral pubkeys). It is split into two explicit paths instead of one "finish()"
  with a decorative flag: "finish_verified()" — the peer's pubkey came from
  an independent source; "finish_tofu()" — the pubkey is taken from the message itself
  (trust-on-first-use), returns the accepted key so that the calling code
  cannot silently forget that it trusted the key without verification.
- "core/session.rs" — frame encryption/decryption, AAD is now =
  VBF_VERSION + FrameType byte + counter (not just the counter) — tampering
  with the version or frame type also breaks the Poly1305 tag. "OrderingGuarantee" —
  an explicit constructor parameter to prevent accidental use over UDP/QUIC.
- "core/examples/peer.rs" — a working example: two processes actually
  connect over TCP, perform a handshake, and exchange encrypted messages.
  Run:
  cargo run --example peer -- server 127.0.0.1:9000
cargo run --example peer -- client 127.0.0.1:9000
- "net/" — a rust-libp2p-based scaffold (Kademlia DHT). "BootstrapNode.peer_id"
  is now mandatory (not "Option") — a trusted bootstrap node without
  identity verification allows node impersonation. There is a separate, explicitly named
  "UntrustedDiscoveryNode" for cases where the risk is knowingly accepted.
  Addresses are typed "Multiaddr", not "String". "MemoryStore" is a known
  limitation of the current stub (the DHT does not survive restarts); a persistent
  store is the next step before real-world use.

What was removed

"ffi-android/" and "ffi-desktop/" were removed from the workspace: they contained only
TODO stubs without a single exported function — that is, a structure with no
functional value. They will be brought back when a real API is available on top of core.

What is deliberately NOT included in the base

This is not forgotten — it is a deliberate boundary between "framework vs fork":

- Peer discovery through DHT in the handshake example — the peer is passed
  manually (IP:port); actual discovery is the responsibility of "net/" + the fork
- Sliding-window anti-replay, UDP/QUIC transport — protocol logic belongs to the fork
  ("OrderingGuarantee" currently supports strict ordering only)
- Traffic obfuscation (Hysteria2-style, mixnet) — Standard/Pro tiers
- Password/PIN generation, UI, production bootstrap-node configuration

The example ("peer.rs") uses "handshake::finish_tofu()" — this protects
only against passive eavesdropping, not against MITM attacks during the first
encounter (the accepted pubkey is printed with an explicit "not independently
verified" label). Real protection requires "handshake::finish_verified()" with a
pubkey from an independent source (DHT, a contact exchanged in advance) —
this is the next step for a fork, not part of the bare framework.

Known limitations not addressed in this version

These are documented honestly to avoid creating the illusion of greater readiness:

- "FrameType::extension(u8)" is the only validated constructor for
  Extension types (0x80-0xFF), but "FrameType::Extension(v)" as a
  tuple variant remains a public constructor that bypasses validation;
  "encode()" catches this before sending data over the wire, but constructing
  an invalid value in memory is still possible
- No rekey/key-epoch API — when the counter ("u64", practically unreachable
  within a reasonable time) is exhausted, the Session simply stops working;
  recreating the session is the responsibility of the calling code
- No test for low-order/invalid X25519 public keys — "x25519-dalek"
  performs clamping according to the specification, but there is no separate
  test for this case in this version
- Streaming parser ("NeedMoreData" vs "Malformed") is not implemented —
  "core/examples/peer.rs" reads frames manually using "read_exact";
  there is no general-purpose "FrameDecoder" for streams in "core"
- CI (fmt/clippy/test/audit) is not configured

Principle

Cryptographic primitives and DHT are audited libraries (RustCrypto,
rust-libp2p), not custom implementations. A bug in a primitive would spread
to all forks at once, so reliability matters more than originality here.
The protocol/features built on top are the forkers' domain, where experimentation
is both possible and necessary.

Stack

Layer| Crate| License
AEAD| "chacha20poly1305"| MIT/Apache-2.0
ECDH| "x25519-dalek"| MIT
Signatures| "ed25519-dalek"| MIT
KDF| "hkdf", "argon2"| MIT/Apache-2.0
DHT| "libp2p" (kad)| MIT/Apache-2.0

There are no GPL/AGPL dependencies in this repository. If an AGPL component
of the ecosystem is needed (self-hosted services), it lives in a separate
repository/process, communicates over the network, and is not linked directly.
FFI (Android/desktop) is not in this repository yet — see "What was removed".

Structure

Skhoron-VBF/
├── core/          crypto, framing, handshake, session, identity — platform-independent
│   └── examples/  peer.rs — working TCP example of handshake+encryption
├── net/           libp2p DHT scaffold
└── LICENSE        MIT

Building

cargo build --workspace
cargo test -p skhoron-vbf-core

Status

Early stage. "core" compiles and contains working cryptographic primitives
and framing with tests. Handshake/protocol — not implemented, next step.