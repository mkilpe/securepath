# Threat model — securepath crypto and network libraries

Status: written 2026-08-25 against the state of this repository (crypto reworked on
Botan 3.9, network rebuilt on TLS 1.3 with exporter-bound ML-DSA authentication).
Companion documents: [crypto.md](crypto.md) (algorithm and wire contract),
[network.md](network.md) (transport design). This document is the intended input
for an external security review; §10 lists what such a review should focus on.

## 1. Scope

In scope: the `crypto` library (keys, signatures, hybrid KEM encryption, envelopes,
certificates and chains, key/secret storage) and the `network` library (TLS transport,
sp handshake, connection/server classes), as used by spsync and packet_transport.

Out of scope: application-level logic built on top (spsync replication semantics,
packet_transport queueing), the deferred key-distribution components (remote_object,
key_server, key_client_lib), host/OS security, side-channel resistance beyond what
Botan provides, and traffic analysis (message sizes and timing are visible).

## 2. Assets

| asset | held in |
|---|---|
| identity private keys (ML-DSA + hybrid KEM halves) | `private_key` impl (Botan `secure_vector`); serialised via `private_data_access` |
| root public key (trust anchor) | process-wide, set at startup via `set_root_public_key()` |
| certificate chains and public keys | `public_key_access` / `certificate_access` stores (sqlite) |
| shared secrets (ss handshake) | `shared_secret_access` store |
| session traffic keys | inside Botan TLS, never exported (only the RFC 5705 exporter derives from them) |
| envelope content keys | ephemeral per envelope |

## 3. Adversary model

* **A1 Network attacker** — full Dolev-Yao control of the network: observe, modify,
  inject, replay, reorder, drop, and actively man-in-the-middle any connection.
* **A2 Future quantum adversary** — records traffic today, breaks classical
  public-key crypto later (harvest-now-decrypt-later), or forges classical
  signatures at attack time.
* **A3 Malicious peer** — a counterparty with a valid connection (possibly validly
  certified) sending malformed or adversarial data.
* **A4 Storage attacker** — reads or tampers with the sqlite stores of a party
  (public keys, certificates, shared secrets, private data).
* Not modelled: an attacker on the host with the process's memory (host compromise
  defeats any library), and denial of service beyond basic input hardening (§7.7).

## 4. Security goals

1. **Confidentiality against A1 and A2**: session traffic and envelope contents
   remain secret even if all classical crypto is later broken (hybrid: the attacker
   must break X25519 *and* ML-KEM at the time of attack).
2. **Peer authentication against A1 and A2**: a completed connection's
   `remote_key_id()` is the identity whose ML-DSA key signed this channel, anchored
   in the root key through certificate chains. Classical-signature forgery must not
   enable impersonation.
3. **Integrity and replay protection** for all transported data (TLS records).
4. **Domain separation**: a signature made for one purpose is unusable for another
   (contexts `""`, `"sp-key"`, `"sp-cert"`, `"sp-revocation"`, `"sp-tls-auth"`, plus
   caller contexts).
5. Non-goals: anonymity, deniability, traffic-analysis resistance, FIPS 140
   validation (Botan has none; the assurance story is BSI-funded development).

## 5. Architecture and trust boundaries

```
 application (spsync, packet_transport)
 ------------------------------- on_connected() only after sp auth
 sp handshake      hello/auth messages, framed        <- custom (§6.1)
 framing           u32 length || DER, 16 MiB cap      <- custom, trivial
 TLS 1.3 (Botan)   hybrid x25519/ML-KEM-768 KEX,
                   AES-256-GCM records, raw-key auth
                   with an EPHEMERAL ECDSA P-256 key  <- standard protocol
 TCP / asio
```

Key point: the TLS layer is *unauthenticated as to identity* (its raw key is an
ephemeral per-context binder contributing nothing to security). Everything the
application may rely on comes from the sp handshake above it. Until `on_connected()`,
the implementation sends nothing except handshake messages.

## 6. Custom constructions and their security arguments

### 6.1 Exporter-bound authentication (replaces "raw ML-DSA key in TLS")

Construction: after TLS is active, each side signs
`binding = exporter("EXPORTER-securepath-auth", role || client_id || server_id, 32)`
with its ML-DSA identity key (context `"sp-tls-auth"`) and sends
`auth { public_key, certificate_chain, signature }`.

This is the standard channel-binding pattern (RFC 5705 exporters; same shape as TLS
1.3 post-handshake client authentication and RFC 9266), not a novel protocol.

*MITM argument*: an A1/A2 attacker relaying between victim A and victim B holds two
TLS channels with two independent exporter values (the exporter derives from each
channel's hybrid key exchange). To impersonate B to A it must present a signature by
B's ML-DSA key over *A's channel's* binding — which B never produces. Breaking the
ephemeral ECDSA binder gains nothing: the attacker still cannot forge ML-DSA.

*Preconditions the implementation enforces* (each closes a historical break of this
pattern):
- TLS 1.3 only — renegotiation does not exist (triple-handshake class).
- Session resumption and tickets disabled (`Session_Manager_Noop`) — the exporter
  always derives from a full fresh key exchange.
- `role` byte plus both hello nonces in the exporter context — no reflection, no
  cross-connection replay, each direction binds differently.
- Per-use signature contexts — an `auth` signature cannot be replayed as a
  certificate or record signature and vice versa.
- Suite id appears in the hellos (inside TLS) and must match the negotiated TLS
  group — parameter downgrade is detected even above TLS's own transcript security.

### 6.2 Certificate model and chain validation

> **Update 2026-08-25 (post-review):** the two revocation weaknesses found in the internal
> review are fixed. (1) Chain validation now consults the verifier's own certificate store
> (`certificate_chain::is_authentic` takes a `certificate_access const&`), so a revoked
> certificate whose stapled revocation the presenter omitted is still rejected — revocation is
> no longer presenter-controlled. (2) A stapled revocation counts only when it targets this
> certificate (matching id) and is signed by the issuer (`certificate::is_revoked`); a
> transplanted or forged revocation is ignored rather than used to force-revoke a valid
> certificate. Tests: `certificate ignores a forged or mismatched stapled revocation`, and the
> `certificate_chain` store-omitted / transplanted-revocation sections (mutation-checked).

Bespoke DER certificate format (2021 design, signature swap to ML-DSA): certificate
{version, type, data, signature, optional revocation, trailing}; key certificates
carry {subject key id, ca_level, restrictions (hostname), metadata}. Chains anchor
in the root key (`set_root_public_key()`, provisioned out of band by the deployment).

Validation rules (in `certificate_chain`): each link's certificate is signed by the
previous link's key (root first), certificate subject == next key's id, each key's
self-signature verifies, cert ids referenced by the key match, ca_level strictly
decreases with depth and level 0 cannot certify, a link may only narrow (never
widen) its issuer's hostname restrictions, any valid revocation on a link makes the
chain not authentic, and for servers the dialled hostname must satisfy the
restriction set.

Assessment: deliberately *not* X.509 — the format is ~5 fields with a strict DER
codec, removing the X.509 parsing/path-building bug surface, at the cost of
validation logic that has no external review history. This logic is the highest-value
audit target (§10). Adversarial tests cover: tampered data/type/signature, wrong
signature context, forged revocation, wrong issuer, broken self-signature, subject
mismatch, ca-level violations, revoked links, unknown root, restriction widening.

### 6.3 Hybrid KEM combiner (envelopes / public-key encryption)

`key = HKDF-SHA3-256(ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519, info =
"securepath-kem-v1/" || suite)` — follows the X-Wing construction (which carries a
security proof; IND-CCA if either component KEM holds, given ML-KEM's ciphertext
binding). ML-KEM implicit rejection keeps decapsulation failures uniform; the AEAD
opening is the only failure signal (`bad_ciphertext`). KATs pin the derivation.

### 6.4 ML-DSA context framing

Botan exposes no FIPS 204 context parameter, so contexts are framed into the signed
message: `"SPSIG" || u8(len(ctx)) || ctx || message`. This is domain separation with
an unambiguous (length-prefixed) encoding; it is *not* FIPS-204-ctx interoperable,
which is acceptable since no external party verifies these signatures.

## 7. Threats and mitigations

| # | threat (adversary) | mitigation |
|---|---|---|
| 7.1 | passive recording, quantum decryption later (A2) | hybrid KEX in TLS; hybrid KEM in envelopes — PQ component protects both |
| 7.2 | active MITM / impersonation (A1, A2) | §6.1 binding; chains to root; classical binder contributes nothing |
| 7.3 | parameter downgrade | TLS 1.3 transcript + suite echo inside TLS (§6.1) |
| 7.4 | replay/reflection of auth messages | exporter freshness per session + role/nonces in context |
| 7.5 | cross-protocol signature reuse | signature contexts everywhere (§6.4) |
| 7.6 | malformed inputs, decompression-bomb-style DER (A3) | strict DER codec with depth limit (64) and size caps; 16 MiB frame cap; handshake timeout; AEAD tag checked in constant time |
| 7.7 | pre-authentication resource exhaustion (A1) | bounded per-connection buffers, timeout, caps. As of 2026-08-26 the frame reader is capped at max_handshake_frame_size (256 KiB) until the peer is authenticated (raised to 16 MiB after), and certificate_chain validation rejects chains longer than max_chain_length (16 links), bounding pre-auth allocation and signature-verification work. *Connection rate limiting remains the application's job* — accepted residual |
| 7.8 | tampered public-key/certificate store (A4) | harmless for trust: authenticity always re-derives from the root key via chains; a tamperer can at most delete (DoS). Revocation is now read from this store during validation (fixed 2026-08-25), so store integrity also bounds revocation availability |
| 7.9 | stolen private-data store (A4) | **residual**: `private_data_database` does not itself encrypt at rest; protection is file permissions unless the application wraps values — see §8 |
| 7.10 | low-entropy shared secret, offline guessing (A1) | **requirement**: ss-handshake secrets must be high-entropy keys, not passwords — an active attacker completing TLS receives an HMAC over a known binding and can grind a weak secret offline; see §8 |
| 7.11 | identity key compromise | revocation objects exist; **no certificate expiry** — see §8 |
| 7.12 | root key compromise | out of scope of the library (single anchor by design); deployments should plan a root rollover procedure using the suite/version fields |
| 7.13 | backend defects | single backend (Botan 3.9, BSI-funded PQC/TLS); KATs pin primitive behaviour; upgrade path tracked |

## 8. Residual risks and open items (honest list)

1. **No external review yet** of §6.1 spec and §6.2 validation logic — the two
   bespoke pieces. Small surface; audit recommended before publication/production.
2. **No certificate validity periods**: the format has no expiry; revocation is the
   only recall mechanism. As of 2026-08-25 chain validation consults the verifier's own
   certificate store for revocations (not only the presenter's stapled copy), so a revoked
   certificate is rejected as long as the revocation has reached that store — distribution of
   revocations to stores is now the operational requirement. Consider adding a validity
   window as a versioned extension before wide deployment.
3. **At-rest encryption** of `private_data_database` is the caller's responsibility
   today (7.9). Consider an encrypted backend (Argon2id-derived key) in the library.
4. **ss handshake entropy requirement** (7.10) is documentation-enforced only.
   Moving to TLS external PSK (authenticates inside the handshake) or a PAKE would
   lift it; deliberately deferred.
5. **Anonymous client mode** (`authenticate_remote() == false`): the server learns
   nothing about the client; any authorisation then rests entirely on the
   application. The default is mutual authentication.
6. Secrets exist as plain `octet_vector` at (de)serialisation boundaries; wiping is
   guaranteed only inside the impl objects (`secure_vector`).
7. No FIPS 140 validation (Botan has none) — known, accepted (§4).
8. packet_transport signs with the default context, matching old behaviour; a
   dedicated `"sp-packet"` context would be cleaner and is a wire change (open
   decision).

## 9. Validation status

150 crypto test cases (KATs: SHA-2/3, RFC 4231/5869/6070/4648, NIST GCM, pinned
combiner and framing vectors; `[security]`: bit flips on signatures/KEM
ciphertexts/AEAD, wrong recipient, suite mismatch, certificate/chain adversarial
suite) and 34 network cases (MITM-binding rejection, tampered auth, suite mismatch,
anonymous-client policy, wrong ss secret, concurrency, boundaries). Full tree:
12/12 suites, zero warnings.

## 10. External review focus (suggested order)

1. §6.1: the binding definition and its implementation in
   `network/encryption/handshake/` — check nothing is sent pre-auth, exporter inputs,
   role/nonce handling, error paths.
2. §6.2: `crypto/certificate_chain.cpp` validation order and failure handling.
3. The DER codec's behaviour on adversarial input (fuzzing the frame + hello + auth
   parsers is the cheapest additional assurance).
4. `tls_stream` state machine (write queue, shutdown, error propagation).
5. The residual list in §8 — confirm each is acceptable for the deployment at hand.

## 11. Planned de-risking

ML-DSA signature schemes for TLS are an active IETF draft; once Botan implements
them, authentication moves inside TLS and §6.1 retires (handshake version bump —
the hello version and suite id exist for exactly this migration). The OpenSSL 3.5 +
X.509 route (doc/network.md option c) remains the fallback that eliminates both
custom pieces at the cost of a second backend.
