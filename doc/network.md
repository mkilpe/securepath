# network library design (TLS 1.3 transport with post-quantum authentication)

Status: DECIDED 2026-08-25 — option (a) adopted (owner decision), with the migration path of
section "Security notes" kept open: when Botan TLS gains ML-DSA signature schemes (IETF draft),
authentication moves inside TLS via a handshake version bump. Original option analysis kept below.

## Finding that shaped this

Botan 3.9's TLS authenticates handshakes only with RSA or ECDSA (`Signature_Scheme::
all_available_schemes()`: no ML-DSA, EdDSA deliberately excluded upstream). So the plan's
"raw ML-DSA public key in TLS (RFC 7250)" cannot be done with Botan. Verified in the spike
(`scratchpad/botan-spike/tls_spike.cpp`): TLS 1.3 over standalone asio, hybrid
`x25519/ML-KEM-768`, AES-256-GCM, mutual raw public keys (ECDSA P-256), identical RFC 5705
exporters on both ends, ML-DSA-65 signature over the exporter verified across the channel.

Options:

| | confidentiality | authentication | backend | notes |
|---|---|---|---|---|
| (a) **Botan TLS 1.3 + exporter-bound ML-DSA auth** | TLS hybrid KEX (PQ) | ML-DSA over the TLS exporter, our certificate chains | Botan only | reviewed channel protocol, Boost-free; TLS raw key is an ephemeral ECDSA binder only |
| (b) own KEM handshake | ML-KEM + X25519 | ML-DSA-signed transcript | Botan only | our own protocol, more to get right, no TLS tooling |
| (c) OpenSSL 3.5 TLS | TLS hybrid KEX | ML-DSA certificates/raw keys natively in TLS | Botan + OpenSSL | `asio::ssl` works out of the box; two crypto backends, key plumbing Botan<->OpenSSL |

Why (a) is sound: the ephemeral TLS raw key is not trusted for identity. Each side signs
the exporter of *its own* channel with its ML-DSA key; a man-in-the-middle holds two
different channels with two different exporters and cannot produce the legitimate peer's
signature over its own exporter. Identity = ML-DSA key + certificate chain, exactly as in
the old public-key handshake; only the key exchange moved into TLS.

## Public API (kept for spsync and packet_transport)

```c++
namespace securepath::network {
class context : public handshake_constructor {          // no asio::ssl::context any more
    context(asio::io_context&, crypto::public_key_access&, crypto::certificate_access&,
            crypto::shared_secret_access&, crypto::private_data_access&);
    ... public_keys(), certificates(), shared_secrets(), private_data(), io_context()
    void add_handshake(int tag, std::function<handshake_base_ptr(handshake_data const&)>);
    virtual version_number product_version() const; virtual std::string personal_identifier() const;
    virtual bool authenticate_remote() const; void set_authenticate_remote(bool);
    crypto::suite suite() const; void set_suite(crypto::suite);                  // NEW: selects the TLS group
};
namespace handshake_tag { enum type { unknown = 0, public_key = 2, shared_secret = 4 }; }  // naked_ssl, diffie_hellman dropped
void enable_client_pk_handshake(context&); void enable_server_pk_handshake(context&);
void enable_client_ss_handshake(context&); void enable_server_ss_handshake(context&);
class encrypted_connection { /* unchanged: connect/send/close/state/endpoints/remote_key_id, on_* hooks */ };
class encrypted_server     { /* unchanged: start/close/create_connection/on_accept */ };
class encrypted_net_base   { /* unchanged minus the ssl members; encrypted_net_base_params unchanged */ };
class net_base, class net_error, enum errc (+ tls_failure), select.hpp  // unchanged
}
```
`enable_client_dh_handshake` is gone (anonymous DH has no PQ replacement and nothing needs it).

## Wire protocol

1. TCP connect.
2. **TLS 1.3 (Botan)**, policy: TLS 1.3 only; groups `HYBRID_X25519_ML_KEM_768` (suite pq1) or
   `HYBRID_SECP384R1_ML_KEM_1024` (pq1_high); ciphers AES-256/GCM; certificate types RawPublicKey
   on both sides, client authentication required; signature schemes ECDSA only; no session
   resumption/tickets (`Session_Manager_Noop`); ALPN `"securepath/2"`. Each `context` owns one
   ephemeral ECDSA P-256 key, generated at construction, used as the TLS raw key for both roles.
   The TLS stream is our own ~300-line `tls_stream` over standalone asio built on
   `Botan::TLS::Client/Server` + `TLS::Callbacks` (plan Q10 option a); all callbacks run on the
   connection's strand.
3. **sp handshake** as the first TLS application records. Framing for every record on the
   stream, handshake and user data alike: `u32 big-endian length || DER payload`, max 16 MiB.
   - `client_hello { version = 2, suite, handshake_request (tag), client_id (random 16 B) }`
   - `server_hello { version = 2, suite, handshake_response, server_id (random 16 B) }`
     (a server that does not offer the requested tag answers `unknown` -> `errc::no_such_handshake`)
   - **pk**: both sides send `auth { public_key, certificate_chain, signature }` where
     `signature = private_key.sign(binding, "sp-tls-auth")` and
     `binding = exporter("EXPORTER-securepath-auth", context = role || client_id || server_id, 32 B)`
     (`role` = 0x01 client / 0x02 server, so the two directions bind differently). Receiver:
     chain is authentic against `context.public_keys()` (root via `crypto::root_public_key()`),
     chain subject == the sent key, signature verifies, hostname restriction (if any) matches the
     address the client dialled; then `remote_key_id()` is set. `authenticate_remote() == false`
     on the server makes the client's `auth` optional (client still authenticates the server).
   - **ss**: both sides send `auth_ss { mac }` with `mac = HMAC-SHA3-512(shared_secret, binding)`,
     secret looked up in `shared_secrets()` by the peer's id. (TLS external PSK would also
     authenticate the handshake itself; kept as a later optimisation, same message flow.)
4. `on_connected()`; `send(octet_span)` becomes one framed record, delivered as one
   `on_received(octet_span)` — message boundaries are preserved as before.
5. Close: TLS close_notify, then TCP shutdown; `on_disconnected(error)` once.

Sizes: an `auth` message is ~2 KB public key + 3.3 KB signature + chain (per link ~5.6 KB)
-> 10-15 KB per side; the handshake timeout (10 s default) and the 16 MiB cap stay.

## Implementation layout

```
network/
  net_base.*  net_error.*  select.*                 ported as they are
  encryption/context.*                              Botan policy/credentials/session manager inside
  encryption/tls_stream.*                           Botan TLS over asio (the spike, productised)
  encryption/framing.*                              u32 length framing
  encryption/handshake/{handshake_base,handshake,protocol,pk_handshake,ss_handshake}.*
                                                    same state machine, messages above
  encryption/encrypted_connection.*  encrypted_server.*  encrypted_net_base.*
  test/ (31 old cases: engine tests become tls_stream tests) + test/support (no asio::ssl)
```
Dropped: `engine.*` (the packet/auth-cipher engine — TLS records replace it),
`dh_handshake.*`, `encrypted_connection_impl_ssl.hpp`, `test_data/ssl_test_data.hpp`.

## Security notes

* Hybrid key exchange gives confidentiality against harvest-now-decrypt-later; authentication
  is ML-DSA (PQ); the ECDSA raw key contributes nothing to security and may be replaced by any
  scheme Botan's TLS gains later (ML-DSA in TLS is an IETF draft) without a wire change.
* Exporter binding follows RFC 8446 §7.5 / RFC 9266-style channel binding; the role byte and
  both hello ids in the context prevent reflection and cross-connection replay.
* Downgrade: `suite` is authenticated by TLS's own transcript (group choice) and again in the
  hellos, which are inside TLS; a mismatch between negotiated group and suite is an error.
