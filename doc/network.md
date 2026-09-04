# network library (TLS 1.3 transport with post-quantum authentication)

Encrypted, message-preserving connections and servers over standalone asio. Confidentiality
comes from TLS 1.3 with a hybrid post-quantum key exchange; peer authentication is ML-DSA
with our own certificate chains, run as a short handshake inside the TLS channel and bound
to it through the TLS exporter. Botan's TLS signs its handshakes only with RSA or ECDSA, so
ML-DSA authentication does not live inside TLS itself; the TLS-level raw key is an ephemeral
ECDSA binder that carries no identity (see Security notes).

Companion documents: [crypto.md](crypto.md) (algorithms and wire contract),
[threat_model.md](threat_model.md).

## Public API

```c++
namespace securepath::network {
class context : public handshake_constructor {
    context(asio::io_context&, crypto::public_key_access&, crypto::certificate_access&,
            crypto::shared_secret_access&, crypto::private_data_access&);
    ... public_keys(), certificates(), shared_secrets(), private_data(), io_context()
    void add_handshake(int tag, std::function<handshake_base_ptr(handshake_data const&)>);
    virtual version_number product_version() const; virtual std::string personal_identifier() const;
    virtual bool authenticate_remote() const; void set_authenticate_remote(bool);
    crypto::suite suite() const; void set_suite(crypto::suite);   // selects the TLS group
};
namespace handshake_tag { enum type { unknown = 0, public_key = 2, shared_secret = 4 }; }
void enable_client_pk_handshake(context&); void enable_server_pk_handshake(context&);
void enable_client_ss_handshake(context&); void enable_server_ss_handshake(context&);
class encrypted_connection { /* connect/send/close/state/endpoints/remote_key_id, on_* hooks */ };
class encrypted_server     { /* start/close/create_connection/on_accept */ };
class encrypted_net_base   { /* shared plumbing; encrypted_net_base_params */ };
class net_base; class net_error; enum errc;
}
```

## Wire protocol

1. TCP connect.
2. **TLS 1.3 (Botan)**, policy: TLS 1.3 only; groups `HYBRID_X25519_ML_KEM_768` (suite pq1) or
   `HYBRID_SECP384R1_ML_KEM_1024` (pq1_high); ciphers AES-256/GCM; certificate types RawPublicKey
   on both sides, client authentication required; signature schemes ECDSA only; no session
   resumption/tickets (`Session_Manager_Noop`); ALPN `"securepath/2"`. Each `context` owns one
   ephemeral ECDSA P-256 key, generated at construction, used as the TLS raw key for both roles.
   The TLS stream is our own `tls_stream` over standalone asio built on
   `Botan::TLS::Client/Server` + `TLS::Callbacks`; all callbacks run on the connection's strand.
3. **sp handshake** as the first TLS application records. Every record on the stream, handshake
   and user data alike, is framed `u32 big-endian length || DER payload`. While the handshake is
   in progress a frame is capped at 256 KiB; once authenticated the cap is 16 MiB.
   - `client_hello { version = 2, suite, handshake_request (tag), client_id (random 16 B) }`
   - `server_hello { version = 2, suite, handshake_response, server_id (random 16 B), server_auth }`
     (a server that does not offer the requested tag answers `unknown` -> `errc::no_such_handshake`)
   - **pk** — the server authenticates first, so the client never discloses its identity to an
     unverified server:
     1. `server_auth` in the server_hello carries the server's
        `auth { public_key, certificate_chain, signature }` where
        `signature = private_key.sign(binding, "sp-tls-auth")` and
        `binding = exporter("EXPORTER-securepath-auth", context = role || client_id || server_id, 32 B)`
        (`role` = 0x01 client / 0x02 server, so the two directions bind differently).
     2. The client verifies it and only then replies with its own `auth`; a client without an own
        key sends empty credentials (anonymous), which the server accepts only when
        `authenticate_remote()` is off.
     3. The server verifies the client and answers `handshake_ack`; only then does the client
        report the connection established.

     Verification of an `auth`: the chain is authentic against `context.public_keys()` (root via
     `crypto::root_public_key()`), at most 16 links, with revocation checked against the
     verifier's own certificate store (a stapled revocation the peer omitted does not go
     unnoticed); the chain subject must equal the sent key; the signature must verify over the
     role-separated binding; for clients, an optional hostname restriction must match the address
     dialled. Then `remote_key_id()` is set.
   - **ss** — reveals no identity, so the client speaks first (`server_auth` stays empty):
     each side sends `auth_ss { secret_id, mac }` (client first, server after verifying) with
     `mac = HMAC-SHA3-512(shared_secret, binding)` over its own role-separated binding; the
     secret is looked up in `shared_secrets()` by the id in the message. The server's mac is the
     client's confirmation, so no ack is needed.
4. `on_connected()`; `send(octet_span)` becomes one framed record, delivered as one
   `on_received(octet_span)` — message boundaries are preserved.
5. Close: TLS close_notify, then TCP shutdown; `on_disconnected(error)` once.

Sizes: an `auth` message is ~2 KB public key + 3.3 KB signature + chain (per link ~5.6 KB)
-> 10-15 KB per side; the handshake timeout is 10 s by default.

## Implementation layout

```
network/
  net_base.*  net_error.*                           connection/server plumbing, error category
  encryption/context.*                              Botan policy/credentials/session manager
  encryption/tls_stream.*                           Botan TLS over asio
  encryption/framing.*                              u32 length framing and the frame caps
  encryption/handshake/{handshake_base,handshake,protocol,pk_handshake,ss_handshake}.*
                                                    hello exchange and the pk/ss variants above
  encryption/encrypted_connection.*  encrypted_server.*  encrypted_net_base.*
  test/  test/support
```

## Security notes

* The hybrid key exchange gives confidentiality against harvest-now-decrypt-later;
  authentication is ML-DSA (PQ). The ECDSA raw key contributes nothing to security: each side
  signs the exporter of *its own* channel with its ML-DSA key, and a man-in-the-middle holds two
  different channels with two different exporters, so it cannot produce the legitimate peer's
  signature over its own exporter. When Botan's TLS gains ML-DSA signature schemes (an IETF
  draft), authentication can move inside TLS via a handshake version bump without a wire change.
* Exporter binding follows RFC 8446 §7.5 / RFC 9266-style channel binding; the role byte and
  both hello ids in the context prevent reflection and cross-connection replay.
* Server-first authentication: the client verifies the server before disclosing its own
  identity; anonymous clients are possible where the server allows them.
* Pre-authentication resource use is bounded: the 256 KiB handshake frame cap and the 16-link
  chain cap limit what an unauthenticated peer can make the receiver allocate or verify
  (see [threat_model.md](threat_model.md)).
* Downgrade: `suite` is authenticated by TLS's own transcript (group choice) and again in the
  hellos, which are inside TLS; a mismatch between negotiated group and suite is an error.
