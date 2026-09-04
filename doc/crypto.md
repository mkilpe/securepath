# crypto library (post-quantum, Botan 3)

Post-quantum cryptography on Botan (>= 3.9): ML-DSA signatures, hybrid X25519/ML-KEM
public-key encryption, AES-256-GCM, SHA-3, an own certificate format and key/secret
storage. Measured on Botan 3.9.0: ML-DSA-65 pk 1952 B, sig 3309 B, sign 1.8 ms;
ML-KEM-768 pk 1184 B, ct 1088 B. Botan exposes no ML-DSA context-string API, so domain
separation is done in the message (see Signatures).

## Design principles

* Quantum-safe by construction: no RSA, ECDSA or classic DH anywhere. Classical
  primitives appear only inside hybrids.
* Every key, signature, encrypted key and handshake hello carries a suite id so
  parameter sets can move later (PQ-to-PQ).
* Botan is the only backend.

## Suites

```c++
enum class suite : std::uint16_t {
    pq1      = 1, // ML-DSA-65 + X25519/ML-KEM-768  + AES-256-GCM + SHA3-512  (NIST level 3, default)
    pq1_high = 2, // ML-DSA-87 + X448/ML-KEM-1024   + AES-256-GCM + SHA3-512  (NIST level 5)
};
suite default_suite();           // pq1
std::string_view to_string(suite);
```
Serialised as an unsigned 16-bit integer. Unknown values -> `unknown_suite` (crypto_error).
Signatures are pure ML-DSA; a composite suite id can be added later.

## Keys

An identity is one ML-DSA signing key plus one hybrid KEM key (X25519 + ML-KEM).

```c++
class public_key {
    public_key_id id() const;                  // SHA3-256 over asn_der(suite, sig_pk, kem_x_pk, kem_pq_pk)
    crypto::suite suite() const;
    octet_vector encrypt(octet_vector const& plaintext) const;               // hybrid KEM + AES-256-GCM, see "Public-key encryption"
    bool verify(signature const&, octet_vector const& data, std::string_view context = {}) const;
    void sign_me(private_key const&);  bool verify_me() const;               // self-signature (context "sp-key")
    void add_certificate_id(certificate_id); void remove_certificate_id(certificate_id);
    std::set<certificate_id> get_cert_ids() const; bool references_certificate(certificate_id const&) const;
    void serialise(serialisation::serialiser&); void serialise(serialisation::deserialiser&);
};
class private_key {
    public_key_id id() const;  crypto::suite suite() const;  crypto::public_key public_key() const;
    void set_public_key(crypto::public_key);                                 // re-signs, must have the same id
    signature sign(octet_vector const& data, std::string_view context = {}) const;
    octet_vector decrypt(octet_vector const& ciphertext) const;              // throws bad_ciphertext
    void metadata(std::string const& key, octet_vector data);  octet_vector metadata(std::string const& key) const;
    void serialise(serialisation::serialiser&); void serialise(serialisation::deserialiser&);
};
private_key generate_private_key(suite = default_suite());                   // key_generation.hpp
```

Wire formats (ASN.1 DER through the serialisation library; every type is a SEQUENCE
and ends with `trailing_data` for forward-compatible extension):

| type | fields |
|---|---|
| `public_key` | version u16 = 2, suite, sig_pk, kem_x_pk, kem_pq_pk, certificate_ids (SET), sig (signature), trailing |
| `private_key` | version u16 = 2, public_key, sig_seed (32 B), kem_x_sk (32/56 B), kem_pq_seed (64 B), metadata (MAP string->octets), trailing |
| `signature` | version u32 = 2, issuer (public_key_id), data |
| `public_key_id` | id (32 B) |

Private material is held in `Botan::secure_vector` inside the impl objects and wiped on
destruction; the *serialised* private key is an ordinary `octet_vector` (callers encrypt it
at rest via `private_data_access`). Seeds are stored, not expanded keys: ML-DSA 32 B,
ML-KEM 64 B (d || z), X25519 32 B / X448 56 B.

## Signatures

ML-DSA (Botan `PK_Signer`, "Randomized") over a framed message

    to_sign = "SPSIG" || u8(len(context)) || context || message

The frame gives per-use domain separation since Botan exposes no FIPS 204 context
parameter. Contexts in use: `""` (application data, default), `"sp-key"` (public key
self-signature), `"sp-cert"` (certificates), `"sp-revocation"`. Callers such as spsync
pass their own (`"spsync-record"`, `"spsync-assign"`). ML-DSA hashes internally; no
pre-hashing (the record digest *is* the message where callers already digest).
`signature::issuer()` is the signer's `public_key_id`.

## Public-key encryption (hybrid KEM)

`public_key::encrypt` / `private_key::decrypt` is a single-shot KEM + AEAD (HPKE-like):

1. ephemeral X25519 (X448 for pq1_high) key pair; `ss_x = X25519(eph_sk, kem_x_pk)`, `ct_x = eph_pk`
2. `(ct_pq, ss_pq) = ML-KEM.Encaps(kem_pq_pk)`
3. combiner (X-Wing style, Botan has no public hybrid KEM outside TLS):
   `key = HKDF-SHA3-256(ikm = ss_pq || ss_x || ct_x || kem_x_pk, salt = empty, info = "securepath-kem-v1/" || to_string(suite), 32 B)`
4. AES-256-GCM, 12 B random iv, AAD = recipient `public_key_id` bytes
5. ciphertext blob = DER SEQUENCE(version u16 = 1, suite, ct_x, ct_pq, iv, encrypted, tag)

Decrypt checks the suite against the private key, decapsulates both halves (ML-KEM
implicit rejection keeps failures uniform), derives `key`, opens the AEAD; any failure
throws `bad_ciphertext`. Sizes for pq1: ct_x 32 B + ct_pq 1088 B + 12 + 16 -> ~1.2 KB overhead.

`encrypted_key` is DER (version u32 = 1, encryptor_id, data) with `data` =
`public_key::encrypt(content_key)`. `enveloped_content` (version, keys, iv, encrypted,
tag) with `envelope()/decrypt()`: a fresh AES-256-GCM content key per envelope, one
`encrypted_key` per recipient.

## Symmetric primitives

| header | backend | notes |
|---|---|---|
| `hash.hpp` | `Botan::HashFunction` | `hash_algorithm { sha256 = 0, sha512 = 1, sha3_256 = 2, sha3_512 = 3 }` |
| `hmac.hpp`, `mac.hpp` | `Botan::MessageAuthenticationCode` "HMAC(...)" | |
| `hkdf.hpp` | `Botan::KDF` "HKDF(SHA-3(512))" etc. | |
| `pbkdf2.hpp` | `Botan::PasswordHashFamily` | PBKDF2 and Argon2id; `argon2id` is the recommended password KDF |
| `aes_gcm.hpp`, `auth_stream_cipher.hpp`, `stream_cipher.hpp` | `Botan::AEAD_Mode` "AES-256/GCM" | streaming process()/process_auth()/tag(); implicit-counter variant = nonce `iv || u64 counter`, counter incremented per tag(); seek() where the header documents it |
| `aes.hpp` | `Botan::StreamCipher` "CTR-BE(AES-256)" | seekable stream cipher |
| `random.hpp` | `Botan::System_RNG` | `random_octet_vector`, `random_string`, `random_data` |
| `encoding.hpp` | `Botan::base64url_*` | |
| `encrypted_content.hpp` | AES-256-GCM | |

## Certificates and trust

Own certificate format (not X.509): `certificate` (type, DER data, signature, optional
revocation, trailing), `key_certificate_data` (subject id, ca_level, restrictions,
metadata), `identifier_certificate_data`, `property_certificate_data`,
`certificate_revocation`, `certificate_chain` and `create_certificate_chain()`.
Certificates are signed with context "sp-cert", revocations with "sp-revocation".
Chain verification caps the length at 16 links and consults the verifier's own
certificate store for revocations in addition to any stapled one.

`root_public_key()` returns the trust anchor set with `set_root_public_key(public_key)`
(process-wide, thread-safe) and throws `errc::no_such_root_key` when none is set;
deployments load it from configuration, tests generate their own through
`test::pki_test_context`.

## Storage

`public_key_access/_cache/_database`, `certificate_access/_cache/_database`,
`shared_secret_access/_cache/_database`, `private_data_access/_cache/_database` on the
`database` library (sqlite). Blob columns accept the post-quantum sizes (~2 KB public
keys, ~3.4 KB signatures, ~1.2 KB per envelope member).

## Test coverage

* known-answer tests: SHA3/HKDF/AES-GCM vectors, the KEM combiner pinned with a fixed
  seed-derived vector, signature framing pinned
* `[security]` tests: bit flips in ML-DSA signatures, KEM ciphertexts, AEAD tags and
  wrong-recipient decrypts must all fail; suite mismatch must be rejected
* size assertions so protocol limits downstream stay honest
* `crypto_test_support` (`test::pki_test_context`) is a library; consumers' tests link it

## Not in this library

Transport security (TLS 1.3 over standalone asio with raw public keys, hybrid key
exchange) lives in `network` — see [network.md](network.md).
