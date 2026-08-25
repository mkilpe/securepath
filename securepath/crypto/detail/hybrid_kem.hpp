// SPDX-License-Identifier: MIT

#pragma once

#include "../suite.hpp"

#include <securepath/serialisation/sequence.hpp>
#include <securepath/util/span.hpp>
#include <securepath/util/types.hpp>

#include <botan/secmem.h>

#include <cstdint>

namespace securepath::crypto::detail {

/**
 * Hybrid KEM: X25519 (X448) + ML-KEM-768 (ML-KEM-1024), combined X-Wing style with
 *   key = HKDF-SHA3-256(ikm = ss_pq || ss_x || ct_x || pk_x, salt = empty,
 *                       info = "securepath-kem-v1/" || to_string(suite), 32 octets)
 */

struct kem_public_key {
	suite id{};
	octet_vector x_pk;
	octet_vector pq_pk;
};

struct kem_private_key {
	suite id{};
	Botan::secure_vector<std::uint8_t> x_sk;
	Botan::secure_vector<std::uint8_t> pq_seed;
};

struct kem_encapsulation {
	octet_vector ct_x;
	octet_vector ct_pq;
	Botan::secure_vector<std::uint8_t> key;
};

/// what public_key::encrypt() produces; DER SEQUENCE, version 1
class hybrid_ciphertext {
public:
	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version & id & ct_x & ct_pq & iv & encrypted & tag;
	}

	std::uint16_t version{1};
	suite id{};
	octet_vector ct_x;
	octet_vector ct_pq;
	octet_vector iv;
	octet_vector encrypted;
	octet_vector tag;
};

std::size_t const kem_key_size = 32;

kem_private_key generate_kem_private_key(suite);
/// throws invalid_key on bad key material
kem_public_key kem_public_part(kem_private_key const&);
/// throws invalid_key when the public key does not fit the suite
kem_encapsulation kem_encapsulate(kem_public_key const&);
/// throws bad_ciphertext for wrong sizes; ML-KEM implicit rejection makes other failures silent (garbage key)
Botan::secure_vector<std::uint8_t> kem_decapsulate(kem_private_key const&, octet_span ct_x, octet_span ct_pq);
/// the combiner alone, exposed for known answer tests
Botan::secure_vector<std::uint8_t> combine_shared_secrets(suite, octet_span ss_pq, octet_span ss_x, octet_span ct_x, octet_span pk_x);

}
