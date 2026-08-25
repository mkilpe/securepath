// SPDX-License-Identifier: MIT

#pragma once

#include "hybrid_kem.hpp"
#include "../public_key.hpp"
#include "../suite.hpp"

#include <securepath/serialisation/deserialiser.hpp>
#include <securepath/serialisation/serialiser.hpp>
#include <securepath/serialisation/types.hpp>
#include <securepath/util/span.hpp>
#include <securepath/util/types.hpp>

#include <botan/secmem.h>

#include <cstdint>
#include <map>
#include <string>

namespace securepath::crypto {

/// wire format: version, public_key, sig_seed, kem_x_sk, kem_pq_seed, metadata, trailing
class private_key_impl {
public:
	private_key_impl() = default;
	/// builds the matching (unsigned) public key from the seeds; throws invalid_key for bad material
	private_key_impl(suite s, Botan::secure_vector<std::uint8_t> sig_seed, detail::kem_private_key kem);

	bool is_valid() const;
	/// ML-DSA signature over an already framed message
	octet_vector sign_framed(octet_span framed) const;
	Botan::secure_vector<std::uint8_t> decapsulate(octet_span ct_x, octet_span ct_pq) const;

	void serialise(serialisation::serialiser&);
	void serialise(serialisation::deserialiser&);

public:
	std::uint16_t version_{2};
	suite suite_{default_suite()};
	public_key public_key_;
	Botan::secure_vector<std::uint8_t> sig_seed_;
	Botan::secure_vector<std::uint8_t> kem_x_sk_;
	Botan::secure_vector<std::uint8_t> kem_pq_seed_;
	std::map<std::string, octet_vector> metadata_;
	serialisation::trailing_data trailing_;
};

}
