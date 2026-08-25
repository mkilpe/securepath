// SPDX-License-Identifier: MIT

#pragma once

#include "../certificate_id.hpp"
#include "../public_key_id.hpp"
#include "../signature.hpp"
#include "../suite.hpp"

#include <securepath/serialisation/deserialiser.hpp>
#include <securepath/serialisation/serialiser.hpp>
#include <securepath/serialisation/types.hpp>
#include <securepath/util/span.hpp>
#include <securepath/util/types.hpp>

#include <cstdint>
#include <set>

namespace securepath::crypto {

/// wire format: version, suite, sig_pk, kem_x_pk, kem_pq_pk, certificate_ids, sig, trailing
class public_key_impl {
public:
	public_key_impl() = default;
	public_key_impl(suite s, octet_vector sig_pk, octet_vector kem_x_pk, octet_vector kem_pq_pk);

	bool is_valid() const;
	/// SHA3-256 over asn_der(suite, sig_pk, kem_x_pk, kem_pq_pk)
	public_key_id construct_id() const;
	/// what sign_me() signs (context "sp-key"): everything except the signature itself
	octet_vector signature_content() const;
	/// ML-DSA verification of an already framed message; false for any failure
	bool verify_framed(octet_span framed, octet_span sig) const;

	void serialise(serialisation::serialiser&);
	void serialise(serialisation::deserialiser&);

public:
	std::uint16_t version_{2};
	suite suite_{default_suite()};
	octet_vector sig_pk_;
	octet_vector kem_x_pk_;
	octet_vector kem_pq_pk_;
	std::set<certificate_id> certificate_ids_;
	signature sig_;
	serialisation::trailing_data trailing_;
	public_key_id id_;
};

}
