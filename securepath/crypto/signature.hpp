// SPDX-License-Identifier: MIT

#pragma once

#include "public_key_id.hpp"

#include <securepath/serialisation/sequence.hpp>
#include <securepath/util/types.hpp>

#include <cstdint>

namespace securepath::crypto {

/// ML-DSA signature (see doc/crypto.md for the message framing) with the signer's key id
class signature {
public:
	signature() = default;
	signature(public_key_id id, octet_vector v)
	: issuer_(std::move(id))
	, data_(std::move(v))
	{}

	public_key_id issuer() const { return issuer_; }
	octet_vector const& data() const { return data_; }

	bool is_valid() const { return !data_.empty(); }

	bool operator==(signature const& sig) const {
		return version_ == sig.version_ && issuer_ == sig.issuer_ && data_ == sig.data_;
	}
	bool operator!=(signature const& sig) const {
		return !(*this == sig);
	}

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version_ & issuer_ & data_;
	}

private:
	std::uint32_t version_{2};
	public_key_id issuer_;
	octet_vector data_;
};

}
