// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/serialisation/sequence.hpp>
#include <securepath/util/types.hpp>

#include <cstdint>

namespace securepath::crypto {

/// content encrypted with AES-256-GCM; the iv is also authenticated
class encrypted_content {
public:
	encrypted_content() = default;
	encrypted_content(octet_vector encrypted_data, octet_vector iv, octet_vector tag);

	bool empty() const;

	octet_vector const& iv() const;
	octet_vector const& content() const;
	octet_vector const& tag() const;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version_ & iv_ & encrypted_ & tag_;
	}

private:
	std::uint32_t version_{0};
	octet_vector iv_;
	octet_vector encrypted_;
	octet_vector tag_;
};

/// sym_key is an aes_gcm_key_size() key
encrypted_content encrypt(octet_vector const& data, octet_vector const& sym_key);
/// throws invalid_tag when the key is wrong or the content was modified
octet_vector decrypt(encrypted_content const&, octet_vector const& sym_key);

}
