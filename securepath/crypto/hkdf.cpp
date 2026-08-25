// SPDX-License-Identifier: MIT

#include "hkdf.hpp"

#include <botan/kdf.h>

namespace securepath::crypto {

octet_vector hkdf_derive_key(hash_algorithm id, std::size_t derived_size, octet_span key, octet_span salt, octet_span info) {
	auto kdf = Botan::KDF::create_or_throw("HKDF(" + detail::botan_hash_name(id) + ")");
	auto res = kdf->derive_key(derived_size, key, salt, info);
	return octet_vector(res.begin(), res.end());
}

octet_vector hkdf_sha3_512_derive_key(std::size_t derived_size, octet_span key, octet_span salt, octet_span info) {
	return hkdf_derive_key(hash_algorithm::sha3_512, derived_size, key, salt, info);
}

}
