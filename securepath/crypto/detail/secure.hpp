// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/types.hpp>

#include <botan/mem_ops.h>
#include <botan/secmem.h>

#include <cstdint>

namespace securepath::crypto::detail {

/// copies secret material into an ordinary vector for serialisation; wipe it with scrub() afterwards
inline octet_vector to_octets(Botan::secure_vector<std::uint8_t> const& v) {
	return octet_vector(v.begin(), v.end());
}

/// moves ordinary vector content into secure storage and wipes the source
inline Botan::secure_vector<std::uint8_t> to_secure(octet_vector& v) {
	Botan::secure_vector<std::uint8_t> ret(v.begin(), v.end());
	Botan::secure_scrub_memory(v.data(), v.size());
	v.clear();
	return ret;
}

inline void scrub(octet_vector& v) {
	Botan::secure_scrub_memory(v.data(), v.size());
	v.clear();
}

}
