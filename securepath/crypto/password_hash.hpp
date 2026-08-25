// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/span.hpp>
#include <securepath/util/types.hpp>

#include <cstdint>

namespace securepath::crypto {

/// recommended password based key derivation (RFC 9106); defaults are the RFC's second recommended option
struct argon2id_parameters {
	std::uint32_t memory_kib{65536};
	std::uint32_t iterations{3};
	std::uint32_t parallelism{1};
};

octet_vector argon2id(std::size_t octets_to_generate, octet_span const& password, octet_span const& salt, argon2id_parameters const& = {});

}
