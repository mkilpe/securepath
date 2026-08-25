// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"

#include <securepath/serialisation/decls.hpp>
#include <securepath/util/span.hpp>

#include <cstdint>
#include <string>

namespace securepath::crypto {

struct unknown_hash_algorithm : crypto_error { using crypto_error::crypto_error; };

/// values are part of the wire format, never renumber
enum class hash_algorithm : std::uint32_t {
	sha256 = 0,
	sha512 = 1,
	sha3_256 = 2,
	sha3_512 = 3
};

serialisation::serialiser& serialise(serialisation::serialiser& s, hash_algorithm const& v);
serialisation::deserialiser& serialise(serialisation::deserialiser& s, hash_algorithm& v);

std::size_t hash_digest_size(hash_algorithm = hash_algorithm::sha3_512);
octet_vector hash(octet_span data, hash_algorithm = hash_algorithm::sha3_512);

namespace detail {
/// Botan's name for the algorithm, throws unknown_hash_algorithm
std::string botan_hash_name(hash_algorithm);
}

}
