// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"

#include <securepath/serialisation/decls.hpp>
#include <securepath/util/span.hpp>

#include <cstdint>

namespace securepath::crypto {

struct unknown_encoding_algorithm : crypto_error { using crypto_error::crypto_error; };
struct invalid_encoding : crypto_error { using crypto_error::crypto_error; };

enum class encoding_algorithm : std::uint32_t {
	base64url = 0
};

serialisation::serialiser& serialise(serialisation::serialiser& s, encoding_algorithm const& v);
serialisation::deserialiser& serialise(serialisation::deserialiser& s, encoding_algorithm& v);

/// base64url (RFC 4648 section 5) without padding
octet_vector encode(octet_span const& data, encoding_algorithm = encoding_algorithm::base64url);
/// accepts input with or without padding, throws invalid_encoding on malformed input
octet_vector decode(octet_span const& data, encoding_algorithm = encoding_algorithm::base64url);

}
