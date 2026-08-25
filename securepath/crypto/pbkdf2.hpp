// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/span.hpp>
#include <securepath/util/types.hpp>

#include <cstdint>

namespace securepath::crypto {

/// PBKDF2 (RFC 8018). Prefer argon2id (password_hash.hpp) for new uses; these stay for existing data.
octet_vector pbkdf2_hmac_sha1(std::size_t octets_to_generate, octet_span const& password, octet_span const& salt, std::size_t iterations = 10000);
octet_vector pbkdf2_hmac_sha512(std::size_t octets_to_generate, octet_span const& password, octet_span const& salt, std::size_t iterations = 10000);

}
