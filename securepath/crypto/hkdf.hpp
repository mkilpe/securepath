// SPDX-License-Identifier: MIT

#pragma once

#include "hash.hpp"

#include <securepath/util/span.hpp>
#include <securepath/util/types.hpp>

namespace securepath::crypto {

/// HKDF (RFC 5869) extract-and-expand with HMAC over the given hash
octet_vector hkdf_derive_key(hash_algorithm id, std::size_t derived_size, octet_span key, octet_span salt, octet_span info);

octet_vector hkdf_sha3_512_derive_key(std::size_t derived_size, octet_span key, octet_span salt, octet_span info);

}
