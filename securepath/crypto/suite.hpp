// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"

#include <securepath/serialisation/decls.hpp>

#include <cstdint>
#include <string_view>

namespace securepath::crypto {

struct unknown_suite : crypto_error { using crypto_error::crypto_error; };

/**
 * Algorithm suite carried by every key, signature, encrypted key and handshake.
 * Values are part of the wire format, never renumber.
 */
enum class suite : std::uint16_t {
	pq1 = 1,      ///< ML-DSA-65 + X25519/ML-KEM-768 + AES-256-GCM + SHA3-512 (NIST level 3)
	pq1_high = 2  ///< ML-DSA-87 + X448/ML-KEM-1024  + AES-256-GCM + SHA3-512 (NIST level 5)
};

suite default_suite();
bool is_known(suite);
/// throws unknown_suite
std::string_view to_string(suite);

serialisation::serialiser& serialise(serialisation::serialiser& s, suite const& v);
/// throws unknown_suite for values this library does not implement
serialisation::deserialiser& serialise(serialisation::deserialiser& s, suite& v);

}
