// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/crypto/private_key.hpp>
#include <securepath/crypto/suite.hpp>
#include <securepath/util/types.hpp>

#include <cstddef>
#include <vector>

namespace securepath::crypto::test {

/// all suites the library implements, for tests that must pass with every parameter set
std::vector<suite> const& all_suites();

/// fresh identities for the suite (ML-DSA key generation is fast, there is no need to cache)
std::vector<private_key> generate_test_keys(std::size_t count, suite = default_suite());

/// copy with one bit flipped at the octet index
octet_vector flip_bit(octet_vector data, std::size_t octet_index, unsigned bit = 0);

}
