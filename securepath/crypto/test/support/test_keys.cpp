// SPDX-License-Identifier: MIT

#include "test_keys.hpp"

#include <securepath/crypto/key_generation.hpp>

#include <stdexcept>

namespace securepath::crypto::test {

std::vector<suite> const& all_suites() {
	static std::vector<suite> const suites = {suite::pq1, suite::pq1_high};
	return suites;
}

std::vector<private_key> generate_test_keys(std::size_t count, suite s) {
	std::vector<private_key> keys;
	keys.reserve(count);
	for(std::size_t i = 0; i != count; ++i) {
		keys.push_back(generate_private_key(s));
	}
	return keys;
}

octet_vector flip_bit(octet_vector data, std::size_t octet_index, unsigned bit) {
	if(octet_index >= data.size() || bit > 7) {
		throw std::out_of_range("flip_bit");
	}
	data[octet_index] ^= static_cast<std::uint8_t>(1u << bit);
	return data;
}

}
