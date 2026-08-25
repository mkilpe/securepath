// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/types.hpp>
#include <securepath/serialisation/util.hpp>

#include "support/test_keys.hpp"

#include <sstream>

namespace securepath::crypto::test {

TEST_CASE("key generation basic test", "[key_generation]") {
	for(suite s : all_suites()) {
		std::ostringstream os;
		auto key = generate_private_key(s);
		serialisation::asn_der_serialise(os, key);

		std::istringstream is(os.str());
		private_key priv_key = serialisation::asn_der_deserialise<private_key>(is);
		CHECK(key.id() == priv_key.id());

		std::istringstream is2(os.str());
		private_key priv_key2 = serialisation::asn_der_deserialise<private_key>(is2);
		CHECK(key.id() == priv_key2.id());
	}
}

TEST_CASE("key generation gives distinct keys", "[key_generation]") {
	auto keys = generate_test_keys(5);
	for(std::size_t i = 0; i != keys.size(); ++i) {
		for(std::size_t j = i+1; j != keys.size(); ++j) {
			CHECK(keys[i].id() != keys[j].id());
		}
	}
}

TEST_CASE("key generation unknown suite", "[key_generation]") {
	CHECK_THROWS_AS(generate_private_key(static_cast<suite>(999)), unknown_suite);
}

TEST_CASE("modified serialised private key", "[key_generation][security]") {
	auto key = generate_private_key();
	octet_vector ser = serialisation::asn_der_serialise(key);

	// flip a bit inside the ML-DSA public key: the id changes and the self signature breaks
	octet_vector modified = flip_bit(ser, 64);
	private_key priv_key = serialisation::asn_der_deserialise<private_key>(modified);
	CHECK(key.id() != priv_key.id());
	CHECK(!priv_key.public_key().verify_me());
}

}
