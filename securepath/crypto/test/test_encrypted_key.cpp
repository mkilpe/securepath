// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/encrypted_key.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::crypto::test {

TEST_CASE("encrypted key basic test", "[encrypted_key]") {
	auto const priv_key = generate_private_key();
	auto const pub_key = priv_key.public_key();

	octet_vector key = random_octet_vector(32);
	encrypted_key e_key = encrypt_key(pub_key, key);
	CHECK(e_key.key_id() == pub_key.id());
	octet_vector res = decrypt_key(priv_key, e_key);

	CHECK(key == res);
}

TEST_CASE("encrypted key fail test", "[encrypted_key]") {
	auto const priv_key = generate_private_key();
	auto const wrong_key_ = generate_private_key();

	octet_vector key = random_octet_vector(32);
	encrypted_key e_key = encrypt_key(priv_key.public_key(), key);

	CHECK_THROWS_AS(decrypt_key(wrong_key_, e_key), wrong_key);
}

TEST_CASE("encrypted key serialisation", "[encrypted_key]") {
	auto const priv_key = generate_private_key();

	octet_vector key = random_octet_vector(32);
	encrypted_key e_key = encrypt_key(priv_key.public_key(), key);

	octet_vector o = serialisation::asn_der_serialise(e_key);
	encrypted_key e_key2 = serialisation::asn_der_deserialise<encrypted_key>(o);

	REQUIRE(e_key.key_id() == e_key2.key_id());
	REQUIRE(e_key.data() == e_key2.data());

	octet_vector key_res = decrypt_key(priv_key, e_key2);
	CHECK(key == key_res);
}

}
