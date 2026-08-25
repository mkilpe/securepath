// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/crypto/enveloped_content.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/serialisation/util.hpp>

#include "support/test_keys.hpp"

namespace securepath::crypto::test {

TEST_CASE("enveloped_content basic test", "[enveloped_content]") {
	for(suite s : all_suites()) {
		auto const priv_key = generate_private_key(s);
		octet_vector const data = random_octet_vector(512);

		enveloped_content content = envelope(priv_key.public_key(), data);
		CHECK(!content.empty());
		CHECK(decrypt(content, priv_key) == data);
	}
}

TEST_CASE("enveloped_content multiple keys", "[enveloped_content]") {
	auto keys = generate_test_keys(4);
	octet_vector const data = random_octet_vector(512);

	std::deque<public_key> deq = {keys[0].public_key(), keys[1].public_key(), keys[2].public_key()};
	enveloped_content content = envelope(deq, data);

	CHECK(data == decrypt(content, keys[0]));
	CHECK(data == decrypt(content, keys[1]));
	CHECK(data == decrypt(content, keys[2]));
	CHECK_THROWS_AS(decrypt(content, keys[3]), wrong_key);
}

TEST_CASE("enveloped_content mixed suites", "[enveloped_content]") {
	auto k1 = generate_private_key(suite::pq1);
	auto k2 = generate_private_key(suite::pq1_high);
	octet_vector const data = random_octet_vector(64);

	enveloped_content content = envelope({k1.public_key(), k2.public_key()}, data);
	CHECK(data == decrypt(content, k1));
	CHECK(data == decrypt(content, k2));
}

TEST_CASE("enveloped_content empty test", "[enveloped_content]") {
	auto const priv_key = generate_private_key();
	octet_vector const data;

	enveloped_content content = envelope(priv_key.public_key(), data);
	CHECK(content.empty());
	CHECK(data == decrypt(content, priv_key));
}

TEST_CASE("enveloped_content serialisation", "[enveloped_content][serialisation]") {
	auto keys = generate_test_keys(3);
	octet_vector const data = random_octet_vector(512);

	std::deque<public_key> deq = {keys[0].public_key(), keys[1].public_key()};
	enveloped_content content = envelope(deq, data);

	auto env_ser = serialisation::asn_der_serialise(content);
	enveloped_content content2 = serialisation::asn_der_deserialise<enveloped_content>(env_ser);

	REQUIRE(!content2.empty());
	CHECK(data == decrypt(content2, keys[0]));
	CHECK(data == decrypt(content2, keys[1]));
	CHECK_THROWS_AS(decrypt(content2, keys[2]), wrong_key);
}

TEST_CASE("enveloped_content enveloper test", "[enveloped_content][enveloper]") {
	auto keys = generate_test_keys(4);
	octet_vector const data = random_octet_vector(256);

	enveloper env(data);
	env.add(keys[0].public_key());
	env.add(keys[2].public_key());

	enveloped_content content = env.result();
	CHECK_NOTHROW(decrypt(content, keys[0]));

	encrypted_key new_key = env.encrypt_key(keys[1].public_key());
	content.add(new_key);

	CHECK(data == decrypt(content, keys[0]));
	CHECK(data == decrypt(content, keys[1]));
	CHECK(data == decrypt(content, keys[2]));
	CHECK_THROWS_AS(decrypt(content, keys[3]), wrong_key);
}

TEST_CASE("enveloped_content invalid_tag", "[enveloped_content][enveloper][security]") {
	auto keys = generate_test_keys(2);
	octet_vector const data = random_octet_vector(128);
	enveloped_content content = envelope(keys[0].public_key(), data);

	octet_vector const key2 = random_octet_vector(aes_gcm_key_size());
	encrypted_key enc_key2 = encrypt_key(keys[1].public_key(), key2);
	content.add(enc_key2);

	CHECK(data == decrypt(content, keys[0]));
	CHECK_THROWS_AS(decrypt(content, keys[1]), invalid_tag);
}

TEST_CASE("enveloped_content enveloper no keys", "[enveloped_content][enveloper]") {
	auto const priv_key = generate_private_key();
	octet_vector const data = random_octet_vector(128);

	enveloper env(data);
	enveloped_content content = env.result();

	CHECK(!content.empty());
	CHECK_THROWS_AS(decrypt(content, priv_key), wrong_key);

	auto env_ser = serialisation::asn_der_serialise(content);
	enveloped_content content2 = serialisation::asn_der_deserialise<enveloped_content>(env_ser);

	CHECK(!content2.empty());
	CHECK_THROWS_AS(decrypt(content2, priv_key), wrong_key);
}

}
