// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/private_key.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/crypto/signature.hpp>
#include <securepath/crypto/types.hpp>
#include <securepath/serialisation/util.hpp>

#include "support/test_keys.hpp"

namespace securepath::crypto::test {

TEST_CASE("private_key basic test", "[private_key]") {
	for(suite s : all_suites()) {
		auto key = generate_private_key(s);
		public_key pub_key = key.public_key();
		CHECK(pub_key.id() == key.id());
		CHECK(key.suite() == s);
		CHECK(pub_key.suite() == s);
		CHECK(key.is_valid());
		CHECK(pub_key.is_valid());
		CHECK(pub_key.verify_me());
	}
}

TEST_CASE("private_key default constructed", "[private_key]") {
	private_key key;
	CHECK(!key.is_valid());
	CHECK(!key.public_key().is_valid());
	CHECK_THROWS_AS(key.sign(random_octet_vector(8)), invalid_key);
	CHECK_THROWS_AS(key.public_key().encrypt(random_octet_vector(8)), invalid_key);
	CHECK(!key.public_key().verify_me());
}

TEST_CASE("private_key decrypt test", "[private_key][public_key][encryption]") {
	for(suite s : all_suites()) {
		auto key = generate_private_key(s);
		auto key2 = generate_private_key(s);
		public_key pub_key = key.public_key();
		public_key pub_key2 = key2.public_key();

		octet_vector data = random_octet_vector(32);
		octet_vector enc_data = pub_key.encrypt(data);
		octet_vector enc_data2 = pub_key2.encrypt(data);
		CHECK(key.decrypt(enc_data) == data);
		CHECK_THROWS_AS(key.decrypt(enc_data2), bad_ciphertext);
		CHECK(pub_key.encrypt(data) != enc_data); // fresh encapsulation and iv every time

		CHECK(key.decrypt(pub_key.encrypt({})).empty());
		octet_vector big = random_octet_vector(100000);
		CHECK(key.decrypt(pub_key.encrypt(big)) == big);
	}
}

TEST_CASE("private_key signature test", "[private_key][public_key][signature]") {
	for(suite s : all_suites()) {
		auto key = generate_private_key(s);
		auto key2 = generate_private_key(s);
		public_key pub_key = key.public_key();
		public_key pub_key2 = key2.public_key();

		octet_vector data = random_octet_vector(32);
		signature sig = key.sign(data);
		CHECK(sig.issuer() == key.id());
		CHECK(sig.is_valid());

		CHECK(pub_key.verify(sig, data));
		CHECK(!pub_key2.verify(sig, data));
		CHECK(!pub_key.verify(sig, random_octet_vector(32)));
		CHECK(!pub_key.verify(signature{}, data));
		CHECK(key.sign(data) != sig); // randomised signing
	}
}

TEST_CASE("private_key signature context", "[private_key][signature]") {
	auto key = generate_private_key();
	public_key pub_key = key.public_key();
	octet_vector data = random_octet_vector(32);

	signature sig = key.sign(data, "spsync-record");
	CHECK(pub_key.verify(sig, data, "spsync-record"));
	CHECK(!pub_key.verify(sig, data));
	CHECK(!pub_key.verify(sig, data, "spsync-assign"));
	CHECK(!pub_key.verify(key.sign(data), data, "spsync-record"));

	CHECK_THROWS_AS(key.sign(data, std::string(256, 'x')), invalid_context);
	CHECK_NOTHROW(key.sign(data, std::string(255, 'x')));
}

TEST_CASE("private_key serialisation", "[private_key][serialisation]") {
	for(suite s : all_suites()) {
		auto key = generate_private_key(s);
		key.metadata("name", {'a', 'b'});
		octet_vector o = serialisation::asn_der_serialise(key);
		private_key res = serialisation::asn_der_deserialise<private_key>(o);
		CHECK(key.id() == res.id());
		CHECK(res.suite() == s);
		CHECK(res.is_valid());
		CHECK(res.metadata("name") == (octet_vector{'a', 'b'}));
		CHECK(res.public_key().verify_me());

		octet_vector data = random_octet_vector(32);
		CHECK(key.public_key().verify(res.sign(data), data));
		CHECK(res.decrypt(key.public_key().encrypt(data)) == data);
		CHECK(key.decrypt(res.public_key().encrypt(data)) == data);
	}
}

TEST_CASE("private_key metadata", "[private_key]") {
	auto key = generate_private_key();

	octet_vector o0 = {};
	octet_vector o1 = random_octet_vector(32);

	key.metadata("data1", o1);
	CHECK(key.metadata("data1") == o1);
	key.metadata("data2", o1);
	CHECK(key.metadata("data1") == o1);
	CHECK(key.metadata("data2") == o1);
	key.metadata("data2", o0);
	CHECK(key.metadata("data1") == o1);
	CHECK(key.metadata("data2") == o0);
}

TEST_CASE("private_key set public key", "[private_key][public_key]") {
	auto key = generate_private_key();
	auto key2 = generate_private_key();
	public_key pub_key = key.public_key();

	CHECK_THROWS_AS(key.set_public_key(key2.public_key()), invalid_key);

	key.set_public_key(key.public_key());
	CHECK(key.public_key().id() == pub_key.id());
	CHECK(key.public_key().verify_me());
}

}
