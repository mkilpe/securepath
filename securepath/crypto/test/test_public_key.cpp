// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/certificate_id.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/serialisation/util.hpp>

#include "support/test_keys.hpp"

namespace securepath::crypto::test {

// some of the public_key test are combined with private_key tests in test_private_key.cpp

TEST_CASE("public_key serialisation", "[public_key][serialisation]") {
	for(suite s : all_suites()) {
		auto priv = generate_private_key(s);
		auto key = priv.public_key();
		octet_vector o = serialisation::asn_der_serialise(key);
		public_key res = serialisation::asn_der_deserialise<public_key>(o);
		CHECK(key.id() == res.id());
		CHECK(res.suite() == s);
		CHECK(res.verify_me());

		octet_vector data = random_octet_vector(16);
		CHECK(res.verify(priv.sign(data), data));
		CHECK(priv.decrypt(res.encrypt(data)) == data);
	}
}

TEST_CASE("public_key default constructed", "[public_key]") {
	public_key key;
	CHECK(!key.is_valid());
	CHECK(!key.verify_me());
	CHECK(key.get_cert_ids().empty());
	CHECK(!key.id().is_valid());
}

TEST_CASE("public_key certificate_id", "[public_key][certificate_id]") {
	auto key = generate_private_key().public_key();

	certificate_id cid1(random_octet_vector(16));
	certificate_id cid2(random_octet_vector(16));

	REQUIRE(cid2 != cid1);
	CHECK(key.get_cert_ids().empty());

	key.add_certificate_id(cid1);
	key.add_certificate_id(cid2);

	std::set<certificate_id> ids = key.get_cert_ids();
	CHECK(ids.size() == 2);
	CHECK(ids.find(cid1) != ids.end());
	CHECK(ids.find(cid2) != ids.end());
	CHECK(key.references_certificate(cid1));

	key.add_certificate_id(cid1);
	key.add_certificate_id(cid2);
	CHECK(key.get_cert_ids().size() == 2);

	key.remove_certificate_id(cid1);
	ids = key.get_cert_ids();
	CHECK(ids.find(cid1) == ids.end());
	CHECK(ids.find(cid2) != ids.end());
	CHECK(!key.references_certificate(cid1));

	key.remove_certificate_id(cid2);
	CHECK(key.get_cert_ids().empty());
}

TEST_CASE("public_key verify", "[public_key][private_key]") {
	auto key = generate_private_key();
	auto key2 = generate_private_key();
	auto pub_key = key.public_key();

	CHECK(pub_key.verify_me());

	pub_key.sign_me(key2);
	CHECK(!pub_key.verify_me());

	pub_key.sign_me(key);
	CHECK(pub_key.verify_me());
}

TEST_CASE("public_key verify certificate_id", "[public_key][private_key][certificate_id]") {
	auto priv_key = generate_private_key();
	auto pub_key = priv_key.public_key();

	pub_key.sign_me(priv_key);
	CHECK(pub_key.verify_me());

	certificate_id cid(random_octet_vector(16));
	pub_key.add_certificate_id(cid);
	CHECK(!pub_key.verify_me());

	pub_key.sign_me(priv_key);
	CHECK(pub_key.verify_me());

	// the certificate ids survive serialisation and stay signed
	auto copy = serialisation::asn_der_deserialise<public_key>(serialisation::asn_der_serialise(pub_key));
	CHECK(copy.verify_me());
	CHECK(copy.get_cert_ids().size() == 1);
	CHECK(copy.references_certificate(cid));

	pub_key.remove_certificate_id(cid);
	CHECK(!pub_key.verify_me());
}

}
