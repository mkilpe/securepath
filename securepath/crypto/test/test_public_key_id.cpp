// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/certificate_id.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_id.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/serialisation/util.hpp>

#include <format>
#include <sstream>
#include <unordered_set>

namespace securepath::crypto::test {

TEST_CASE("public_key_id basic test", "[public_key_id]") {
	auto key = generate_private_key();
	public_key_id id = key.id();
	CHECK(id.is_valid());
	CHECK(id.data().size() == 32);

	octet_vector data = id.data();
	public_key_id id2(data);
	public_key_id id3(id.in_hex());
	public_key_id id4(key.public_key());

	CHECK(id == id2);
	CHECK(id == id3);
	CHECK(id == id4);
	CHECK(id.in_hex() == id2.in_hex());
	CHECK(id != generate_private_key().id());
	CHECK(!public_key_id().is_valid());

	std::ostringstream os;
	os << id;
	CHECK(os.str() == id.in_hex());
	CHECK(std::format("{}", id) == id.in_hex());

	std::unordered_set<public_key_id> set = {id, id2};
	CHECK(set.size() == 1);
}

TEST_CASE("public_key_id serialisation", "[public_key_id][serialisation]") {
	public_key_id id = generate_private_key().id();
	octet_vector o = serialisation::asn_der_serialise(id);
	public_key_id id2 = serialisation::asn_der_deserialise<public_key_id>(o);
	CHECK(id == id2);
}

TEST_CASE("certificate_id basic test", "[certificate_id]") {
	certificate_id id(random_octet_vector(32));
	certificate_id id2(id.in_hex());
	CHECK(id == id2);
	CHECK(id != certificate_id(random_octet_vector(32)));
	CHECK(!certificate_id().is_valid());
	CHECK(std::format("{}", id) == id.in_hex());

	octet_vector o = serialisation::asn_der_serialise(id);
	CHECK(serialisation::asn_der_deserialise<certificate_id>(o) == id);
}

}
