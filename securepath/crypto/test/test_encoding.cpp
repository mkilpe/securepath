// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/encoding.hpp>
#include <securepath/crypto/random.hpp>

#include <string>

namespace securepath::crypto::test {

namespace {

std::string as_string(octet_vector const& v) {
	return std::string(v.begin(), v.end());
}

octet_vector as_octets(std::string const& s) {
	return octet_vector(s.begin(), s.end());
}

}

TEST_CASE("encoding_basic_test", "[encoding]") {
	for(std::size_t size : {0u, 1u, 2u, 3u, 4u, 5u, 100u, 19999u}) {
		octet_vector const o = random_octet_vector(size);
		CHECK(decode(encode(o)) == o);
	}
}

TEST_CASE("encoding_empty_test", "[encoding]") {
	octet_vector const o = {};
	CHECK(encode(o).empty());
	CHECK(decode(o).empty());
}

TEST_CASE("encoding known answers", "[encoding][kat]") {
	// RFC 4648 section 10 vectors, url-safe alphabet without padding
	CHECK(as_string(encode(as_octets("f"))) == "Zg");
	CHECK(as_string(encode(as_octets("fo"))) == "Zm8");
	CHECK(as_string(encode(as_octets("foo"))) == "Zm9v");
	CHECK(as_string(encode(as_octets("foob"))) == "Zm9vYg");
	CHECK(as_string(encode(as_octets("fooba"))) == "Zm9vYmE");
	CHECK(as_string(encode(as_octets("foobar"))) == "Zm9vYmFy");
	CHECK(as_string(encode(octet_vector{0xfb, 0xff})) == "-_8");

	CHECK(decode(as_octets("Zm9vYmE")) == as_octets("fooba"));
	CHECK(decode(as_octets("Zm9vYmE=")) == as_octets("fooba"));
	CHECK(decode(as_octets("-_8")) == (octet_vector{0xfb, 0xff}));
}

TEST_CASE("invalid encoding", "[encoding]") {
	octet_vector const o = {};
	CHECK_THROWS_AS(encode(o, static_cast<encoding_algorithm>(678)), unknown_encoding_algorithm);
	CHECK_THROWS_AS(decode(o, static_cast<encoding_algorithm>(678)), unknown_encoding_algorithm);
	CHECK_THROWS_AS(decode(as_octets("Z")), invalid_encoding);
	CHECK_THROWS_AS(decode(as_octets("Zm9v*mE")), invalid_encoding);
}

}
