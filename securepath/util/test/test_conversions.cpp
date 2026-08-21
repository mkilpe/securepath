// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/util/conversions.hpp>
#include <securepath/util/string_util.hpp>

#include <stdexcept>

namespace securepath::test {

TEST_CASE("conversions to hex", "[conversions]") {
		
	uint8_t x1[] = {0,1,9,10,15};
	octet_vector v1(std::begin(x1), std::end(x1));
	CHECK(to_hex(v1) == "0001090A0F");
	
	octet_vector v2 = {16,255};
	CHECK(to_hex(v2) == "10FF");

	octet_vector v3 = {0};
	CHECK(to_hex(v3) == "00");

}

TEST_CASE("conversions from hex to hex", "[conversions]") {

	std::string s1 = "02AF2BE203DC";
	std::string s2 = "00";
	std::string s3 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
	std::string s4 = "F0F1F2F3F4F5F6F8F9F100";

	CHECK(s1 == to_hex(from_hex(s1)));
	CHECK(s2 == to_hex(from_hex(s2)));
	CHECK(s3 == to_hex(from_hex(s3)));
	CHECK(s4 == to_hex(from_hex(s4)));

}

TEST_CASE("conversions long", "[conversions]") {

	octet_vector vec = securepath::test::random_octet_vector((std::size_t)10000);
	std::string res(vec.begin(), vec.end());

	std::string h1 = to_hex(vec); // conversions version
	std::string h2 = to_hex(res, ""); // string_util version

	CHECK(h1 == h2);
	CHECK(from_hex(h1) == from_hex(h2));

}

TEST_CASE("conversions exceptions", "[conversions]") {

	CHECK_NOTHROW(from_hex("AA"));
	CHECK_THROWS_AS(from_hex("AAA"), std::exception);
	CHECK_THROWS_AS(from_hex("AAG"), std::exception);
	CHECK_THROWS_AS(from_hex("AAG"), std::exception);
	CHECK_THROWS_AS(from_hex("AG"), std::exception);
	CHECK_THROWS_AS(from_hex("AAG32425"), std::exception);
	CHECK_THROWS_AS(from_hex("0"), std::exception);
	CHECK_THROWS_AS(from_hex("AAAAAJ"), std::exception);
}

TEST_CASE("conversions empty", "[conversions]") {

	octet_vector v;
	CHECK(to_hex(v) == "");

	octet_vector v2 = from_hex("");
	CHECK(v2.size() == 0);

}

TEST_CASE("conversions to_hex characters", "[conversions]") {

	octet_vector vec = securepath::test::random_octet_vector((std::size_t)100);
	std::string res = to_hex(vec);

	bool b = true;
	for(char c : res) {
		if(c < '0' || (c > '9' && c < 'A') || c > 'F') {
			b = false;
		}
	}
	CHECK(b);

}

}
