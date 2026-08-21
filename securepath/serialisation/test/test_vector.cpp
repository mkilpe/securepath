// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include "util.hpp"
#include "types.hpp"

namespace securepath::serialisation::test {

TEST_CASE("vector basic serialisation", "[vector][serialisation]") {

	CHECK(check<octet_vector>(octet_vector(10,'a')));
	CHECK(check<octet_vector>(octet_vector(0,'a')));

	std::vector<topt> v;
	CHECK(check(v));
	v.push_back(topt{}); v.push_back(topt{}); v.push_back(topt{});
	CHECK(check(v));

}

TEST_CASE("vector long", "[vector][serialisation]") {

	CHECK(check<octet_vector>(securepath::test::random_octet_vector(100000)));

}

TEST_CASE("octet_vector serialisation", "[vector][serialisation]") {

	octet_vector o = securepath::test::random_octet_vector((std::size_t)50);
	octet_vector res;
		
	std::stringstream ss;
	auto ser = make_serialiser<asn_der_encoder<std::stringstream>>(ss);

	serialise(ser, o);

	auto deser = make_deserialiser<asn_der_decoder<std::stringstream>>(ss);
	serialise(deser, res);

	CHECK(res == o);

}

TEST_CASE("vector serialisation test", "[vector][serialisation]") {

	std::string s = "test_string";
	std::vector<char> vec(s.begin(), s.end());
	std::vector<char> res;;

	std::stringstream ss;
	
	auto ser = make_serialiser<asn_der_encoder<std::stringstream>>(ss);
	serialise<char>(ser, vec);
	
	auto deser = make_deserialiser<asn_der_decoder<std::stringstream>>(ss);
	serialise<char>(deser, res);

	CHECK(vec == res);
	
}

TEST_CASE("vector serialised content", "[vector][serialisation]") {

	CHECK(check_same_ser<octet_vector>(octet_vector(10,'a'), octet_vector(10,'a')));
	CHECK(check_same_ser<octet_vector>(octet_vector(0,'a'), octet_vector(0,'a')));
	CHECK(!check_same_ser<octet_vector>(octet_vector(10,'a'), octet_vector(11,'a')));

	octet_vector o1 = securepath::test::random_octet_vector(10000);
	octet_vector o2 = o1;
	octet_vector o3 = o1;

	o1[9990] = (std::uint8_t)200;
	o2[9990] = (std::uint8_t)201;
	o3[9990] = (std::uint8_t)200;

	CHECK(!check_same_ser(o1,o2));
	CHECK(check_same_ser(o1,o3));
	CHECK(!check_same_ser(o2,o3));

	std::vector<int> v1 = {1, 2, 3, 4, 5};
	std::vector<int> v2 = {1, 2, 3, 5, 4};

	CHECK(!check_same_ser(v1, v2));

}

TEST_CASE("vector modified content", "[vector][serialisation]") {

	octet_vector o = securepath::test::random_octet_vector(10000);
	octet_vector ser1 = asn_der_serialise(o);
	octet_vector ser2(ser1);

	ser2[6666] ^= 0x01;
		
	CHECK(ser1 != ser2);

	octet_vector res1 = asn_der_deserialise<octet_vector>(ser1);
	octet_vector res2 = asn_der_deserialise<octet_vector>(ser2);

	CHECK(res1 != res2);
	CHECK(o == res1);
	CHECK(o != res2);

}

}
