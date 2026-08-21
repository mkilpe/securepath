// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include "util.hpp"
#include <securepath/serialisation/set.hpp>

namespace securepath::serialisation::test {

TEST_CASE("set basic serialisation", "[set][serialisation]") {

	std::set<int> s = {2, 4, 6, 8, 10, 12};
	std::set<int> res;

	std::stringstream ss;
	
	auto ser = make_serialiser<asn_der_encoder<std::stringstream>>(ss);
	serialise<int>(ser, s);
	
	auto deser = make_deserialiser<asn_der_decoder<std::stringstream>>(ss);
	serialise<int>(deser, res);

	CHECK(s == res);

}

TEST_CASE("set serialised content", "[set][serialisation]") {

	std::set<int> s1 = {2, 4, 6, 8, 10, 12};
	std::set<int> s2 = {2, 4, 6, 8, 12, 10};
	std::set<int> s3 = {2, 4, 6, 8, 10, 12, 0};
	std::set<int> s4 = {2, 4, 6, 8, 10, 12, 1};

	CHECK(s1 == s2);

	CHECK(check_same_ser<std::set<int>>(s1, s2));
	CHECK(!check_same_ser<std::set<int>>(s1, s3));
	CHECK(!check_same_ser<std::set<int>>(s1, s4));

	std::set<int> empty_set = {};

	CHECK(check_same_ser<std::set<int>>(empty_set, empty_set));

}

TEST_CASE("set long", "[set][serialisation]") {

	std::set<int> s;
	
	for(int i = 0; i < 10000; ++i) {
		s.insert(i);
	}

	CHECK(check(s));

	std::set<int> copy_s = s;
	CHECK(check_same_ser<std::set<int>>(s, copy_s));

	s.insert(0);
	s.insert(1);
	copy_s.insert(1);
	copy_s.insert(0);

	CHECK(check_same_ser<std::set<int>>(s, copy_s));

}

}
