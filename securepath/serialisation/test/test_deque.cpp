// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include "util.hpp"

#include <securepath/serialisation/deque.hpp>

namespace securepath::serialisation::test {

TEST_CASE("deque serialisation basics", "[deque][serialisation]") {

	std::deque<int> d = {3, 5, 7, 9, 11};
	std::deque<int> res;

	std::stringstream ss;
	
	auto ser = make_serialiser<asn_der_encoder<std::stringstream>>(ss);
	serialise<int>(ser, d);
	
	auto deser = make_deserialiser<asn_der_decoder<std::stringstream>>(ss);
	serialise<int>(deser, res);

	CHECK(d == res);

}

TEST_CASE("deque serialised content", "[deque][serialisation]") {

	std::deque<int> s1 = {1, 2, 3, 4};
	std::deque<int> s2 = {1, 2, 3, 4};
	std::deque<int> s3 = {1, 2, 3, 4, 0};
	std::deque<int> s4 = {1, 2, 3, 0, 4};

	CHECK(check_same_ser<std::deque<int>>(s1, s2));
	CHECK(!check_same_ser<std::deque<int>>(s1, s3));
	CHECK(!check_same_ser<std::deque<int>>(s3, s4));

	std::deque<int> empty_deq = {};

	CHECK(check_same_ser<std::deque<int>>(empty_deq, empty_deq));

}

TEST_CASE("deque long", "[deque][serialisation]") {

	std::deque<int> d;
	
	for(int i = 0; i < 10000; ++i) {
		d.push_back(i);
	}

	CHECK(check(d));

	std::deque<int> copy_d = d;
	CHECK(check_same_ser<std::deque<int>>(d, copy_d));

	d.push_back(0);
	copy_d.push_back(1);

	CHECK(!check_same_ser<std::deque<int>>(d, copy_d));

}

}
