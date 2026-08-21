// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <securepath/serialisation/util.hpp>
#include <securepath/util/timer.hpp>

#include <iostream>
#include <sstream>

namespace securepath::serialisation::test {

void test3(octet_vector const& o) {
	std::stringstream ss;
	asn_der_serialise(ss, o);
}

void test4(octet_vector const& o) {
	auto res = asn_der_serialise(o);
}

void test1(int x, octet_vector const& o) {

	timer t;
	std::vector<uint64_t> results;

	for(int i = 0; i < x; ++i) {
		std::stringstream ss;

		t.reset();

		asn_der_serialise(ss, o);

		uint64_t res = t.elapsed_nanoseconds();
		results.push_back(res);
	}

	for(uint64_t u : results) {
		std::cout << u << std::endl;
	}

}

void test2(int x, octet_vector const& o) {

	timer t;
	std::vector<uint64_t> results;

	for(int i = 0; i < x; ++i) {
		
		t.reset();

		asn_der_serialise(o);
		
		uint64_t res = t.elapsed_nanoseconds();
		results.push_back(res);
	}

	for(uint64_t u : results) {
		std::cout << u << std::endl;
	}

}

}
