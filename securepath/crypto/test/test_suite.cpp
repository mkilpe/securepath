// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/suite.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::crypto::test {

TEST_CASE("suite basics", "[suite]") {
	CHECK(default_suite() == suite::pq1);
	CHECK(to_string(suite::pq1) == "pq1");
	CHECK(to_string(suite::pq1_high) == "pq1_high");
	CHECK(is_known(suite::pq1));
	CHECK(!is_known(static_cast<suite>(0)));
	CHECK(!is_known(static_cast<suite>(3)));
	CHECK_THROWS_AS(to_string(static_cast<suite>(3)), unknown_suite);
	CHECK(static_cast<std::uint16_t>(suite::pq1) == 1);
	CHECK(static_cast<std::uint16_t>(suite::pq1_high) == 2);
}

TEST_CASE("suite serialisation", "[suite][serialisation]") {
	for(suite s : {suite::pq1, suite::pq1_high}) {
		auto ser = serialisation::asn_der_serialise(s);
		CHECK(serialisation::asn_der_deserialise<suite>(ser) == s);
	}
	std::uint16_t unknown = 77;
	auto ser = serialisation::asn_der_serialise(unknown);
	CHECK_THROWS_AS(serialisation::asn_der_deserialise<suite>(ser), unknown_suite);
}

}
