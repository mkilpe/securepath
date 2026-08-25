// SPDX-License-Identifier: MIT

#include "suite_parameters.hpp"

namespace securepath::crypto::detail {

namespace {

suite_parameters const pq1_parameters{
	suite::pq1, "pq1",
	Botan::DilithiumMode::ML_DSA_6x5, Botan::KyberMode::ML_KEM_768,
	false, 32,
	1952, 32, 3309,
	1184, 64, 1088
};

suite_parameters const pq1_high_parameters{
	suite::pq1_high, "pq1_high",
	Botan::DilithiumMode::ML_DSA_8x7, Botan::KyberMode::ML_KEM_1024,
	true, 56,
	2592, 32, 4627,
	1568, 64, 1568
};

}

suite_parameters const& parameters(suite s) {
	if(s == suite::pq1) {
		return pq1_parameters;
	}
	if(s == suite::pq1_high) {
		return pq1_high_parameters;
	}
	throw unknown_suite("unknown crypto suite");
}

}
