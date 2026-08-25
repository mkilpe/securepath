// SPDX-License-Identifier: MIT

#include "suite.hpp"

#include <securepath/serialisation/enum.hpp>

namespace securepath::crypto {

suite default_suite() {
	return suite::pq1;
}

bool is_known(suite s) {
	return s == suite::pq1 || s == suite::pq1_high;
}

std::string_view to_string(suite s) {
	std::string_view ret;
	if(s == suite::pq1) {
		ret = "pq1";
	} else if(s == suite::pq1_high) {
		ret = "pq1_high";
	} else {
		throw unknown_suite("unknown crypto suite");
	}
	return ret;
}

serialisation::serialiser& serialise(serialisation::serialiser& s, suite const& v) {
	return securepath::serialisation::serialise(s, v);
}

serialisation::deserialiser& serialise(serialisation::deserialiser& s, suite& v) {
	securepath::serialisation::serialise(s, v);
	if(!is_known(v)) {
		throw unknown_suite("unknown crypto suite in serialised data");
	}
	return s;
}

}
