// SPDX-License-Identifier: MIT

#include "conversions.hpp"

#include <stdexcept>

namespace securepath {

std::string to_hex(octet_span v) {
	char const values[] = "0123456789ABCDEF";
	std::string s;
	for(auto&& e : v) {
		s += values[e >> 4];
		s += values[e & 0x0F];
	}
	return s;
}

static int get_value(char c) {
	int v = 0;
	if(c >= '0' && c <= '9') {
		v = c - '0';
	} else if(c >= 'A' && c <= 'F') {
		v = c - 'A' + 10;
	} else if(c >= 'a' && c <= 'f') {
		v = c - 'a' + 10;
	} else {
		throw std::runtime_error("invalid hex string");
	}
	return v;
}

octet_vector from_hex(std::string_view s) {
	if(s.size() % 2) {
		throw std::runtime_error("invalid hex string lenght");
	}
	octet_vector res;
	for(std::size_t i = 0; i != s.size(); i += 2) {
		int v1 = get_value(s[i]);
		int v2 = get_value(s[i+1]);
		res.push_back(static_cast<std::uint8_t>(v1 << 4 | v2));
	}
	return res;
}

}
