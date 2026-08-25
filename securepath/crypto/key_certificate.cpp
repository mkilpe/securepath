// SPDX-License-Identifier: MIT

#include "key_certificate.hpp"

#include "error.hpp"

#include <securepath/log/log.hpp>

#include <algorithm>
#include <cctype>
#include <ostream>

namespace securepath::crypto {

namespace {

std::string to_lower(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return s;
}

}

bool key_cert_restriction::is_subset_of(key_cert_restriction const& other) const {
	bool ret = !other.has_hostname();
	if(!ret) {
		std::string const other_host = to_lower(other.hostname());
		std::string const my_host = to_lower(hostname());
		std::string other_host_sub = other_host;
		if(other_host_sub.front() != '.') {
			other_host_sub = "." + other_host_sub;
		}
		ret = my_host == other_host || my_host.ends_with(other_host_sub);
	}
	if(!ret) {
		LOG_TRACE("'{}' is not subset of '{}'", hostname_, other.hostname_);
	}
	return ret;
}

bool operator==(key_cert_restriction const& l, key_cert_restriction const& r) {
	return l.hostname() == r.hostname();
}

std::string to_string(key_cert_restriction const& rest) {
	return "[hostname: " + rest.hostname() + "]";
}

std::ostream& operator<<(std::ostream& out, key_cert_restriction const& rest) {
	return out << to_string(rest);
}

key_cert_restriction merge(key_cert_restriction const& rest1, key_cert_restriction const& rest2) {
	key_cert_restriction ret;
	if(rest1.is_subset_of(rest2)) {
		ret = rest1;
	} else if(rest2.is_subset_of(rest1)) {
		ret = rest2;
	} else {
		throw error(make_error_code(errc::invalid_operation), "cannot merge key certificate restrictions");
	}
	return ret;
}

}
