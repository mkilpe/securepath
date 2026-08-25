// SPDX-License-Identifier: MIT

#include "encoding.hpp"

#include <securepath/serialisation/enum.hpp>

#include <botan/base64.h>
#include <botan/exceptn.h>

#include <algorithm>
#include <string>

namespace securepath::crypto {
namespace {

void check_known(encoding_algorithm id) {
	if(id != encoding_algorithm::base64url) {
		throw unknown_encoding_algorithm();
	}
}

octet_vector encode_base64url(octet_span const& data) {
	std::string s = Botan::base64_encode(data.data(), data.size());
	std::erase(s, '=');
	std::replace(s.begin(), s.end(), '+', '-');
	std::replace(s.begin(), s.end(), '/', '_');
	return octet_vector(s.begin(), s.end());
}

octet_vector decode_base64url(octet_span const& data) {
	std::string s(data.begin(), data.end());
	std::replace(s.begin(), s.end(), '-', '+');
	std::replace(s.begin(), s.end(), '_', '/');
	std::erase(s, '=');
	if(s.size() % 4 == 1) {
		throw invalid_encoding("base64url: invalid length");
	}
	s.append((4 - s.size() % 4) % 4, '=');
	try {
		auto res = Botan::base64_decode(s, false);
		return octet_vector(res.begin(), res.end());
	} catch(Botan::Exception const& e) {
		throw invalid_encoding(std::string("base64url: ") + e.what());
	}
}

}

serialisation::serialiser& serialise(serialisation::serialiser& s, encoding_algorithm const& v) {
	return securepath::serialisation::serialise(s, v);
}

serialisation::deserialiser& serialise(serialisation::deserialiser& s, encoding_algorithm& v) {
	return securepath::serialisation::serialise(s, v);
}

octet_vector encode(octet_span const& data, encoding_algorithm id) {
	check_known(id);
	return encode_base64url(data);
}

octet_vector decode(octet_span const& data, encoding_algorithm id) {
	check_known(id);
	return decode_base64url(data);
}

}
