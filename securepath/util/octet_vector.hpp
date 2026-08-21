// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"

#include <algorithm>
#include <string>

namespace securepath {

inline
octet_vector subbuffer(octet_vector const& vec, octet_vector::size_type pos, octet_vector::size_type len = -1) {
	octet_vector v;
	if(pos < vec.size()) {
		if(len == std::size_t(-1)) {
			len = vec.size() - pos;
		}
		len = std::min(len, vec.size()-pos);
		v.insert(v.end(), vec.begin()+pos, vec.begin()+pos+len);
	}
	return v;
}

inline
octet_vector operator+(octet_vector const& v1, octet_vector const& v2) {
	octet_vector ret(v1);
	ret.insert(ret.end(), v2.begin(), v2.end());
	return ret;
}

inline
octet_vector operator^(octet_vector const& v1, octet_vector const& v2) {
	octet_vector ret(v1);
	auto it2 = v2.begin();

	for(auto it1 = ret.begin(); it1 != ret.end() && it2 != v2.end(); ++it1, ++it2) {
		*it1 ^= *it2;
	}

	if( it2 != v2.end() ) {
		ret.insert(ret.end(), it2, v2.end());
	}

	return ret;
}

inline octet_vector to_octet_vector(std::string const& s) {
	return octet_vector(s.begin(), s.end());
}

}

