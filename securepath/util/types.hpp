// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>


namespace securepath {

using octet_vector = std::vector<uint8_t>;

}

namespace std {
	template<> struct hash<securepath::octet_vector> {
		std::size_t operator()(securepath::octet_vector const& vec) const {
			std::size_t seed = 0;
			for(auto&& v : vec) {
				seed ^= hash<securepath::octet_vector::value_type>()(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
			}
			return seed;
		}
	};
}

