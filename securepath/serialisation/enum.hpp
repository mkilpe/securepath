// SPDX-License-Identifier: MIT

#pragma once

#include "deserialiser.hpp"
#include "serialiser.hpp"

#include <type_traits>

namespace securepath::serialisation {

template<typename T, typename = std::enable_if_t<std::is_enum_v<T>>>
inline
serialiser& serialise(serialiser& s, T const& v) {
	s & static_cast<std::underlying_type_t<T>>(v);
	return s;
}

template<typename T, typename = std::enable_if_t<std::is_enum_v<T>>>
inline
deserialiser& serialise(deserialiser& s, T& v) {
	std::underlying_type_t<T> value{};
	s & value;
	v = static_cast<T>(value);
	return s;
}

}
