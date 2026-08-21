// SPDX-License-Identifier: MIT

#pragma once

#include "container.hpp"

#include <securepath/util/types.hpp>

namespace securepath::serialisation {

template<typename T>
inline
serialiser& serialise(serialiser& s, std::vector<T> const& v) {
	container_serialise(s, v);
	return s;
}

template<typename T>
inline
deserialiser& serialise(deserialiser& s, std::vector<T>& v) {
	container_serialise(s, v);
	return s;
}

inline
serialiser& serialise(serialiser& s, octet_vector const& v) {
	s.handle(v);
	return s;
}

inline
deserialiser& serialise(deserialiser& s, octet_vector& v) {
	s.handle(v);
	return s;
}

}

