// SPDX-License-Identifier: MIT

#pragma once

#include "container.hpp"

#include <set>

namespace securepath::serialisation {

//we don't asn.1 der set encoding rules because it is slow and makes no sense for us, so encode as sequence

template<typename K>
inline
serialiser& serialise(serialiser& s, std::set<K> const& v) {
	container_serialise(s, v);
	return s;
}

template<typename K>
inline
deserialiser& serialise(deserialiser& s, std::set<K>& v) {
	container_serialise(s, v);
	return s;
}

}
