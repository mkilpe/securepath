// SPDX-License-Identifier: MIT

#pragma once

#include "container.hpp"

#include <map>

namespace securepath::serialisation {

template<typename T1, typename T2>
inline
serialiser& serialise(serialiser& s, std::pair<T1, T2> const& v) {
	sequence<serialiser> seq(s);
	seq & v.first & v.second;
	return s;
}

template<typename T1, typename T2>
inline
deserialiser& serialise(deserialiser& s, std::pair<T1, T2>& v) {
	sequence<deserialiser> seq(s);
	seq & v.first & v.second;
	return s;
}

template<typename K, typename T>
inline
serialiser& serialise(serialiser& s, std::map<K, T> const& v) {
	container_serialise(s, v);
	return s;
}

template<typename K, typename T>
inline
deserialiser& serialise(deserialiser& s, std::map<K, T>& v) {
	container_serialise<std::map<K, T>, std::pair<K, T>>(s, v);
	return s;
}

}

