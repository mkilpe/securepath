// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/serialisation/deserialiser.hpp>
#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/serialiser.hpp>

namespace securepath::serialisation {

template<typename Container>
inline
void container_serialise(serialiser& s, Container& v) {
	sequence<serialiser> seq(s);
	for(auto&& e : v) {
		seq & e;
	}
}

template<typename Container, typename Element = typename Container::value_type>
inline
void container_serialise(deserialiser& s, Container& v) {
	v.clear();
	sequence<deserialiser> seq(s);
	for(;!s.is_end_of_sequence();) {
		auto const pos_before = s.position();
		Element temp{};
		seq & temp;
		if(s.position() == pos_before) {
			// an element that consumes nothing (e.g. an absent optional) would
			// repeat forever, growing the container until memory runs out
			throw serialisation_error("container element did not consume any data");
		}
		v.insert(v.end(), std::move(temp));
	}
}

}

