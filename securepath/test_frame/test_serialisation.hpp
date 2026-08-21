// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/serialisation/util.hpp>

#include <sstream>

namespace securepath::test {
namespace detail {
	template<typename Type>
	Type to_ser_to_deser(Type t) {
		Type temp{};
		std::stringstream ss;
		auto ser = serialisation::make_serialiser<serialisation::asn_der_encoder<std::stringstream>>(ss);
		ser & t;

		auto deser = serialisation::make_deserialiser<serialisation::asn_der_decoder<std::stringstream>>(ss);
		deser & temp;

		return temp;
	}
}

template<typename Type>
bool check_serialisation(Type t) {
	return t == detail::to_ser_to_deser<Type>(t);
}

template<typename Type>
bool check_serialisation_without_compare(Type t) {
	auto recycled_obj = detail::to_ser_to_deser<Type>(t);
	auto o1 = serialisation::asn_der_serialise(recycled_obj);
	auto o2 = serialisation::asn_der_serialise(t);
	return o1 == o2;

}

template<typename Type>
bool compare_ser(Type const& t1, Type const& t2) {
	auto o1 = serialisation::asn_der_serialise(t1);
	auto o2 = serialisation::asn_der_serialise(t2);
	return o1 == o2;
}

}

