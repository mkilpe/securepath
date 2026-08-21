// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/test_frame/test_serialisation.hpp>

namespace securepath::serialisation::test {

template<typename Type>
bool check(Type t) {
	return securepath::test::check_serialisation(t);
}

template<typename Type>
bool check_same_ser(Type t1, Type t2) {
	auto o1 = asn_der_serialise(t1);
	auto o2 = asn_der_serialise(t2);
	return o1 == o2;
}

}

