// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include "util.hpp"
#include "types.hpp"

#include <securepath/util/octet_vector.hpp>

#include <type_traits>

namespace securepath::serialisation::test {

TEST_CASE("choice basic", "[choice][serialisation]") {

	{
		std::stringstream ss;
		auto ser = make_serialiser<asn_der_encoder<std::stringstream>>(ss);
		test1 t1{2};
		choice<test_types>::serialise(ser, t1);
		auto deser = make_deserialiser<asn_der_decoder<std::stringstream>>(ss);
		test_visitor v{};
		choice<test_types>::deserialise(deser, v);
		CHECK((v.t1 == t1 && !v.t2));
	}

	{
		std::stringstream ss;
		auto ser = make_serialiser<asn_der_encoder<std::stringstream>>(ss);
		test2 t2{};
		choice<test_types>::serialise(ser, t2);
		auto deser = make_deserialiser<asn_der_decoder<std::stringstream>>(ss);
		test_visitor v{};
		choice<test_types>::deserialise(deser, v);
		CHECK((!v.t1 && v.t2 == t2));
	}
	{
		test1 t1{2};
		octet_vector data = asn_der_serialise_choice<test_types>(t1);
		test_visitor v{};
		asn_der_deserialise_choice<test_types>(data, v);
		CHECK((v.t1 == t1 && !v.t2));
	}
	{
		test1 t1{2};
		octet_vector data = asn_der_serialise_choice<test_types>(t1);
		int res = asn_der_deserialise_choice<test_types, int>(data, [](auto){return 1;});
		CHECK(res == 1);

		test1 test_res = asn_der_deserialise_choice<test_types, test1>(data, [](auto x){return x;});
		CHECK(test_res == t1);

		// try to visit and return something that the value cannot be converted to
		CHECK_THROWS_AS((asn_der_deserialise_choice<test_types, int>(data, [](auto x){return x;})), serialisation_error);
	}
}

TEST_CASE("choice type not exist", "[choice][serialisation]") {

	std::stringstream ss;
	test3 t(1337);

	auto ser = make_serialiser<asn_der_encoder<std::stringstream>>(ss);
	choice<test_types2>::serialise(ser, t);

	auto deser = make_deserialiser<asn_der_decoder<std::stringstream>>(ss);
	test_visitor2 v{};
	CHECK_THROWS_AS(choice<test_types>::deserialise(deser, v), serialisation_error);
}

TEST_CASE("packet desialiser", "[choice][serialisation]") {
	packet_deserialiser_base pdb;
	{
		test1 t1{2};
		octet_vector data = asn_der_serialise(t1);
		pdb.do_check(octet_span(data), [](auto& d, octet_span s){
			CHECK(asn_der_deserialise<test1>(s).i == 2);
			test1 t;
			d & t;
			CHECK(t.i == 2);
		});
	}
	{
		test1 t1{2};
		octet_vector data = asn_der_serialise(t1) + asn_der_serialise(t1)
			+ asn_der_serialise(t1);
		int i = 0;
		pdb.do_check(octet_span(data.data(), data.size()-1), [&](auto&, octet_span){ ++i; });
		CHECK(i == 2);
		pdb.do_check(octet_span(data.data()+data.size()-1, data.data()+data.size()), [&](auto&, octet_span){ ++i; });
		CHECK(i == 3);
	}

	packet_deserialiser<test_types> pd;
	{
		test1 t1{2};
		octet_vector data = asn_der_serialise_choice<test_types>(t1);
		int i = 0;
		pd.handle(octet_span(data), [&](auto value){
			if constexpr (std::is_same_v<std::decay_t<decltype(value)>, test1>) {
				CHECK(value.i == 2);
				++i;
			}
		});
		CHECK(i == 1);
	}
}

}
