// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include "util.hpp"
#include <securepath/serialisation/enum.hpp>
#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/map.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::serialisation::test {

enum enum1 { first = 1, second, third };

enum class enum2 { first = 2, second, third };

enum enum3 { aaa, bbb, ccc };

enum class enum4 { ddd, eee, fff };

class enum_box {
public:
	enum_box() = default;
	enum_box(enum1 e1, enum2 e2, enum3 e3, enum4 e4)
	: e1_(e1), e2_(e2), e3_(e3), e4_(e4)
	{}

	enum1 e1() { return e1_; }
	enum2 e2() { return e2_; }
	enum3 e3() { return e3_; }
	enum4 e4() { return e4_; }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & e1_ & e2_ & e3_ & e4_;
	}
private:
	enum1 e1_;
	enum2 e2_;
	enum3 e3_;
	enum4 e4_;
};

TEST_CASE("enum basic serialisation", "[enum][serialisation]") {
	enum e1 { a = 1, b };
	enum class e2 { a = 1, b, c = 100, d };

	CHECK(check(a));
	CHECK(check(b));
	CHECK(check(e2::a));
	CHECK(check(e2::b));
	CHECK(check(e2::c));
	CHECK(check(e2::d));
}

TEST_CASE("enum serialisation test", "[enum][serialisation]") {

	enum_box box1(enum1::first, enum2::first, enum3::aaa, enum4::ddd);
	enum_box box2(enum1::second, enum2::third, enum3::bbb, enum4::eee);
	
	auto ser1 = asn_der_serialise(box1);
	auto ser2 = asn_der_serialise(box2);

	enum_box res1 = asn_der_deserialise<enum_box>(ser1);
	enum_box res2 = asn_der_deserialise<enum_box>(ser2);

	CHECK((box1.e1() == res1.e1() && box1.e2() == res1.e2() && box1.e3() == res1.e3() && box1.e4() == res1.e4()));
	CHECK((box2.e1() == res2.e1() && box2.e2() == res2.e2() && box2.e3() == res2.e3() && box2.e4() == res2.e4()));

}

TEST_CASE("enum map test", "[enum][serialisation]") {

	std::map<int, enum1> m1;
	m1.insert({1, enum1::first});
	m1.insert({2, enum1::second});

	std::map<int, enum2> m2;
	m2.insert({1, enum2::first});

	std::map<int, enum3> m3;
	m3.insert({1, enum3::aaa});
	m3.insert({2, enum3::ccc});

	std::map<int, enum4> m4;
	m4.insert({1, enum4::ddd});
	m4.insert({2, enum4::eee});

	CHECK(check(m1));
	CHECK(check(m2));
	CHECK(check(m3));
	CHECK(check(m4));

}

}
