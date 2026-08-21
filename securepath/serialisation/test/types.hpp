// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/serialisation/choice.hpp>
#include <securepath/serialisation/tag.hpp>
#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/vector.hpp>
#include <securepath/serialisation/map.hpp>

namespace securepath::serialisation::test {

struct t {
	int obj = 1;

	bool operator==(t o) const {
		return obj == o.obj;
	}
};

struct t1 : t {
	template<typename S>
	void serialise(S& s) {
		s & implicit_tag(1, obj);
	}
};

struct t2 : t {
	template<typename S>
	void serialise(S& s) {
		s & explicit_tag(2, obj);
	}
};

struct seq : t {
	template<typename S>
	void serialise(S& s) {
		sequence<S> seq(s);
		s & obj;
	}
};

struct topt {
	topt(std::optional<int> a = std::nullopt, std::optional<int> b = std::nullopt)
	: a(a)
	, b(b)
	{}

	template<typename S>
	void serialise(S& s) {
		sequence<S> seq(s);
		s & i & implicit_tag(1, a) & explicit_tag(2, b) & c;
	}

	bool operator==(topt o) const {
		return i == o.i && a == o.a && b == o.b && c == o.c;
	}

	int i = 1;
	std::optional<int> a;
	std::optional<int> b;
	int c = 2;
};

struct test1 {
	test1(int i = 0)
	: i(i)
	{}

	template<typename S>
	void serialise(S& s) {
		sequence<S> seq(s);
		s & i;
	}

	bool operator==(test1 o) const {
		return i == o.i;
	}

	int i;
};
struct test2 {
	test2(std::optional<topt> a = std::nullopt)
	: a(a)
	{}

	template<typename S>
	void serialise(S& s) {
		sequence<S> seq(s);
		s & implicit_tag(1, a);
	}

	bool operator==(test2 o) const {
		return a == o.a;
	}

	std::optional<topt> a;
};

struct test3 {
	test3(int i = 0)
	: i(i)
	{}

	template<typename S>
	void serialise(S& s) {
		sequence<S> seq(s);
		s & i;
	}

	bool operator==(test3 o) const {
		return i == o.i;
	}

	int i;
};

struct test_visitor {
	void operator()(test1 t) {
		t1 = t;
	}
	void operator()(test2 t) {
		t2 = t;
	}
	std::optional<test1> t1;
	std::optional<test2> t2;
};

struct test_visitor2 {
	void operator()(test1 t) {
		t1 = t;
	}
	void operator()(test2 t) {
		t2 = t;
	}
	void operator()(test3 t) {
		t3 = t;
	}
	std::optional<test1> t1;
	std::optional<test2> t2;
	std::optional<test3> t3;
};

struct test_type_1 {
	test_type_1(int i = 0, int j = 9, char c = 'a', char d = 'z', std::string s = "")
	: i_(i)
	, j_(j)
	, c_(c)
	, d_(d)
	, s_(s)
	{}

	std::string to_string() {
		return std::to_string(i_) + std::to_string(j_) + c_ + d_ + s_;
	}

	template<typename S>
	void serialise(S& s) {
		sequence<S> seq(s);
		s & i_ & c_ & s_;	// j ja d not included
	}

	private:
		int i_;
		int j_;
		char c_;
		char d_;
		std::string s_;
};


using test_types =
	typelist<type_tag<test1, 1>,
			type_tag<test2, 2>>;

using test_types2 =
	typelist<type_tag<test1, 1>,
			type_tag<test2, 2>,
			type_tag<test3, 3>>;

}

