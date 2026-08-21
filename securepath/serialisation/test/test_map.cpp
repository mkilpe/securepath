// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include "util.hpp"
#include "types.hpp"

namespace securepath::serialisation::test {

TEST_CASE("map basic serialisation", "[map][serialisation]") {

	std::map<std::string, t1> v;
	CHECK(check(v));
	v.insert({"1", t1{}}); v.insert({"2", t1{}}); v.insert({"3", t1{}});
	CHECK(check(v));	
	
}

TEST_CASE("map long serialisation", "[map][serialisation]") {
	
	std::map<int, int> m;
	for(int i = 0; i < 10000; ++i) {
		m[i] = i+1;
	}
	CHECK(check(m));

}

TEST_CASE("map serialised content", "[map][serialisation]") {

	std::map<std::string, int> m1;
	m1.insert({"1", 1}); m1.insert({"2", 2}); m1.insert({"3", 3});
	std::map<std::string, int> m2;
	m2.insert({"1", 1}); m2.insert({"2", 2}); m2.insert({"3", 3});
	std::map<std::string, int> m3;
	m3.insert({"1", 1}); m3.insert({"2", 2}); m3.insert({"3", 0});

	CHECK(check_same_ser<std::map<std::string, int>>(m1, m2));
	CHECK(!check_same_ser<std::map<std::string, int>>(m1, m3));

	std::map<std::string, std::string> empty = {};
	CHECK(check_same_ser<std::map<std::string, std::string>>(empty, empty));

}

TEST_CASE("map identical", "[map][serialisation]" ) {

	std::map<std::string, int> m1;
	m1.insert({"1", 1}); m1.insert({"2", 2}); m1.insert({"3", 3});

	std::map<std::string, int> m2;
	m2.insert({"2", 2}); m2.insert({"3", 3}); m2.insert({"1", 1});

	CHECK(check_same_ser<std::map<std::string, int>>(m1, m2));

}

}
