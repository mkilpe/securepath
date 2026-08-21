// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/util/tuple_util.hpp>

#include <algorithm>
#include <string>

namespace securepath::test {

TEST_CASE("tuple_util init test", "[tuple_util]") {

	CHECK_NOTHROW(make_tuple_without<int>());
	CHECK_NOTHROW(make_tuple_without<std::string>(nullptr));
	CHECK_NOTHROW(make_tuple_without<std::string>(1));
	CHECK_NOTHROW(make_tuple_without<void>(1));

}

TEST_CASE("tuple_util basic test", "[tuple_util]") {

	int i = 1;
	int j = 2;
	double d = 1.1;
	bool b = true;
	char c = 'c';
	std::string s = "hop";
	
	auto res1 = make_tuple_without<int>(i, j);
	auto res2 = make_tuple_without<double>(i, j);
	auto res3 = make_tuple_without<int>(d, i, b, j, c, s);

	CHECK(std::tuple_size_v<decltype(res1)> == 0);
	CHECK(std::tuple_size_v<decltype(res2)> == 2);
	REQUIRE(std::tuple_size_v<decltype(res3)> == 4);

	std::tuple<double, bool, char, std::string> expected3(d, b, c, s);
	CHECK(expected3 == res3);
	
}

}
