// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include "util.hpp"
#include "types.hpp"

namespace securepath::serialisation::test {

TEST_CASE("serialisation basic types", "[serialisation]") {
	CHECK(check<int>(1234));
	CHECK(check<int>(0));
	CHECK(check<int>(-1234));
	CHECK(check<std::uint64_t>(0));
	CHECK(check<std::uint64_t>(-1337));
	CHECK(check<std::uint64_t>(1337));
	CHECK(check<bool>(true));
	CHECK(check<bool>(false));
	CHECK(check<std::string>("test"));
	CHECK(check<std::string>(""));
	CHECK(check<std::string>(" "));
	CHECK(check<std::string>("    a              b           c          "));
	CHECK(check<time_point>(std::chrono::time_point_cast<std::chrono::milliseconds>(time_point::clock::now())));
	CHECK(securepath::test::check_serialisation_without_compare(0.123));
	CHECK(securepath::test::check_serialisation_without_compare(0.123f));
}

TEST_CASE("serialisation optional", "[serialisation]") {
	CHECK(check<std::optional<int>>(1234));
	CHECK(check<std::optional<int>>(0));
	CHECK(check<std::optional<int>>(-1234));
	CHECK(check<std::optional<int>>(std::nullopt));
	CHECK(check<std::optional<bool>>(false));
	CHECK(check<std::optional<bool>>(true));
	CHECK(check<std::optional<bool>>(std::nullopt));
	CHECK(check<topt>(topt{1, 2}));
	CHECK(check<topt>(topt{1, std::nullopt}));
	CHECK(check<topt>(topt{std::nullopt, 2}));
	CHECK(check<topt>(topt{}));
	CHECK(check<std::optional<topt>>(topt{}));
	CHECK(check<std::optional<topt>>(std::nullopt));
}

TEST_CASE("serialisation serialised content", "[serialisation]") {

	CHECK(check_same_ser<int>(1234, 1234));
	CHECK(check_same_ser<int>(0, 0));
	CHECK(check_same_ser<int>(-1234, -1234));
	CHECK(check_same_ser<std::uint64_t>(0, 0));
	CHECK(check_same_ser<std::uint64_t>(-1337, -1337));
	CHECK(check_same_ser<std::uint64_t>(1337, 1337));
	CHECK(check_same_ser<bool>(true, true));
	CHECK(check_same_ser<bool>(false, false));
	CHECK(check_same_ser<std::string>("test", "test"));
	CHECK(check_same_ser<std::string>("", ""));
	CHECK(check_same_ser<std::string>(" ", " "));
	CHECK(check_same_ser<std::string>("    a              b           c          ", "    a              b           c          "));

	CHECK(!check_same_ser<int>(1, 2));
	CHECK(!check_same_ser<int>(100000, 100001));
	CHECK(!check_same_ser<std::uint64_t>(1337, 1338));
	CHECK(!check_same_ser<bool>(true, false));
	CHECK(!check_same_ser<std::string>("test", "testi"));
	CHECK(!check_same_ser<std::string>("test", "test "));
	CHECK(!check_same_ser<std::string>("", " "));

	test1 t1(10000);
	test1 t2(10001);
	test1 t3(10000);

	CHECK(!check_same_ser(t1,t2));
	CHECK(check_same_ser(t1,t3));
	CHECK(!check_same_ser(t2,t3));

}

TEST_CASE("serialisation object serialise","[serialisation]") {

	test_type_1 t1(1, 2, 'c', 'd', "sss");
	test_type_1 t2(1, 3, 'c', 'e', "sss");
	test_type_1 t3(1, 0, 'c', 'x', "sss");
	test_type_1 t4(0, 2, 'c', 'd', "sss");

	CHECK(check_same_ser(t1, t2));
	CHECK(check_same_ser(t1, t2));
	CHECK(check_same_ser(t1, t3));
	CHECK(!check_same_ser(t1, t4));

	test_type_1 res1 = securepath::test::detail::to_ser_to_deser<test_type_1>(t1);
	test_type_1 res2 = securepath::test::detail::to_ser_to_deser<test_type_1>(t2);
	test_type_1 res3 = securepath::test::detail::to_ser_to_deser<test_type_1>(t3);
	test_type_1 res4 = securepath::test::detail::to_ser_to_deser<test_type_1>(t4);

	std::string expected1 = "19czsss";
	std::string expected2 = "09czsss";

	CHECK(res1.to_string() == expected1);
	CHECK(res2.to_string() == expected1);
	CHECK(res3.to_string() == expected1);
	CHECK(res4.to_string() == expected2);

}

}
