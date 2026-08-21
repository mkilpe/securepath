// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/util/typelist.hpp>

namespace securepath::test {

template<typename Type, uint64_t Tag>
struct test_tag {
	static uint64_t const tag = Tag;
	using type = Type;
};

template<typename Type>
struct test_tag2 {
	using ttt = Type;
};

struct type1 {
};

struct type2 {
};

using list1 = typelist<test_tag<bool, 1>,
			test_tag<int, 2>,
			test_tag<char, 3>,
			test_tag<std::string, 4>,
			test_tag<type1, 5>,
			test_tag<type2, 6> >;

using list2 = typelist<test_tag2<type1>,
			test_tag2<type2>>;

TEST_CASE("typelist get element", "[typelist]") {
 	
 	using first = get_element<begin<list1>::type, end<list1>::type, 0>::type;
 	using second = get_element<begin<list1>::type, end<list1>::type, 1>::type;
 	using third = get_element<begin<list1>::type, end<list1>::type, 2>::type;
 	using forth = get_element<begin<list1>::type, end<list1>::type, 3>::type;
 	using fifth = get_element<begin<list1>::type, end<list1>::type, 4>::type;
 	using last = get_element<begin<list1>::type, end<list1>::type, 5>::type;

 	CHECK(std::is_same<first::type, bool>::value);
 	CHECK(std::is_same<second::type, int>::value);
 	CHECK(std::is_same<third::type, char>::value);
 	CHECK(std::is_same<forth::type, std::string>::value);
 	CHECK(std::is_same<fifth::type, type1>::value);
 	CHECK(std::is_same<last::type, type2>::value);
 	 	
 	CHECK((uint64_t)first::tag == (uint64_t)1);
 	CHECK((uint64_t)second::tag == (uint64_t)2);
 	CHECK((uint64_t)third::tag == (uint64_t)3);
 	CHECK((uint64_t)forth::tag == (uint64_t)4);
 	CHECK((uint64_t)fifth::tag == (uint64_t)5);
 	CHECK((uint64_t)last::tag == (uint64_t)6);

 	using first_ttt = get_element<begin<list2>::type, end<list2>::type, 0>::type;
	using second_ttt = get_element<begin<list2>::type, end<list2>::type, 1>::type;

	CHECK(std::is_same<first_ttt::ttt, type1>::value);
	CHECK(std::is_same<second_ttt::ttt, type2>::value);

}

TEST_CASE("typelist nth element", "[typelist]") {

	using first = nth_element<list1, 0>::type;
	using forth = nth_element<list1, 3>::type;
	using last = nth_element<list1, 5>::type;

	CHECK(std::is_same<first::type, bool>::value);
	CHECK(std::is_same<forth::type, std::string>::value);
	CHECK(std::is_same<last::type, type2>::value);

	using first_ttt = nth_element<list2, 0>::type;
	using second_ttt = nth_element<list2, 1>::type;
	
	CHECK(std::is_same<first_ttt::ttt, type1>::value);
	CHECK(std::is_same<second_ttt::ttt, type2>::value);

}

}
