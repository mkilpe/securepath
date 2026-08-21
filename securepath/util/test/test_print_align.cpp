// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/util/print_align.hpp>

namespace securepath::test {

TEST_CASE("print_align basic", "[print_align]") {

	std::ostringstream os;
	{
		print_align p(os);
		p << "test";
	}
	std::string out = os.str();
	CHECK(out == "test");

	os.clear();
	os.str("");
	
	{
		print_align p(os);
		p << "test";
		p.align(2);
	}

	out = os.str();
	CHECK(out == "te");
	
}

TEST_CASE("print_align init align", "[print_align]") {

	std::string s = "init";

	std::ostringstream os;
	os << s;

	REQUIRE(os.str() == s);

	print_align p(os, (std::size_t)2);

	CHECK(os.str() == s + "  ");

}

}
