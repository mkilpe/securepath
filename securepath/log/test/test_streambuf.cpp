// SPDX-License-Identifier: MIT

#include <securepath/log/detail/streambuf.hpp>
#include <securepath/log/detail/util.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <iostream>

namespace securepath::log::test {

TEST_CASE("ologstreambuf basic test", "[streambuf][log]") {

	char buffer[11] = {"          "};
	
	ologstreambuf buf(buffer, 2);
	std::ostream os(&buf);
	
	std::string empty = "";
	std::string s0 = "  ";
	std::string s1 = "test";
	std::string s2 = " abcdefg";
	std::string s3 = "0123456789012345678901234567890123456";
	
	os << s1 << s2 << s3 << s3 << empty << s0 << s2 << s1 << s3 << empty << empty;
	
	std::string res(buf.begin(), buf.end());
	CHECK(res == s0+s1+s2+s3+s3+s0+s2+s1+s3);

}

TEST_CASE("ologstreambuf small buffer test", "[streambuf][log]") {
	
	char buffer[1] = {""};
	ologstreambuf buf(buffer, 0);
	std::ostream os(&buf);

	std::string s = "test";

	os << s;
	std::string res(buf.begin(), buf.end());
	CHECK(res == s);
	CHECK(buf.size() == s.size());
	
}

}
