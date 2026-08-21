// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/util/print_util.hpp>

namespace securepath::test {

using namespace std::literals;

TEST_CASE("print_util empty", "[print_util]") {

	std::ostringstream os;
	print_list(os, ""s, "-");
	CHECK("" == os.str());

}

TEST_CASE("print_util basic", "[print_util]") {

	std::ostringstream os;
	print_list(os, "test test"s, "-");
	CHECK("t-e-s-t- -t-e-s-t" == os.str());

	os.clear();
	os.str("");

	std::vector<int> v = {1,2,3,4};
	print_list(os, v, "");
	CHECK("1234" == os.str());

}

TEST_CASE("rprint_util random", "[print_util]") {

	std::ostringstream os;
	octet_vector o = securepath::test::random_octet_vector((std::size_t)50);
	print_list(os, o, "");

	CHECK(os.str() == std::string(o.begin(), o.end()));

}

}
