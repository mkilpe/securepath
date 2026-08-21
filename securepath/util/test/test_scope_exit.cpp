// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/util/scope_exit.hpp>

namespace securepath::test {

TEST_CASE("scope exit", "[scope_exit]") {
	int i = 0;

	{
		scope_exit e([&]{++i;});
	}
	CHECK(i == 1);
	try {
		scope_exit e([&]{++i;});
		throw 1;
	} catch(...) {
	}
	CHECK(i == 2);
}

}
