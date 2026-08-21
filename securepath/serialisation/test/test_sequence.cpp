// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include "util.hpp"
#include "types.hpp"

namespace securepath::serialisation::test {

TEST_CASE("sequence basic serialisation", "[sequence][serialisation]") {
	CHECK(check<seq>(seq{}));
}

}
