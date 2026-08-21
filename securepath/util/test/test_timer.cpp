// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/util/timer.hpp>

#include <chrono>
#include <thread>

namespace securepath::test {

TEST_CASE("timer basic", "[timer]") {

	timer t;
	std::this_thread::sleep_for(std::chrono::seconds(2));
	CHECK(t.elapsed_milliseconds() > 0);
	CHECK(t.elapsed_seconds() > 0);
	CHECK((t.elapsed_milliseconds() > 1900 && t.elapsed_milliseconds() < 2100));
	t.reset();
	CHECK(t.elapsed_seconds() < 1);
	
}	

}
