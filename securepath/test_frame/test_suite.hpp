// SPDX-License-Identifier: MIT

#include <catch2/catch_all.hpp>
#include <securepath/util/timer.hpp>
#include <chrono>

namespace securepath {

using namespace std::literals::chrono_literals;

#define WAIT(expr, time_to_wait) \
	do { \
		timer t; \
		for(; t.elapsed_milliseconds() < std::chrono::duration_cast<std::chrono::milliseconds>(time_to_wait).count() && !(expr);) { \
			std::this_thread::sleep_for(100ms); \
		} \
	} while (0)

#define WAIT_CHECK(expr, time_to_wait) \
	do { \
		timer t; \
		for(; t.elapsed_milliseconds() < std::chrono::duration_cast<std::chrono::milliseconds>(time_to_wait).count() && !(expr);) { \
			std::this_thread::sleep_for(100ms); \
		} \
		CHECK(expr); \
	} while (0)

#define WAIT_REQUIRE(expr, time_to_wait) \
	do { \
		timer t; \
		for(; t.elapsed_milliseconds() < std::chrono::duration_cast<std::chrono::milliseconds>(time_to_wait).count() && !(expr);) { \
			std::this_thread::sleep_for(100ms); \
		} \
		REQUIRE(expr); \
	} while (0)

}
