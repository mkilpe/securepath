// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/util/timer.hpp>

#include <chrono>
#include <thread>

namespace securepath::test {

TEST_CASE("timer basic", "[timer]") {
	// same clock the timer uses, so the readings bracket the timer's interval
	// exactly and the checks stay valid regardless of scheduling delays
	using ref_clock = std::chrono::high_resolution_clock;

	auto const before = ref_clock::now();
	timer t;
	std::this_thread::sleep_for(std::chrono::milliseconds(200));
	auto const elapsed_ms = t.elapsed_milliseconds();
	auto const after = ref_clock::now();

	// the sleep bounds it from below, the outer bracket from above
	auto const outer_ms = std::chrono::duration_cast<std::chrono::milliseconds>(after - before).count();
	CHECK(elapsed_ms >= 200);
	CHECK(elapsed_ms <= static_cast<std::uint64_t>(outer_ms));
	CHECK(t.elapsed_microseconds() >= 200000);

	auto const reset_before = ref_clock::now();
	t.reset();
	auto const reset_elapsed = t.elapsed_milliseconds();
	auto const reset_after = ref_clock::now();
	auto const reset_outer = std::chrono::duration_cast<std::chrono::milliseconds>(reset_after - reset_before).count();
	CHECK(reset_elapsed <= static_cast<std::uint64_t>(reset_outer));
}

}
