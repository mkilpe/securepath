// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/timer.hpp>

#include <atomic>
#include <cstdint>
#include <thread>

namespace securepath::event_system {
namespace test {

using namespace std::literals;

//wait for the asynchronous event to happen
inline void wait_for_event(std::uint64_t ms, std::atomic<bool>& happened) {
	for(timer t; t.elapsed_milliseconds() < ms && !happened; ) {
		std::this_thread::sleep_for(10ms);
	}
}

template<typename F>
void wait_for_event(std::uint64_t ms, F f) {
	for(timer t; t.elapsed_milliseconds() < ms && !f(); ) {
		std::this_thread::sleep_for(10ms);
	}
}

}
}

