// SPDX-License-Identifier: MIT

#pragma once

#include <chrono>

namespace securepath {

template<typename Clock>
class basic_timer {
public:
	using clock = Clock;

	basic_timer()
	: start_(clock::now())
	{}

	void reset() {
		start_  = clock::now();
	}

	uint64_t elapsed_seconds() const {
		return std::chrono::duration_cast<std::chrono::seconds>(clock::now()-start_).count();
	}

	uint64_t elapsed_milliseconds() const {
		return std::chrono::duration_cast<std::chrono::milliseconds>(clock::now()-start_).count();
	}

	uint64_t elapsed_microseconds() const {
		return std::chrono::duration_cast<std::chrono::microseconds>(clock::now()-start_).count();
	}

	uint64_t elapsed_nanoseconds() const {
		return std::chrono::duration_cast<std::chrono::nanoseconds>(clock::now()-start_).count();
	}

	typename clock::time_point start_time_point() const {
		return start_;
	}

	typename clock::time_point current_time_point() const {
		return clock::now();
	}

private:
	typename clock::time_point start_;
};

using timer = basic_timer<std::chrono::high_resolution_clock>;
using monotonic_timer = basic_timer<std::chrono::steady_clock>;

}

