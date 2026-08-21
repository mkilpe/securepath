// SPDX-License-Identifier: MIT

#pragma once

#include <chrono>
#include <string>
#include <sstream>

namespace securepath::test {

template<typename T>
std::string duration_to_string(T dur) {
	std::ostringstream out;
	uint64_t elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(dur).count();
	uint64_t elapsed_millis = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();
	uint64_t elapsed_micros = std::chrono::duration_cast<std::chrono::microseconds>(dur).count();
	uint64_t elapsed_nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(dur).count();
	if(elapsed_seconds >= 10) {
	 	out << elapsed_millis << " seconds";
	} else if(elapsed_millis >= 10) {
	 	out << elapsed_millis << " milliseconds";
	} else if(elapsed_micros >= 10) {
		out << elapsed_micros << " microseconds";
	} else {
		out << elapsed_nanos << " nanoseconds";
	}
	return out.str();
}

}

