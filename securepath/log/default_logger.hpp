// SPDX-License-Identifier: MIT

#pragma once

#include "backend/backend.hpp"
#include "detail/streambuf.hpp"
#include "detail/util.hpp"

#include <chrono>

namespace securepath::log {

template<typename Func, typename... Args>
void default_log_impl(Func func, log_info const& info, std::format_string<Args...> fmt, Args&&... args) {
	using time_point = std::chrono::time_point<std::chrono::system_clock>;

	char buffer[256] = {"                                                                      "};
	std::tm t{};
	auto time = time_point::clock::now();

	if(gmtime(time_point::clock::to_time_t(time), t)) {
		std::snprintf(buffer, 20, "%02u.%02u.%04u %02u:%02u:%02u"
			, static_cast<unsigned int>(t.tm_mday), static_cast<unsigned int>(t.tm_mon + 1)
			, static_cast<unsigned int>(t.tm_year + 1900), static_cast<unsigned int>(t.tm_hour)
			, static_cast<unsigned int>(t.tm_min), static_cast<unsigned int>(t.tm_sec));
		int ms = std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count() % 1000;
		std::snprintf(buffer + 19, 6, ".%03u ", static_cast<unsigned int>(ms));
	}

	add_log_info_to_buffer(buffer, 24, 68, info);

	ologstreambuf buf(buffer, 70);
	std::ostream os(&buf);

	std::print(os, fmt, std::forward<Args>(args)...);
	func(formatted_message{info, std::string_view{buf.begin(), buf.size()}, std::string_view{}});
}

template<typename... Args>
void default_log(log_info const& info, std::format_string<Args...> fmt, Args&&... args) {
	default_log_impl(backend::log, info, fmt, std::forward<Args>(args)...);
}

}

