// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/log/types.hpp>

#include <ctime>
#include <exception>
#include <ostream>
#include <type_traits>

#include <iostream>

namespace securepath::log {

// NOTE: std gmtime is not thread safe
bool gmtime(std::time_t time, std::tm& out);
std::time_t timegm(std::tm& in);
void add_log_info_to_buffer(char* buffer, int first_index, int last_index, log_info const& info);

template<typename T>
inline auto output(std::ostream& out, T const& t) -> decltype(out << t, void()) {
	out << t;
}

inline void output(std::ostream& out, std::exception const& t) {
	out << t.what();
}

inline void print_impl(std::ostream& out, char const* p) {
	char const* start = p;
	for(; *p && *p != '%'; ++p) {
		if(*p == '\\' && *(p+1) == '%') {
			if(start < p) {
				out.write(start, p-start);
			}
			++p; // skip the '\\'
			start = p;
		}
	}
	if(start < p) {
		out.write(start, p-start);
	}
}

template<typename Head, typename... Params>
inline void print_impl(std::ostream& out, char const* p, Head&& h, Params const&... params) {
	char const* start = p;
	for(; *p && *p != '%'; ++p) {
		if(*p == '\\' && *(p+1) == '%') {
			if(start < p) {
				out.write(start, p-start);
			}
			++p; // skip the '\\'
			start = p;
		}
	}
	if(start < p) {
		out.write(start, p-start);
	}
	if(*p) {
		output(out, h);
		print_impl(out, p+1, params...);
	}
}

template<typename... Params>
inline void print(std::ostream& out, char const* msg, Params const&... params) {
	print_impl(out, msg, params...);
}

}

