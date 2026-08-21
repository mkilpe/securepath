// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/log/log.hpp>

#include <print>
#include <iostream>

namespace securepath {

template<typename... Params>
void debug_print(std::format_string<Params...> fmt, Params&&... params) {
	std::print(std::cout, fmt, std::forward<Params>(params)...);
	std::cout << std::endl;
	LOG_TRACE(fmt, std::forward<Params>(params)...);
}

}

