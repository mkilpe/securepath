// SPDX-License-Identifier: MIT

#pragma once

#include "default_logger.hpp"

namespace securepath::log {

/**	
 *	Log handler that uses default logger (default_logger.hpp) and basic backend (basic_backend)
 *	Function is called by log macros (log.hpp)
 */
template<typename... Args>
void log_handler(log_info const& info, std::format_string<Args...> fmt, Args&&... args) {
	if(backend::get_min_log_level() <= info.level) {
		default_log(info, fmt, std::forward<Args>(args)...);
	}
}

/**
 *	Log handler that can be used by custom logger and backend.
 *	See tutorial for usage examples.
 */
template<typename Logger, typename... Args, typename = typename Logger::logger_type>
void log_handler(log_info const& info, Logger& logger, std::format_string<Args...> fmt, Args&&... args) {
	if(logger.get_min_log_level() <= info.level) {
		logger.log(info, fmt, std::forward<Args>(args)...);
	}
}

}

