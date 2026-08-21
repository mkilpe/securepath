// SPDX-License-Identifier: MIT

#pragma once

#include "log_handler.hpp"

/**
 *	Macros that can be used for logging messages.
 *	The level is checked before the arguments are evaluated, so argument
 *	expressions cost nothing when the level is disabled. Custom loggers with
 *	their own levels must call log_handler directly instead of these macros.
 */
#define LOG_TRACE(...) SP_LOG_IMPL(0, __VA_ARGS__)
#define LOG_INFO(...) SP_LOG_IMPL(4, __VA_ARGS__)
#define LOG_WARN(...) SP_LOG_IMPL(7, __VA_ARGS__)
#define SP_LOG_IMPL(level, ...) \
	do { \
		if(::securepath::log::backend::get_min_log_level() <= (level)) { \
			::securepath::log::log_handler(::securepath::log::log_info{__FILE__, __LINE__, level}, __VA_ARGS__); \
		} \
	} while(false)

