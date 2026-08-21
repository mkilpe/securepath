// SPDX-License-Identifier: MIT

#pragma once

#include <mutex>

namespace securepath::log {

/**
 *	Defines mutex_type and lock_guard used in log/backend implementation.
 */
using mutex_type = std::mutex;
using lock_guard = std::lock_guard<mutex_type>;

}

