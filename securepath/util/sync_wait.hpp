// SPDX-License-Identifier: MIT

#pragma once

#include "future.hpp"
#include "task.hpp"

#include <coroutine>
#include <exception>
#include <type_traits>
#include <utility>

namespace securepath {

namespace detail {

/// eagerly started, self-destroying coroutine used to drive a task from non-coroutine code
struct fire_and_forget {
	struct promise_type {
		fire_and_forget get_return_object() {
			return {};
		}
		std::suspend_never initial_suspend() noexcept {
			return {};
		}
		std::suspend_never final_suspend() noexcept {
			return {};
		}
		void return_void() {
		}
		void unhandled_exception() {
			std::terminate();
		}
	};
};

template<typename T>
fire_and_forget run_sync_wait(task<T> t, promise<T> result) {
	try {
		if constexpr(std::is_void_v<T>) {
			co_await std::move(t);
			result.set_value();
		} else {
			result.set_value(co_await std::move(t));
		}
	} catch(...) {
		result.set_exception(std::current_exception());
	}
}

}

/// Runs the task and blocks the calling thread until it completes; returns its result or rethrows.
template<typename T>
T sync_wait(task<T> t) {
	promise<T> result;
	auto fut = result.get_future();
	detail::run_sync_wait(std::move(t), std::move(result));
	return fut.get();
}

}
