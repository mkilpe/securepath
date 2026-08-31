// SPDX-License-Identifier: MIT

#pragma once

#include <coroutine>
#include <exception>
#include <optional>
#include <utility>

namespace securepath {

template<typename T>
class task;

namespace detail {

/// resumes the awaiting coroutine (if any) when a task completes
struct task_final_awaiter {
	bool await_ready() const noexcept {
		return false;
	}

	template<typename Promise>
	std::coroutine_handle<> await_suspend(std::coroutine_handle<Promise> handle) const noexcept {
		auto continuation = handle.promise().continuation();
		return continuation ? continuation : std::noop_coroutine();
	}

	void await_resume() const noexcept {
	}
};

/// shared parts of the task coroutine promise
class task_promise_base {
public:
	std::suspend_always initial_suspend() noexcept {
		return {};
	}

	task_final_awaiter final_suspend() noexcept {
		return {};
	}

	void unhandled_exception() {
		error_ = std::current_exception();
	}

	void set_continuation(std::coroutine_handle<> continuation) noexcept {
		continuation_ = continuation;
	}

	std::coroutine_handle<> continuation() const noexcept {
		return continuation_;
	}

protected:
	void rethrow_if_error() const {
		if(error_) {
			std::rethrow_exception(error_);
		}
	}

private:
	std::coroutine_handle<> continuation_;
	std::exception_ptr error_;
};

template<typename T>
class task_promise : public task_promise_base {
public:
	task<T> get_return_object();

	void return_value(T value) {
		value_.emplace(std::move(value));
	}

	T take_value() {
		rethrow_if_error();
		return std::move(*value_);
	}

private:
	std::optional<T> value_;
};

template<>
class task_promise<void> : public task_promise_base {
public:
	task<void> get_return_object();

	void return_void() {
	}

	void take_value() {
		rethrow_if_error();
	}
};

}

/**
 * Lazy coroutine task: the body starts running when the task is awaited and the awaiting
 * coroutine resumes once it completes, on whichever thread completes it. Await once; use
 * sync_wait() to run a task from non-coroutine code.
 */
template<typename T = void>
class [[nodiscard]] task {
public:
	using promise_type = detail::task_promise<T>;

	task() = default;

	explicit task(std::coroutine_handle<promise_type> handle) noexcept
	: handle_(handle)
	{
	}

	task(task&& other) noexcept
	: handle_(std::exchange(other.handle_, {}))
	{
	}

	task& operator=(task&& other) noexcept {
		if(this != &other) {
			destroy();
			handle_ = std::exchange(other.handle_, {});
		}
		return *this;
	}

	~task() {
		destroy();
	}

	auto operator co_await() noexcept {
		struct awaiter {
			bool await_ready() const noexcept {
				return handle.done();
			}
			std::coroutine_handle<> await_suspend(std::coroutine_handle<> continuation) const noexcept {
				handle.promise().set_continuation(continuation);
				return handle;
			}
			T await_resume() const {
				return handle.promise().take_value();
			}
			std::coroutine_handle<promise_type> handle;
		};
		return awaiter{handle_};
	}

private:
	void destroy() {
		if(handle_) {
			handle_.destroy();
			handle_ = {};
		}
	}

private:
	std::coroutine_handle<promise_type> handle_;
};

namespace detail {

template<typename T>
task<T> task_promise<T>::get_return_object() {
	return task<T>(std::coroutine_handle<task_promise<T>>::from_promise(*this));
}

inline task<void> task_promise<void>::get_return_object() {
	return task<void>(std::coroutine_handle<task_promise<void>>::from_promise(*this));
}

}

}
