// SPDX-License-Identifier: MIT

#pragma once

#include <coroutine>
#include <exception>
#include <future>
#include <memory>
#include <mutex>
#include <utility>

namespace securepath {

namespace detail {

template<typename T>
struct future_state {
	std::promise<T> promise;
	std::future<T> future{promise.get_future()};
	std::coroutine_handle<> continuation;
	std::mutex mutex;
	bool ready{};
};

}

/**
 * Single-shot future for asynchronous calls. get() blocks until the result is available;
 * co_await suspends the awaiting coroutine and resumes it once the result is available (on
 * whichever thread completes the promise, i.e. the io thread). Use one of get()/co_await per
 * future.
 */
template<typename T>
class future {
public:
	future() = default;

	explicit future(std::shared_ptr<detail::future_state<T>> state)
	: state_(std::move(state))
	{
	}

	T get() {
		return state_->future.get();
	}

	bool await_ready() const noexcept {
		return false;
	}

	bool await_suspend(std::coroutine_handle<> continuation) {
		std::unique_lock l{state_->mutex};
		if(state_->ready) {
			return false;
		}
		state_->continuation = continuation;
		return true;
	}

	T await_resume() {
		return state_->future.get();
	}

private:
	std::shared_ptr<detail::future_state<T>> state_;
};

namespace detail {

/// shared implementation of the producer side; completes the future at most once
template<typename T>
class promise_base {
public:
	promise_base()
	: state_(std::make_shared<future_state<T>>())
	{
	}

	future<T> get_future() const {
		return future<T>(state_);
	}

	void set_exception(std::exception_ptr e) {
		complete([&](future_state<T>& s) { s.promise.set_exception(std::move(e)); });
	}

protected:
	template<typename Setter>
	void complete(Setter setter) {
		std::coroutine_handle<> continuation;
		{
			std::unique_lock l{state_->mutex};
			if(state_->ready) {
				return;
			}
			setter(*state_);
			state_->ready = true;
			continuation = std::exchange(state_->continuation, nullptr);
		}
		if(continuation) {
			continuation.resume();
		}
	}

private:
	std::shared_ptr<future_state<T>> state_;
};

}

/// Producer side used to complete a future exactly once; later completions are ignored.
template<typename T>
class promise : public detail::promise_base<T> {
public:
	void set_value(T value) {
		this->complete([&](detail::future_state<T>& s) { s.promise.set_value(std::move(value)); });
	}
};

/// promise producing future<void>
template<>
class promise<void> : public detail::promise_base<void> {
public:
	void set_value() {
		complete([&](detail::future_state<void>& s) { s.promise.set_value(); });
	}
};

}
