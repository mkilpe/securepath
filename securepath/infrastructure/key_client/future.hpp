// SPDX-License-Identifier: MIT

#pragma once

#include <exception>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <utility>

namespace securepath::key_client {

namespace detail {

template<typename T>
struct future_state {
	std::promise<T> promise;
	std::future<T> future{promise.get_future()};
	std::function<void(std::future<T>)> continuation;
	std::mutex mutex;
	bool ready{};
};

}

/**
 * Minimal future for the key client's asynchronous calls. get() blocks until the result is
 * available; then(f) invokes f(std::future<T>) once it is available (on whichever thread completes
 * the result, i.e. the io thread). Use one of get()/then() per future.
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

	template<typename F>
	void then(F f) {
		std::function<void(std::future<T>)> cont =
			[f = std::move(f)](std::future<T> fut) mutable { f(std::move(fut)); };
		bool run_now = false;
		{
			std::unique_lock l{state_->mutex};
			if(state_->ready) {
				run_now = true;
			} else {
				state_->continuation = std::move(cont);
			}
		}
		if(run_now) {
			cont(std::move(state_->future));
		}
	}

private:
	std::shared_ptr<detail::future_state<T>> state_;
};

/// Producer side used by the client to complete a future exactly once.
template<typename T>
class promise {
public:
	promise()
	: state_(std::make_shared<detail::future_state<T>>())
	{
	}

	future<T> get_future() const {
		return future<T>(state_);
	}

	void set_value(T value) {
		complete([&](detail::future_state<T>& s) { s.promise.set_value(std::move(value)); });
	}

	void set_exception(std::exception_ptr e) {
		complete([&](detail::future_state<T>& s) { s.promise.set_exception(std::move(e)); });
	}

private:
	template<typename Setter>
	void complete(Setter setter) {
		std::function<void(std::future<T>)> cont;
		{
			std::unique_lock l{state_->mutex};
			if(state_->ready) {
				return;
			}
			setter(*state_);
			state_->ready = true;
			cont = std::move(state_->continuation);
			state_->continuation = nullptr;
		}
		if(cont) {
			cont(std::move(state_->future));
		}
	}

private:
	std::shared_ptr<detail::future_state<T>> state_;
};

/// promise producing future<void>
template<>
class promise<void> {
public:
	promise()
	: state_(std::make_shared<detail::future_state<void>>())
	{
	}

	future<void> get_future() const {
		return future<void>(state_);
	}

	void set_value() {
		complete([&](detail::future_state<void>& s) { s.promise.set_value(); });
	}

	void set_exception(std::exception_ptr e) {
		complete([&](detail::future_state<void>& s) { s.promise.set_exception(std::move(e)); });
	}

private:
	template<typename Setter>
	void complete(Setter setter) {
		std::function<void(std::future<void>)> cont;
		{
			std::unique_lock l{state_->mutex};
			if(state_->ready) {
				return;
			}
			setter(*state_);
			state_->ready = true;
			cont = std::move(state_->continuation);
			state_->continuation = nullptr;
		}
		if(cont) {
			cont(std::move(state_->future));
		}
	}

private:
	std::shared_ptr<detail::future_state<void>> state_;
};

}
