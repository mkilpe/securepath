// SPDX-License-Identifier: MIT

#pragma once

#include "task.hpp"

#include <coroutine>
#include <exception>
#include <optional>
#include <type_traits>
#include <utility>

namespace securepath {

/// something work can be submitted to, e.g. an asio executor or strand
template<typename E>
concept executor = requires(E ex, void(*work)()) {
	ex.execute(work);
};

namespace detail {

template<executor Executor>
class schedule_awaiter {
public:
	explicit schedule_awaiter(Executor ex)
	: executor_(std::move(ex))
	{
	}

	bool await_ready() const noexcept {
		return false;
	}

	void await_suspend(std::coroutine_handle<> handle) {
		executor_.execute([handle] { handle.resume(); });
	}

	void await_resume() const noexcept {
	}

private:
	Executor executor_;
};

template<typename A>
decltype(auto) get_awaiter(A&& a) {
	if constexpr(requires { std::forward<A>(a).operator co_await(); }) {
		return std::forward<A>(a).operator co_await();
	} else {
		return std::forward<A>(a);
	}
}

/// result type of co_await'ing an A
template<typename A>
using await_result_t = decltype(get_awaiter(std::declval<A>()).await_resume());

}

/// Awaitable that resumes the awaiting coroutine on the executor.
template<executor Executor>
auto schedule(Executor ex) {
	return detail::schedule_awaiter<Executor>(std::move(ex));
}

/**
 * Awaits the awaitable and resumes the awaiting coroutine on the executor instead of on the
 * thread that completed the awaitable, e.g.
 *   co_await resume_on(strand, client.async_find_key(id));
 * The result (or exception) of the awaitable is passed through. The executor must eventually run
 * the work submitted to it, otherwise the returned task never completes.
 */
template<executor Executor, typename Awaitable>
	requires std::is_void_v<detail::await_result_t<Awaitable>>
task<void> resume_on(Executor ex, Awaitable a) {
	std::exception_ptr error;
	try {
		co_await std::move(a);
	} catch(...) {
		error = std::current_exception();
	}
	co_await schedule(std::move(ex));
	if(error) {
		std::rethrow_exception(error);
	}
}

template<executor Executor, typename Awaitable>
	requires (!std::is_void_v<detail::await_result_t<Awaitable>>)
task<detail::await_result_t<Awaitable>> resume_on(Executor ex, Awaitable a) {
	using result_type = detail::await_result_t<Awaitable>;
	std::exception_ptr error;
	std::optional<result_type> result;
	try {
		result.emplace(co_await std::move(a));
	} catch(...) {
		error = std::current_exception();
	}
	co_await schedule(std::move(ex));
	if(error) {
		std::rethrow_exception(error);
	}
	co_return std::move(*result);
}

}
