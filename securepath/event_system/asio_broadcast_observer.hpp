// SPDX-License-Identifier: MIT

#pragma once

#include "impl/bc_observer_impl.hpp"

#include <asio/io_context.hpp>
#include <asio/post.hpp>
#include <asio/strand.hpp>

#include <atomic>
#include <cassert>
#include <memory>
#include <mutex>
#include <tuple>
#include <utility>

namespace securepath::event_system {

struct asio_bc_observer_caller {

	template<typename Func, typename Event, std::size_t... I>
	void make_call(Func f, Event const& ev, std::index_sequence<I...>) {
		f(std::get<I>(ev.params)...);
	}

	template<typename Func, typename Event>
	void operator()(Func f, Event const& ev) {
		if(enabled_) {
			std::unique_lock lock{mutex_};
			if(enabled_) {
				make_call(f, ev, std::make_index_sequence<Event::size>{});
			}
		}
	}

	void disable() {
		enabled_ = false;
		//make sure there is no call in progress
		std::unique_lock lock{mutex_};
	}

private:
	std::atomic<bool> enabled_ = true;
	mutable std::recursive_mutex mutex_;
};

class asio_broadcast_observer : public bc_observer_impl {
public:
	asio_broadcast_observer(broadcast_event_handler&, asio::io_context&);
	~asio_broadcast_observer();

	template<typename Event, typename Func>
	void connect(Func f);

private:
	asio::io_context& context_;
	asio::strand<asio::io_context::executor_type> strand_;
	std::shared_ptr<asio_bc_observer_caller> caller_;
};

template<typename Event, typename Func>
void asio_broadcast_observer::connect(Func f) {
	auto rf = [this, f, caller = caller_](std::shared_ptr<event_base> ev) mutable {
		asio::post(this->strand_, [f, caller, ev = std::move(ev)]() mutable
			{
				assert(caller);
				assert(ev);
				(*caller)(f, static_cast<event<Event> const&>(*ev));
			});
	};
	bc_observer_impl::connect(typeid(Event), std::make_unique<broadcast_observer_func<Event, decltype(rf)>>(rf));
}

}

