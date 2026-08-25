// SPDX-License-Identifier: MIT

#pragma once

#include "impl/bc_observer_impl.hpp"
#include "event_handler.hpp"
#include "event_loop.hpp"

#include <memory>
#include <mutex>

namespace securepath::event_system {

class event_loop_broadcast_observer : public event_handler, public bc_observer_impl {
public:
	event_loop_broadcast_observer(broadcast_event_handler&, event_system::event_loop&);
	~event_loop_broadcast_observer();

	template<typename Event>
	void connect();
};

template<typename Event>
void event_loop_broadcast_observer::connect() {
	auto rf = [this](std::shared_ptr<event_base> ev) mutable {
		emit(ev->create_unique());
	};
	bc_observer_impl::connect(typeid(Event), std::make_unique<broadcast_observer_func<Event, decltype(rf)>>(rf));
}

}

