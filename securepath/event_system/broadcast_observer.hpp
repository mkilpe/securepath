// SPDX-License-Identifier: MIT

#pragma once

#include "broadcast_event_handler.hpp"

#include <memory>
#include <utility>

namespace securepath::event_system {

class broadcast_observer {
public:
	virtual ~broadcast_observer() {}
	virtual void handle_event(std::shared_ptr<event_base>) = 0;
};

class broadcast_observer_func_base {
public:
	virtual ~broadcast_observer_func_base() {}
	virtual void do_call(std::shared_ptr<event_base>) = 0;
};

template<typename Event, typename Func>
class broadcast_observer_func : public broadcast_observer_func_base {
public:
	using event_type = Event;
	using function_type = Func;

	broadcast_observer_func(function_type f)
	: func_(std::move(f))
	{}

	virtual void do_call(std::shared_ptr<event_base> ev) {
		func_(std::move(ev));
	}

	function_type func_;
};

}

