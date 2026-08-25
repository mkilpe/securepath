// SPDX-License-Identifier: MIT

#pragma once

#include "event.hpp"

#include <memory>
#include <mutex>
#include <unordered_map>
#include <typeindex>

namespace securepath::event_system {

class broadcast_observer;

class broadcast_event_handler {
public:
	template<typename Event, typename... Args>
	void emit(Args&&...);

	void register_observer(broadcast_observer*, std::type_index);
	void deregister_observer(broadcast_observer*, std::type_index);
	void deregister_observer(broadcast_observer*);
private:
	void emit_event(std::shared_ptr<event_base>);
private:
	using mutex_type = std::mutex;
	using lock_type = std::unique_lock<mutex_type>;
	using observers_type = std::unordered_multimap<std::type_index, broadcast_observer*>;
	mutable mutex_type mutex_;
	observers_type observers_;
};

template<typename Event, typename... Args>
void broadcast_event_handler::emit(Args&&... args) {
	std::shared_ptr<event_base> ev(std::make_shared<event<Event>>(std::forward<Args>(args)...));
	emit_event(std::move(ev));
}

}

