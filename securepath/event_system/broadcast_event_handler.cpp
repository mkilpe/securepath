// SPDX-License-Identifier: MIT

#include "broadcast_event_handler.hpp"
#include "broadcast_observer.hpp"

namespace securepath::event_system {

void broadcast_event_handler::register_observer(broadcast_observer* ob, std::type_index index) {
	lock_type lock{mutex_};

	//check if that observer is already registered for the given event type
	auto it_pair = observers_.equal_range(index);
	for(; it_pair.first != it_pair.second && it_pair.first->second != ob; ++it_pair.first) {}

	if(it_pair.first == it_pair.second) {
		observers_.insert(observers_type::value_type{index, ob});
	}
}

void broadcast_event_handler::deregister_observer(broadcast_observer* ob, std::type_index index) {
	lock_type lock{mutex_};
	auto it_pair = observers_.equal_range(index);
	for(;it_pair.first != it_pair.second;) {
		if(it_pair.first->second == ob) {
			it_pair.first = observers_.erase(it_pair.first);
		} else {
			++it_pair.first;
		}
	}
}

void broadcast_event_handler::deregister_observer(broadcast_observer* ob) {
	lock_type lock{mutex_};
	for(auto it = observers_.begin(); it != observers_.end();) {
		if(it->second == ob) {
			it = observers_.erase(it);
		} else {
			++it;
		}
	}
}

void broadcast_event_handler::emit_event(std::shared_ptr<event_base> ev) {
	lock_type lock{mutex_};
	auto it_pair = observers_.equal_range(ev->type);
	for(;it_pair.first != it_pair.second; ++it_pair.first) {
		it_pair.first->second->handle_event(ev);
	}
}

}
