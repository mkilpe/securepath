// SPDX-License-Identifier: MIT

#pragma once

#include "../broadcast_observer.hpp"

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <typeindex>

namespace securepath::event_system {

class bc_observer_impl : public broadcast_observer {
public:
	bc_observer_impl(broadcast_event_handler&);

	void connect(std::type_index, std::unique_ptr<broadcast_observer_func_base>);

	/// Disconnects all functions for specific event type.
	template<typename Event>
	void disconnect();

	void disconnect(std::type_index);
	void disconnect_all();

	void handle_event(std::shared_ptr<event_base>) override;
protected:
	~bc_observer_impl();

	using mutex_type = std::mutex;
	using lock_type = std::unique_lock<mutex_type>;
	using funcs_type = std::multimap<std::type_index, std::unique_ptr<broadcast_observer_func_base>>;

	mutable mutex_type mutex_;
	broadcast_event_handler& handler_;
	funcs_type funcs_;
};

template<typename Event>
void bc_observer_impl::disconnect() {
	disconnect(typeid(Event));
}

}

