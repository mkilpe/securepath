// SPDX-License-Identifier: MIT

#include "bc_observer_impl.hpp"

#include <securepath/log/log.hpp>

namespace securepath::event_system {

bc_observer_impl::bc_observer_impl(broadcast_event_handler& handler)
: handler_(handler)
{
}

bc_observer_impl::~bc_observer_impl() {
}

void bc_observer_impl::connect(std::type_index index, std::unique_ptr<broadcast_observer_func_base> p) {
	LOG_TRACE("observer connect {}", index.name());
	{
		lock_type lock{mutex_};
		funcs_.insert(funcs_type::value_type{index, std::move(p)});
	}
	handler_.register_observer(this, index);
}

void bc_observer_impl::disconnect(std::type_index index) {
	{
		lock_type lock{mutex_};
		funcs_.erase(index);
	}
	handler_.deregister_observer(this, index);
}

void bc_observer_impl::disconnect_all() {
	{
		lock_type lock{mutex_};
		funcs_.clear();
	}
	handler_.deregister_observer(this);
}

void bc_observer_impl::handle_event(std::shared_ptr<event_base> ev) {
	lock_type lock{mutex_};
	auto it_pair = funcs_.equal_range(ev->type);
	for(;it_pair.first != it_pair.second; ++it_pair.first) {
		it_pair.first->second->do_call(ev);
	}
}

}
