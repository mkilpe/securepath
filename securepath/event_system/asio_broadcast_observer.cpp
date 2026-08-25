// SPDX-License-Identifier: MIT

#include "asio_broadcast_observer.hpp"

#include <securepath/log/log.hpp>

namespace securepath::event_system {

asio_broadcast_observer::asio_broadcast_observer(broadcast_event_handler& handler, asio::io_context& context)
: bc_observer_impl(handler)
, context_(context)
, strand_(context.get_executor())
, caller_(std::make_shared<asio_bc_observer_caller>())
{
}

asio_broadcast_observer::~asio_broadcast_observer() {
	handler_.deregister_observer(this);
	caller_->disable();
}

}
