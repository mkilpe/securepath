// SPDX-License-Identifier: MIT

#include "event_loop_broadcast_observer.hpp"

namespace securepath::event_system {

event_loop_broadcast_observer::event_loop_broadcast_observer(broadcast_event_handler& handler, event_system::event_loop& loop)
: event_handler(loop)
, bc_observer_impl(handler)
{
}

event_loop_broadcast_observer::~event_loop_broadcast_observer() {
	handler_.deregister_observer(this);
}

}
