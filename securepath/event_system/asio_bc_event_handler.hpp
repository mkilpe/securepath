// SPDX-License-Identifier: MIT

#pragma once

#include "broadcast_event_handler.hpp"

#include <asio/io_context.hpp>

namespace securepath::event_system {

class asio_bc_event_handler : public broadcast_event_handler {
public:
	asio_bc_event_handler(asio::io_context& context)
	: io_context_(context)
	{
	}

	~asio_bc_event_handler() {
	}

	asio::io_context& context() {
		return io_context_;
	}
private:
	asio::io_context& io_context_;
};

}

