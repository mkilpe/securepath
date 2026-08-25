// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"

#include <securepath/infrastructure/packet_transport/protocol/ports.hpp>
#include <securepath/database/connection.hpp>
#include <securepath/event_system/event_handler.hpp>
#include <securepath/network/encryption/context.hpp>
#include <securepath/util/error.hpp>
#include <securepath/util/types.hpp>

#include <chrono>
#include <memory>
#include <string_view>

using namespace std::chrono_literals;

namespace securepath::packet_transport {

/**
 *  Client interface to transport packets from peer to peer via server
 */
class packet_client {
public:
	packet_client(network::context&, event_system::event_handler&, database::connection_ptr);
	~packet_client();

	/// emit pending events from database that has not yet been marked as seen
	void emit_pending_packets();

	/// connect to the server
	error connect(std::string_view host, std::uint16_t port = default_packet_server_port, std::chrono::seconds timeout = 10s);

	/// close connection
	void close();

	/// send packet to other user via server, returns unique key to the packet (see events)
	packet_key_type send_packet(octet_vector data, receiver);

private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}
