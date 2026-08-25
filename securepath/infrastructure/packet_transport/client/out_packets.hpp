// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"

#include <securepath/infrastructure/packet_transport/protocol/protocol.hpp>
#include <securepath/database/connection.hpp>
#include <securepath/serialisation/util.hpp>

#include <deque>

namespace securepath::packet_transport {

class out_packets {
public:
	out_packets(database::connection_ptr);

	/// insert transport packet to the database so that we can ensure its transportation
	ack_type insert(protocol::transport_packet const&);

	/// remove the packet from the database when received ack from server
	void remove(ack_type);

	/// get all pending packets when connecting to send again
	std::deque<protocol::transport_packet> get_pending_packets() const;

private:
	database::connection_ptr db_;
};

}
