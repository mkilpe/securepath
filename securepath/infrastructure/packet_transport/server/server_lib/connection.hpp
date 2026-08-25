// SPDX-License-Identifier: MIT

#pragma once

#include "packet_server_context.hpp"
#include "packet_storage.hpp"

#include <securepath/infrastructure/packet_transport/protocol/protocol.hpp>

#include <securepath/util/error.hpp>
#include <securepath/util/span.hpp>
#include <securepath/util/types.hpp>

#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <span>

namespace securepath::packet_transport {

class connection : public std::enable_shared_from_this<connection> {
public:
	connection(packet_server_context&);
	virtual ~connection() = default;

	securepath::error on_connect(protocol::hello const& p, crypto::public_key_id id);

	void handle(protocol::transport_packet const&);
	void handle(protocol::ack_packet const&);
	void handle(protocol::error_packet const&);

	void send(packet_handle const&, transport_payload);
	void send(ack_type);
	void send(std::deque<stored_packet> const&);

private:
	virtual void send(octet_span s) = 0;
	template<typename T> void send_packet(T const& p);

private:
	mutable std::mutex mutex_;
	packet_server_context& context_;
	crypto::public_key_id id_;
	std::map<ack_type, packet_handle> ack_map_;
};

}
