// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"

#include <securepath/infrastructure/packet_transport/protocol/protocol.hpp>
#include <securepath/database/connection.hpp>
#include <securepath/serialisation/util.hpp>

#include <deque>
#include <memory>
#include <optional>

namespace securepath::packet_transport {

class in_packets;

class in_packet {
public:
	in_packet(in_packets*, std::int64_t key, transport_payload, database::connection_ptr);

	void mark_seen();
	transport_payload const& packet() const;

	/// Set arbitrary data attached to the packet
	template<typename Type>
	void set_data(Type const& t) {
		set_data_impl(serialisation::asn_der_serialise(t));
	}

	/// Get arbitrary data attached to the packet
	template<typename Type>
	std::optional<Type> data() const {
		auto v = data_impl();
		return !v.empty() ? serialisation::asn_der_deserialise<Type>(v) : std::optional<Type>();
	}

private:
	void set_data_impl(octet_vector const&);
	octet_vector data_impl() const;

private:
	in_packets* packets_{};
	std::int64_t key_{};
	transport_payload packet_;
	database::connection_ptr db_;
};

using in_packet_handle = std::shared_ptr<in_packet>;

class in_packets {
public:
	in_packets(database::connection_ptr);

	/// insert incoming transport packet to the database so that we can ensure it is handled
	in_packet_handle insert(transport_payload);

	/// remove the packet from the database when received ack from server
	void remove(std::int64_t key);

	/// get all pending packets when connecting to send again
	std::deque<in_packet_handle> get_pending_packets();

private:
	database::connection_ptr db_;
};

}
