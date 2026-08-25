// SPDX-License-Identifier: MIT

#include "out_packets.hpp"

#include <securepath/log/log.hpp>

namespace securepath::packet_transport {

out_packets::out_packets(database::connection_ptr db)
: db_(db)
{
	if(!db_->has_table("out_packets")) {
		std::string prepare_str =
			"CREATE TABLE out_packets("
				"key INTEGER PRIMARY KEY, "
				"packet BLOB);";
		db_->prepare(prepare_str).execute();
	}
}

ack_type out_packets::insert(protocol::transport_packet const& p) {
	auto q = db_->prepare("INSERT INTO out_packets(packet) VALUES(:d);");
	q.bind(":d", serialisation::asn_der_serialise(p));
	q.execute();
	return q.last_inserted_row_id();
}

void out_packets::remove(ack_type ack) {
	auto q = db_->prepare("DELETE FROM out_packets WHERE key = :key;");
	q.bind(":key", ack);
	q.execute();
}

std::deque<protocol::transport_packet> out_packets::get_pending_packets() const {
	std::deque<protocol::transport_packet> ret;
	auto q = db_->prepare("SELECT key, packet FROM out_packets;");
	auto res = q.execute();
	for(; res; res.next()) {
		protocol::transport_packet p =
			serialisation::asn_der_deserialise<protocol::transport_packet>(res.value<octet_vector>(1).value());
		p.ack = res.value<ack_type>(0).value();
		ret.push_back(std::move(p));
	}
	LOG_TRACE("outgoing pending packets [size={}]", ret.size());
	return ret;
}

}
