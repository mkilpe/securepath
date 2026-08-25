// SPDX-License-Identifier: MIT

#include "in_packets.hpp"

#include <securepath/log/log.hpp>

namespace securepath::packet_transport {

in_packet::in_packet(in_packets* p, std::int64_t key, transport_payload packet, database::connection_ptr db)
: packets_(p)
, key_(key)
, packet_(std::move(packet))
, db_(db)
{
}

void in_packet::mark_seen() {
	packets_->remove(key_);
}

transport_payload const& in_packet::packet() const {
	return packet_;
}

void in_packet::set_data_impl(octet_vector const& d) {
	auto q = db_->prepare("UPDATE in_packets SET userdata = :data WHERE key = :key;");
	q.bind(":key", key_);
	q.bind(":data", d);
	q.execute();
}

octet_vector in_packet::data_impl() const {
	octet_vector ret;
	auto q = db_->prepare("SELECT userdata FROM in_packets WHERE key = :key;");
	q.bind(":key", key_);
	auto res = q.execute();
	if(res) {
		ret = res.value<octet_vector>(0).value_or(ret);
	}
	return ret;
}

in_packets::in_packets(database::connection_ptr db)
: db_(db)
{
	if(!db_->has_table("in_packets")) {
		std::string prepare_str =
			"CREATE TABLE in_packets("
				"key INTEGER PRIMARY KEY, "
				"packet BLOB, "
				"userdata BLOB NULL);";
		db_->prepare(prepare_str).execute();
	}
}

in_packet_handle in_packets::insert(transport_payload p) {
	auto q = db_->prepare("INSERT INTO in_packets(packet) VALUES(:d);");
	q.bind(":d", serialisation::asn_der_serialise(p));
	q.execute();
	return std::make_shared<in_packet>(this, q.last_inserted_row_id(), std::move(p), db_);
}

void in_packets::remove(std::int64_t key) {
	auto q = db_->prepare("DELETE FROM in_packets WHERE key = :key;");
	q.bind(":key", key);
	q.execute();
}

std::deque<in_packet_handle> in_packets::get_pending_packets() {
	std::deque<in_packet_handle> ret;
	auto q = db_->prepare("SELECT key, packet FROM in_packets;");
	auto res = q.execute();
	for(; res; res.next()) {
		transport_payload p =
			serialisation::asn_der_deserialise<transport_payload>(res.value<octet_vector>(1).value());
		ret.push_back(std::make_shared<in_packet>(this, res.value<std::int64_t>(0).value(), std::move(p), db_));
	}
	LOG_TRACE("incoming pending packets [size={}]", ret.size());
	return ret;
}

}
