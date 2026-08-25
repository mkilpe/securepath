// SPDX-License-Identifier: MIT

#include "connection.hpp"

#include <securepath/log/log.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::packet_transport {

connection::connection(packet_server_context& c)
: context_(c)
{
}

securepath::error connection::on_connect(protocol::hello const& p, crypto::public_key_id id) {
	LOG_TRACE("on_connect for user {}", id);
	id_ = std::move(id);
	send_packet(protocol::hello{p});
	context_.on_connect(id_, shared_from_this());
	// no error
	return securepath::error();
}

void connection::handle(protocol::transport_packet const& p) {
	securepath::error error;
	try {
		if(p.packet.signature.issuer() == id_) {
			context_.transport_packet(id_, p, shared_from_this());
		} else {
			LOG_WARN("sender signature from different key than the connection");
		}
	} catch(securepath::error const& err) {
		LOG_WARN("exception while handling transport_packet: {} [kid={}]", err, id_);
		error = err;
	} catch(std::exception const& ex) {
		LOG_WARN("exception while handling transport_packet: {} [kid={}]", ex.what(), id_);
		error = make_error(securepath::errc::unknown_error);
	}
	if(error) {
		send_packet(protocol::error_packet{p.ack, std::move(error)});
	}
}

void connection::handle(protocol::ack_packet const& p) {
	securepath::error error;
	try {
		std::unique_lock l{mutex_};
		auto it = ack_map_.find(p.ack);
		if(it != ack_map_.end()) {
			it->second.mark_as_acked();
		} else {
			LOG_TRACE("unknown ack packet from client [ack={}]", p.ack);
		}
	} catch(securepath::error const& err) {
		LOG_WARN("exception while handling ack_packet: {} [kid={}]", err, id_);
		error = err;
	} catch(std::exception const& ex) {
		LOG_WARN("exception while handling ack_packet: {} [kid={}]", ex.what(), id_);
		error = make_error(securepath::errc::unknown_error);
	}
	if(error) {
		send_packet(protocol::error_packet{p.ack, std::move(error)});
	}
}

void connection::handle(protocol::error_packet const& p) {
	LOG_INFO("error packet from client: {} [kid={}]", protocol::describe(p.error), id_);
}

template<typename T>
void connection::send_packet(T const& p) {
	send(serialisation::asn_der_serialise_choice<protocol::types>(p));
}

void connection::send(packet_handle const& h, transport_payload payload) {
	{
		std::unique_lock l{mutex_};
		ack_map_.insert(std::make_pair(h.ack(), h));
	}
	send_packet(protocol::transport_packet{id_, std::move(payload), h.ack()});
}

void connection::send(ack_type ack) {
	send_packet(protocol::ack_packet{ack});
}

void connection::send(std::deque<stored_packet> const& packets) {
	{
		std::unique_lock l{mutex_};
		for(auto&& v : packets) {
			ack_map_.insert(std::make_pair(v.handle.ack(), v.handle));
		}
	}
	for(auto&& v : packets) {
		send_packet(protocol::transport_packet{id_, v.packet, v.handle.ack()});
	}
}

}
