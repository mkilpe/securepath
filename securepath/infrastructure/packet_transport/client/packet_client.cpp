// SPDX-License-Identifier: MIT

#include "packet_client.hpp"
#include "events.hpp"
#include "out_packets.hpp"

#include <securepath/infrastructure/packet_transport/protocol/protocol.hpp>

#include <securepath/crypto/private_data_access.hpp>
#include <securepath/crypto/public_key_access.hpp>
#include <securepath/network/encryption/encrypted_connection.hpp>
#include <securepath/network/encryption/error.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/timer.hpp>

#include <atomic>

namespace securepath::packet_transport {

class packet_client::impl : public network::encrypted_connection {
public:
	impl(network::context& c, event_system::event_handler& h, database::connection_ptr db)
	: encrypted_connection(c)
	, context(c)
	, handler(h)
	, packets_to_in(db)
	, packets_to_out(db)
	{}

	using encrypted_connection::send;

	template<typename T>
	void send(T const& p) {
		encrypted_connection::send(serialisation::asn_der_serialise_choice<protocol::types>(p));
	}

	void shutdown(error const& err = {}) {
		LOG_TRACE("closing packet client connection");
		encrypted_connection::close();
		on_disconnected(err);
	}

	void on_connected() override {
		LOG_TRACE("packet client connected, sending hello...");
		hello_done = false;
		deser.clear();
		send(protocol::hello{});
	}

	void on_disconnected(securepath::error const& error) override {
		LOG_INFO("packet client disconnected: {}", error);
		handler.emit<events::on_disconnect>(error);
	}

	void on_sent(std::size_t) override {
	}

	void on_received(octet_span s) override {
		deser.handle(s,
			[this](auto const& packet) {
				this->handle(packet);
			});
	}

	void handle(protocol::hello const& p) {
		if(p.error) {
			LOG_WARN("server responded with error: {}", protocol::describe(p.error));
			shutdown(protocol::to_error(p.error));
		} else {
			hello_done = true;
			// notify higher level that we are connected now
			handler.emit<events::on_connect>();

			for(auto&& v : packets_to_out.get_pending_packets()) {
				send(v);
			}
		}
	}

	void handle(protocol::error_packet const& p) {
		LOG_WARN("error from server: {}", protocol::describe(p.error));
		packets_to_out.remove(p.ack);
		handler.emit<events::on_error>(packet_dir::out, p.ack, protocol::to_error(p.error));
	}

	void handle(protocol::transport_packet const& p) {
		auto handle = packets_to_in.insert(p.packet);
		handler.emit<events::on_packet>(handle);
		send(protocol::ack_packet{p.ack});
	}

	void handle(protocol::ack_packet const& p) {
		packets_to_out.remove(p.ack);
	}

public:
	network::context& context;
	event_system::event_handler& handler;
	serialisation::packet_deserialiser<protocol::types> deser;
	in_packets packets_to_in;
	out_packets packets_to_out;
	std::atomic<bool> hello_done{};
};

packet_client::packet_client(network::context& c, event_system::event_handler& h, database::connection_ptr db)
: impl_(std::make_unique<impl>(c, h, db))
{
}

packet_client::~packet_client() {
	impl_->shutdown();
}

void packet_client::emit_pending_packets() {
	for(auto&& v : impl_->packets_to_in.get_pending_packets()) {
		impl_->handler.emit<events::on_packet>(v);
	}
}

error packet_client::connect(std::string_view host, std::uint16_t port, std::chrono::seconds timeout) {
	error err;
	if(impl_->state() == network::encrypted_connection::not_connected) {
		impl_->connect(host, port, timeout);
	} else {
		LOG_TRACE("calling connect in some other than not_connected state");
		if(impl_->state() == network::encrypted_connection::connected) {
			err = make_error(network::errc::already_connected);
		} else {
			err = make_error(securepath::errc::invalid_state, "calling connect in some other than not_connected state");
		}
	}
	return err;
}

void packet_client::close() {
	impl_->shutdown();
}

packet_key_type packet_client::send_packet(octet_vector data, receiver rec) {
	timer t;

	auto my_key = my_private_key(impl_->context.private_data());

	protocol::transport_packet p;
	crypto::enveloper env{std::move(data)};

	auto key = impl_->context.public_keys().find(rec.id);
	if(!key) {
		LOG_WARN("could not find public key to envelope packet [kid={}]", rec.id);
		throw make_error(crypto::errc::no_such_key, "could not find public key to envelope packet");
	}
	env.add(*key);

	p.packet.data = env.result();
	p.packet.signature = my_key.sign(serialisation::asn_der_serialise(p.packet.data));
	p.rec = std::move(rec);
	p.ack = impl_->packets_to_out.insert(p);

	// try to send the message if we have connection, otherwise it is in the db waiting
	if(impl_->state() == network::encrypted_connection::connected && impl_->hello_done) {
		impl_->send(p);
	}

	LOG_TRACE("sending packet took {} ms", t.elapsed_milliseconds());

	return p.ack;
}

}
