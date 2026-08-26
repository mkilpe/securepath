// SPDX-License-Identifier: MIT

#include "key_server_connection.hpp"

#include <securepath/log/log.hpp>
#include <securepath/network/net_error.hpp>

#include <functional>

namespace securepath::key_server {

key_server_connection::key_server_connection(network::context& c,
	std::shared_ptr<network::encrypted_server> server, key_store& store)
: encrypted_connection(c, network::handshake_tag::public_key, std::move(server))
, store_(store)
{
}

key_server_connection::~key_server_connection() {
	encrypted_connection::close();
}

void key_server_connection::on_received(octet_span s) {
	try {
		deser_.handle(s, std::ref(*this));
	} catch(std::exception const& ex) {
		LOG_WARN("error handling key request: {}", ex.what());
		encrypted_connection::close();
	}
}

void key_server_connection::on_disconnected(securepath::error const& error) {
	LOG_TRACE("key server connection disconnected: {}", error);
}

void key_server_connection::operator()(protocol::register_key_request const& p) {
	protocol::register_key_response resp;
	resp.id = p.id;
	try {
		store_.register_key(p.key);
	} catch(securepath::error const& err) {
		resp.error = network::net_error(err);
	} catch(std::exception const& ex) {
		resp.error = network::net_error(make_error(securepath::errc::unknown_error, ex.what()));
	}
	send_response(resp);
}

void key_server_connection::operator()(protocol::find_key_request const& p) {
	protocol::find_key_response resp;
	resp.id = p.id;
	try {
		resp.key = store_.find_key(p.kid);
	} catch(securepath::error const& err) {
		resp.error = network::net_error(err);
	}
	send_response(resp);
}

void key_server_connection::operator()(protocol::find_certificate_request const& p) {
	protocol::find_certificate_response resp;
	resp.id = p.id;
	try {
		resp.cert = store_.find_certificate(p.cid);
	} catch(securepath::error const& err) {
		resp.error = network::net_error(err);
	}
	send_response(resp);
}

template<typename T>
void key_server_connection::operator()(T const&) {
	LOG_WARN("unexpected message on key server connection, closing");
	encrypted_connection::close();
}

template<typename Response>
void key_server_connection::send_response(Response const& resp) {
	encrypted_connection::send(serialisation::asn_der_serialise_choice<protocol::types>(resp));
}

}
