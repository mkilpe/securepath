// SPDX-License-Identifier: MIT

#include "handshake.hpp"
#include "protocol.hpp"

#include <securepath/network/encryption/error.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/log/log.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/error.hpp>

#include <cassert>

namespace securepath::network {

namespace {

std::uint8_t const client_role_byte{0x01};
std::uint8_t const server_role_byte{0x02};
std::string_view const binding_label{"EXPORTER-securepath-auth"};
std::size_t const binding_size{32};

octet_vector binding_context(std::uint8_t role, octet_vector const& client_id, octet_vector const& server_id) {
	octet_vector ctx;
	ctx.reserve(1 + client_id.size() + server_id.size());
	ctx.push_back(role);
	ctx.insert(ctx.end(), client_id.begin(), client_id.end());
	ctx.insert(ctx.end(), server_id.begin(), server_id.end());
	return ctx;
}

}

handshake::handshake(handshake_constructor& c, exporter_function exporter, endpoint_role role)
: context_(c)
, exporter_(std::move(exporter))
, role_(role)
{
}

handshake_result handshake::start(handshake_data data) {
	requested_ = std::move(data);
	client_hello_sent_ = true;
	client_id_ = crypto::random_octet_vector(handshake_protocol::hello_id_size);
	handshake_protocol::client_hello hello{context_.suite(), requested_.tag(), client_id_};
	return handshake_result{handshake_op_state::in_progress, serialisation::asn_der_serialise(hello)};
}

handshake_result handshake::handle_packet(octet_span data) {
	handshake_result res;
	if(client_hello_sent_) {
		client_hello_sent_ = false;
		res = handle_server_hello(data);
	} else if(!handshake_) {
		res = handle_client_hello(data);
	} else {
		try {
			res = handshake_->handle_packet(data);
		} catch(std::exception const& ex) {
			LOG_WARN("handling handshake packet failed: {}", ex.what());
		}
	}
	return res;
}

handshake_binding handshake::derive_binding() const {
	std::uint8_t const local_role = role_ == endpoint_role::client ? client_role_byte : server_role_byte;
	std::uint8_t const remote_role = role_ == endpoint_role::client ? server_role_byte : client_role_byte;
	handshake_binding b;
	b.local = exporter_(binding_label, binding_context(local_role, client_id_, server_id_), binding_size);
	b.remote = exporter_(binding_label, binding_context(remote_role, client_id_, server_id_), binding_size);
	return b;
}

handshake_result handshake::make_concrete() {
	requested_.set_binding(derive_binding());
	handshake_ = context_.construct_handshake(requested_);
	return handshake_ ? handshake_result{handshake_op_state::in_progress, {}}
		: handshake_result{handshake_op_state::error, {}};
}

handshake_result handshake::handle_client_hello(octet_span data) {
	assert(!handshake_);
	try {
		auto hello = serialisation::asn_der_deserialise<handshake_protocol::client_hello>(data);
		if(hello.version != handshake_protocol::current_version) {
			// the version is the migration lever for moving authentication into TLS
			// once Botan gains ML-DSA signature schemes (doc/network.md); unknown
			// versions are rejected until such a negotiation exists
			LOG_WARN("client hello version {} not supported", hello.version);
			return handshake_result{handshake_op_state::error, {}};
		}
		if(hello.suite != context_.suite()) {
			LOG_WARN("client hello suite mismatch");
			return handshake_result{handshake_op_state::error, {}};
		}
		client_id_ = hello.client_id;
		server_id_ = crypto::random_octet_vector(handshake_protocol::hello_id_size);
		requested_ = handshake_data{hello.handshake_request};
		handshake_protocol::server_hello reply{context_.suite(), hello.handshake_request, server_id_};
		octet_vector packet = serialisation::asn_der_serialise(reply);
		if(make_concrete().state == handshake_op_state::error) {
			return handshake_result{handshake_op_state::error, {}};
		}
		return handshake_result{handshake_op_state::in_progress, std::move(packet)};
	} catch(std::exception const& ex) {
		LOG_WARN("failed to handle client hello: {}", ex.what());
	}
	return handshake_result{handshake_op_state::error, {}};
}

handshake_result handshake::handle_server_hello(octet_span data) {
	assert(!handshake_);
	try {
		auto hello = serialisation::asn_der_deserialise<handshake_protocol::server_hello>(data);
		if(hello.version != handshake_protocol::current_version) {
			LOG_WARN("server hello version {} not supported", hello.version);
			return handshake_result{handshake_op_state::error, {}};
		}
		if(hello.handshake_response != requested_.tag() || hello.suite != context_.suite()) {
			LOG_WARN("server hello does not match request");
			return handshake_result{handshake_op_state::error, {}};
		}
		server_id_ = hello.server_id;
		if(make_concrete().state == handshake_op_state::error) {
			return handshake_result{handshake_op_state::error, {}};
		}
		return handshake_->start();
	} catch(std::exception const& ex) {
		LOG_WARN("failed to handle server hello: {}", ex.what());
	}
	return handshake_result{handshake_op_state::error, {}};
}

std::optional<crypto::public_key_id> handshake::remote_key_id() const {
	std::optional<crypto::public_key_id> ret;
	if(handshake_) {
		ret = handshake_->remote_key_id();
	}
	return ret;
}

}
