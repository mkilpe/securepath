// SPDX-License-Identifier: MIT

#pragma once

#include "handshake_base.hpp"

#include <securepath/crypto/suite.hpp>
#include <securepath/util/span.hpp>
#include <securepath/util/types.hpp>

#include <any>
#include <functional>
#include <optional>
#include <string>

namespace securepath::network {

/// Role of this endpoint in the TLS channel and the authentication.
enum class endpoint_role {
	client,
	server
};

/// Function that returns a TLS exporter value (RFC 5705); supplied by the transport.
using exporter_function = std::function<octet_vector(std::string_view label, octet_span context, std::size_t length)>;

/// The requested handshake and data specific to it.
class handshake_data {
public:
	handshake_data() = default;
	handshake_data(int tag, std::any data = {})
	: tag_(tag)
	, data_(std::move(data))
	{}

	int tag() const { return tag_; }
	std::string network_address() const { return network_address_; }
	void set_network_address(std::string const& addr) { network_address_ = addr; }

	handshake_binding const& binding() const { return binding_; }
	void set_binding(handshake_binding b) { binding_ = std::move(b); }

	template<typename T>
	std::optional<T> extract() const {
		std::optional<T> ret;
		if(T const* d = std::any_cast<T>(&data_)) {
			ret = *d;
		}
		return ret;
	}
private:
	int tag_{};
	std::string network_address_;
	handshake_binding binding_;
	std::any data_;
};

/// Interface to construct concrete handshakes (implemented by network::context).
class handshake_constructor {
public:
	virtual handshake_base_ptr construct_handshake(handshake_data const&) const = 0;
	virtual crypto::suite suite() const = 0;
protected:
	~handshake_constructor() = default;
};

/**
 * Drives the hello negotiation and then the concrete handshake. The hellos exchange the requested
 * tag, the suite and a random id per side; the channel binding is derived from the TLS exporter over
 * (role || client_id || server_id) and handed to the concrete handshake. See doc/network.md.
 */
class handshake {
public:
	handshake(handshake_constructor& c, exporter_function exporter, endpoint_role role);

	/// client side: produce the client_hello
	handshake_result start(handshake_data data);
	handshake_result handle_packet(octet_span data);
	std::optional<crypto::public_key_id> remote_key_id() const;
private:
	handshake_result handle_client_hello(octet_span data);
	handshake_result handle_server_hello(octet_span data);
	handshake_binding derive_binding() const;
	handshake_result make_concrete();

	handshake_constructor& context_;
	exporter_function exporter_;
	endpoint_role role_;
	handshake_data requested_;
	octet_vector client_id_;
	octet_vector server_id_;
	bool client_hello_sent_{};
	handshake_base_ptr handshake_;
};

}
