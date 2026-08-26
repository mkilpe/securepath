// SPDX-License-Identifier: MIT

#pragma once

#include "handshake_base.hpp"

#include <securepath/network/net_error.hpp>
#include <securepath/crypto/suite.hpp>
#include <securepath/serialisation/sequence.hpp>
#include <securepath/util/error.hpp>
#include <securepath/util/types.hpp>

#include <cstdint>

namespace securepath::network::handshake_protocol {

std::uint16_t constexpr current_version{2};
std::size_t constexpr hello_id_size{16};

/// First packet sent by the client to request a handshake variant.
struct client_hello {
	client_hello() = default;
	client_hello(crypto::suite s, int req, octet_vector id)
	: suite(s)
	, handshake_request(req)
	, client_id(std::move(id))
	{}

	std::uint16_t version{current_version};
	crypto::suite suite{crypto::suite::pq1};
	int handshake_request{handshake_tag::unknown};
	octet_vector client_id;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version & suite & handshake_request & client_id;
	}
};

/// Server answer selecting the variant (or unknown when it is not offered). It also carries the
/// concrete handshake's server-first authentication payload (server_auth): for the public-key
/// variant this is the server's own authentication, sent here so the client verifies the server
/// before it discloses its identity. It is empty when the concrete handshake has the client speak
/// first (the shared-secret variant, which reveals no identity). See doc/threat_model.md.
struct server_hello {
	server_hello() = default;
	server_hello(crypto::suite s, int resp, octet_vector id, octet_vector auth = {})
	: suite(s)
	, handshake_response(resp)
	, server_id(std::move(id))
	, server_auth(std::move(auth))
	{}

	std::uint16_t version{current_version};
	crypto::suite suite{crypto::suite::pq1};
	int handshake_response{handshake_tag::unknown};
	octet_vector server_id;
	octet_vector server_auth;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version & suite & handshake_response & server_id & server_auth;
	}
};

/// Sent by the server to the client once the client's authentication has been accepted, so the
/// client only reports the connection as established after the server has accepted it (the
/// public-key variant, where the server verifies the client last). The shared-secret variant does
/// not need it: the server's own mac is the client's confirmation.
struct handshake_ack {
	std::uint16_t version{current_version};

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version;
	}
};

using error = network::net_error;

}
