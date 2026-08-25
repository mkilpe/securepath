// SPDX-License-Identifier: MIT

#pragma once

#include "error.hpp"
#include "types.hpp"

#include <securepath/network/net_error.hpp>
#include <securepath/serialisation/choice.hpp>
#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/vector.hpp>
#include <securepath/util/typelist.hpp>

#include <cstdint>

namespace securepath::packet_transport::protocol {
inline namespace v1 {

std::uint16_t const current_version{1};

/// always first packet to negotiate version
struct hello {
	int version{current_version};
	ack_type ack{};
	network::net_error error;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & version & ack & error;
	}
};

struct transport_packet {
	receiver rec;
	transport_payload packet;
	ack_type ack{};

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & rec & packet & ack;
	}
};

struct ack_packet {
	ack_type ack{};

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & ack;
	}
};

struct error_packet {
	error_packet(ack_type ack = {}, securepath::error err = {})
	: ack(ack)
	, error(std::move(err))
	{}

	ack_type ack{};
	network::net_error error;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & ack & error;
	}
};

using serialisation::type_tag;

using types =
	typelist<type_tag<hello, 1>,
			 type_tag<transport_packet, 2>,
			 type_tag<ack_packet, 3>,
			 type_tag<error_packet, 4> >;

}
}
