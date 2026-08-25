// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/crypto/enveloped_content.hpp>
#include <securepath/crypto/public_key_id.hpp>
#include <securepath/crypto/signature.hpp>
#include <securepath/serialisation/sequence.hpp>

#include <cstdint>

namespace securepath::packet_transport {

using ack_type = std::int64_t;

/// the payload transported from user to user: data enveloped for the receiver, signed by the sender
struct transport_payload {
	crypto::enveloped_content data;
	crypto::signature signature;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & data & signature;
	}
};

struct receiver {
	crypto::public_key_id id;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & id;
	}
};

}
