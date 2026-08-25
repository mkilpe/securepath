// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/crypto/public_key_id.hpp>
#include <securepath/util/span.hpp>
#include <securepath/util/types.hpp>

#include <cstdint>
#include <optional>

namespace securepath::network {

/// Requested handshake variants, negotiated in the hello exchange. Values are on the wire.
namespace handshake_tag {
	enum type {
		unknown = 0,
		public_key = 2,   ///< mutual public-key + certificate-chain authentication (pk)
		shared_secret = 4 ///< pre-shared-secret authentication (ss)
	};
}

using handshake_type = handshake_tag::type;

enum class handshake_op_state {
	in_progress,
	succeeded,
	error
};

/// The channel binding a handshake authenticates: the TLS exporter for the local and the peer role.
struct handshake_binding {
	octet_vector local;  ///< signed/mac'd by us
	octet_vector remote; ///< the peer's signature/mac is verified against this
};

/// One step of a concrete handshake: a packet to send to the peer (may be empty) and the new state.
struct handshake_result {
	handshake_op_state state{handshake_op_state::error};
	octet_vector packet;
};

/**
 * A concrete authentication handshake carried inside the (already encrypted) TLS channel.
 * The orchestrating handshake feeds it the peer's packets and sends the packets it produces.
 */
class handshake_base {
public:
	virtual ~handshake_base() = default;

	/// client side sends the first packet; the server side returns an error (it never starts)
	virtual handshake_result start() = 0;
	virtual handshake_result handle_packet(octet_span data) = 0;
	virtual int type() const = 0;
	virtual std::optional<crypto::public_key_id> remote_key_id() const { return std::nullopt; }
};

using handshake_base_ptr = std::unique_ptr<handshake_base>;

}
