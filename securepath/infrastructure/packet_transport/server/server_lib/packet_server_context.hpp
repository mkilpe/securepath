// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/infrastructure/packet_transport/protocol/protocol.hpp>
#include <securepath/crypto/public_key_id.hpp>

#include <memory>

namespace securepath::packet_transport {

class connection;

class packet_server_context {
protected:
	~packet_server_context() = default;

public:
	virtual void on_connect(crypto::public_key_id const&, std::shared_ptr<connection>) = 0;
	virtual void transport_packet(crypto::public_key_id const&, protocol::transport_packet const&, std::shared_ptr<connection>) = 0;
};

}
