// SPDX-License-Identifier: MIT

#pragma once

#include "key_store.hpp"

#include <securepath/infrastructure/key_server/protocol/protocol.hpp>
#include <securepath/network/encryption/encrypted_connection.hpp>
#include <securepath/network/encryption/encrypted_server.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/span.hpp>
#include <securepath/util/types.hpp>

#include <memory>

namespace securepath::key_server {

/// Server side of one client connection: answers key/certificate requests from the key_store. The
/// operator() overloads are the deserialiser visitor; unexpected message types close the connection.
class key_server_connection : public network::encrypted_connection {
public:
	key_server_connection(network::context&, std::shared_ptr<network::encrypted_server>, key_store&);
	~key_server_connection() override;

	void operator()(protocol::register_key_request const&);
	void operator()(protocol::find_key_request const&);
	void operator()(protocol::find_certificate_request const&);
	template<typename T>
	void operator()(T const&);

protected:
	void on_received(octet_span) override;
	void on_disconnected(securepath::error const&) override;

private:
	template<typename Response>
	void send_response(Response const&);

private:
	key_store& store_;
	serialisation::packet_deserialiser<protocol::types> deser_;
};

}
