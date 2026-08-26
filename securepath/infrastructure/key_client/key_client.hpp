// SPDX-License-Identifier: MIT

#pragma once

#include "future.hpp"

#include <securepath/crypto/certificate.hpp>
#include <securepath/crypto/certificate_id.hpp>
#include <securepath/crypto/public_key.hpp>
#include <securepath/crypto/public_key_id.hpp>
#include <securepath/event_system/broadcast_event_handler.hpp>
#include <securepath/network/encryption/context.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

using namespace std::chrono_literals;

namespace securepath::key_client {

/**
 * Client for the unknown-user key server: registers a public key and looks up keys and
 * certificates over an encrypted connection. The connection uses the public-key handshake with the
 * client anonymous (no own credentials); the client still authenticates the server. Connection
 * state is reported through event_handler() as key_client::events::on_connect / on_disconnect.
 */
class client {
public:
	client();
	explicit client(network::context&);
	~client();

	void connect(std::string_view host, std::uint16_t port, std::chrono::seconds timeout = 10s);
	void close();
	void wait_for_connection() const;

	/// broadcast handler emitting key_client::events::on_connect / on_disconnect
	event_system::broadcast_event_handler& event_handler() noexcept;

	void register_key(crypto::public_key const&);
	std::optional<crypto::public_key> find_key(crypto::public_key_id const&) const;
	std::optional<crypto::certificate> find_certificate(crypto::certificate_id const&) const;

	future<void> async_register_key(crypto::public_key const&);
	future<std::optional<crypto::public_key>> async_find_key(crypto::public_key_id const&) const;
	future<std::optional<crypto::certificate>> async_find_certificate(crypto::certificate_id const&) const;

private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}
