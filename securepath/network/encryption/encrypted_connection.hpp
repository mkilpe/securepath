// SPDX-License-Identifier: MIT

#pragma once

#include "context.hpp"

#include <securepath/crypto/public_key_id.hpp>
#include <securepath/util/error.hpp>
#include <securepath/util/span.hpp>

#include <asio/ip/tcp.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

namespace securepath::network {

using namespace std::literals;
using tcp_endpoint = asio::ip::tcp::endpoint;

class encrypted_server;

namespace detail {
	class encrypted_connection_impl;
}

/**
 * Encrypted, message-preserving connection over TLS 1.3 (see doc/network.md). The connection is
 * asynchronous; all calls return immediately and the virtual callbacks are serialised on a strand.
 * Derive and override the callbacks; call close() before destroying a derived object.
 */
class encrypted_connection {
public:
	enum connection_state {
		not_connected,
		connecting,
		connected
	};

	encrypted_connection(network::context&, handshake_data = handshake_tag::public_key,
		std::shared_ptr<encrypted_server> = nullptr);
	virtual ~encrypted_connection();

	virtual void connect(std::string_view const& network_address, std::uint16_t port,
		std::chrono::seconds timeout = 10s);
	/// send one message; the peer receives exactly one on_received() with the same bytes
	virtual void send(octet_span);
	virtual void close();

	connection_state state() const noexcept;
	tcp_endpoint local_endpoint() const noexcept;
	tcp_endpoint remote_endpoint() const noexcept;
	asio::ip::tcp::socket& socket() const noexcept;
	std::optional<crypto::public_key_id> remote_key_id() const;
	network::context& context() const;

protected:
	virtual void on_connected() {}
	virtual void on_disconnected(securepath::error const& error) {}
	virtual void on_sent(std::size_t bytes) {}
	virtual void on_received(octet_span) {}
	virtual void start_server_handshake(std::chrono::seconds timeout = 10s);

private:
	encrypted_connection(encrypted_connection const&) = delete;
	encrypted_connection& operator=(encrypted_connection const&) = delete;

	friend class encrypted_server;
	friend class detail::encrypted_connection_impl;

	std::shared_ptr<detail::encrypted_connection_impl> impl_;
};

}
