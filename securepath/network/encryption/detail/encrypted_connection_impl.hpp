// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/network/encryption/encrypted_connection.hpp>
#include <securepath/network/encryption/encrypted_server.hpp>
#include <securepath/network/encryption/framing.hpp>
#include <securepath/network/encryption/handshake/handshake.hpp>
#include <securepath/network/encryption/tls_stream.hpp>

#include <asio/ip/tcp.hpp>
#include <asio/steady_timer.hpp>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>

namespace securepath::network::detail {

/**
 * Drives one encrypted connection: TCP connect/accept, the TLS 1.3 handshake, the framed sp
 * authentication handshake and then framed message transfer. Every step runs on the strand.
 */
class encrypted_connection_impl : public std::enable_shared_from_this<encrypted_connection_impl> {
public:
	encrypted_connection_impl(encrypted_connection* client, context& c,
		std::shared_ptr<encrypted_server> s, handshake_data data);
	~encrypted_connection_impl();

	void connect(std::string_view network_address, std::uint16_t port, std::chrono::seconds timeout);
	void start_server_handshake(std::chrono::seconds timeout);
	void send(octet_span data);
	void close();

	void do_close();

	asio::ip::tcp::socket& plain_socket();
	std::optional<crypto::public_key_id> remote_key_id() const;

	encrypted_connection::connection_state state() const { return state_; }
	tcp_endpoint local_endpoint() const;
	tcp_endpoint remote_endpoint() const;
	context& connection_context() const { return context_; }

	handshake_data const& initial_handshake_data() const { return handshake_data_; }
	bool is_closed() const { return is_closed_; }

private:
	void on_resolve(std::string network_address, std::error_code error, asio::ip::tcp::resolver::results_type res);
	void on_connect(std::string network_address, std::error_code error, asio::ip::tcp::endpoint ep);
	void start_tls(endpoint_role role);
	void on_tls_handshake(std::error_code ec);
	void start_sp_handshake();
	void on_handshake_frame(std::error_code ec, octet_vector frame);
	void advance_handshake(handshake_result const& res);
	void become_connected();
	void receive_data();
	void on_data_frame(std::error_code ec, octet_vector frame);
	void do_send();
	void start_timeout(std::chrono::seconds timeout);
	void on_timeout(std::error_code ec);
	void handle_disconnect(std::optional<std::error_code> const& error);
	void notify_connected();
	void notify_sent(std::size_t bytes);
	void notify_received(octet_span data);
	octet_vector exporter(std::string_view label, octet_span ctx, std::size_t length);

	mutable std::mutex mutex_;
	context& context_;
	std::shared_ptr<encrypted_server> server_;
	strand_type strand_;
	asio::ip::tcp::resolver resolver_;
	asio::steady_timer timer_;
	asio::ip::tcp::socket socket_;
	std::shared_ptr<tls_stream> tls_;
	std::unique_ptr<frame_reader> reader_;
	std::unique_ptr<handshake> handshake_;
	endpoint_role role_{endpoint_role::client};
	encrypted_connection* client_{};
	handshake_data handshake_data_;
	std::optional<crypto::public_key_id> remote_kid_;
	tcp_endpoint local_endpoint_;
	tcp_endpoint remote_endpoint_;
	std::deque<octet_vector> out_queue_;
	std::atomic<encrypted_connection::connection_state> state_{encrypted_connection::not_connected};
	std::atomic<bool> is_connected_{};
	std::atomic<bool> is_closed_{};
	bool writing_{};
	bool disconnected_{};
};

}
