// SPDX-License-Identifier: MIT

#include "encrypted_connection.hpp"
#include "detail/encrypted_connection_impl.hpp"

#include <securepath/network/encryption/error.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/error.hpp>

#include <asio/bind_executor.hpp>
#include <asio/connect.hpp>
#include <asio/dispatch.hpp>
#include <asio/post.hpp>

namespace securepath::network {

// ---- encrypted_connection (thin wrapper over the impl) --------------------------------------

encrypted_connection::encrypted_connection(network::context& c, handshake_data data,
	std::shared_ptr<encrypted_server> s)
: impl_(std::make_shared<detail::encrypted_connection_impl>(this, c, std::move(s), std::move(data)))
{
}

encrypted_connection::~encrypted_connection() {
	impl_->close();
}

void encrypted_connection::connect(std::string_view const& network_address, std::uint16_t port,
	std::chrono::seconds timeout)
{
	if(impl_->is_closed()) {
		impl_ = std::make_shared<detail::encrypted_connection_impl>(this, impl_->connection_context(),
			nullptr, impl_->initial_handshake_data());
	}
	impl_->connect(network_address, port, timeout);
}

void encrypted_connection::send(octet_span s) {
	impl_->send(s);
}

void encrypted_connection::close() {
	impl_->close();
}

encrypted_connection::connection_state encrypted_connection::state() const noexcept {
	return impl_->state();
}

tcp_endpoint encrypted_connection::local_endpoint() const noexcept {
	return impl_->local_endpoint();
}

tcp_endpoint encrypted_connection::remote_endpoint() const noexcept {
	return impl_->remote_endpoint();
}

asio::ip::tcp::socket& encrypted_connection::socket() const noexcept {
	return impl_->plain_socket();
}

void encrypted_connection::start_server_handshake(std::chrono::seconds timeout) {
	impl_->start_server_handshake(timeout);
}

std::optional<crypto::public_key_id> encrypted_connection::remote_key_id() const {
	return impl_->remote_key_id();
}

network::context& encrypted_connection::context() const {
	return impl_->connection_context();
}

}
