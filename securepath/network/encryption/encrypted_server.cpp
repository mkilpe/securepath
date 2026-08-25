// SPDX-License-Identifier: MIT

#include "encrypted_server.hpp"

#include <securepath/log/log.hpp>

#include <cassert>

namespace securepath::network {

encrypted_server::encrypted_server(network::context& c)
: context_(c)
, acceptor_(c.io_context())
{
}

encrypted_server::~encrypted_server() {
	LOG_TRACE("~encrypted_server {}", static_cast<void*>(this));
}

void encrypted_server::start(tcp_endpoint const& endpoint, std::chrono::seconds timeout) {
	assert(!weak_from_this().expired() && "encrypted_server must be constructed as a shared_ptr");
	std::unique_lock lock{mutex_};
	timeout_ = timeout;
	acceptor_.open(endpoint.protocol());
	acceptor_.set_option(asio::socket_base::reuse_address{true});
	acceptor_.bind(endpoint);
	acceptor_.listen();
	start_accept();
}

void encrypted_server::close() {
	decltype(sessions_) sessions;
	{
		std::unique_lock lock{mutex_};
		std::error_code ec;
		acceptor_.close(ec);
		sessions_.swap(sessions);
	}
	for(auto&& c : sessions) {
		c.second->close();
	}
}

network::context& encrypted_server::context() const {
	return context_;
}

tcp_endpoint encrypted_server::local_endpoint() const {
	std::unique_lock lock{mutex_};
	std::error_code ec;
	return acceptor_.local_endpoint(ec);
}

void encrypted_server::remove(void* ptr) {
	std::unique_lock lock{mutex_};
	sessions_.erase(ptr);
}

std::shared_ptr<encrypted_connection> encrypted_server::create_connection() {
	return std::make_shared<encrypted_connection>(context_, handshake_tag::public_key, shared_from_this());
}

void encrypted_server::start_accept() {
	auto c = create_connection();
	acceptor_.async_accept(c->socket(), [this, self = shared_from_this(), c](std::error_code error) {
		on_accepted(c, error);
	});
}

void encrypted_server::on_accepted(std::shared_ptr<encrypted_connection> session, std::error_code error) {
	if(!error) {
		std::chrono::seconds timeout;
		{
			std::unique_lock lock{mutex_};
			timeout = timeout_;
			sessions_[session.get()] = session;
		}
		on_accept(session);
		session->start_server_handshake(timeout);
		std::unique_lock lock{mutex_};
		if(acceptor_.is_open()) {
			start_accept();
		}
	} else if(error != asio::error::operation_aborted) {
		LOG_TRACE("accept failed: {}", error.message());
		std::unique_lock lock{mutex_};
		if(acceptor_.is_open()) {
			start_accept();
		}
	}
}

}
