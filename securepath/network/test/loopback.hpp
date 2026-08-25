// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/network/encryption/tls_stream.hpp>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>

#include <chrono>
#include <future>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>

namespace securepath::network::test {

using namespace std::literals;

/// io_context on two threads plus a loopback acceptor; handshakes streams synchronously for tests
class loopback {
public:
	explicit loopback(int threads = 2)
	: acceptor_(io_, asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0))
	{
		for(int i = 0; i != threads; ++i) {
			threads_.emplace_back([this] { io_.run(); });
		}
	}

	~loopback() {
		guard_.reset();
		io_.stop();
		for(auto& t : threads_) {
			t.join();
		}
	}

	asio::io_context& io() { return io_; }
	asio::ip::tcp::endpoint endpoint() const { return acceptor_.local_endpoint(); }

	/// connected socket pair (client, server)
	std::pair<asio::ip::tcp::socket, asio::ip::tcp::socket> socket_pair() {
		asio::ip::tcp::socket client(io_);
		client.connect(acceptor_.local_endpoint());
		asio::ip::tcp::socket server = acceptor_.accept();
		return {std::move(client), std::move(server)};
	}

	std::shared_ptr<tls_stream> make_stream(asio::ip::tcp::socket socket, std::shared_ptr<tls_credentials const> creds,
		Botan::TLS::Group_Params group = tls_stream::default_group)
	{
		return std::make_shared<tls_stream>(std::move(socket), asio::make_strand(io_), std::move(creds), group);
	}

	/// client + server streams with completed handshakes
	std::pair<std::shared_ptr<tls_stream>, std::shared_ptr<tls_stream>> connected_pair() {
		auto [cs, ss] = socket_pair();
		auto client = make_stream(std::move(cs), creds_);
		auto server = make_stream(std::move(ss), creds_);
		auto ec = handshake(client, server);
		if(ec.first || ec.second) {
			throw std::runtime_error("loopback handshake failed: " + ec.first.message() + " / " + ec.second.message());
		}
		return {client, server};
	}

	static std::pair<std::error_code, std::error_code> handshake(std::shared_ptr<tls_stream> const& client,
		std::shared_ptr<tls_stream> const& server)
	{
		std::promise<std::error_code> cp, sp;
		auto cf = cp.get_future();
		auto sf = sp.get_future();
		server->async_handshake(tls_role::server, [&](std::error_code ec) { sp.set_value(ec); });
		client->async_handshake(tls_role::client, [&](std::error_code ec) { cp.set_value(ec); });
		return {wait(cf), wait(sf)};
	}

	template<typename T>
	static T wait(std::future<T>& f, std::chrono::seconds timeout = 10s) {
		if(f.wait_for(timeout) != std::future_status::ready) {
			throw std::runtime_error("timeout waiting for async operation");
		}
		return f.get();
	}

	std::shared_ptr<tls_credentials const> credentials() const { return creds_; }

private:
	asio::io_context io_;
	asio::executor_work_guard<asio::io_context::executor_type> guard_{io_.get_executor()};
	asio::ip::tcp::acceptor acceptor_;
	std::shared_ptr<tls_credentials const> creds_{std::make_shared<tls_credentials>()};
	std::vector<std::thread> threads_;
};

}
