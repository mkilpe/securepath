// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/network/encryption/encrypted_connection.hpp>
#include <securepath/network/encryption/encrypted_server.hpp>
#include <securepath/network/encryption/handshake/pk_handshake.hpp>

#include <condition_variable>
#include <mutex>
#include <optional>
#include <vector>
#include <stdexcept>

namespace securepath::network::test {

using namespace std::literals;

/// Client connection that blocks the test thread until connected/failed and collects received bytes.
struct test_client : encrypted_connection {
	explicit test_client(network::context& c, handshake_data data = handshake_data{handshake_tag::public_key})
	: encrypted_connection(c, std::move(data))
	{}

	~test_client() override {
		close();
	}

	void wait_for_connection(std::chrono::seconds timeout = 5s) {
		std::unique_lock lock{mutex};
		if(!cond.wait_for(lock, timeout, [this] { return done; })) {
			throw std::runtime_error("connection timeout");
		}
		if(failure) {
			throw std::runtime_error("connection failed: " + failure->message());
		}
	}

	std::size_t received_size() const {
		std::unique_lock lock{mutex};
		return received.size();
	}

	octet_vector received_data() const {
		std::unique_lock lock{mutex};
		return received;
	}

	void clear_received() {
		std::unique_lock lock{mutex};
		received.clear();
		sizes.clear();
	}

	std::vector<std::size_t> message_sizes() const {
		std::unique_lock lock{mutex};
		return sizes;
	}

	/// allow wait_for_connection() to be used again after close() for reconnect tests
	void reset_state() {
		std::unique_lock lock{mutex};
		done = false;
		failure.reset();
	}

	void on_connected() override {
		std::unique_lock lock{mutex};
		done = true;
		cond.notify_all();
	}

	void on_disconnected(securepath::error const& err) override {
		std::unique_lock lock{mutex};
		if(!done && err) {
			failure = err.code();
		}
		done = true;
		cond.notify_all();
	}

	void on_received(octet_span s) override {
		std::unique_lock lock{mutex};
		received.insert(received.end(), s.begin(), s.end());
		sizes.push_back(s.size());
		cond.notify_all();
	}

	mutable std::mutex mutex;
	std::condition_variable cond;
	bool done{};
	std::optional<std::error_code> failure;
	octet_vector received;
	std::vector<std::size_t> sizes;
};

/// Server connection that echoes every received message back.
struct echo_connection : encrypted_connection {
	using encrypted_connection::encrypted_connection;

	void on_received(octet_span s) override {
		send(s);
	}
};

/// Server whose accepted connections echo, using the given handshake tag.
struct echo_server : encrypted_server {
	echo_server(network::context& c, int tag)
	: encrypted_server(c)
	, tag_(tag)
	{}

	std::shared_ptr<encrypted_connection> create_connection() override {
		return std::make_shared<echo_connection>(context(), handshake_data{tag_}, shared_from_this());
	}

	int tag_;
};

}
