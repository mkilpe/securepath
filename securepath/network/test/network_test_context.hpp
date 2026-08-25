// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/network/encryption/context.hpp>
#include <securepath/network/encryption/handshake/pk_handshake.hpp>
#include <securepath/network/encryption/handshake/ss_handshake.hpp>

#include <securepath/crypto/certificate_cache.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/private_data_cache.hpp>
#include <securepath/crypto/shared_secret_cache.hpp>
#include <securepath/crypto/test/support/pki_test_context.hpp>
#include <securepath/crypto/test/support/public_key_test_cache.hpp>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>

#include <deque>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace securepath::network::test {

/// One endpoint's crypto data accesses, anchored at the shared test root key.
struct endpoint_state {
	explicit endpoint_state(crypto::public_key const& root)
	: keys(root)
	{}

	crypto::test::public_key_test_cache keys;
	crypto::certificate_cache certs;
	crypto::shared_secret_cache secrets;
	crypto::private_data_cache private_data;
};

/// io_context on a thread pool plus a server context and any number of client contexts, all sharing
/// one test PKI root; helpers wire up the pk and ss handshakes.
class network_test_context {
public:
	explicit network_test_context(crypto::suite suite = crypto::default_suite(), int threads = 4)
	: suite_(suite)
	, pki_(suite)
	{
		server_ctx_.set_suite(suite_);
		for(int i = 0; i != threads; ++i) {
			threads_.emplace_back([this] { io_.run(); });
		}
	}

	~network_test_context() {
		guard_.reset();
		io_.stop();
		for(auto& t : threads_) {
			t.join();
		}
	}

	asio::io_context& io() { return io_; }
	network::context& server_context() { return server_ctx_; }
	network::context& client_context(std::size_t n) { return clients_.at(n)->ctx; }
	crypto::private_key root_key() const { return pki_.root; }

	void setup_pk_server(std::string const& host = "") {
		auto key = crypto::generate_private_key(suite_);
		auto chain = pki_.chain_for_server_key(key, host);
		server_.private_data.set_my_private_key(key);
		server_.private_data.set_my_certificate_chain(chain);
		enable_server_pk_handshake(server_ctx_);
		server_ctx_.set_suite(suite_);
	}

	std::size_t add_pk_client() {
		auto& c = new_client();
		auto key = crypto::generate_private_key(suite_);
		auto chain = pki_.chain_for_server_key(key, "");
		c.state->private_data.set_my_private_key(key);
		c.state->private_data.set_my_certificate_chain(chain);
		enable_client_pk_handshake(c.ctx);
		return clients_.size() - 1;
	}

	/// pk client with no own key or chain (can only be accepted when the server does not authenticate)
	std::size_t add_anonymous_client() {
		auto& c = new_client();
		enable_client_pk_handshake(c.ctx);
		return clients_.size() - 1;
	}

	/// both sides store the same secret under the same secret id; the client selects it
	std::size_t add_ss_client(octet_vector const& secret_id, octet_vector const& secret) {
		server_.secrets.insert(octet_span(secret_id), octet_span(secret));
		enable_server_ss_handshake(server_ctx_);
		auto& c = new_client();
		c.state->secrets.insert(octet_span(secret_id), octet_span(secret));
		c.ctx.set_shared_secret_id(secret_id);
		enable_client_ss_handshake(c.ctx);
		return clients_.size() - 1;
	}

private:
	struct client {
		explicit client(asio::io_context& io, crypto::public_key const& root)
		: state(std::make_unique<endpoint_state>(root))
		, ctx(io, state->keys, state->certs, state->secrets, state->private_data)
		{}

		std::unique_ptr<endpoint_state> state;
		network::context ctx;
	};

	client& new_client() {
		clients_.push_back(std::make_unique<client>(io_, pki_.root.public_key()));
		clients_.back()->ctx.set_suite(suite_);
		return *clients_.back();
	}

	crypto::suite suite_;
	crypto::test::pki_test_context pki_;
	asio::io_context io_;
	asio::executor_work_guard<asio::io_context::executor_type> guard_{io_.get_executor()};
	endpoint_state server_{pki_.root.public_key()};
	network::context server_ctx_{io_, server_.keys, server_.certs, server_.secrets, server_.private_data};
	std::deque<std::unique_ptr<client>> clients_;
	std::vector<std::thread> threads_;
};

}
