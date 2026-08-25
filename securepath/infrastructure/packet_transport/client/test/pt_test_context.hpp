// SPDX-License-Identifier: MIT

#pragma once

// Local packet-transport test context (server + n clients sharing one io_context) built directly
// on crypto_test_support. The network library's own test support (network::test::test_context)
// can replace this once it is settled.

#include <securepath/crypto/certificate_cache.hpp>
#include <securepath/crypto/private_data_cache.hpp>
#include <securepath/crypto/public_key_id.hpp>
#include <securepath/crypto/shared_secret_cache.hpp>
#include <securepath/crypto/test/support/pki_test_context.hpp>
#include <securepath/crypto/test/support/public_key_test_cache.hpp>
#include <securepath/network/encryption/context.hpp>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>

#include <deque>
#include <memory>
#include <thread>

namespace securepath::packet_transport::test {

class pt_test_context {
public:
	explicit pt_test_context(int threads = 2);
	~pt_test_context();

	void add_client(int amount = 1);
	network::context& client_context(int n);
	network::context& server_context();
	void add_client_keys_for_server();
	void share_client_keys();
	crypto::public_key_id key_id(int n) const;

private:
	struct instance {
		instance(asio::io_context& io, crypto::public_key const& root_key)
		: keys{root_key}
		, context{io, keys, certs, shared_secret, private_data}
		{}

		crypto::certificate_cache certs;
		crypto::test::public_key_test_cache keys;
		crypto::shared_secret_cache shared_secret;
		crypto::private_data_cache private_data;
		network::context context;
	};

	instance& client(int n);
	instance const& client(int n) const;

private:
	std::vector<std::thread> threads_;
	asio::io_context io_;
	crypto::test::pki_test_context pki_context_;
	std::deque<std::unique_ptr<instance>> clients_;
	instance server_{io_, pki_context_.root.public_key()};
	asio::executor_work_guard<asio::io_context::executor_type> io_guard_{io_.get_executor()};
};

}
