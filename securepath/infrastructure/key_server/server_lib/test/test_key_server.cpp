// SPDX-License-Identifier: MIT

#include <securepath/infrastructure/key_server/server_lib/key_server.hpp>
#include <securepath/infrastructure/key_client/key_client.hpp>

#include <securepath/crypto/certificate_cache.hpp>
#include <securepath/crypto/identifier_certificate.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/private_data_cache.hpp>
#include <securepath/crypto/public_key_cache.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/crypto/shared_secret_cache.hpp>
#include <securepath/crypto/test/support/pki_test_context.hpp>
#include <securepath/crypto/test/support/public_key_test_cache.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>

#include <thread>
#include <vector>

namespace securepath::key_server::test {

namespace {

/// one endpoint's crypto stores anchored at the shared test root
struct endpoint {
	explicit endpoint(crypto::public_key const& root)
	: keys(root)
	{
	}

	crypto::test::public_key_test_cache keys;
	crypto::certificate_cache certs;
	crypto::shared_secret_cache secrets;
	crypto::private_data_cache private_data;
};

struct fixture {
	fixture()
	{
		for(int i = 0; i != 3; ++i) {
			threads.emplace_back([this] { io.run(); });
		}
		// server identity: a key certified by the pki root, stored in the server's private data
		auto server_key = crypto::generate_private_key();
		auto chain = pki.chain_for_server_key(server_key, "");
		server.private_data.set_my_private_key(server_key);
		server.private_data.set_my_certificate_chain(chain);
	}

	~fixture() {
		guard.reset();
		io.stop();
		for(auto& t : threads) {
			t.join();
		}
	}

	network::context server_context() {
		return network::context(io, server.keys, server.certs, server.secrets, server.private_data);
	}

	network::context client_context() {
		return network::context(io, client.keys, client.certs, client.secrets, client.private_data);
	}

	crypto::test::pki_test_context pki;
	asio::io_context io;
	asio::executor_work_guard<asio::io_context::executor_type> guard{io.get_executor()};
	endpoint server{pki.root.public_key()};
	endpoint client{pki.root.public_key()};
	std::vector<std::thread> threads;
};

}

TEST_CASE("key server serves keys and certificates to an anonymous client", "[key_server]") {
	fixture f;
	auto sctx = f.server_context();
	server_params params;
	params.endpoint = asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0);
	server server(sctx, params);
	REQUIRE(server.run(2, 0) == 0);

	auto port = server.local_endpoint().port();
	REQUIRE(port != 0);

	auto cctx = f.client_context();
	key_client::client client(cctx);
	client.connect("127.0.0.1", port);
	REQUIRE_NOTHROW(client.wait_for_connection());

	// register a fresh key and read it back
	auto user_key = crypto::generate_private_key().public_key();
	REQUIRE_NOTHROW(client.register_key(user_key));

	auto found = client.find_key(user_key.id());
	REQUIRE(found);
	CHECK(found->id() == user_key.id());

	// a key that was never registered is not found
	auto absent = crypto::generate_private_key().public_key();
	CHECK(!client.find_key(absent.id()));

	// certificate lookup: insert one on the server side, find it from the client
	auto ca_key = crypto::generate_private_key();
	auto cert = crypto::create_identifier_certificate(ca_key, "someone");
	f.server.certs.insert(cert);
	auto found_cert = client.find_certificate(cert.id());
	REQUIRE(found_cert);
	CHECK(found_cert->id() == cert.id());

	// an absent certificate id is not found
	CHECK(!client.find_certificate(crypto::certificate_id(crypto::random_octet_vector(32))));

	client.close();
	server.close();
}

TEST_CASE("key server rejects an invalid or duplicate key registration", "[key_server][security]") {
	fixture f;
	auto sctx = f.server_context();
	server_params params;
	params.endpoint = asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0);
	server server(sctx, params);
	REQUIRE(server.run(2, 0) == 0);
	auto port = server.local_endpoint().port();

	auto cctx = f.client_context();
	key_client::client client(cctx);
	client.connect("127.0.0.1", port);
	REQUIRE_NOTHROW(client.wait_for_connection());

	// a default-constructed (unsigned) public key is not self-authentic -> rejected
	crypto::public_key invalid;
	CHECK_THROWS(client.register_key(invalid));

	// registering the same valid key twice fails the second time
	auto key = crypto::generate_private_key().public_key();
	REQUIRE_NOTHROW(client.register_key(key));
	CHECK_THROWS(client.register_key(key));

	client.close();
	server.close();
}

TEST_CASE("async_find_key delivers the result through then()", "[key_server]") {
	fixture f;
	auto sctx = f.server_context();
	server_params params;
	params.endpoint = asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0);
	server server(sctx, params);
	REQUIRE(server.run(2, 0) == 0);
	auto port = server.local_endpoint().port();

	auto cctx = f.client_context();
	key_client::client client(cctx);
	client.connect("127.0.0.1", port);
	REQUIRE_NOTHROW(client.wait_for_connection());

	auto key = crypto::generate_private_key().public_key();
	client.register_key(key);

	std::promise<std::optional<crypto::public_key>> got;
	auto fut = got.get_future();
	client.async_find_key(key.id()).then([&](std::future<std::optional<crypto::public_key>> r) {
		try {
			got.set_value(r.get());
		} catch(...) {
			got.set_exception(std::current_exception());
		}
	});
	auto result = fut.get();
	REQUIRE(result);
	CHECK(result->id() == key.id());

	client.close();
	server.close();
}

}
