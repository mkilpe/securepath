// SPDX-License-Identifier: MIT

#include "network_test_context.hpp"
#include "test_client.hpp"

#include <securepath/crypto/private_data_access.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <memory>

namespace securepath::network::test {

namespace {

handshake_data pk_no_restriction() {
	return handshake_data{handshake_tag::public_key, pk_handshake_client_data{false}};
}

/// echo server that records the last accepted connection for server-side assertions
struct capturing_echo_server : echo_server {
	using echo_server::echo_server;

	void on_accept(std::shared_ptr<encrypted_connection> const& c) override {
		std::unique_lock lock{mutex};
		last = c;
	}

	std::shared_ptr<encrypted_connection> last_connection() {
		std::unique_lock lock{mutex};
		return last;
	}

	std::mutex mutex;
	std::shared_ptr<encrypted_connection> last;
};

octet_vector pattern(std::size_t size) {
	octet_vector v(size);
	std::uint8_t x = 3;
	for(auto& b : v) {
		b = x;
		x = static_cast<std::uint8_t>(x * 31 + 7);
	}
	return v;
}

void echo_roundtrip(test_client& client, std::size_t size, std::chrono::seconds timeout = 10s) {
	client.clear_received();
	auto data = pattern(size);
	client.send(data);
	WAIT_CHECK(client.received_size() == data.size(), timeout);
	CHECK(client.received_data() == data);
}

}

TEST_CASE("pk connection authenticates both sides", "[network][pk][connection]") {
	network_test_context tc;
	tc.setup_pk_server();
	auto ci = tc.add_pk_client();
	auto server = std::make_shared<capturing_echo_server>(tc.server_context(), handshake_tag::public_key);
	server->start(tcp_endpoint(asio::ip::make_address("127.0.0.1"), 0));

	test_client client(tc.client_context(ci), pk_no_restriction());
	client.connect("127.0.0.1", server->local_endpoint().port());
	REQUIRE_NOTHROW(client.wait_for_connection());

	auto server_key_id = crypto::my_private_key(tc.server_context().private_data()).id();
	auto client_key_id = crypto::my_private_key(tc.client_context(ci).private_data()).id();
	CHECK(client.remote_key_id() == server_key_id);
	auto session = server->last_connection();
	REQUIRE(session);
	WAIT_CHECK(session->state() == encrypted_connection::connected, 5s);
	CHECK(session->remote_key_id() == client_key_id);

	echo_roundtrip(client, 1);
	echo_roundtrip(client, 4 * 1024 * 1024);
	server->close();
}

TEST_CASE("pk connection message boundaries are preserved", "[network][pk][connection]") {
	network_test_context tc;
	tc.setup_pk_server();
	auto ci = tc.add_pk_client();
	auto server = std::make_shared<echo_server>(tc.server_context(), handshake_tag::public_key);
	server->start(tcp_endpoint(asio::ip::make_address("127.0.0.1"), 0));

	test_client client(tc.client_context(ci), pk_no_restriction());
	client.connect("127.0.0.1", server->local_endpoint().port());
	REQUIRE_NOTHROW(client.wait_for_connection());

	std::vector<octet_vector> messages{pattern(1), pattern(777), pattern(65536), pattern(3)};
	std::size_t total{};
	for(auto const& m : messages) {
		client.send(m);
		total += m.size();
	}
	WAIT_CHECK(client.received_size() == total, 10s);
	std::vector<std::size_t> expected_sizes{1, 777, 65536, 3};
	CHECK(client.message_sizes() == expected_sizes);
	server->close();
}

TEST_CASE("server without client auth accepts an anonymous client", "[network][pk][connection]") {
	network_test_context tc;
	tc.setup_pk_server();
	tc.server_context().set_authenticate_remote(false);
	auto ci = tc.add_anonymous_client();
	auto server = std::make_shared<capturing_echo_server>(tc.server_context(), handshake_tag::public_key);
	server->start(tcp_endpoint(asio::ip::make_address("127.0.0.1"), 0));

	test_client client(tc.client_context(ci), pk_no_restriction());
	client.connect("127.0.0.1", server->local_endpoint().port());
	REQUIRE_NOTHROW(client.wait_for_connection());
	CHECK(client.remote_key_id() == crypto::my_private_key(tc.server_context().private_data()).id());
	auto session = server->last_connection();
	REQUIRE(session);
	CHECK(!session->remote_key_id());
	echo_roundtrip(client, 256);
	server->close();
}

TEST_CASE("server requiring client auth rejects an anonymous client", "[network][pk][connection]") {
	network_test_context tc;
	tc.setup_pk_server();
	auto ci = tc.add_anonymous_client();
	auto server = std::make_shared<echo_server>(tc.server_context(), handshake_tag::public_key);
	server->start(tcp_endpoint(asio::ip::make_address("127.0.0.1"), 0));

	test_client client(tc.client_context(ci), pk_no_restriction());
	client.connect("127.0.0.1", server->local_endpoint().port());
	REQUIRE_THROWS(client.wait_for_connection());
	server->close();
}

TEST_CASE("client rejects a server whose chain is not rooted for it", "[network][pk][connection]") {
	network_test_context tc_server;   // its own root
	network_test_context tc_client;   // a different root
	tc_server.setup_pk_server();
	tc_server.server_context().set_authenticate_remote(false);
	auto ci = tc_client.add_pk_client();
	auto server = std::make_shared<echo_server>(tc_server.server_context(), handshake_tag::public_key);
	server->start(tcp_endpoint(asio::ip::make_address("127.0.0.1"), 0));

	test_client client(tc_client.client_context(ci), pk_no_restriction());
	client.connect("127.0.0.1", server->local_endpoint().port());
	REQUIRE_THROWS(client.wait_for_connection());
	server->close();
}

TEST_CASE("client host restriction rejects a mismatching server certificate", "[network][pk][connection]") {
	network_test_context tc;
	tc.setup_pk_server("test.fi");
	tc.server_context().set_authenticate_remote(false);
	auto ci = tc.add_pk_client();
	auto server = std::make_shared<echo_server>(tc.server_context(), handshake_tag::public_key);
	server->start(tcp_endpoint(asio::ip::make_address("127.0.0.1"), 0));

	// default handshake_data => require_host_restriction is on; the dialled 127.0.0.1 does not
	// match the certificate restriction test.fi
	test_client client(tc.client_context(ci));
	client.connect("127.0.0.1", server->local_endpoint().port());
	REQUIRE_THROWS(client.wait_for_connection());
	server->close();
}

TEST_CASE("unrestricted server certificate passes the client host restriction", "[network][pk][connection]") {
	network_test_context tc;
	tc.setup_pk_server();
	auto ci = tc.add_pk_client();
	auto server = std::make_shared<echo_server>(tc.server_context(), handshake_tag::public_key);
	server->start(tcp_endpoint(asio::ip::make_address("127.0.0.1"), 0));

	test_client client(tc.client_context(ci));   // restriction on
	client.connect("127.0.0.1", server->local_endpoint().port());
	REQUIRE_NOTHROW(client.wait_for_connection());
	server->close();
}

TEST_CASE("ten concurrent pk clients", "[network][pk][connection]") {
	network_test_context tc;
	tc.setup_pk_server();
	auto server = std::make_shared<echo_server>(tc.server_context(), handshake_tag::public_key);
	server->start(tcp_endpoint(asio::ip::make_address("127.0.0.1"), 0));
	auto port = server->local_endpoint().port();

	std::vector<std::unique_ptr<test_client>> clients;
	for(int i = 0; i != 10; ++i) {
		auto ci = tc.add_pk_client();
		clients.push_back(std::make_unique<test_client>(tc.client_context(ci), pk_no_restriction()));
		clients.back()->connect("127.0.0.1", port);
	}
	for(auto& c : clients) {
		REQUIRE_NOTHROW(c->wait_for_connection(10s));
	}
	for(auto& c : clients) {
		echo_roundtrip(*c, 1024);
	}
	server->close();
}

TEST_CASE("pk connection reconnects after close", "[network][pk][connection]") {
	network_test_context tc;
	tc.setup_pk_server();
	auto ci = tc.add_pk_client();
	auto server = std::make_shared<echo_server>(tc.server_context(), handshake_tag::public_key);
	server->start(tcp_endpoint(asio::ip::make_address("127.0.0.1"), 0));

	test_client client(tc.client_context(ci), pk_no_restriction());
	for(int i = 0; i != 3; ++i) {
		client.connect("127.0.0.1", server->local_endpoint().port());
		REQUIRE_NOTHROW(client.wait_for_connection());
		client.close();
		client.reset_state();
	}
	server->close();
}

TEST_CASE("pk connection works with the level 5 suite", "[network][pk][connection][suite]") {
	network_test_context tc{crypto::suite::pq1_high};
	tc.setup_pk_server();
	auto ci = tc.add_pk_client();
	auto server = std::make_shared<echo_server>(tc.server_context(), handshake_tag::public_key);
	server->start(tcp_endpoint(asio::ip::make_address("127.0.0.1"), 0));

	test_client client(tc.client_context(ci), pk_no_restriction());
	client.connect("127.0.0.1", server->local_endpoint().port());
	REQUIRE_NOTHROW(client.wait_for_connection());
	echo_roundtrip(client, 4096);
	server->close();
}

}
