// SPDX-License-Identifier: MIT

#include "network_test_context.hpp"
#include "test_client.hpp"

#include <securepath/crypto/random.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <memory>

namespace securepath::network::test {

TEST_CASE("ss connection round trip", "[network][ss][connection]") {
	network_test_context tc;
	octet_vector secret_id{'p','a','i','r','1'};
	auto ci = tc.add_ss_client(secret_id, crypto::random_octet_vector(32));
	auto server = std::make_shared<echo_server>(tc.server_context(), handshake_tag::shared_secret);
	server->start(tcp_endpoint(asio::ip::make_address("127.0.0.1"), 0));

	test_client client(tc.client_context(ci), handshake_data{handshake_tag::shared_secret});
	client.connect("127.0.0.1", server->local_endpoint().port());
	REQUIRE_NOTHROW(client.wait_for_connection());
	octet_vector data{1, 2, 3, 4, 5};
	client.send(data);
	WAIT_CHECK(client.received_size() == data.size(), 5s);
	CHECK(client.received_data() == data);
	server->close();
}

TEST_CASE("ss connection with a wrong secret fails", "[network][ss][connection][security]") {
	network_test_context tc;
	octet_vector secret_id{'p','a','i','r','1'};
	auto ci = tc.add_ss_client(secret_id, crypto::random_octet_vector(32));
	tc.client_context(ci).shared_secrets().insert(octet_span(secret_id), octet_span(crypto::random_octet_vector(32)));
	auto server = std::make_shared<echo_server>(tc.server_context(), handshake_tag::shared_secret);
	server->start(tcp_endpoint(asio::ip::make_address("127.0.0.1"), 0));

	test_client client(tc.client_context(ci), handshake_data{handshake_tag::shared_secret});
	client.connect("127.0.0.1", server->local_endpoint().port());
	REQUIRE_THROWS(client.wait_for_connection());
	server->close();
}

}
