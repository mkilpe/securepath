// SPDX-License-Identifier: MIT

#include "network_test_context.hpp"

#include <securepath/network/encryption/handshake/handshake.hpp>
#include <securepath/crypto/hash.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <string>

namespace securepath::network::test {

namespace {

/// deterministic fake TLS exporter: both sides derive the same value from (label, context)
exporter_function fake_exporter(std::string const& channel = "channel-1") {
	return [channel](std::string_view label, octet_span context, std::size_t length) {
		octet_vector input(channel.begin(), channel.end());
		input.insert(input.end(), label.begin(), label.end());
		input.insert(input.end(), context.begin(), context.end());
		auto digest = crypto::hash(input, crypto::hash_algorithm::sha3_512);
		digest.resize(length);
		return digest;
	};
}

struct drive_result {
	bool client_ok{};
	bool server_ok{};
};

/// run the packets between the two handshake drivers; mutate lets a test tamper with a packet
drive_result drive(handshake& client, handshake& server, handshake_data data,
	std::function<void(octet_vector&)> mutate = {})
{
	drive_result res;
	auto c = client.start(std::move(data));
	handshake_result s{};
	bool server_done{};
	for(int i = 0; i != 10; ++i) {
		if(c.state == handshake_op_state::error) {
			return res;
		}
		if(!c.packet.empty()) {
			octet_vector packet = c.packet;
			if(mutate) {
				mutate(packet);
			}
			s = server.handle_packet(packet);
			if(s.state == handshake_op_state::error) {
				return res;
			}
			server_done = server_done || s.state == handshake_op_state::succeeded;
		}
		if(c.state == handshake_op_state::succeeded && server_done) {
			res.client_ok = true;
			res.server_ok = true;
			return res;
		}
		if(!s.packet.empty()) {
			c = client.handle_packet(s.packet);
			s.packet.clear();
		} else if(c.state == handshake_op_state::succeeded) {
			res.client_ok = true;
			res.server_ok = server_done;
			return res;
		}
	}
	return res;
}

}

TEST_CASE("pk handshake authenticates over a shared binding", "[network][handshake][pk]") {
	network_test_context tc;
	tc.setup_pk_server();
	auto ci = tc.add_pk_client();
	handshake client{tc.client_context(ci), fake_exporter(), endpoint_role::client};
	handshake server{tc.server_context(), fake_exporter(), endpoint_role::server};

	auto res = drive(client, server, handshake_data{handshake_tag::public_key, pk_handshake_client_data{false}});
	CHECK(res.client_ok);
	CHECK(res.server_ok);
	CHECK(client.remote_key_id() == crypto::my_private_key(tc.server_context().private_data()).id());
	CHECK(server.remote_key_id() == crypto::my_private_key(tc.client_context(ci).private_data()).id());
}

TEST_CASE("pk handshake rejects a tampered auth packet", "[network][handshake][pk][security]") {
	network_test_context tc;
	tc.setup_pk_server();
	auto ci = tc.add_pk_client();
	handshake client{tc.client_context(ci), fake_exporter(), endpoint_role::client};
	handshake server{tc.server_context(), fake_exporter(), endpoint_role::server};

	int packet_no{};
	auto res = drive(client, server, handshake_data{handshake_tag::public_key, pk_handshake_client_data{false}},
		[&](octet_vector& packet) {
			++packet_no;
			if(packet_no == 2 && !packet.empty()) {   // 1 = client_hello, 2 = client auth
				packet.back() ^= 0x01;
			}
		});
	CHECK(!res.server_ok);
}

TEST_CASE("pk handshake rejects differing channel bindings", "[network][handshake][pk][security]") {
	// a man in the middle holds two TLS channels; the exporters differ, so the signatures
	// each side makes over its own channel never verify on the other channel
	network_test_context tc;
	tc.setup_pk_server();
	auto ci = tc.add_pk_client();
	handshake client{tc.client_context(ci), fake_exporter("channel-a"), endpoint_role::client};
	handshake server{tc.server_context(), fake_exporter("channel-b"), endpoint_role::server};

	auto res = drive(client, server, handshake_data{handshake_tag::public_key, pk_handshake_client_data{false}});
	CHECK(!res.client_ok);
	CHECK(!res.server_ok);
}

TEST_CASE("pk handshake rejects a suite mismatch", "[network][handshake][pk]") {
	network_test_context tc;
	tc.setup_pk_server();
	auto ci = tc.add_pk_client();
	tc.client_context(ci).set_suite(crypto::suite::pq1_high);
	handshake client{tc.client_context(ci), fake_exporter(), endpoint_role::client};
	handshake server{tc.server_context(), fake_exporter(), endpoint_role::server};

	auto res = drive(client, server, handshake_data{handshake_tag::public_key, pk_handshake_client_data{false}});
	CHECK(!res.client_ok);
	CHECK(!res.server_ok);
}

TEST_CASE("handshake with an unknown tag fails", "[network][handshake]") {
	network_test_context tc;
	tc.setup_pk_server();
	auto ci = tc.add_pk_client();
	handshake client{tc.client_context(ci), fake_exporter(), endpoint_role::client};
	handshake server{tc.server_context(), fake_exporter(), endpoint_role::server};

	auto res = drive(client, server, handshake_data{handshake_tag::shared_secret});
	CHECK(!res.client_ok);
	CHECK(!res.server_ok);
}

TEST_CASE("ss handshake authenticates with the shared secret", "[network][handshake][ss]") {
	network_test_context tc;
	octet_vector secret_id{'p','a','i','r','1'};
	auto ci = tc.add_ss_client(secret_id, crypto::random_octet_vector(32));
	handshake client{tc.client_context(ci), fake_exporter(), endpoint_role::client};
	handshake server{tc.server_context(), fake_exporter(), endpoint_role::server};

	auto res = drive(client, server, handshake_data{handshake_tag::shared_secret});
	CHECK(res.client_ok);
	CHECK(res.server_ok);
}

TEST_CASE("ss handshake rejects a wrong secret", "[network][handshake][ss][security]") {
	network_test_context tc;
	octet_vector secret_id{'p','a','i','r','1'};
	auto ci = tc.add_ss_client(secret_id, crypto::random_octet_vector(32));
	// overwrite the client's copy of the secret with a different one
	tc.client_context(ci).shared_secrets().insert(octet_span(secret_id), octet_span(crypto::random_octet_vector(32)));
	handshake client{tc.client_context(ci), fake_exporter(), endpoint_role::client};
	handshake server{tc.server_context(), fake_exporter(), endpoint_role::server};

	auto res = drive(client, server, handshake_data{handshake_tag::shared_secret});
	CHECK(!res.server_ok);
}

}
