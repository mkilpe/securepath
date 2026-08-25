// SPDX-License-Identifier: MIT

#include "pt_test_context.hpp"

#include <securepath/infrastructure/packet_transport/client/events.hpp>
#include <securepath/infrastructure/packet_transport/client/packet_client.hpp>
#include <securepath/infrastructure/packet_transport/server/server_lib/packet_server.hpp>

#include <securepath/crypto/private_data_access.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/event_system/event_loop.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <cstdio>
#include <future>

namespace securepath::packet_transport::test {

static database::connection_ptr open_db(int i, bool remove) {
	std::string name = "in_packets_" + std::to_string(i) + ".db";
	if(remove) {
		std::remove(name.c_str());
	}
	return database::sqlite::create_sqlite_connection(name);
}

struct packet_test_client : event_system::event_handler, packet_client {
	packet_test_client(event_system::event_loop& loop, pt_test_context& tc, int i, bool remove = true)
	: event_handler(loop)
	, packet_client(tc.client_context(i), *this, open_db(i, remove))
	, context(tc.client_context(i))
	{}

	~packet_test_client() {
		stop_handler();
	}

	void on_connect() {
		LOG_TRACE("on_connect");
		connected.set_value();
	}

	void on_disconnect(error err) {
		LOG_TRACE("on_disconnect [err={}]", err);
	}

	void on_packet(in_packet_handle h) {
		LOG_TRACE("on_packet");
		{
			std::unique_lock l{mutex};
			in.push_back(h->packet());
		}
		if(mark_seen) {
			h->mark_seen();
		}
	}

	void on_error(packet_dir, packet_key_type, error) {
	}

	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		dispatch( *ev
			, event_dest<events::on_connect>(&packet_test_client::on_connect)
			, event_dest<events::on_disconnect>(&packet_test_client::on_disconnect)
			, event_dest<events::on_packet>(&packet_test_client::on_packet)
			, event_dest<events::on_error>(&packet_test_client::on_error));
	}

	void wait_for_connection() {
		auto f = connected.get_future();
		REQUIRE(f.wait_for(5s) == std::future_status::ready);
		connected = std::promise<void>{};
	}

	void send_packet(crypto::public_key_id rec) {
		auto data = securepath::test::random_octet_vector(8);
		packet_client::send_packet(data, receiver{rec});
		std::unique_lock l{mutex};
		out.push_back(data);
	}

	std::size_t in_size() const {
		std::unique_lock l{mutex};
		return in.size();
	}

	void check_in_equals(std::deque<octet_vector> const& list) const {
		REQUIRE(in.size() == list.size());
		for(std::size_t i = 0; i != in.size(); ++i) {
			auto& p = in[i];
			auto pkey = context.public_keys().find(p.signature.issuer());
			REQUIRE(pkey);
			REQUIRE(pkey->verify(p.signature, serialisation::asn_der_serialise(p.data)));
			auto data = decrypt(p.data, my_private_key(context.private_data()));
			CHECK(list[i] == data);
		}
	}

public:
	mutable std::mutex mutex;

	network::context& context;

	std::atomic<bool> mark_seen{true};

	std::deque<transport_payload> in;
	std::deque<octet_vector> out;

	std::promise<void> connected;
};

TEST_CASE("packet client test", "[unit]") {
	std::remove("packets.db");
	pt_test_context context;
	context.add_client(2);
	context.add_client_keys_for_server();
	context.share_client_keys();

	event_system::single_thread_event_loop loop;

	packet_server server(context.server_context());
	server.run();

	SECTION("send, receive, pending packets") {
		packet_test_client pc0(loop, context, 0);
		packet_test_client pc1(loop, context, 1);

		pc0.connect("127.0.0.1");
		pc1.connect("127.0.0.1");
		pc0.wait_for_connection();
		pc1.wait_for_connection();

		pc0.send_packet(context.key_id(1));
		WAIT_REQUIRE(pc1.in_size() == 1, 2s);
		pc1.check_in_equals(pc0.out);
		pc1.in.clear();

		pc1.mark_seen = false;
		pc0.out.clear();
		for(int i = 0; i != 5; ++i) {
			pc0.send_packet(context.key_id(1));
		}
		WAIT_REQUIRE(pc1.in_size() == 5, 2s);
		pc1.in.clear();
		pc1.emit_pending_packets();
		WAIT_REQUIRE(pc1.in_size() == 5, 2s);
		pc1.check_in_equals(pc0.out);

		// the unseen packets stay in the database over a client restart
		{
			packet_test_client pc1b(loop, context, 1, false);
			pc1b.emit_pending_packets();
			WAIT_REQUIRE(pc1b.in_size() == 5, 2s);
			pc1b.in.clear();
			pc1b.emit_pending_packets();
			std::this_thread::sleep_for(2s);
			REQUIRE(pc1b.in_size() == 0);
		}
	}

	SECTION("offline receiver gets stored packet exactly once") {
		packet_test_client pc0(loop, context, 0);
		packet_test_client pc1(loop, context, 1);

		pc0.connect("127.0.0.1");
		pc0.wait_for_connection();

		pc0.send_packet(context.key_id(1));
		std::this_thread::sleep_for(1s);

		pc1.connect("127.0.0.1");
		pc1.wait_for_connection();
		WAIT_REQUIRE(pc1.in_size() == 1, 2s);

		pc1.close();
		pc1.connect("127.0.0.1");
		pc1.wait_for_connection();
		std::this_thread::sleep_for(1s);
		REQUIRE(pc1.in_size() == 1);
	}

	SECTION("offline sender delivers on connect exactly once") {
		packet_test_client pc0(loop, context, 0);
		packet_test_client pc1(loop, context, 1);

		pc1.connect("127.0.0.1");
		pc1.wait_for_connection();

		pc0.send_packet(context.key_id(1));
		std::this_thread::sleep_for(1s);

		LOG_TRACE("---------");
		pc0.connect("127.0.0.1");
		pc0.wait_for_connection();
		WAIT_REQUIRE(pc1.in_size() == 1, 2s);

		pc0.close();
		pc0.connect("127.0.0.1");
		pc0.wait_for_connection();
		std::this_thread::sleep_for(1s);
		REQUIRE(pc1.in_size() == 1);
	}

	server.close();
	std::remove("packets.db");
}

TEST_CASE("packet client multipacket test", "[unit]") {
	int const client_count = 20;
	int const packet_count = 100;

	std::remove("packets.db");
	pt_test_context context{24};
	context.add_client(client_count);
	context.add_client_keys_for_server();
	context.share_client_keys();

	event_system::single_thread_event_loop loop;

	packet_server server(context.server_context());
	server.run();

	{
		std::deque<packet_test_client> clients;

		for(int i = 0; i != client_count; ++i) {
			clients.emplace_back(loop, context, i);
			clients.back().connect("127.0.0.1");
		}
		for(auto&& c : clients) {
			c.wait_for_connection();
		}
		for(int i = 0; i != client_count; ++i) {
			for(int x = 0; x != packet_count; ++x) {
				clients[i].send_packet(context.key_id(client_count-i-1));
			}
		}
		for(int i = 0; i != client_count; ++i) {
			WAIT_REQUIRE(clients[i].in_size() == static_cast<std::size_t>(packet_count), 30s);
		}
		for(int i = 0; i != client_count; ++i) {
			clients[i].check_in_equals(clients[client_count-i-1].out);
		}
	}

	server.close();
	std::remove("packets.db");
	for(int i = 0; i != client_count; ++i) {
		std::remove(("in_packets_" + std::to_string(i) + ".db").c_str());
	}
}

}
