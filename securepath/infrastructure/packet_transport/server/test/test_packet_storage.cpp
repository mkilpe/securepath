// SPDX-License-Identifier: MIT

#include <securepath/infrastructure/packet_transport/server/server_lib/packet_storage.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/log/log.hpp>
#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/util/octet_vector.hpp>

#include <cstdio>
#include <future>
#include <map>
#include <set>

namespace securepath::packet_transport::test {

struct packet_client {
	packet_client(int i, packet_storage& s)
	: num(i)
	, storage(s)
	, t([&]{entry();})
	{}

	~packet_client() {
		close();
	}

	void close() {
		if(t.joinable()) {
			t.join();
		}
	}

	void entry() {
		std::uint64_t elapsed = 0;
		transport_payload p{};
		for(int i = 0; i != count; ++i) {
			std::unique_lock l{mutex};
			timer t;
			packet_handle h = storage.insert(id, p, i+1, id, [&](auto, auto ack){on_ack(ack);});
			elapsed += t.elapsed_microseconds();
			sent.insert(std::make_pair(i+1, h));
		}
		LOG_TRACE("insert took on average: {} microseconds", elapsed/count);
	}

	void on_ack(ack_type ack) {
		std::unique_lock l{mutex};
		acked.insert(ack);
	}

	void ack() {
		std::deque<std::future<void>> temp;
		{
			std::unique_lock l{mutex};
			for(auto v : sent) {
				temp.push_back(std::async(std::launch::async, [handle = v.second]() mutable { handle.mark_as_acked(); }));
				received.insert(v.second.ack());
			}
		}
		for(auto&& v : temp) {
			v.wait();
		}
	}

	void receive(std::deque<stored_packet> p) {
		for(auto&& v : p) {
			v.handle.mark_as_acked();
			received.insert(v.handle.ack());
		}
	}

	bool all_received() const {
		return received.size() == static_cast<std::size_t>(count);
	}

	std::set<ack_type> get_acked() const {
		std::unique_lock l{mutex};
		return acked;
	}

	void wait_for_sender_ack() {
		CAPTURE(num);
		WAIT(static_cast<std::size_t>(count) == get_acked().size(), 20s);
		REQUIRE(static_cast<std::size_t>(count) == get_acked().size());
	}

	void end_check() {
		close();

		CAPTURE(num);

		CHECK(sent.size() == static_cast<std::size_t>(count));
		CHECK(sent.size() == received.size());

		CHECK(sent.size() == get_acked().size());
	}

	int const count{1000};

	mutable std::mutex mutex;

	crypto::public_key_id id{securepath::test::random_octet_vector(8)};
	std::map<ack_type, packet_handle> sent;
	std::set<ack_type> acked;
	std::set<ack_type> received;

	int const num;
	packet_storage& storage;
	std::thread t;
};


TEST_CASE("packet storage test", "[unit]") {
	std::remove("test_packets.db");

	auto r1 = crypto::public_key_id(to_octet_vector("test1"));
	{
		packet_storage packets(database::sqlite::create_sqlite_connection("test_packets.db"));

		transport_payload p{};
		{
			std::atomic_flag acked{};
			auto handle = packets.insert(r1, p, 1, r1, [&](auto...){acked.test_and_set();});
			WAIT_CHECK(acked.test(), 1s);

			CHECK(packets.get_pending_packets(r1).size() == 1);
			handle.mark_as_acked();
		}

		std::this_thread::sleep_for(1s);
		CHECK(packets.get_pending_packets(r1).size() == 0);

		{
			std::atomic_flag acked{};
			auto handle = packets.insert(r1, p, 2, r1, [&](auto...){acked.test_and_set();});
			WAIT_CHECK(acked.test(), 1s);
		}
		{
			std::atomic_flag acked{};
			auto handle = packets.insert(r1, p, 3, r1, [&](auto...){acked.test_and_set();});
			WAIT_CHECK(acked.test(), 1s);
		}

		CHECK(packets.get_pending_packets(r1).size() == 2);
	}
	{
		packet_storage packets(database::sqlite::create_sqlite_connection("test_packets.db"));
		CHECK(packets.get_pending_packets(r1).size() == 2);
	}
	std::remove("test_packets.db");
}

TEST_CASE("packet storage ack test", "[unit]") {
	int const count{10};
	std::remove("test_packets.db");
	auto db = database::sqlite::create_sqlite_connection("test_packets.db");
	database::sqlite::set_to_wal_mode(db);
	packet_storage packets(db);
	std::vector<std::unique_ptr<packet_client>> clients;

	try {
		for(int i = 0; i != count; ++i) {
			clients.push_back(std::make_unique<packet_client>(i, packets));
		}

		for(auto&& c : clients) {
			c->wait_for_sender_ack();
			c->ack();
		}

		for(auto&& c : clients) {
			c->end_check();
		}
	} catch(...) {
		packets.close();
		throw;
	}
	packets.close();
	std::remove("test_packets.db");
}

TEST_CASE("packet storage get packet test", "[unit]") {
	int const count{10};
	std::remove("test_packets.db");
	auto db = database::sqlite::create_sqlite_connection("test_packets.db");
	database::sqlite::set_to_wal_mode(db);
	packet_storage packets(db);
	std::vector<std::unique_ptr<packet_client>> clients;

	try {
		for(int i = 0; i != count; ++i) {
			clients.push_back(std::make_unique<packet_client>(i, packets));
		}

		auto func = [&]
			{
				bool all = true;
				for(auto&& c : clients) {
					c->receive(packets.get_pending_packets(c->id));
					all = all && c->all_received();
				}
				return all;
			};

		WAIT(func(), 5s);

		for(auto&& c : clients) {
			c->wait_for_sender_ack();
			CHECK(c->all_received());
			CHECK(packets.get_pending_packets(c->id).size() == 0);
		}

		for(auto&& c : clients) {
			c->end_check();
		}
	} catch(...) {
		packets.close();
		throw;
	}
	packets.close();
	std::remove("test_packets.db");
}

}
