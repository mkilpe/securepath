// SPDX-License-Identifier: MIT

#include <securepath/infrastructure/packet_transport/client/in_packets.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <cstdio>

namespace securepath::packet_transport::test {

TEST_CASE("in_packets test", "[unit]") {
	std::remove("in_packets.db");
	{
		in_packets packets(database::sqlite::create_sqlite_connection("in_packets.db"));

		CHECK_NOTHROW(packets.remove(1));
		CHECK(packets.get_pending_packets().size() == 0);

		transport_payload p{};

		auto handle = packets.insert(p);
		CHECK(!handle->data<int>());
		handle->set_data(1);
		REQUIRE(handle->data<int>());
		CHECK(*handle->data<int>() == 1);
		CHECK(packets.get_pending_packets().size() == 1);
		CHECK_NOTHROW(handle->mark_seen());
		CHECK(packets.get_pending_packets().size() == 0);

		packets.insert(p);
		packets.insert(p);
		handle = packets.insert(p);
		packets.insert(p);
		packets.insert(p);

		CHECK(packets.get_pending_packets().size() == 5);
		handle->mark_seen();
		CHECK(packets.get_pending_packets().size() == 4);

		auto list = packets.get_pending_packets();
		list.front()->mark_seen();

		CHECK(packets.get_pending_packets().size() == 3);
	}
	{
		in_packets packets(database::sqlite::create_sqlite_connection("in_packets.db"));
		CHECK(packets.get_pending_packets().size() == 3);
	}
	std::remove("in_packets.db");
}

}
