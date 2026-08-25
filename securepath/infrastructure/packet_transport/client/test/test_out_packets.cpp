// SPDX-License-Identifier: MIT

#include <securepath/infrastructure/packet_transport/client/out_packets.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <cstdio>

namespace securepath::packet_transport::test {

TEST_CASE("out_packets test", "[unit]") {
	std::remove("out_packets.db");
	{
		out_packets packets(database::sqlite::create_sqlite_connection("out_packets.db"));

		CHECK_NOTHROW(packets.remove(1));
		CHECK(packets.get_pending_packets().size() == 0);

		protocol::transport_packet p{};

		CHECK(packets.insert(p) == 1);
		CHECK(packets.get_pending_packets().size() == 1);
		CHECK_NOTHROW(packets.remove(1));
		CHECK(packets.get_pending_packets().size() == 0);

		CHECK(packets.insert(p) == 1);
		CHECK(packets.insert(p) == 2);
		CHECK(packets.insert(p) == 3);
		CHECK(packets.insert(p) == 4);
		CHECK(packets.insert(p) == 5);

		CHECK(packets.get_pending_packets().size() == 5);
		CHECK_NOTHROW(packets.remove(3));
		CHECK(packets.get_pending_packets().size() == 4);
	}
	{
		out_packets packets(database::sqlite::create_sqlite_connection("out_packets.db"));
		CHECK(packets.get_pending_packets().size() == 4);
	}
	std::remove("out_packets.db");
}

}
