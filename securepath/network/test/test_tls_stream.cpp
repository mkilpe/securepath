// SPDX-License-Identifier: MIT

#include "loopback.hpp"

#include <securepath/network/encryption/framing.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <asio/write.hpp>

#include <atomic>
#include <future>
#include <numeric>

namespace securepath::network::test {

TEST_CASE("tls_stream handshake negotiates the hybrid PQ group", "[network][tls]") {
	loopback lb;
	auto [client, server] = lb.connected_pair();
	CHECK(client->is_active());
	CHECK(server->is_active());
	CHECK(client->negotiated_group() == Botan::TLS::Group_Params(Botan::TLS::Group_Params::HYBRID_X25519_ML_KEM_768));
	CHECK(server->negotiated_group() == Botan::TLS::Group_Params(Botan::TLS::Group_Params::HYBRID_X25519_ML_KEM_768));
	CHECK(client->negotiated_group_name().find("ML-KEM-768") != std::string::npos);
	CHECK(!client->error());
	CHECK(!server->error());
	CHECK(!lb.credentials()->public_key_bits().empty());
}

TEST_CASE("tls_stream exporters agree and are bound to label and context", "[network][tls]") {
	loopback lb;
	auto [client, server] = lb.connected_pair();
	auto c1 = client->exporter("EXPORTER-securepath-auth", "client", 32);
	auto s1 = server->exporter("EXPORTER-securepath-auth", "client", 32);
	REQUIRE(c1.size() == 32);
	CHECK(c1 == s1);
	CHECK(client->exporter("EXPORTER-securepath-auth", "server", 32) != c1);
	CHECK(client->exporter("EXPORTER-other", "client", 32) != c1);
	CHECK(client->exporter("EXPORTER-securepath-auth", "client", 48).size() == 48);

	// a second connection has a different exporter
	auto [client2, server2] = lb.connected_pair();
	CHECK(client2->exporter("EXPORTER-securepath-auth", "client", 32) != c1);
}

TEST_CASE("tls_stream exporter before handshake throws", "[network][tls]") {
	loopback lb;
	auto [cs, ss] = lb.socket_pair();
	auto client = lb.make_stream(std::move(cs), lb.credentials());
	CHECK_THROWS(client->exporter("EXPORTER-securepath-auth", "", 32));
	CHECK_FALSE(client->negotiated_group());
}

namespace {
	octet_vector pattern(std::size_t size) {
		octet_vector v(size);
		std::uint8_t x = 0;
		for(auto& b : v) {
			b = x;
			x = static_cast<std::uint8_t>(x * 31 + 7);
		}
		return v;
	}

	/// echo one frame: client sends, server echoes, client receives
	octet_vector echo(std::shared_ptr<tls_stream> const& client, std::shared_ptr<tls_stream> const& server,
		octet_vector const& payload)
	{
		frame_reader server_reader(server);
		frame_reader client_reader(client);
		std::promise<std::error_code> sent;
		std::promise<std::pair<std::error_code, octet_vector>> echoed;
		auto sent_f = sent.get_future();
		auto echoed_f = echoed.get_future();
		server_reader.async_receive_frame([&](std::error_code ec, octet_vector data) {
			REQUIRE(!ec);
			async_send_frame(server, data, [&](std::error_code ec2) { sent.set_value(ec2); });
		});
		client_reader.async_receive_frame([&](std::error_code ec, octet_vector data) {
			echoed.set_value({ec, std::move(data)});
		});
		std::promise<std::error_code> client_sent;
		auto client_sent_f = client_sent.get_future();
		async_send_frame(client, payload, [&](std::error_code ec) { client_sent.set_value(ec); });
		REQUIRE(!loopback::wait(client_sent_f));
		REQUIRE(!loopback::wait(sent_f));
		auto [ec, data] = loopback::wait(echoed_f);
		REQUIRE(!ec);
		return data;
	}
}

TEST_CASE("framing echoes small and large frames", "[network][tls][framing]") {
	loopback lb;
	auto [client, server] = lb.connected_pair();
	CHECK(echo(client, server, {1, 2, 3, 4, 5}) == octet_vector{1, 2, 3, 4, 5});
	CHECK(echo(client, server, {}).empty());
	auto big = pattern(5 * 1024 * 1024);
	CHECK(echo(client, server, big) == big);
	// the stream still works afterwards
	CHECK(echo(client, server, {9}) == octet_vector{9});
}

TEST_CASE("framing keeps message boundaries for back-to-back frames", "[network][tls][framing]") {
	loopback lb;
	auto [client, server] = lb.connected_pair();
	frame_reader reader(server);
	std::promise<std::vector<octet_vector>> got;
	auto got_f = got.get_future();
	std::vector<octet_vector> frames;
	std::function<void(std::error_code, octet_vector)> on_frame = [&](std::error_code ec, octet_vector data) {
		REQUIRE(!ec);
		frames.push_back(std::move(data));
		if(frames.size() == 3) {
			got.set_value(frames);
		} else {
			reader.async_receive_frame(on_frame);
		}
	};
	reader.async_receive_frame(on_frame);
	for(std::uint8_t i = 1; i <= 3; ++i) {
		async_send_frame(client, octet_vector(i * 1000, i), [](std::error_code ec) { REQUIRE(!ec); });
	}
	auto result = loopback::wait(got_f);
	REQUIRE(result.size() == 3);
	for(std::size_t i = 0; i != 3; ++i) {
		CHECK(result[i] == octet_vector((i + 1) * 1000, static_cast<std::uint8_t>(i + 1)));
	}
}

TEST_CASE("framing rejects frames above the cap", "[network][tls][framing]") {
	loopback lb;
	auto [client, server] = lb.connected_pair();

	SECTION("sending") {
		std::promise<std::error_code> p;
		auto f = p.get_future();
		octet_vector too_big(max_frame_size + 1);
		async_send_frame(client, too_big, [&](std::error_code ec) { p.set_value(ec); });
		CHECK(loopback::wait(f) == make_error_code(errc::invalid_data));
		CHECK(client->is_active());
	}
	SECTION("receiving a header that claims too much") {
		frame_reader reader(server);
		std::promise<std::error_code> p;
		auto f = p.get_future();
		reader.async_receive_frame([&](std::error_code ec, octet_vector) { p.set_value(ec); });
		octet_vector header{0x01, 0x00, 0x00, 0x01};
		client->async_write(header, [](std::error_code ec, std::size_t) { REQUIRE(!ec); });
		CHECK(loopback::wait(f) == make_error_code(errc::invalid_record));
	}
	SECTION("encode/decode round trip") {
		auto frame = encode_frame(octet_vector{7, 8, 9});
		REQUIRE(frame.size() == 7);
		CHECK(decode_frame_length(std::span<std::uint8_t const, frame_header_size>(frame.data(), 4)) == 3);
	}
}

TEST_CASE("tls_stream handshake fails cleanly on mismatched groups", "[network][tls][security]") {
	loopback lb;
	auto [cs, ss] = lb.socket_pair();
	auto client = lb.make_stream(std::move(cs), lb.credentials(), Botan::TLS::Group_Params::HYBRID_X25519_ML_KEM_768);
	auto server = lb.make_stream(std::move(ss), lb.credentials(), Botan::TLS::Group_Params::HYBRID_SECP384R1_ML_KEM_1024);
	auto [cec, sec] = loopback::handshake(client, server);
	CHECK(cec);
	CHECK(sec);
	CHECK(sec == make_error_code(errc::handshake_failed));
	CHECK_FALSE(client->is_active());
	CHECK_FALSE(server->is_active());
	CHECK_FALSE(client->negotiated_group());

	// operations after a failed handshake complete with an error, never hang
	std::promise<std::error_code> wp;
	auto wf = wp.get_future();
	client->async_write(octet_vector{1}, [&](std::error_code ec, std::size_t) { wp.set_value(ec); });
	CHECK(loopback::wait(wf));
}

TEST_CASE("tls_stream handshake against a non-TLS peer fails", "[network][tls][security]") {
	loopback lb;
	auto [cs, ss] = lb.socket_pair();
	auto server = lb.make_stream(std::move(ss), lb.credentials());
	std::promise<std::error_code> p;
	auto f = p.get_future();
	server->async_handshake(tls_role::server, [&](std::error_code ec) { p.set_value(ec); });
	std::string garbage(64, 'x');
	asio::write(cs, asio::buffer(garbage));
	CHECK(loopback::wait(f) == make_error_code(errc::handshake_failed));
}

TEST_CASE("tls_stream shutdown sends close_notify and silences handlers", "[network][tls]") {
	loopback lb;
	auto [client, server] = lb.connected_pair();

	std::atomic<int> server_read_calls{};
	std::promise<std::error_code> server_read;
	auto server_read_f = server_read.get_future();
	std::array<std::uint8_t, 16> buf{};
	server->async_read_some(buf, [&](std::error_code ec, std::size_t) {
		++server_read_calls;
		server_read.set_value(ec);
	});

	std::promise<std::error_code> sd;
	auto sd_f = sd.get_future();
	client->async_shutdown([&](std::error_code ec) { sd.set_value(ec); });
	CHECK(!loopback::wait(sd_f));
	CHECK(loopback::wait(server_read_f) == make_error_code(errc::connection_closed));   // close_notify reached the peer
	CHECK_FALSE(client->is_active());

	// after shutdown nothing is delivered any more; new operations fail immediately
	std::atomic<int> late_calls{};
	std::promise<std::error_code> late;
	auto late_f = late.get_future();
	client->async_read_some(buf, [&](std::error_code ec, std::size_t) { ++late_calls; late.set_value(ec); });
	CHECK(loopback::wait(late_f) == make_error_code(errc::connection_closed));
	std::promise<std::error_code> late_write;
	auto late_write_f = late_write.get_future();
	client->async_write(octet_vector{1}, [&](std::error_code ec, std::size_t) { late_write.set_value(ec); });
	CHECK(loopback::wait(late_write_f) == make_error_code(errc::connection_closed));

	// the server side can shut down too
	std::promise<std::error_code> ssd;
	auto ssd_f = ssd.get_future();
	server->async_shutdown([&](std::error_code ec) { ssd.set_value(ec); });
	CHECK(!loopback::wait(ssd_f));
	std::this_thread::sleep_for(200ms);
	CHECK(server_read_calls == 1);
	CHECK(late_calls == 1);
}

TEST_CASE("tls_stream close aborts pending operations", "[network][tls]") {
	loopback lb;
	auto [client, server] = lb.connected_pair();
	std::promise<std::error_code> p;
	auto f = p.get_future();
	std::array<std::uint8_t, 16> buf{};
	client->async_read_some(buf, [&](std::error_code ec, std::size_t) { p.set_value(ec); });
	client->close();
	CHECK(loopback::wait(f) == make_error_code(errc::connection_closed));
	CHECK_FALSE(client->is_active());
}

TEST_CASE("tls_stream server handles concurrent clients", "[network][tls]") {
	loopback lb;
	constexpr int count = 10;
	std::vector<std::shared_ptr<tls_stream>> clients, servers;
	std::vector<std::future<std::error_code>> handshakes;
	std::vector<std::promise<std::error_code>> promises(2 * count);
	for(int i = 0; i != count; ++i) {
		auto [cs, ss] = lb.socket_pair();
		clients.push_back(lb.make_stream(std::move(cs), lb.credentials()));
		servers.push_back(lb.make_stream(std::move(ss), lb.credentials()));
	}
	for(int i = 0; i != count; ++i) {
		auto& sp = promises[static_cast<std::size_t>(2 * i)];
		auto& cp = promises[static_cast<std::size_t>(2 * i + 1)];
		handshakes.push_back(sp.get_future());
		handshakes.push_back(cp.get_future());
		servers[static_cast<std::size_t>(i)]->async_handshake(tls_role::server, [&sp](std::error_code ec) { sp.set_value(ec); });
		clients[static_cast<std::size_t>(i)]->async_handshake(tls_role::client, [&cp](std::error_code ec) { cp.set_value(ec); });
	}
	for(auto& f : handshakes) {
		CHECK(!loopback::wait(f));
	}
	for(int i = 0; i != count; ++i) {
		auto idx = static_cast<std::size_t>(i);
		octet_vector payload(1000 + idx, static_cast<std::uint8_t>(i));
		CHECK(echo(clients[idx], servers[idx], payload) == payload);
	}
}

}
