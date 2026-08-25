// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/infrastructure/packet_transport/protocol/ports.hpp>
#include <securepath/network/encrypted_net_base.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>

using namespace std::chrono_literals;

namespace securepath::packet_transport {

struct packet_server_params : network::encrypted_net_base_params
{
	std::uint16_t port{default_packet_server_port};
	std::string packet_db{"packets.db"};

	/// this will override the above port if set
	std::optional<asio::ip::tcp::endpoint> endpoint;
	asio::ip::tcp::endpoint create_endpoint() const;

	std::chrono::seconds timeout{10s};
};


class packet_server : public network::encrypted_net_base {
public:
	explicit packet_server(packet_server_params = {});
	/// This overload uses the context for accesses instead of the databases specified in encrypted_net_base_params
	packet_server(network::context& context, packet_server_params = {});
	~packet_server();

	void close();

	/// run the io threads and start accepting connections
	int run(int net_threads, int work_threads) override;
	int run();
	int run_and_wait(int net_threads, int work_threads) override;
	int run_and_wait();

private:
	bool init() override;
	void check_key();

private:
	std::optional<network::context> server_context_store_;
	network::context* server_context_{};

	class impl;
	// encrypted_server requires this to be shared_ptr
	std::shared_ptr<impl> impl_;
};

}
