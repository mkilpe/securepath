// SPDX-License-Identifier: MIT

#pragma once

#include "defaults.hpp"

#include <securepath/network/encrypted_net_base.hpp>

#include <asio/ip/tcp.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>

using namespace std::chrono_literals;

namespace securepath::key_server {

struct server_params : network::encrypted_net_base_params {
	std::uint16_t port{default_key_server_port};
	/// overrides the port above when set
	std::optional<asio::ip::tcp::endpoint> endpoint;
	asio::ip::tcp::endpoint create_endpoint() const;
	std::chrono::seconds timeout{10s};
};

/**
 * Key distribution server for unknown (anonymous) clients. The server authenticates itself with the
 * public-key handshake; clients verify it but send no credentials of their own
 * (authenticate_remote is off). Subclass to extend it (spsync_server derives from this).
 */
class server : public network::encrypted_net_base {
public:
	explicit server(server_params = {});
	/// uses the given context for the crypto accesses instead of the databases in the params
	server(network::context& context, server_params = {});
	~server();

	void close() override;
	int run(int net_threads, int work_threads) override;
	int run();
	int run_and_wait(int net_threads, int work_threads) override;
	int run_and_wait();

	/// the endpoint the server is bound to (with the real port when started on port 0)
	asio::ip::tcp::endpoint local_endpoint() const;

protected:
	bool init() override;

private:
	server_params params_;
	std::optional<network::context> server_context_store_;
	network::context* server_context_{};

	class impl;
	// encrypted_server requires shared ownership
	std::shared_ptr<impl> impl_;
};

}
