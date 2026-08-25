// SPDX-License-Identifier: MIT

#pragma once

#include "context.hpp"
#include "encrypted_connection.hpp"

#include <chrono>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace securepath::network {

/**
 * Accepts encrypted connections and owns each one until it is closed. The virtual callbacks are
 * serialised per connection on its strand.
 */
class encrypted_server : public std::enable_shared_from_this<encrypted_server> {
public:
	explicit encrypted_server(network::context&);
	virtual ~encrypted_server();

	void start(tcp_endpoint const& endpoint, std::chrono::seconds timeout = 10s);
	void close();
	network::context& context() const;
	/// the endpoint the acceptor is bound to (with the real port when started with port 0)
	tcp_endpoint local_endpoint() const;

protected:
	virtual std::shared_ptr<encrypted_connection> create_connection();
	virtual void on_accept(std::shared_ptr<encrypted_connection> const&) {}

private:
	encrypted_server(encrypted_server const&) = delete;
	encrypted_server& operator=(encrypted_server const&) = delete;

	friend class detail::encrypted_connection_impl;

	void start_accept();
	void on_accepted(std::shared_ptr<encrypted_connection>, std::error_code error);
	void remove(void*);

	mutable std::recursive_mutex mutex_;
	network::context& context_;
	std::chrono::seconds timeout_{10s};
	asio::ip::tcp::acceptor acceptor_;
	std::unordered_map<void*, std::shared_ptr<encrypted_connection>> sessions_;
};

}
