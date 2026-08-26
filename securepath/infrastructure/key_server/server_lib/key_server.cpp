// SPDX-License-Identifier: MIT

#include "key_server.hpp"
#include "key_server_connection.hpp"
#include "key_store.hpp"

#include <securepath/network/encryption/encrypted_server.hpp>
#include <securepath/network/encryption/handshake/pk_handshake.hpp>
#include <securepath/log/log.hpp>

namespace securepath::key_server {

asio::ip::tcp::endpoint server_params::create_endpoint() const {
	return endpoint.value_or(asio::ip::tcp::endpoint(asio::ip::address_v4::any(), port));
}

struct server::impl : network::encrypted_server {
	impl(network::context& context, key_store store)
	: encrypted_server(context)
	, context_(context)
	, store_(store)
	{
	}

	std::shared_ptr<network::encrypted_connection> create_connection() override {
		return std::make_shared<key_server_connection>(context_, shared_from_this(), store_);
	}

public:
	network::context& context_;
	key_store store_;
};

server::server(server_params params)
: encrypted_net_base(network::server_tag, params)
, params_(std::move(params))
, server_context_store_(construct_context())
, server_context_(&*server_context_store_)
, impl_(std::make_shared<impl>(*server_context_, key_store{keys(), certs()}))
{
	server_context_->set_authenticate_remote(false);
	network::enable_server_pk_handshake(*server_context_);
}

server::server(network::context& context, server_params params)
: encrypted_net_base(context)
, params_(std::move(params))
, server_context_(&context)
, impl_(std::make_shared<impl>(*server_context_, key_store{keys(), certs()}))
{
	server_context_->set_authenticate_remote(false);
	network::enable_server_pk_handshake(*server_context_);
}

server::~server() {
	close();
}

void server::close() {
	impl_->close();
	encrypted_net_base::close();
}

int server::run(int net_threads, int work_threads) {
	auto ep = params_.create_endpoint();
	LOG_INFO("Starting key server (endpoint={}:{})", ep.address().to_string(), ep.port());
	int ret = encrypted_net_base::run(net_threads, work_threads);
	if(ret == 0) {
		impl_->start(ep, params_.timeout);
	}
	return ret;
}

int server::run() {
	return run(4, 0);
}

int server::run_and_wait(int net_threads, int work_threads) {
	int ret = run(net_threads, work_threads);
	if(ret == 0) {
		encrypted_net_base::wait();
	}
	return ret;
}

int server::run_and_wait() {
	return run_and_wait(4, 0);
}

asio::ip::tcp::endpoint server::local_endpoint() const {
	return impl_->local_endpoint();
}

bool server::init() {
	return encrypted_net_base::init();
}

}
