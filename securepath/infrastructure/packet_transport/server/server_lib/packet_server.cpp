// SPDX-License-Identifier: MIT

#include "packet_server.hpp"
#include "connection.hpp"
#include "packet_storage.hpp"

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/network/encryption/encrypted_server.hpp>
#include <securepath/network/encryption/error.hpp>
#include <securepath/network/encryption/handshake/pk_handshake.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/server_common/key_check.hpp>

#include <cassert>
#include <format>

namespace securepath::packet_transport {

asio::ip::tcp::endpoint packet_server_params::create_endpoint() const {
	return endpoint.value_or(asio::ip::tcp::endpoint(asio::ip::address_v4::any(), port));
}

class packet_server_client
	: public connection
	, public network::encrypted_connection
{
public:
	packet_server_client(
		network::context& c,
		std::shared_ptr<network::encrypted_server> server,
		network::handshake_data hdata,
		packet_server_context& context)
	: connection(context)
	, encrypted_connection(c, std::move(hdata), server)
	{
	}

	~packet_server_client() {
		encrypted_connection::close();
	}

	void send(octet_span s) override {
		encrypted_connection::send(s);
	}

	void close() override {
		terminate(securepath::error());
	}

	void terminate(securepath::error const& err) {
		encrypted_connection::close();
		on_disconnected(err);
	}

	void on_connected() override {
		if(!remote_key_id()) {
			LOG_WARN("no client key set, closing connection...");
			terminate(make_error(protocol::errc::invalid_client_key));
		}
		// if key was set, we are waiting to receive client hello next
	}

	void on_disconnected(securepath::error const& error) override {
		LOG_TRACE("client disconnected ({}): {}", remote_key_id().value_or(crypto::public_key_id{}), error);
	}

	void on_sent(std::size_t) override {
	}

	void on_received(octet_span s) override {
		try {
			deser_.handle(s, std::ref(*this));
		} catch(error const& err) {
			LOG_WARN("error while handling packet [err={}]", err);
			terminate(err);
		} catch(...) {
			LOG_WARN("unknown exception while handling network packet");
			terminate(make_error(protocol::errc::invalid_state));
		}
	}

	void operator()(protocol::hello const& p) {
		LOG_INFO("client version: {}", p.version);
		auto key_id = remote_key_id();
		assert(key_id);
		auto err = connection::on_connect(p, *key_id);
		if(err) {
			//on_connect failed, lets close, maybe client is too old version
			LOG_INFO("failed to connect, closing connection...");
			terminate(err);
		} else {
			//all good
			connection_good_ = true;
			LOG_TRACE("client connection successfully connected ({})", *key_id);
		}
	}

	template<typename T>
	void operator()(T const& p) {
		if(connection_good_) {
			this->handle(p);
		} else {
			LOG_WARN("packets before client hello received");
			terminate(make_error(protocol::errc::invalid_state));
		}
	}

private:
	serialisation::packet_deserialiser<protocol::types> deser_;
	bool connection_good_{};
};

static database::connection_ptr open_packets_db(packet_server_params const& params) {
	auto db = database::sqlite::create_sqlite_connection(params.packet_db);
	database::sqlite::set_to_wal_mode(db);
	return db;
}

struct packet_server::impl
	: public network::encrypted_server
	, public packet_server_context
{
	impl(network::context& context, packet_server_params p)
	: encrypted_server(context)
	, context(context)
	, params(std::move(p))
	, handshake_data(network::handshake_tag::public_key)
	, storage(open_packets_db(params))
	{}

	std::shared_ptr<network::encrypted_connection> create_connection() override {
		return std::make_shared<packet_server_client>(context, shared_from_this(), handshake_data, *this);
	}

	void on_accept(std::shared_ptr<network::encrypted_connection> const&) override {
	}

	void on_connect(crypto::public_key_id const& id, std::shared_ptr<connection> conn) override {
		//add to conns
		{
			std::unique_lock l{mutex};
			conns[id] = conn;
		}
		//send pending packets from storage
		auto packets = storage.get_pending_packets(id);
		if(!packets.empty()) {
			LOG_TRACE("sending {} pending packets for {}", packets.size(), id);
			conn->send(packets);
		}
	}

	void do_ack(crypto::public_key_id const& sender, std::weak_ptr<connection> const& wconn, ack_type ack) {
		auto p = wconn.lock();
		if(p) {
			p->send(ack);
		} else {
			std::unique_lock l{mutex};
			auto it = conns.find(sender);
			if(it != conns.end()) {
				auto sp = it->second.lock();
				if(sp) {
					sp->send(ack);
				}
			}
		}
	}

	void transport_packet(crypto::public_key_id const& sender, protocol::transport_packet const& p, std::shared_ptr<connection> conn) override {
		//push to storage (push to queue to be put in db and ack when pushed there)
		std::weak_ptr<connection> wconn{conn};
		auto handle = storage.insert(p.rec.id, p.packet, p.ack, sender, [this, wconn](auto const& sender, auto ack)
			{
				do_ack(sender, wconn, ack);
			});

		//send if receivers online
		std::unique_lock l{mutex};
		auto it = conns.find(p.rec.id);
		if(it != conns.end()) {
			auto c = it->second.lock();
			if(c) {
				c->send(handle, p.packet);
			}
		}
	}

public:
	mutable std::mutex mutex;
	network::context& context;
	packet_server_params params;
	network::handshake_data handshake_data;

	packet_storage storage;
	std::unordered_map<crypto::public_key_id, std::weak_ptr<connection>> conns;
};

packet_server::packet_server(packet_server_params params)
: encrypted_net_base(network::server_tag, params)
, server_context_store_(construct_context())
, server_context_(&*server_context_store_)
, impl_(std::make_shared<impl>(*server_context_, std::move(params)))
{
	network::enable_server_pk_handshake(*server_context_);
}

packet_server::packet_server(network::context& context, packet_server_params params)
: encrypted_net_base(context)
, server_context_(&context)
, impl_(std::make_shared<impl>(*server_context_, std::move(params)))
{
}

packet_server::~packet_server() {
	close();
}

void packet_server::close() {
	impl_->close();
	encrypted_net_base::close();
}

int packet_server::run(int net_threads, int work_threads) {
	auto ep = impl_->params.create_endpoint();
	LOG_INFO("Starting packet server (endpoint={}:{})", ep.address().to_string(), ep.port());
	int ret = encrypted_net_base::run(net_threads, work_threads);
	if(ret == 0) {
		impl_->start(ep, impl_->params.timeout);
	}
	return ret;
}

int packet_server::run() {
	return run(4, 0);
}

int packet_server::run_and_wait(int net_threads, int work_threads) {
	int ret = run(net_threads, work_threads);
	if(ret == 0) {
		encrypted_net_base::wait();
	}
	return ret;
}

int packet_server::run_and_wait() {
	return run_and_wait(4, 0);
}

bool packet_server::init() {
	if(encrypted_net_base::init()) {
		check_key();
	}
	return true;
}

void packet_server::check_key() {
	server_common::check_server_key(*server_context_);
}

}
