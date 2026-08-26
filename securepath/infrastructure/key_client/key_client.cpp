// SPDX-License-Identifier: MIT

#include "key_client.hpp"
#include "events.hpp"

#include <securepath/infrastructure/key_server/protocol/protocol.hpp>

#include <securepath/network/encryption/encrypted_connection.hpp>
#include <securepath/network/encryption/error.hpp>
#include <securepath/network/encryption/handshake/pk_handshake.hpp>
#include <securepath/log/log.hpp>
#include <securepath/serialisation/util.hpp>

#include <functional>
#include <map>
#include <mutex>

namespace securepath::key_client {

namespace protocol = securepath::key_server::protocol;

namespace {

securepath::error to_error(network::net_error const& e) {
	std::string msg = e.message();
	if(!e.aux_message().empty()) {
		msg += ": " + e.aux_message();
	}
	return make_error(securepath::errc::unknown_error, msg);
}

network::handshake_data anonymous_pk_handshake() {
	// public-key handshake, no client-side host restriction; the client authenticates the server
	// but sends no credentials of its own
	return network::handshake_data{network::handshake_tag::public_key, network::pk_handshake_client_data{false}};
}

}

class client::impl : public network::encrypted_connection {
public:
	explicit impl(network::context& c)
	: encrypted_connection(c, anonymous_pk_handshake())
	{
		network::enable_client_pk_handshake(c);
	}

	template<typename Request>
	void send_request(Request const& r) {
		encrypted_connection::send(serialisation::asn_der_serialise_choice<protocol::types>(r));
	}

	std::uint32_t next_id() {
		return ++next_id_;
	}

	future<void> async_register_key(crypto::public_key const& key) {
		promise<void> pr;
		auto fut = pr.get_future();
		std::uint32_t id = 0;
		{
			std::unique_lock l{mutex_};
			id = next_id();
			register_pending_.emplace(id, std::move(pr));
		}
		send_request(protocol::register_key_request{id, key});
		return fut;
	}

	future<std::optional<crypto::public_key>> async_find_key(crypto::public_key_id const& kid) {
		promise<std::optional<crypto::public_key>> pr;
		auto fut = pr.get_future();
		std::uint32_t id = 0;
		{
			std::unique_lock l{mutex_};
			id = next_id();
			find_key_pending_.emplace(id, std::move(pr));
		}
		send_request(protocol::find_key_request{id, kid});
		return fut;
	}

	future<std::optional<crypto::certificate>> async_find_certificate(crypto::certificate_id const& cid) {
		promise<std::optional<crypto::certificate>> pr;
		auto fut = pr.get_future();
		std::uint32_t id = 0;
		{
			std::unique_lock l{mutex_};
			id = next_id();
			find_cert_pending_.emplace(id, std::move(pr));
		}
		send_request(protocol::find_certificate_request{id, cid});
		return fut;
	}

	void wait_for_connection() const {
		connect_future_.get();
	}

	void reset_connect_promise() {
		connect_promise_ = std::promise<void>{};
		connect_future_ = connect_promise_.get_future().share();
	}

	// ---- connection callbacks ----
	void on_connected() override {
		LOG_TRACE("key client connected");
		deser_.clear();
		try {
			connect_promise_.set_value();
		} catch(...) {
		}
		events_.emit<events::on_connect>();
	}

	void on_disconnected(securepath::error const& error) override {
		LOG_TRACE("key client disconnected: {}", error);
		fail_all(error ? error : make_error(network::errc::connection_closed));
		try {
			connect_promise_.set_exception(std::make_exception_ptr(
				error ? error : make_error(network::errc::connection_closed)));
		} catch(...) {
		}
		events_.emit<events::on_disconnect>(error);
	}

	void on_received(octet_span s) override {
		try {
			deser_.handle(s, std::ref(*this));
		} catch(std::exception const& ex) {
			LOG_WARN("key client error handling response: {}", ex.what());
		}
	}

	// ---- deserialiser visitor ----
	void operator()(protocol::register_key_response const& p) {
		auto pr = take(register_pending_, p.id);
		if(pr) {
			if(p.error) {
				pr->set_exception(std::make_exception_ptr(to_error(p.error)));
			} else {
				pr->set_value();
			}
		}
	}

	void operator()(protocol::find_key_response const& p) {
		auto pr = take(find_key_pending_, p.id);
		if(pr) {
			if(p.error) {
				pr->set_exception(std::make_exception_ptr(to_error(p.error)));
			} else {
				pr->set_value(p.key);
			}
		}
	}

	void operator()(protocol::find_certificate_response const& p) {
		auto pr = take(find_cert_pending_, p.id);
		if(pr) {
			if(p.error) {
				pr->set_exception(std::make_exception_ptr(to_error(p.error)));
			} else {
				pr->set_value(p.cert);
			}
		}
	}

	template<typename T>
	void operator()(T const&) {
		LOG_WARN("unexpected message on key client connection");
	}

	void fail_all(securepath::error const& err) {
		auto reg = take_all(register_pending_);
		auto fk = take_all(find_key_pending_);
		auto fc = take_all(find_cert_pending_);
		for(auto& [id, pr] : reg) {
			pr.set_exception(std::make_exception_ptr(err));
		}
		for(auto& [id, pr] : fk) {
			pr.set_exception(std::make_exception_ptr(err));
		}
		for(auto& [id, pr] : fc) {
			pr.set_exception(std::make_exception_ptr(err));
		}
	}

private:
	template<typename Map>
	std::optional<typename Map::mapped_type> take(Map& m, std::uint32_t id) {
		std::unique_lock l{mutex_};
		auto it = m.find(id);
		if(it == m.end()) {
			LOG_WARN("response for unknown request id {}", id);
			return std::nullopt;
		}
		auto pr = std::move(it->second);
		m.erase(it);
		return pr;
	}

	template<typename Map>
	Map take_all(Map& m) {
		std::unique_lock l{mutex_};
		Map out;
		out.swap(m);
		return out;
	}

public:
	event_system::broadcast_event_handler events_;

private:
	std::mutex mutex_;
	std::uint32_t next_id_{};
	std::promise<void> connect_promise_;
	std::shared_future<void> connect_future_{connect_promise_.get_future().share()};
	std::map<std::uint32_t, promise<void>> register_pending_;
	std::map<std::uint32_t, promise<std::optional<crypto::public_key>>> find_key_pending_;
	std::map<std::uint32_t, promise<std::optional<crypto::certificate>>> find_cert_pending_;
	serialisation::packet_deserialiser<protocol::types> deser_;
};

client::client()
{
	throw make_error(securepath::errc::not_supported, "key_client::client requires a network::context");
}

client::client(network::context& context)
: impl_(std::make_unique<impl>(context))
{
}

client::~client() {
	if(impl_) {
		impl_->close();
	}
}

void client::connect(std::string_view host, std::uint16_t port, std::chrono::seconds timeout) {
	impl_->reset_connect_promise();
	impl_->connect(host, port, timeout);
}

void client::close() {
	impl_->close();
	impl_->reset_connect_promise();
}

void client::wait_for_connection() const {
	impl_->wait_for_connection();
}

event_system::broadcast_event_handler& client::event_handler() noexcept {
	return impl_->events_;
}

void client::register_key(crypto::public_key const& key) {
	async_register_key(key).get();
}

std::optional<crypto::public_key> client::find_key(crypto::public_key_id const& kid) const {
	return async_find_key(kid).get();
}

std::optional<crypto::certificate> client::find_certificate(crypto::certificate_id const& cid) const {
	return async_find_certificate(cid).get();
}

future<void> client::async_register_key(crypto::public_key const& key) {
	return impl_->async_register_key(key);
}

future<std::optional<crypto::public_key>> client::async_find_key(crypto::public_key_id const& kid) const {
	return impl_->async_find_key(kid);
}

future<std::optional<crypto::certificate>> client::async_find_certificate(crypto::certificate_id const& cid) const {
	return impl_->async_find_certificate(cid);
}

}
