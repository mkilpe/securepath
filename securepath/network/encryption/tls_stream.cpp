// SPDX-License-Identifier: MIT

#include "tls_stream.hpp"

#include <securepath/log/log.hpp>
#include <securepath/util/error.hpp>

#include <asio/bind_executor.hpp>
#include <asio/dispatch.hpp>
#include <asio/post.hpp>
#include <asio/write.hpp>
#include <botan/auto_rng.h>
#include <botan/credentials_manager.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/tls_alert.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_client.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/tls_server.h>
#include <botan/tls_session.h>
#include <botan/tls_session_manager_noop.h>
#include <botan/tls_version.h>
#include <botan/x509_key.h>

#include <algorithm>
#include <exception>
#include <utility>

namespace securepath::network {

namespace {

class raw_key_credentials final : public Botan::Credentials_Manager {
public:
	explicit raw_key_credentials(Botan::RandomNumberGenerator& rng)
	: key_(std::make_shared<Botan::ECDSA_PrivateKey>(rng, Botan::EC_Group::from_name("secp256r1")))
	{}

	std::shared_ptr<Botan::Public_Key> find_raw_public_key(std::vector<std::string> const& key_types,
		std::string const&, std::string const&) override
	{
		std::shared_ptr<Botan::Public_Key> ret;
		if(std::ranges::find(key_types, key_->algo_name()) != key_types.end()) {
			ret = key_->public_key();
		}
		return ret;
	}

	std::shared_ptr<Botan::Private_Key> private_key_for(Botan::Public_Key const&, std::string const&,
		std::string const&) override
	{
		return key_;
	}

	octet_vector public_key_bits() const {
		return Botan::X509::BER_encode(*key_);
	}

private:
	std::shared_ptr<Botan::ECDSA_PrivateKey> key_;
};

class pq_tls_policy final : public Botan::TLS::Policy {
public:
	explicit pq_tls_policy(Botan::TLS::Group_Params group) : group_(group) {}

	std::vector<Botan::TLS::Group_Params> key_exchange_groups() const override { return {group_}; }
	std::vector<std::string> allowed_ciphers() const override { return {"AES-256/GCM"}; }
	std::vector<std::string> allowed_macs() const override { return {"AEAD"}; }
	std::vector<std::string> allowed_signature_methods() const override { return {"ECDSA"}; }
	bool allow_tls12() const override { return false; }
	bool allow_tls13() const override { return true; }
	std::vector<Botan::TLS::Certificate_Type> accepted_server_certificate_types() const override {
		return {Botan::TLS::Certificate_Type::RawPublicKey};
	}
	std::vector<Botan::TLS::Certificate_Type> accepted_client_certificate_types() const override {
		return {Botan::TLS::Certificate_Type::RawPublicKey};
	}
	bool require_client_certificate_authentication() const override { return true; }
	std::size_t new_session_tickets_upon_handshake_success() const override { return 0; }
	std::size_t maximum_session_tickets_per_client_hello() const override { return 0; }
	bool tls_13_middlebox_compatibility_mode() const override { return false; }

private:
	Botan::TLS::Group_Params group_;
};

std::error_code map_tls_exception(std::exception const& e, bool handshake_done) {
	LOG_WARN("tls failure: {}", e.what());
	return handshake_done ? make_error_code(errc::tls_failure) : make_error_code(errc::handshake_failed);
}

std::error_code map_socket_error(std::error_code ec) {
	std::error_code ret = ec;
	if(ec == asio::error::eof || ec == asio::error::connection_reset || ec == asio::error::operation_aborted) {
		ret = make_error_code(errc::connection_closed);
	}
	return ret;
}

}

// ---- tls_credentials -------------------------------------------------------------------------

tls_credentials::tls_credentials() {
	Botan::AutoSeeded_RNG rng;
	manager_ = std::make_shared<raw_key_credentials>(rng);
}

tls_credentials::~tls_credentials() = default;

std::shared_ptr<Botan::Credentials_Manager> const& tls_credentials::manager() const {
	return manager_;
}

octet_vector tls_credentials::public_key_bits() const {
	return static_cast<raw_key_credentials const&>(*manager_).public_key_bits();
}

std::shared_ptr<Botan::TLS::Policy const> make_pq_tls_policy(Botan::TLS::Group_Params group) {
	return std::make_shared<pq_tls_policy>(group);
}

// ---- Botan callback adapter ------------------------------------------------------------------

class tls_stream::callbacks final : public Botan::TLS::Callbacks {
public:
	explicit callbacks(tls_stream& stream) : stream_(stream) {}

	void tls_emit_data(std::span<std::uint8_t const> data) override { stream_.on_emit(data); }
	void tls_record_received(std::uint64_t, std::span<std::uint8_t const> data) override { stream_.on_record(data); }
	void tls_alert(Botan::TLS::Alert alert) override { stream_.on_alert(alert); }
	void tls_session_established(Botan::TLS::Session_Summary const& summary) override { stream_.on_established(summary); }
	void tls_session_activated() override { stream_.on_activated(); }

	/// the raw key is only a channel binder, identity is verified above TLS
	void tls_verify_raw_public_key(Botan::Public_Key const&, Botan::Usage_Type, std::string_view,
		Botan::TLS::Policy const&) override
	{}

	std::string tls_server_choose_app_protocol(std::vector<std::string> const& client_protos) override {
		std::string ret;
		if(std::ranges::find(client_protos, tls_application_protocol) != client_protos.end()) {
			ret = tls_application_protocol;
		}
		return ret;
	}

private:
	tls_stream& stream_;
};

// ---- tls_stream ------------------------------------------------------------------------------

tls_stream::tls_stream(socket_type socket, strand_type strand, std::shared_ptr<tls_credentials const> credentials,
	Botan::TLS::Group_Params group)
: socket_(std::move(socket))
, strand_(std::move(strand))
, credentials_(std::move(credentials))
, group_(group)
, rng_(std::make_shared<Botan::AutoSeeded_RNG>())
, policy_(make_pq_tls_policy(group))
, sessions_(std::make_shared<Botan::TLS::Session_Manager_Noop>())
, callbacks_(std::make_shared<callbacks>(*this))
{
}

tls_stream::~tls_stream() {
	// the channel must go before the callbacks object it points to
	channel_.reset();
}

void tls_stream::async_handshake(tls_role role, handshake_handler handler) {
	asio::dispatch(strand_, [self = shared_from_this(), role, handler = std::move(handler)]() mutable {
		if(self->channel_ || self->closed_) {
			asio::post(self->strand_, [handler = std::move(handler)] { handler(make_error_code(errc::already_connected)); });
			return;
		}
		self->handshake_ = std::move(handler);
		self->do_handshake(role);
	});
}

void tls_stream::do_handshake(tls_role role) {
	try {
		if(role == tls_role::client) {
			channel_ = std::make_unique<Botan::TLS::Client>(callbacks_, sessions_, credentials_->manager(), policy_, rng_,
				Botan::TLS::Server_Information("securepath", 0), Botan::TLS::Protocol_Version::TLS_V13,
				std::vector<std::string>{std::string(tls_application_protocol)});
		} else {
			channel_ = std::make_unique<Botan::TLS::Server>(callbacks_, sessions_, credentials_->manager(), policy_, rng_);
		}
		start_read();
	} catch(std::exception const& e) {
		fail(map_tls_exception(e, false));
	}
}

// ---- socket read side -----------------------------------------------------------------------

void tls_stream::start_read() {
	bool paused = plain_in_.size() - plain_pos_ >= read_high_water_mark;
	if(reading_ || closed_ || error_ || peer_closed_ || paused) {
		return;
	}
	reading_ = true;
	socket_.async_read_some(asio::buffer(net_in_),
		asio::bind_executor(strand_, [self = shared_from_this()](std::error_code ec, std::size_t bytes) {
			self->on_read(ec, bytes);
		}));
}

void tls_stream::on_read(std::error_code ec, std::size_t bytes) {
	reading_ = false;
	if(closed_) {
		return;
	}
	if(ec) {
		if(closing_ || activated_) {
			peer_closed_ = true;
			deliver_read();
			finish_shutdown();
		} else {
			fail(map_socket_error(ec));
		}
		return;
	}
	try {
		channel_->received_data(std::span(net_in_.data(), bytes));
	} catch(std::exception const& e) {
		fail(map_tls_exception(e, activated_));
		return;
	}
	deliver_read();
	start_read();
}

void tls_stream::on_record(std::span<std::uint8_t const> data) {
	plain_in_.insert(plain_in_.end(), data.begin(), data.end());
}

void tls_stream::compact_plain_in() {
	if(plain_pos_ == plain_in_.size()) {
		plain_in_.clear();
		plain_pos_ = 0;
	} else if(plain_pos_ > plain_in_.size() / 2) {
		plain_in_.erase(plain_in_.begin(), plain_in_.begin() + static_cast<std::ptrdiff_t>(plain_pos_));
		plain_pos_ = 0;
	}
}

void tls_stream::async_read_some(std::span<std::uint8_t> buffer, transfer_handler handler) {
	asio::dispatch(strand_, [self = shared_from_this(), buffer, handler = std::move(handler)]() mutable {
		self->do_read_some(buffer, std::move(handler));
	});
}

void tls_stream::do_read_some(std::span<std::uint8_t> buffer, transfer_handler handler) {
	if(pending_read_) {
		asio::post(strand_, [handler = std::move(handler)] {
			handler(std::make_error_code(std::errc::operation_in_progress), 0);
		});
		return;
	}
	if(closed_ || closing_) {
		asio::post(strand_, [handler = std::move(handler), ec = error_] {
			handler(ec ? ec : make_error_code(errc::connection_closed), 0);
		});
		return;
	}
	pending_buffer_ = buffer;
	pending_read_ = std::move(handler);
	deliver_read();
	start_read();
}

void tls_stream::deliver_read() {
	if(!pending_read_) {
		return;
	}
	std::size_t available = plain_in_.size() - plain_pos_;
	if(available > 0) {
		std::size_t n = std::min(available, pending_buffer_.size());
		std::copy_n(plain_in_.begin() + static_cast<std::ptrdiff_t>(plain_pos_), n, pending_buffer_.begin());
		plain_pos_ += n;
		compact_plain_in();
		auto handler = std::exchange(pending_read_, nullptr);
		handler({}, n);
	} else if(error_ || peer_closed_) {
		auto handler = std::exchange(pending_read_, nullptr);
		handler(error_ ? error_ : make_error_code(errc::connection_closed), 0);
	}
}

// ---- socket write side ----------------------------------------------------------------------

void tls_stream::on_emit(std::span<std::uint8_t const> data) {
	out_queue_.push_back({octet_vector(data.begin(), data.end()), nullptr, 0});
	start_write();
}

void tls_stream::async_write(octet_span data, transfer_handler handler) {
	asio::dispatch(strand_, [self = shared_from_this(), data = octet_vector(data.begin(), data.end()),
		handler = std::move(handler)]() mutable
	{
		self->do_write(std::move(data), std::move(handler));
	});
}

void tls_stream::do_write(octet_vector data, transfer_handler handler) {
	if(error_ || closed_ || closing_ || !activated_) {
		auto ec = error_ ? error_ : make_error_code(errc::connection_closed);
		asio::post(strand_, [handler = std::move(handler), ec] { handler(ec, 0); });
		return;
	}
	try {
		channel_->send(data);
	} catch(std::exception const& e) {
		fail(map_tls_exception(e, true));
		asio::post(strand_, [handler = std::move(handler), ec = error_] { handler(ec, 0); });
		return;
	}
	// marker: completes once every record emitted for this write has been written
	out_queue_.push_back({{}, std::move(handler), data.size()});
	start_write();
}

void tls_stream::complete_write_markers() {
	// handlers are posted, never invoked inline: a handler may start the next write and
	// re-enter start_write(), which must not race the write this sweep is part of
	while(!out_queue_.empty() && out_queue_.front().data.empty()) {
		auto item = std::move(out_queue_.front());
		out_queue_.pop_front();
		if(item.handler) {
			asio::post(strand_, [handler = std::move(item.handler), ec = error_, bytes = item.user_bytes] {
				handler(ec, ec ? 0 : bytes);
			});
		}
	}
}

void tls_stream::start_write() {
	if(writing_ || closed_) {
		return;
	}
	complete_write_markers();
	if(out_queue_.empty()) {
		if(closing_) {
			finish_shutdown();
		}
		return;
	}
	writing_ = true;
	asio::async_write(socket_, asio::buffer(out_queue_.front().data),
		asio::bind_executor(strand_, [self = shared_from_this()](std::error_code ec, std::size_t) {
			self->on_written(ec);
		}));
}

void tls_stream::on_written(std::error_code ec) {
	writing_ = false;
	if(closed_) {
		return;
	}
	if(!out_queue_.empty()) {
		out_queue_.pop_front();
	}
	if(ec) {
		fail(map_socket_error(ec));
		return;
	}
	start_write();
}

// ---- session events -------------------------------------------------------------------------

void tls_stream::on_established(Botan::TLS::Session_Summary const& summary) {
	kex_parameters_ = summary.kex_parameters().value_or("");
	LOG_TRACE("tls session established: {} {} {}", summary.version().to_string(), summary.kex_algo(), kex_parameters_);
}

void tls_stream::on_activated() {
	activated_ = true;
	if(handshake_) {
		auto handler = std::exchange(handshake_, nullptr);
		asio::post(strand_, [handler = std::move(handler)] { handler({}); });
	}
}

void tls_stream::on_alert(Botan::TLS::Alert const& alert) {
	if(alert.type() == Botan::TLS::Alert::CloseNotify) {
		LOG_TRACE("tls close_notify received");
		peer_closed_ = true;
	} else if(alert.is_fatal()) {
		LOG_WARN("tls fatal alert: {}", alert.type_string());
		fail(make_error_code(activated_ ? errc::tls_failure : errc::handshake_failed));
	}
}

// ---- shutdown / close / errors --------------------------------------------------------------

void tls_stream::async_shutdown(shutdown_handler handler) {
	asio::dispatch(strand_, [self = shared_from_this(), handler = std::move(handler)]() mutable {
		self->do_shutdown(std::move(handler));
	});
}

void tls_stream::do_shutdown(shutdown_handler handler) {
	if(closed_ || closing_ || error_) {
		auto ec = error_ ? error_ : make_error_code(errc::connection_closed);
		asio::post(strand_, [handler = std::move(handler), ec] { handler(ec); });
		return;
	}
	closing_ = true;
	shutdown_ = std::move(handler);
	if(pending_read_) {
		auto pending = std::exchange(pending_read_, nullptr);
		asio::post(strand_, [pending = std::move(pending)] {
			pending(make_error_code(errc::connection_closed), 0);
		});
	}
	try {
		if(channel_ && !channel_->is_closed_for_writing()) {
			channel_->close();
		}
	} catch(std::exception const& e) {
		LOG_WARN("tls close failed: {}", e.what());
	}
	start_write();
}

void tls_stream::finish_shutdown() {
	if(!closing_ || writing_ || !out_queue_.empty() || closed_) {
		return;
	}
	std::error_code ignored;
	socket_.shutdown(socket_type::shutdown_send, ignored);
	if(peer_closed_) {
		socket_.close(ignored);
		closed_ = true;
	}
	if(shutdown_) {
		auto handler = std::exchange(shutdown_, nullptr);
		asio::post(strand_, [handler = std::move(handler)] { handler({}); });
	}
}

void tls_stream::close() {
	asio::dispatch(strand_, [self = shared_from_this()] {
		if(self->closed_) {
			return;
		}
		self->closed_ = true;
		std::error_code ignored;
		self->socket_.close(ignored);
		self->fail_pending(self->error_ ? self->error_ : make_error_code(errc::connection_closed));
	});
}

void tls_stream::fail(std::error_code ec) {
	if(error_ || closed_) {
		return;
	}
	error_ = ec;
	closed_ = true;
	std::error_code ignored;
	socket_.close(ignored);
	fail_pending(ec);
}

void tls_stream::fail_pending(std::error_code ec) {
	if(handshake_) {
		auto handler = std::exchange(handshake_, nullptr);
		asio::post(strand_, [handler = std::move(handler), ec] { handler(ec); });
	}
	if(pending_read_) {
		auto handler = std::exchange(pending_read_, nullptr);
		asio::post(strand_, [handler = std::move(handler), ec] { handler(ec, 0); });
	}
	std::deque<out_item> queue;
	queue.swap(out_queue_);
	for(auto& item : queue) {
		if(item.handler) {
			asio::post(strand_, [handler = std::move(item.handler), ec] { handler(ec, 0); });
		}
	}
	if(shutdown_) {
		auto handler = std::exchange(shutdown_, nullptr);
		asio::post(strand_, [handler = std::move(handler), ec] { handler(ec); });
	}
}

// ---- queries --------------------------------------------------------------------------------

octet_vector tls_stream::exporter(std::string_view label, std::string_view context, std::size_t length) const {
	if(!channel_ || !activated_) {
		throw securepath::error(make_error_code(errc::invalid_data), "tls exporter requested before the handshake completed");
	}
	auto key = channel_->key_material_export(label, context, length).bits_of();
	return octet_vector(key.begin(), key.end());
}

std::optional<Botan::TLS::Group_Params> tls_stream::negotiated_group() const {
	std::optional<Botan::TLS::Group_Params> ret;
	if(activated_ && group_.to_string().value_or("?") == kex_parameters_) {
		ret = group_;
	}
	return ret;
}

std::string tls_stream::negotiated_group_name() const {
	return kex_parameters_;
}

bool tls_stream::is_active() const {
	return activated_ && !closed_ && !closing_ && !error_ && !peer_closed_;
}

std::error_code tls_stream::error() const {
	return error_;
}

tls_stream::socket_type& tls_stream::socket() {
	return socket_;
}

strand_type const& tls_stream::strand() const {
	return strand_;
}

}
