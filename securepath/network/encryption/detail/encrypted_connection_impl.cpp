// SPDX-License-Identifier: MIT

#include "encrypted_connection_impl.hpp"

#include <securepath/network/encryption/error.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/error.hpp>

#include <asio/bind_executor.hpp>
#include <asio/connect.hpp>
#include <asio/dispatch.hpp>
#include <asio/post.hpp>

namespace securepath::network::detail {

using namespace std::literals;

encrypted_connection_impl::encrypted_connection_impl(encrypted_connection* client, context& c,
	std::shared_ptr<encrypted_server> s, handshake_data data)
: context_(c)
, server_(std::move(s))
, strand_(asio::make_strand(c.io_context()))
, resolver_(c.io_context())
, timer_(c.io_context())
, socket_(c.io_context())
, client_(client)
, handshake_data_(std::move(data))
{
}

encrypted_connection_impl::~encrypted_connection_impl() {
	LOG_TRACE("destructing encrypted_connection impl {}", static_cast<void*>(this));
}

asio::ip::tcp::socket& encrypted_connection_impl::plain_socket() {
	return tls_ ? tls_->socket() : socket_;
}

std::optional<crypto::public_key_id> encrypted_connection_impl::remote_key_id() const {
	std::unique_lock l{mutex_};
	return remote_kid_;
}

tcp_endpoint encrypted_connection_impl::local_endpoint() const {
	std::unique_lock l{mutex_};
	return local_endpoint_;
}

tcp_endpoint encrypted_connection_impl::remote_endpoint() const {
	std::unique_lock l{mutex_};
	return remote_endpoint_;
}

octet_vector encrypted_connection_impl::exporter(std::string_view label, octet_span ctx, std::size_t length) {
	return tls_->exporter(label, std::string_view(reinterpret_cast<char const*>(ctx.data()), ctx.size()), length);
}

// ---- connect / accept -----------------------------------------------------------------------

void encrypted_connection_impl::connect(std::string_view network_address, std::uint16_t port,
	std::chrono::seconds timeout)
{
	if(state_ != encrypted_connection::not_connected) {
		throw securepath::error(securepath::errc::invalid_state, "invalid state when connecting");
	}
	state_ = encrypted_connection::connecting;
	std::string address{network_address};
	handshake_data_.set_network_address(address);
	resolver_.async_resolve(address, std::to_string(port),
		asio::bind_executor(strand_, [this, self = shared_from_this(), address](std::error_code ec, auto res) {
			on_resolve(address, ec, res);
		}));
	start_timeout(timeout);
}

void encrypted_connection_impl::on_resolve(std::string network_address, std::error_code error,
	asio::ip::tcp::resolver::results_type res)
{
	if(!error && client_) {
		asio::async_connect(socket_, res,
			asio::bind_executor(strand_, [this, self = shared_from_this(), network_address](std::error_code ec, asio::ip::tcp::endpoint const& ep) {
				on_connect(network_address, ec, ep);
			}));
	} else if(error != asio::error::operation_aborted) {
		handle_disconnect(error);
	}
}

void encrypted_connection_impl::on_connect(std::string network_address, std::error_code error,
	asio::ip::tcp::endpoint ep)
{
	if(!error && client_) {
		start_tls(endpoint_role::client);
	} else if(error != asio::error::operation_aborted) {
		handle_disconnect(error);
	}
}

void encrypted_connection_impl::start_server_handshake(std::chrono::seconds timeout) {
	state_ = encrypted_connection::connecting;
	start_timeout(timeout);
	asio::dispatch(strand_, [this, self = shared_from_this()] {
		if(client_) {
			start_tls(endpoint_role::server);
		}
	});
}

void encrypted_connection_impl::start_tls(endpoint_role role) {
	role_ = role;
	{
		std::error_code ec;
		std::unique_lock l{mutex_};
		local_endpoint_ = socket_.local_endpoint(ec);
		remote_endpoint_ = socket_.remote_endpoint(ec);
	}
	tls_ = std::make_shared<tls_stream>(std::move(socket_), strand_, context_.credentials(), context_.tls_group());
	auto tls_role_value = role == endpoint_role::client ? tls_role::client : tls_role::server;
	tls_->async_handshake(tls_role_value, asio::bind_executor(strand_,
		[this, self = shared_from_this()](std::error_code ec) {
			on_tls_handshake(ec);
		}));
}

// ---- sp handshake ---------------------------------------------------------------------------

void encrypted_connection_impl::on_tls_handshake(std::error_code ec) {
	if(ec) {
		handle_disconnect(ec);
		return;
	}
	reader_ = std::make_unique<frame_reader>(tls_);
	// keep pre-auth allocations small until the peer is authenticated
	reader_->set_max_frame_size(max_handshake_frame_size);
	auto exporter = [this, self = shared_from_this()](std::string_view label, octet_span ctx, std::size_t len) {
		return this->exporter(label, ctx, len);
	};
	handshake_ = std::make_unique<handshake>(context_, std::move(exporter), role_);
	if(role_ == endpoint_role::client) {
		advance_handshake(handshake_->start(handshake_data_));
	} else {
		start_sp_handshake();
	}
}

void encrypted_connection_impl::start_sp_handshake() {
	reader_->async_receive_frame(asio::bind_executor(strand_,
		[this, self = shared_from_this()](std::error_code ec, octet_vector frame) {
			on_handshake_frame(ec, std::move(frame));
		}));
}

void encrypted_connection_impl::on_handshake_frame(std::error_code ec, octet_vector frame) {
	if(ec) {
		handle_disconnect(ec);
		return;
	}
	handshake_result res;
	try {
		res = handshake_->handle_packet(frame);
	} catch(std::exception const& ex) {
		LOG_WARN("handshake packet failed: {}", ex.what());
	}
	advance_handshake(res);
}

void encrypted_connection_impl::advance_handshake(handshake_result const& res) {
	if(res.state == handshake_op_state::error) {
		handle_disconnect(make_error_code(errc::handshake_failed));
		return;
	}
	if(!res.packet.empty()) {
		async_send_frame(tls_, res.packet, asio::bind_executor(strand_,
			[this, self = shared_from_this()](std::error_code ec) {
				if(ec) {
					handle_disconnect(ec);
				}
			}));
	}
	if(res.state == handshake_op_state::succeeded) {
		become_connected();
	} else {
		start_sp_handshake();
	}
}

void encrypted_connection_impl::become_connected() {
	std::error_code ec;
	timer_.cancel(ec);
	{
		std::unique_lock l{mutex_};
		remote_kid_ = handshake_->remote_key_id();
	}
	state_ = encrypted_connection::connected;
	is_connected_ = true;
	// the peer is authenticated now; allow full-size application frames
	reader_->set_max_frame_size(max_frame_size);
	notify_connected();
	receive_data();
	do_send();
}

// ---- data transfer --------------------------------------------------------------------------

void encrypted_connection_impl::receive_data() {
	if(!is_connected_ || !client_) {
		return;
	}
	reader_->async_receive_frame(asio::bind_executor(strand_,
		[this, self = shared_from_this()](std::error_code ec, octet_vector frame) {
			on_data_frame(ec, std::move(frame));
		}));
}

void encrypted_connection_impl::on_data_frame(std::error_code ec, octet_vector frame) {
	if(ec) {
		handle_disconnect(ec);
		return;
	}
	notify_received(octet_span(frame));
	receive_data();
}

void encrypted_connection_impl::send(octet_span data) {
	{
		std::unique_lock l{mutex_};
		out_queue_.emplace_back(data.begin(), data.end());
	}
	if(is_connected_) {
		asio::post(strand_, [this, self = shared_from_this()] { do_send(); });
	}
}

void encrypted_connection_impl::do_send() {
	octet_vector payload;
	{
		std::unique_lock l{mutex_};
		if(writing_ || out_queue_.empty() || !is_connected_) {
			return;
		}
		writing_ = true;
		payload = std::move(out_queue_.front());
		out_queue_.pop_front();
	}
	std::size_t size = payload.size();
	async_send_frame(tls_, payload, asio::bind_executor(strand_,
		[this, self = shared_from_this(), size](std::error_code ec) {
			{
				std::unique_lock l{mutex_};
				writing_ = false;
			}
			if(ec) {
				handle_disconnect(ec);
			} else {
				notify_sent(size);
				do_send();
			}
		}));
}

// ---- timeout / shutdown ---------------------------------------------------------------------

void encrypted_connection_impl::start_timeout(std::chrono::seconds timeout) {
	timer_.expires_after(timeout);
	timer_.async_wait(asio::bind_executor(strand_, [this, self = shared_from_this()](std::error_code ec) {
		on_timeout(ec);
	}));
}

void encrypted_connection_impl::on_timeout(std::error_code ec) {
	if(!ec && state_ != encrypted_connection::connected) {
		LOG_TRACE("connection timed out");
		handle_disconnect(std::make_error_code(std::errc::timed_out));
	}
}

void encrypted_connection_impl::handle_disconnect(std::optional<std::error_code> const& error) {
	if(disconnected_) {
		return;
	}
	disconnected_ = true;
	is_connected_ = false;
	std::error_code ec;
	timer_.cancel(ec);
	resolver_.cancel();
	if(tls_) {
		tls_->close();
	} else if(socket_.is_open()) {
		socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
		socket_.close(ec);
	}
	securepath::error err(error.value_or(securepath::errc::not_an_error));
	if(client_) {
		auto handle = client_;
		client_ = nullptr;
		handle->on_disconnected(err);
		if(server_) {
			server_->remove(handle);
			server_.reset();
		}
	}
	is_closed_ = true;
	state_ = encrypted_connection::not_connected;
}

void encrypted_connection_impl::do_close() {
	if(server_ && client_) {
		auto server = server_;
		auto client = client_;
		asio::post(strand_, [self = shared_from_this(), server, client] { server->remove(client); });
		server_.reset();
	}
	client_ = nullptr;
	handle_disconnect(std::nullopt);
}

void encrypted_connection_impl::close() {
	if(is_closed_.exchange(true)) {
		return;
	}
	if(strand_.running_in_this_thread()) {
		do_close();
		return;
	}
	bool done{};
	std::condition_variable cond;
	auto self = shared_from_this();
	asio::dispatch(strand_, [this, self, &done, &cond] {
		do_close();
		std::unique_lock l{mutex_};
		done = true;
		cond.notify_all();
	});
	std::unique_lock l{mutex_};
	for(; !cond.wait_for(l, 50ms, [&done] { return done; });) {
		// the io_context may already be stopped (tear-down with the connection still queued in a
		// cancelled handler); no thread will ever run the dispatch, so finish the close inline —
		// with a stopped io_context nothing runs concurrently on the strand
		if(context_.io_context().stopped()) {
			l.unlock();
			do_close();
			return;
		}
	}
}

// ---- notifications (always on the strand) ---------------------------------------------------

void encrypted_connection_impl::notify_connected() {
	if(client_) {
		client_->on_connected();
	}
}

void encrypted_connection_impl::notify_sent(std::size_t bytes) {
	if(client_) {
		client_->on_sent(bytes);
	}
}

void encrypted_connection_impl::notify_received(octet_span data) {
	if(client_) {
		client_->on_received(data);
	}
}

}
