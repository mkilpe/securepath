// SPDX-License-Identifier: MIT

#pragma once

#include "error.hpp"

#include <securepath/util/span.hpp>
#include <securepath/util/types.hpp>

#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/strand.hpp>
#include <botan/tls_algos.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

namespace Botan {
	class Credentials_Manager;
	class RandomNumberGenerator;
	namespace TLS {
		class Channel;
		class Policy;
		class Session_Manager;
		class Alert;
		class Session_Summary;
	}
}

namespace securepath::network {

using strand_type = asio::strand<asio::io_context::executor_type>;

enum class tls_role {
	client,
	server
};

/**
 * TLS-level identity: an ephemeral ECDSA P-256 raw public key (RFC 7250).
 *
 * Botan's TLS can only sign handshakes with RSA/ECDSA, so this key carries no identity; it
 * merely binds the channel. The real (post-quantum) authentication happens above TLS with an
 * ML-DSA signature over exporter() (see doc/network.md). One instance per network::context.
 */
class tls_credentials {
public:
	tls_credentials();
	~tls_credentials();

	std::shared_ptr<Botan::Credentials_Manager> const& manager() const;
	/// DER encoded SubjectPublicKeyInfo of the raw key (for logging/tests)
	octet_vector public_key_bits() const;

private:
	std::shared_ptr<Botan::Credentials_Manager> manager_;
};

/// TLS 1.3 only, the given (hybrid PQ) key exchange group only, AES-256/GCM, raw public keys on
/// both sides, client authentication required, no session tickets.
std::shared_ptr<Botan::TLS::Policy const> make_pq_tls_policy(Botan::TLS::Group_Params group);

/// ALPN protocol identifier used by both sides
constexpr std::string_view tls_application_protocol{"securepath/2"};

/**
 * Asynchronous TLS 1.3 stream over a TCP socket, built on Botan::TLS::Client/Server.
 *
 * Create with std::make_shared. Every completion handler is invoked on the strand given at
 * construction; the public async_* functions may be called from any thread. Only one
 * async_read_some and any number of async_write calls may be outstanding at a time; writes
 * complete in order. exporter() and the state queries are meant to be called after the
 * handshake handler has run (e.g. from handlers on the strand).
 */
class tls_stream : public std::enable_shared_from_this<tls_stream> {
public:
	using socket_type = asio::ip::tcp::socket;
	using handshake_handler = std::function<void(std::error_code)>;
	using transfer_handler = std::function<void(std::error_code, std::size_t)>;
	using shutdown_handler = std::function<void(std::error_code)>;

	static constexpr Botan::TLS::Group_Params default_group{Botan::TLS::Group_Params::HYBRID_X25519_ML_KEM_768};
	/// socket reads pause when this much decrypted data waits for the user
	static constexpr std::size_t read_high_water_mark{1024 * 1024};

	tls_stream(socket_type socket, strand_type strand, std::shared_ptr<tls_credentials const> credentials,
		Botan::TLS::Group_Params group = default_group);
	~tls_stream();

	tls_stream(tls_stream const&) = delete;
	tls_stream& operator=(tls_stream const&) = delete;

	/// Run the TLS handshake in the given role; the handler gets the first error or success
	void async_handshake(tls_role role, handshake_handler handler);
	/// Encrypt and send data; the handler runs once the records reached the socket
	void async_write(octet_span data, transfer_handler handler);
	/// Receive some decrypted data (at least one byte unless error); one outstanding call at a time
	void async_read_some(std::span<std::uint8_t> buffer, transfer_handler handler);
	/// Send close_notify, finish pending writes and shut the socket down for sending. Any pending
	/// read completes with errc::connection_closed before the shutdown handler runs; no user
	/// handler is invoked afterwards.
	void async_shutdown(shutdown_handler handler);
	/// Abort immediately without close_notify; pending handlers complete with errc::connection_closed
	void close();

	/// RFC 5705 exporter of the established session (throws if the handshake is not complete)
	octet_vector exporter(std::string_view label, std::string_view context, std::size_t length) const;
	/// The negotiated key exchange group, when it is the configured one (nullopt before the handshake)
	std::optional<Botan::TLS::Group_Params> negotiated_group() const;
	/// Botan's name of the negotiated key exchange, e.g. "x25519/ML-KEM-768"
	std::string negotiated_group_name() const;
	/// true between the end of the handshake and close/shutdown/error
	bool is_active() const;
	/// first error seen by the stream (empty if none)
	std::error_code error() const;

	socket_type& socket();
	strand_type const& strand() const;

private:
	class callbacks;
	friend class callbacks;

	struct out_item {
		octet_vector data;
		transfer_handler handler;
		std::size_t user_bytes{};
	};

	void do_handshake(tls_role role);
	void start_read();
	void on_read(std::error_code ec, std::size_t bytes);
	void start_write();
	void on_written(std::error_code ec);
	void complete_write_markers();
	void do_write(octet_vector data, transfer_handler handler);
	void do_read_some(std::span<std::uint8_t> buffer, transfer_handler handler);
	void deliver_read();
	void do_shutdown(shutdown_handler handler);
	void finish_shutdown();
	void fail(std::error_code ec);
	void fail_pending(std::error_code ec);
	void compact_plain_in();

	// Botan callbacks (always on the strand, from within channel_ calls)
	void on_emit(std::span<std::uint8_t const> data);
	void on_record(std::span<std::uint8_t const> data);
	void on_alert(Botan::TLS::Alert const& alert);
	void on_established(Botan::TLS::Session_Summary const& summary);
	void on_activated();

private:
	socket_type socket_;
	strand_type strand_;
	std::shared_ptr<tls_credentials const> credentials_;
	Botan::TLS::Group_Params group_;
	std::shared_ptr<Botan::RandomNumberGenerator> rng_;
	std::shared_ptr<Botan::TLS::Policy const> policy_;
	std::shared_ptr<Botan::TLS::Session_Manager> sessions_;
	std::shared_ptr<callbacks> callbacks_;
	std::unique_ptr<Botan::TLS::Channel> channel_;

	handshake_handler handshake_;
	shutdown_handler shutdown_;
	std::span<std::uint8_t> pending_buffer_;
	transfer_handler pending_read_;

	std::array<std::uint8_t, 16384> net_in_{};
	octet_vector plain_in_;
	std::size_t plain_pos_{};
	std::deque<out_item> out_queue_;

	std::string kex_parameters_;
	std::error_code error_;
	bool reading_{};
	bool writing_{};
	bool activated_{};
	bool peer_closed_{};
	bool closing_{};
	bool closed_{};
};

}
