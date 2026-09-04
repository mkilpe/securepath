// SPDX-License-Identifier: MIT

#include "pk_handshake.hpp"
#include "protocol.hpp"

#include <securepath/network/encryption/error.hpp>
#include <securepath/crypto/certificate_chain.hpp>
#include <securepath/crypto/private_data_access.hpp>
#include <securepath/crypto/public_key.hpp>
#include <securepath/crypto/signature.hpp>
#include <securepath/log/log.hpp>
#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/error.hpp>

#include <optional>

namespace securepath::network {

namespace {

std::string_view const auth_context{"sp-tls-auth"};

// pk protocol inside the TLS channel; the server authenticates first (its auth is carried in
// the server_hello), so the client discloses its identity only to a verified server:
//   server --> auth (credentials: server public key, chain, signature over the server binding)
//   client --> auth (credentials: client public key, chain, signature over the client binding)
//   server --> handshake_ack
// The client always authenticates the server. A client without an own key sends empty
// credentials; the server accepts that only when context.authenticate_remote() is off.
struct auth_credentials {
	crypto::public_key key;
	crypto::certificate_chain chain;
	crypto::signature sig;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & key & chain & sig;
	}
};

struct auth {
	std::optional<auth_credentials> creds;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & creds;
	}
};

auth make_auth(context& c, handshake_binding const& binding, bool required) {
	auth ret;
	auto key = c.private_data().my_private_key();
	auto chain = c.private_data().my_certificate_chain();
	if(!key || !chain) {
		if(required) {
			throw error(make_error_code(errc::invalid_data), "no own key or certificate chain");
		}
		LOG_INFO("no own credentials, sending unauthenticated auth");
		return ret;
	}
	ret.creds = auth_credentials{key->public_key(), *chain, key->sign(binding.local, auth_context)};
	return ret;
}

bool verify_credentials(context& c, auth_credentials const& creds, handshake_binding const& binding,
	crypto::key_cert_restriction const* rest)
{
	bool ok = rest
		? creds.chain.is_authentic(c.public_keys(), c.certificates(), *rest)
		: creds.chain.is_authentic(c.public_keys(), c.certificates());
	if(!ok) {
		LOG_WARN("peer certificate chain is not authentic");
		return false;
	}
	if(creds.chain.subject().id() != creds.key.id()) {
		LOG_WARN("peer key does not match its certificate chain");
		return false;
	}
	if(!creds.key.verify(creds.sig, binding.remote, auth_context)) {
		LOG_WARN("peer channel-binding signature is not valid");
		return false;
	}
	return true;
}

struct pk_handshake_base : handshake_base {
	explicit pk_handshake_base(context& c)
	: context_(c)
	{}

	int type() const override {
		return handshake_tag::public_key;
	}
	std::optional<crypto::public_key_id> remote_key_id() const override {
		return remote_kid_;
	}

	context& context_;
	std::optional<crypto::public_key_id> remote_kid_;
};

struct client_pk_handshake final : pk_handshake_base {
	client_pk_handshake(context& c, handshake_data const& data)
	: pk_handshake_base(c)
	, data_(data)
	{}

	handshake_result start() override {
		// the server authenticates first (its auth is carried in the server_hello); the client
		// never sends the first authentication message
		return handshake_result{handshake_op_state::error, {}};
	}

	handshake_result handle_packet(octet_span data) override {
		try {
			if(!server_verified_) {
				return verify_server_and_reply(data);
			}
			// second server message: acknowledgement that our auth was accepted
			auto ack = serialisation::asn_der_deserialise<handshake_protocol::handshake_ack>(data);
			if(ack.version != handshake_protocol::current_version) {
				LOG_WARN("handshake ack version {} not supported", ack.version);
				return handshake_result{handshake_op_state::error, {}};
			}
			return handshake_result{handshake_op_state::succeeded, {}};
		} catch(std::exception const& ex) {
			LOG_WARN("client pk handshake failed: {}", ex.what());
		}
		return handshake_result{handshake_op_state::error, {}};
	}

	handshake_result verify_server_and_reply(octet_span data) {
		auto msg = serialisation::asn_der_deserialise<auth>(data);
		if(!msg.creds) {
			LOG_WARN("server sent no credentials");
			return handshake_result{handshake_op_state::error, {}};
		}
		crypto::key_cert_restriction rest;
		bool restrict = data_.extract<pk_handshake_client_data>().value_or(pk_handshake_client_data{}).require_host_restriction;
		if(restrict) {
			rest.hostname(data_.network_address());
		}
		if(!verify_credentials(context_, *msg.creds, data_.binding(), restrict ? &rest : nullptr)) {
			return handshake_result{handshake_op_state::error, {}};
		}
		remote_kid_ = msg.creds->key.id();
		server_verified_ = true;
		// the server is authenticated; only now do we disclose our own identity (the client may
		// be anonymous when the server does not require client authentication). We stay
		// in-progress until the server acknowledges it accepted us.
		auto reply = make_auth(context_, data_.binding(), false);
		return handshake_result{handshake_op_state::in_progress, serialisation::asn_der_serialise(reply)};
	}

	handshake_data data_;
	bool server_verified_{};
};

struct server_pk_handshake final : pk_handshake_base {
	using pk_handshake_base::pk_handshake_base;

	handshake_result start() override {
		try {
			// the server authenticates first; this message is carried in the server_hello
			auto msg = make_auth(context_, binding_, true);
			return handshake_result{handshake_op_state::in_progress, serialisation::asn_der_serialise(msg)};
		} catch(std::exception const& ex) {
			LOG_WARN("server pk handshake failed to start: {}", ex.what());
		}
		return handshake_result{handshake_op_state::error, {}};
	}

	handshake_result handle_packet(octet_span data) override {
		try {
			auto msg = serialisation::asn_der_deserialise<auth>(data);
			if(msg.creds) {
				if(!verify_credentials(context_, *msg.creds, binding_, nullptr)) {
					return handshake_result{handshake_op_state::error, {}};
				}
				remote_kid_ = msg.creds->key.id();
			} else if(context_.authenticate_remote()) {
				LOG_WARN("client sent no credentials but authentication is required");
				return handshake_result{handshake_op_state::error, {}};
			}
			// the server's own auth was already sent with the server_hello; acknowledge the client
			// so it reports the connection established only now that we have accepted it
			handshake_protocol::handshake_ack ack;
			return handshake_result{handshake_op_state::succeeded, serialisation::asn_der_serialise(ack)};
		} catch(std::exception const& ex) {
			LOG_WARN("server pk handshake failed: {}", ex.what());
		}
		return handshake_result{handshake_op_state::error, {}};
	}

	void set_binding(handshake_binding b) {
		binding_ = std::move(b);
	}

	handshake_binding binding_;
};

}

handshake_base_ptr construct_client_pk_handshake(context& c, handshake_data const& data) {
	return std::make_unique<client_pk_handshake>(c, data);
}

handshake_base_ptr construct_server_pk_handshake(context& c, handshake_data const& data) {
	auto h = std::make_unique<server_pk_handshake>(c);
	h->set_binding(data.binding());
	return h;
}

void enable_client_pk_handshake(context& c) {
	c.add_handshake(handshake_tag::public_key, [&c](handshake_data const& info) {
		return construct_client_pk_handshake(c, info);
	});
}

void enable_server_pk_handshake(context& c) {
	c.add_handshake(handshake_tag::public_key, [&c](handshake_data const& info) {
		return construct_server_pk_handshake(c, info);
	});
}

void enable_pk_handshake(context& c) {
	c.add_handshake(handshake_tag::public_key, [&c](handshake_data const& info) {
		return info.role() == endpoint_role::server
			? construct_server_pk_handshake(c, info)
			: construct_client_pk_handshake(c, info);
	});
}

}
