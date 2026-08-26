// SPDX-License-Identifier: MIT

#include "ss_handshake.hpp"

#include <securepath/network/encryption/error.hpp>
#include <securepath/crypto/hmac.hpp>
#include <securepath/crypto/shared_secret_access.hpp>
#include <securepath/log/log.hpp>
#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/error.hpp>

namespace securepath::network {

namespace {

// ss protocol inside the TLS channel (after the hello exchange):
//   each side --> auth_ss (the secret id, HMAC-SHA3-512 of its binding under that secret)
// Both sides hold the same secret under the same id; the client picks the id
// (context::shared_secret_id()), the server answers with the id the client used.
struct auth_ss {
	octet_vector secret_id;
	octet_vector mac;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & secret_id & mac;
	}
};

octet_vector make_auth_ss(context& c, octet_vector const& secret_id, handshake_binding const& binding) {
	auto secret = c.shared_secrets().find(octet_span(secret_id));
	if(!secret) {
		throw error(make_error_code(errc::key_not_authentic), "no shared secret for id");
	}
	auto m = crypto::create_hmac(crypto::hash_algorithm::sha3_512, *secret);
	return serialisation::asn_der_serialise(auth_ss{secret_id, m->calculate(binding.local)});
}

bool verify_auth_ss(context& c, auth_ss const& msg, handshake_binding const& binding) {
	auto secret = c.shared_secrets().find(octet_span(msg.secret_id));
	if(!secret) {
		LOG_WARN("no shared secret for peer id");
		return false;
	}
	auto m = crypto::create_hmac(crypto::hash_algorithm::sha3_512, *secret);
	return m->verify(octet_span(binding.remote), octet_span(msg.mac));
}

struct ss_handshake_base : handshake_base {
	ss_handshake_base(context& c, octet_vector secret_id, handshake_binding binding)
	: context_(c)
	, secret_id_(std::move(secret_id))
	, binding_(std::move(binding))
	{}

	int type() const override {
		return handshake_tag::shared_secret;
	}

	context& context_;
	octet_vector secret_id_;
	handshake_binding binding_;
};

struct client_ss_handshake final : ss_handshake_base {
	using ss_handshake_base::ss_handshake_base;

	handshake_result start() override {
		try {
			return handshake_result{handshake_op_state::in_progress, make_auth_ss(context_, secret_id_, binding_)};
		} catch(std::exception const& ex) {
			LOG_WARN("client ss handshake failed to start: {}", ex.what());
		}
		return handshake_result{handshake_op_state::error, {}};
	}

	handshake_result handle_packet(octet_span data) override {
		try {
			auto msg = serialisation::asn_der_deserialise<auth_ss>(data);
			if(msg.secret_id == secret_id_ && verify_auth_ss(context_, msg, binding_)) {
				return handshake_result{handshake_op_state::succeeded, {}};
			}
		} catch(std::exception const& ex) {
			LOG_WARN("client ss handshake failed: {}", ex.what());
		}
		return handshake_result{handshake_op_state::error, {}};
	}
};

struct server_ss_handshake final : ss_handshake_base {
	using ss_handshake_base::ss_handshake_base;

	handshake_result start() override {
		// the shared-secret variant reveals no identity, so the client speaks first: the server
		// sends no server-first payload and waits for the client's mac
		return handshake_result{handshake_op_state::in_progress, {}};
	}

	handshake_result handle_packet(octet_span data) override {
		try {
			auto msg = serialisation::asn_der_deserialise<auth_ss>(data);
			if(verify_auth_ss(context_, msg, binding_)) {
				return handshake_result{handshake_op_state::succeeded, make_auth_ss(context_, msg.secret_id, binding_)};
			}
		} catch(std::exception const& ex) {
			LOG_WARN("server ss handshake failed: {}", ex.what());
		}
		return handshake_result{handshake_op_state::error, {}};
	}
};

}

handshake_base_ptr construct_client_ss_handshake(context& c, handshake_data const& data) {
	return std::make_unique<client_ss_handshake>(c, c.shared_secret_id(), data.binding());
}

handshake_base_ptr construct_server_ss_handshake(context& c, handshake_data const& data) {
	return std::make_unique<server_ss_handshake>(c, c.shared_secret_id(), data.binding());
}

void enable_client_ss_handshake(context& c) {
	c.add_handshake(handshake_tag::shared_secret, [&c](handshake_data const& info) {
		return construct_client_ss_handshake(c, info);
	});
}

void enable_server_ss_handshake(context& c) {
	c.add_handshake(handshake_tag::shared_secret, [&c](handshake_data const& info) {
		return construct_server_ss_handshake(c, info);
	});
}

}
