// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/crypto/certificate.hpp>
#include <securepath/crypto/certificate_id.hpp>
#include <securepath/crypto/public_key.hpp>
#include <securepath/crypto/public_key_id.hpp>
#include <securepath/network/net_error.hpp>
#include <securepath/serialisation/sequence.hpp>
#include <securepath/util/typelist.hpp>

#include <cstdint>
#include <optional>

namespace securepath::key_server::protocol {
inline namespace v1 {

std::uint16_t const current_version{1};

/// client -> server: register a self-signed public key
struct register_key_request {
	std::uint32_t id{};
	crypto::public_key key;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & id & key;
	}
};

/// client -> server: look up a public key by its id
struct find_key_request {
	std::uint32_t id{};
	crypto::public_key_id kid;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & id & kid;
	}
};

/// client -> server: look up a certificate by its id
struct find_certificate_request {
	std::uint32_t id{};
	crypto::certificate_id cid;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & id & cid;
	}
};

/// server -> client: result of register_key_request (error set on failure)
struct register_key_response {
	std::uint32_t id{};
	network::net_error error;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & id & error;
	}
};

/// server -> client: result of find_key_request
struct find_key_response {
	std::uint32_t id{};
	std::optional<crypto::public_key> key;
	network::net_error error;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & id & key & error;
	}
};

/// server -> client: result of find_certificate_request
struct find_certificate_response {
	std::uint32_t id{};
	std::optional<crypto::certificate> cert;
	network::net_error error;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & id & cert & error;
	}
};

using serialisation::type_tag;

using types =
	typelist<type_tag<register_key_request, 1>,
			 type_tag<find_key_request, 2>,
			 type_tag<find_certificate_request, 3>,
			 type_tag<register_key_response, 4>,
			 type_tag<find_key_response, 5>,
			 type_tag<find_certificate_response, 6> >;

}
}
