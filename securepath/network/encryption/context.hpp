// SPDX-License-Identifier: MIT

#pragma once

#include "handshake/handshake.hpp"
#include "tls_stream.hpp"

#include <securepath/common/version_number.hpp>
#include <securepath/crypto/suite.hpp>

#include <botan/tls_algos.h>

#include <functional>
#include <map>
#include <memory>
#include <string>

namespace securepath::crypto {
	class public_key_access;
	class certificate_access;
	class shared_secret_access;
	class private_data_access;
}

namespace securepath::network {

/**
 * Shared configuration for encrypted connections: the crypto data accesses, the suite (which selects
 * the TLS key-exchange group), an ephemeral TLS channel-binding key and the handshake registry.
 * See doc/network.md.
 */
class context : public handshake_constructor {
public:
	context(asio::io_context& io
		, crypto::public_key_access& keys
		, crypto::certificate_access& certs
		, crypto::shared_secret_access& shared_secrets
		, crypto::private_data_access& data);

	asio::io_context& io_context() const;
	crypto::public_key_access& public_keys() const;
	crypto::certificate_access& certificates() const;
	crypto::shared_secret_access& shared_secrets() const;
	crypto::private_data_access& private_data() const;

	handshake_base_ptr construct_handshake(handshake_data const&) const override;
	crypto::suite suite() const override;
	void add_handshake(int tag, std::function<handshake_base_ptr(handshake_data const&)>);

	virtual version_number product_version() const;
	virtual std::string personal_identifier() const;
	virtual bool authenticate_remote() const;
	void set_authenticate_remote(bool enabled);

	void set_suite(crypto::suite);
	/// TLS key exchange group for the current suite
	Botan::TLS::Group_Params tls_group() const;
	std::shared_ptr<tls_credentials const> const& credentials() const;

	/// local identifier for the shared-secret handshake (looks up the secret shared with a peer)
	octet_vector shared_secret_id() const;
	void set_shared_secret_id(octet_vector id);

private:
	asio::io_context& io_context_;
	crypto::public_key_access& public_keys_;
	crypto::certificate_access& certs_;
	crypto::shared_secret_access& shared_secrets_;
	crypto::private_data_access& private_data_;
	std::map<int, std::function<handshake_base_ptr(handshake_data const&)>> handshakes_;
	std::shared_ptr<tls_credentials const> credentials_{std::make_shared<tls_credentials>()};
	crypto::suite suite_{crypto::default_suite()};
	octet_vector shared_secret_id_;
	bool auth_remote_{true};
};

}
