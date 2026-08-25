// SPDX-License-Identifier: MIT

#include "context.hpp"

#include <securepath/network/encryption/error.hpp>
#include <securepath/crypto/private_data_access.hpp>
#include <securepath/crypto/public_key_access.hpp>
#include <securepath/crypto/certificate_access.hpp>
#include <securepath/crypto/shared_secret_access.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/error.hpp>
#include <securepath/version.hpp>

namespace securepath::network {

context::context(asio::io_context& io
	, crypto::public_key_access& keys
	, crypto::certificate_access& certs
	, crypto::shared_secret_access& shared_secrets
	, crypto::private_data_access& data)
: io_context_(io)
, public_keys_(keys)
, certs_(certs)
, shared_secrets_(shared_secrets)
, private_data_(data)
{
}

asio::io_context& context::io_context() const {
	return io_context_;
}

crypto::public_key_access& context::public_keys() const {
	return public_keys_;
}

crypto::certificate_access& context::certificates() const {
	return certs_;
}

crypto::shared_secret_access& context::shared_secrets() const {
	return shared_secrets_;
}

crypto::private_data_access& context::private_data() const {
	return private_data_;
}

handshake_base_ptr context::construct_handshake(handshake_data const& info) const {
	auto it = handshakes_.find(info.tag());
	if(it == handshakes_.end()) {
		LOG_WARN("invalid handshake was requested: {}", info.tag());
		throw error(make_error_code(errc::no_such_handshake));
	}
	return it->second(info);
}

crypto::suite context::suite() const {
	return suite_;
}

void context::add_handshake(int tag, std::function<handshake_base_ptr(handshake_data const&)> f) {
	handshakes_[tag] = std::move(f);
}

version_number context::product_version() const {
	return library_version();
}

std::string context::personal_identifier() const {
	return "";
}

bool context::authenticate_remote() const {
	return auth_remote_;
}

void context::set_authenticate_remote(bool enabled) {
	auth_remote_ = enabled;
}

void context::set_suite(crypto::suite s) {
	suite_ = s;
}

Botan::TLS::Group_Params context::tls_group() const {
	if(suite_ == crypto::suite::pq1_high) {
		return Botan::TLS::Group_Params::HYBRID_SECP384R1_ML_KEM_1024;
	}
	return Botan::TLS::Group_Params::HYBRID_X25519_ML_KEM_768;
}

std::shared_ptr<tls_credentials const> const& context::credentials() const {
	return credentials_;
}

octet_vector context::shared_secret_id() const {
	return shared_secret_id_;
}

void context::set_shared_secret_id(octet_vector id) {
	shared_secret_id_ = std::move(id);
}

}
