// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/crypto/certificate.hpp>
#include <securepath/crypto/certificate_access.hpp>
#include <securepath/crypto/certificate_id.hpp>
#include <securepath/crypto/public_key.hpp>
#include <securepath/crypto/public_key_access.hpp>
#include <securepath/crypto/public_key_id.hpp>

#include <optional>

namespace securepath::key_server {

/**
 * The key-distribution operations served to unknown (anonymous) users: register a self-signed
 * public key and look up keys and certificates. This is the logic that the remote_object-based
 * unknown_user_ro_object used to expose over RPC.
 */
class key_store {
public:
	key_store(crypto::public_key_access& keys, crypto::certificate_access& certs);

	/// insert a public key; throws if the key is not self-authentic or already registered
	void register_key(crypto::public_key const& key);
	std::optional<crypto::public_key> find_key(crypto::public_key_id const& kid) const;
	std::optional<crypto::certificate> find_certificate(crypto::certificate_id const& cid) const;

private:
	crypto::public_key_access& keys_;
	crypto::certificate_access& certs_;
};

}
