// SPDX-License-Identifier: MIT

#include "key_store.hpp"

#include <securepath/crypto/error.hpp>
#include <securepath/log/log.hpp>

namespace securepath::key_server {

key_store::key_store(crypto::public_key_access& keys, crypto::certificate_access& certs)
: keys_(keys)
, certs_(certs)
{
}

void key_store::register_key(crypto::public_key const& key) {
	if(!key.verify_me()) {
		LOG_WARN("register_key: invalid public key");
		throw make_error(crypto::errc::invalid_public_key, "public key is not self-authentic");
	}
	if(keys_.find(key.id())) {
		LOG_WARN("register_key: public key {} already exists", key.id());
		throw make_error(crypto::errc::invalid_public_key, "public key already registered");
	}
	LOG_INFO("registering key {}", key.id());
	keys_.insert(key);
}

std::optional<crypto::public_key> key_store::find_key(crypto::public_key_id const& kid) const {
	LOG_TRACE("find_key({})", kid);
	return keys_.find(kid);
}

std::optional<crypto::certificate> key_store::find_certificate(crypto::certificate_id const& cid) const {
	LOG_TRACE("find_certificate({})", cid);
	return certs_.find(cid);
}

}
