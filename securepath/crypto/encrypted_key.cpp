// SPDX-License-Identifier: MIT

#include "encrypted_key.hpp"

#include "private_key.hpp"
#include "public_key.hpp"

#include <securepath/log/log.hpp>

namespace securepath::crypto {

encrypted_key encrypt_key(public_key const& pkey, octet_vector const& key) {
	return encrypted_key{pkey.id(), pkey.encrypt(key)};
}

octet_vector decrypt_key(private_key const& pkey, encrypted_key const& key) {
	if(key.key_id() != pkey.id()) {
		LOG_TRACE("trying to decrypt with wrong key [{} != {}]", pkey.id(), key.key_id());
		throw wrong_key();
	}
	return pkey.decrypt(key.data());
}

}
