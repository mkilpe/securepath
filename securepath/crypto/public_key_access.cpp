// SPDX-License-Identifier: MIT

#include "public_key_access.hpp"

#include <securepath/log/log.hpp>

namespace securepath::crypto {

std::optional<public_key> public_key_access::find_root_key(std::optional<public_key_id> key_id) const {
	std::optional<public_key> ret;
	if(has_root_public_key()) {
		public_key root = root_public_key();
		if(!key_id || *key_id == root.id()) {
			ret = root;
		}
	} else {
		LOG_WARN("root public key requested but none has been set");
	}
	return ret;
}

}
