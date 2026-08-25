// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/crypto/public_key_access.hpp>

namespace securepath::crypto::test {

inline
auto public_key_access_find_func(public_key_access_ptr access) {
	return [access](public_key_id const& id){ return access->find(id); };
}

inline
auto public_key_access_insert_func(public_key_access_ptr access) {
	return [access](public_key const& key){ access->insert(key); };
}

inline
auto public_key_access_remove_func(public_key_access_ptr access) {
	return [access](public_key_id const& id){ access->remove(id); };
}

}
