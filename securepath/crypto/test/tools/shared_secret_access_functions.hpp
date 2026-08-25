// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/crypto/shared_secret_access.hpp>

namespace securepath::crypto::test {

inline
auto shared_secret_find_func(shared_secret_access_ptr access) {
	return [access](octet_span const& key){ return access->find(key); };
}

inline
auto shared_secret_insert_func(shared_secret_access_ptr access) {
	return [access](octet_span const& key, octet_span const& data){ access->insert(key, data); };
}

inline
auto shared_secret_remove_func(shared_secret_access_ptr access) {
	return [access](octet_span const& key){ access->remove(key); };
}

}
