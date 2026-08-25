// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/crypto/certificate_access.hpp>

#include <string>

namespace securepath::crypto::test {

inline
auto access_find_func(certificate_access_ptr access) {
	return [access](certificate_id const& id){ return access->find(id); };
}

inline
auto access_insert_func(certificate_access_ptr access) {
	return [access](certificate const& cert){ access->insert(cert); };
}

inline
auto access_remove_func(certificate_access_ptr access) {
	return [access](certificate_id const& id){ access->remove(id); };
}

inline
auto access_search_func(certificate_access_ptr access) {
	return [access](std::string const& identifier){ return access->search_identifier(identifier); };
}

}
