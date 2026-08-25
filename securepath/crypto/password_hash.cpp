// SPDX-License-Identifier: MIT

#include "password_hash.hpp"
#include "types.hpp"

#include <botan/pwdhash.h>

#include <string_view>

namespace securepath::crypto {

octet_vector argon2id(std::size_t octets_to_generate, octet_span const& password, octet_span const& salt, argon2id_parameters const& params) {
	if(password.empty() || salt.size() < 8) {
		throw crypto_error("argon2id: password must be non-empty and salt at least 8 octets");
	}
	auto pwd = Botan::PasswordHashFamily::create_or_throw("Argon2id")->from_params(params.memory_kib, params.iterations, params.parallelism);
	octet_vector ret(octets_to_generate);
	pwd->hash(ret, std::string_view(reinterpret_cast<char const*>(password.data()), password.size()), salt);
	return ret;
}

}
