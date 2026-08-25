// SPDX-License-Identifier: MIT

#include "pbkdf2.hpp"
#include "types.hpp"

#include <botan/pwdhash.h>

#include <string_view>

namespace securepath::crypto {
namespace {

octet_vector pbkdf2(std::string const& algorithm, std::size_t octets, octet_span const& password, octet_span const& salt, std::size_t iterations) {
	if(password.empty() || salt.empty() || iterations == 0) {
		throw crypto_error("pbkdf2: password, salt and iterations must be non-empty");
	}
	auto pwd = Botan::PasswordHashFamily::create_or_throw(algorithm)->from_params(iterations);
	octet_vector ret(octets);
	pwd->hash(ret, std::string_view(reinterpret_cast<char const*>(password.data()), password.size()), salt);
	return ret;
}

}

octet_vector pbkdf2_hmac_sha1(std::size_t octets_to_generate, octet_span const& password, octet_span const& salt, std::size_t iterations) {
	return pbkdf2("PBKDF2(SHA-1)", octets_to_generate, password, salt, iterations);
}

octet_vector pbkdf2_hmac_sha512(std::size_t octets_to_generate, octet_span const& password, octet_span const& salt, std::size_t iterations) {
	return pbkdf2("PBKDF2(SHA-512)", octets_to_generate, password, salt, iterations);
}

}
