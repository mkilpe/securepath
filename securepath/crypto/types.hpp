// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/types.hpp>

#include <stdexcept>

namespace securepath::crypto {

struct crypto_error : std::runtime_error {
	using std::runtime_error::runtime_error;
	crypto_error() : std::runtime_error("") {}
};

/// authentication tag did not match
struct invalid_tag : crypto_error { using crypto_error::crypto_error; };
/// ciphertext could not be decrypted (wrong key, corrupt data, bad tag)
struct bad_ciphertext : crypto_error { using crypto_error::crypto_error; };
/// key material is unusable (empty key, wrong size, mismatching id)
struct invalid_key : crypto_error { using crypto_error::crypto_error; };
/// symmetric key of wrong size
struct invalid_key_size : crypto_error { using crypto_error::crypto_error; };
/// iv/nonce of wrong size
struct invalid_iv_size : crypto_error { using crypto_error::crypto_error; };
/// signature context longer than 255 octets
struct invalid_context : crypto_error { using crypto_error::crypto_error; };

}
