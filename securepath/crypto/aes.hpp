// SPDX-License-Identifier: MIT

#pragma once

#include "stream_cipher.hpp"

#include <securepath/util/types.hpp>

namespace securepath::crypto {

std::size_t aes_stream_cipher_key_size();
std::size_t aes_stream_cipher_iv_size();

/// AES-256 in CTR mode (big endian counter over the whole block); seekable; no authentication
stream_cipher_ptr create_aes_stream_encryptor(octet_vector const& key, octet_vector const& iv);
stream_cipher_ptr create_aes_stream_decryptor(octet_vector const& key, octet_vector const& iv);

}
