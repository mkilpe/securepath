// SPDX-License-Identifier: MIT

#pragma once

#include "auth_stream_cipher.hpp"

#include <securepath/util/types.hpp>

#include <cstdint>

namespace securepath::crypto {

/*
 * AES-256-GCM as an incremental authenticated stream cipher.
 *
 * Semantics (identical for encryptor and decryptor):
 *  - process_auth() and process() may be interleaved in any order; the tag is the
 *    standard GCM tag over AAD = concatenation of all process_auth() data and
 *    C = concatenation of all ciphertext (for a decryptor: the ciphertext fed in).
 *    Segment boundaries are not authenticated, callers feed self-delimiting data.
 *  - process() returns output immediately (CTR keystream); the tag is computed on
 *    tag(), which keeps a copy of the plaintext until then. Memory use per tag period
 *    is therefore the size of the data processed in it.
 *  - tag(out, n) writes the first n octets (1..16) of the 16-octet tag.
 *  - The decryptor computes the tag; the caller compares it (use constant time
 *    comparison, e.g. tag_matches()).
 */

std::size_t aes_gcm_key_size();
/// the nonce size, 12 octets (96 bits, the GCM recommended size, the only one supported)
std::size_t aes_gcm_iv_size();
std::size_t aes_gcm_tag_size();
/// maximum message length per nonce, (2^39)-256 bits (64 GiB)
std::uint64_t aes_gcm_max_data_size();
/// iv prefix size for the implicit counter variant (prefix 4 + counter 8 = 12 octet nonce)
std::size_t aes_gcm_implicit_counter_iv_size();

/// constant time comparison of two tags
bool tag_matches(octet_vector const& l, octet_vector const& r);

/// Normal gcm encryptor/decryptor using the given 12 octet nonce. After tag() the cipher cannot be used any more.
auth_stream_cipher_ptr create_aes_gcm_stream_encryptor(octet_vector const& key, octet_vector const& iv);
auth_stream_cipher_ptr create_aes_gcm_stream_decryptor(octet_vector const& key, octet_vector const& iv);

/**
 * Gcm encryptor/decryptor with an implicit 64-bit counter: nonce = iv (4 octets) || counter (big endian).
 * Every tag() finishes the current message and increments the counter, so the cipher handles a
 * sequence of messages. seek(counter) resets the counter and resynchronises the cipher.
 */
auth_stream_cipher_ptr create_aes_gcm_implicit_counter_stream_encryptor(octet_vector const& key, octet_vector const& iv, std::uint64_t counter = 0);
auth_stream_cipher_ptr create_aes_gcm_implicit_counter_stream_decryptor(octet_vector const& key, octet_vector const& iv, std::uint64_t counter = 0);

}
