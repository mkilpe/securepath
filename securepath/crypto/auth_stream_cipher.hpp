// SPDX-License-Identifier: MIT

#pragma once

#include "stream_cipher.hpp"

namespace securepath::crypto {

/**
 * Authenticated stream cipher (AEAD used incrementally).
 * process_auth() feeds additional authenticated data, process() the plaintext/ciphertext;
 * tag() produces the authentication tag over everything fed so far. See aes_gcm.hpp for
 * the ordering rules and what happens after tag().
 */
class auth_stream_cipher : public stream_cipher {
public:
	virtual std::size_t default_tag_size() const = 0;
	virtual std::size_t iv_size() const = 0;
	virtual std::uint64_t max_data_size() const = 0;
	virtual std::uint64_t max_auth_data_size() const = 0;

	virtual void process_auth(std::uint8_t const* begin, std::uint8_t const* end) = 0;
	/// writes tag_size (<= default_tag_size()) octets of the tag to out
	virtual void tag(std::uint8_t* out, std::size_t tag_size) = 0;

	void process_auth(octet_vector const& data) {
		process_auth(data.data(), data.data()+data.size());
	}

	octet_vector tag() {
		octet_vector ret(default_tag_size());
		tag(ret.data(), ret.size());
		return ret;
	}
};

using auth_stream_cipher_ptr = std::unique_ptr<auth_stream_cipher>;

}
