// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/types.hpp>

#include <cstdint>
#include <memory>

namespace securepath::crypto {

class stream_cipher {
public:
	virtual ~stream_cipher() = default;

	virtual std::size_t key_size() const = 0;
	/// out must have room for end-begin octets; in-place (out == begin) is allowed
	virtual void process(std::uint8_t const* begin, std::uint8_t const* end, std::uint8_t* out) = 0;
	virtual void seek(std::uint64_t pos) = 0;

	octet_vector process(octet_vector const& data) {
		octet_vector res(data.size());
		process(data.data(), data.data()+data.size(), res.data());
		return res;
	}
};

using stream_cipher_ptr = std::unique_ptr<stream_cipher>;

}
