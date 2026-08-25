// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/span.hpp>
#include <securepath/util/types.hpp>

#include <cstdint>
#include <memory>

namespace securepath::crypto {

class mac {
public:
	virtual ~mac() = default;

	virtual std::size_t size() const = 0;
	virtual std::size_t calculate(std::uint8_t const* begin, std::uint8_t const* end, std::uint8_t* out) = 0;
	/// constant time comparison of the calculated mac against the given one (size() octets)
	virtual bool verify(std::uint8_t const* begin, std::uint8_t const* end, std::uint8_t const* mac) = 0;

	octet_vector calculate(octet_span message) {
		octet_vector ret(size());
		calculate(message.data(), message.data()+message.size(), ret.data());
		return ret;
	}
	bool verify(octet_span message, octet_span mac) {
		return mac.size() == size() && verify(message.data(), message.data()+message.size(), mac.data());
	}
};

using mac_ptr = std::unique_ptr<mac>;

}
