// SPDX-License-Identifier: MIT

#include "random.hpp"
#include "detail/rng.hpp"

#include <securepath/util/byte_order.hpp>

#include <botan/system_rng.h>

#include <limits>
#include <stdexcept>

namespace securepath::crypto {

namespace detail {

Botan::RandomNumberGenerator& rng() {
	return Botan::system_rng();
}

}

namespace {

std::uint32_t next_u32() {
	std::uint8_t buf[4];
	detail::rng().randomize(buf, sizeof(buf));
	return from_endian<std::uint32_t>(buf);
}

template<typename Container>
Container random_container(std::size_t size) {
	Container ret(size, 0);
	if(size) {
		detail::rng().randomize(reinterpret_cast<std::uint8_t*>(&ret[0]), size);
	}
	return ret;
}

}

std::string random_string(std::size_t size) {
	return random_container<std::string>(size);
}

octet_vector random_octet_vector(std::size_t size) {
	return random_container<octet_vector>(size);
}

void random_data(std::size_t size, std::uint8_t* out) {
	if(size) {
		detail::rng().randomize(out, size);
	}
}

std::uint32_t random_number(std::uint32_t min, std::uint32_t max) {
	if(min > max) {
		throw std::invalid_argument("random_number: min > max");
	}
	std::uint64_t const range = std::uint64_t(max) - min + 1;
	if(range == std::uint64_t(1) << 32) {
		return next_u32();
	}
	// rejection sampling keeps the distribution uniform
	std::uint64_t const limit = (std::uint64_t(1) << 32) - ((std::uint64_t(1) << 32) % range);
	std::uint32_t v = next_u32();
	while(v >= limit) {
		v = next_u32();
	}
	return static_cast<std::uint32_t>(min + v % range);
}

}
