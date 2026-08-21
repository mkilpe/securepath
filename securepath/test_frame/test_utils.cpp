// SPDX-License-Identifier: MIT

#include "test_utils.hpp"

#include <cstdlib>
#include <random>

namespace securepath::test {

template<typename T>
T random_container(std::size_t size) {
	T res(size, 0);
	for(auto&& v : res) {
		v = std::rand() % 256;
	}
	return res;
}

octet_vector random_octet_vector(std::size_t size) {
	return random_container<octet_vector>(size);
}

std::string random_string(std::size_t size) {
	return random_container<std::string>(size);
}

std::uint32_t random_uint32(std::uint32_t min, std::uint32_t max) {
	static std::default_random_engine gen;
	std::uniform_int_distribution<std::uint32_t> uniform_dist(min, max);
	return uniform_dist(gen);
}

}
