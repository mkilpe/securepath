// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/octet_vector.hpp>
#include <string>

namespace securepath::test {

//weak pseudo random for testing only
octet_vector random_octet_vector(std::size_t size);
std::string random_string(std::size_t size);
std::uint32_t random_uint32(std::uint32_t min, std::uint32_t max);

}

