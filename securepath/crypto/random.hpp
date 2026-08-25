// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/types.hpp>

#include <cstdint>
#include <string>

namespace securepath::crypto {

std::string random_string(std::size_t size);
octet_vector random_octet_vector(std::size_t size);

void random_data(std::size_t size, std::uint8_t* out);

/// uniformly distributed random number in [min, max]
std::uint32_t random_number(std::uint32_t min, std::uint32_t max);

}
