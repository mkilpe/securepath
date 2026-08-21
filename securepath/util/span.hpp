// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <span>

namespace securepath {

template<typename T>
using mutable_span = std::span<T>;

using octet_span = std::span<std::uint8_t const>;

}

